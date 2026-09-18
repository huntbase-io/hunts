---
analysis: A simple rule might alert on any root process in /tmp, but this hunt uses
  fleet-wide prevalence to filter noise, scopes via known vulnerabilities, and uses
  an agent to weigh the entire lifecycle (path + root + discovery).
blind_spots:
- id: no-endpoint-telemetry
  question: whether a host without an endpoint agent is running payloads in /tmp
  requires: hb_process_activity from every host
  risk: A host missing an agent will appear silent, potentially hiding a successful
    exploit.
  stage: initial-foothold-execution
- id: in-memory-only-exploit
  question: whether an exploit was loaded as a kernel module or used a fileless mechanism
  requires: hb_module_activity and Auditd syscall logs
  risk: A purely in-memory exploit that does not drop a binary to a writable path
    will bypass the primary behavior query.
  stage: privilege-escalation-trigger
coverage:
- stage: initial-foothold-execution
  status: covered
  steps:
  - root-processes-in-writable-paths
  - rare-writable-binaries
- stage: privilege-escalation-trigger
  status: covered
  steps:
  - root-processes-in-writable-paths
  - identify-vulnerable-linux-hosts
- stage: privilege-transition-to-root
  status: covered
  steps:
  - root-processes-in-writable-paths
- stage: post-escalation-verification
  status: covered
  steps:
  - post-escalation-discovery
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Local privilege escalation is the critical pivot in Linux intrusions.
    Identifying the outcome (root transition) and precursors (writable paths) provides
    a durable defense against novel exploit implementations that bypass name-based
    rules.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has achieved root privileges on a Linux host by executing
  an exploit from a world-writable directory, followed by a transition of the process
  lineage to UID 0.
labels:
- hunt
- attack.t1548.001
- attack.t1068
- attack.t1190
- attack.t1033
name: Linux LPE via Writable Path Execution
parameters:
  discovery_tools:
    default:
    - whoami
    - id
    - logname
    - hostname
    - uname
    description: Common commands used to verify root status after escalation.
    from:
      kind: article
      observed: '2026-09-11'
      ref: Elastic LPE Research
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of process and vulnerability history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus on; leave empty to hunt across the entire
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with Linux servers hosting public-facing applications or those with
  known kernel vulnerabilities (CVEs) as identified in the scoping step.
references:
- name: 'Elastic Security Labs: Linux Detection Engineering - Local Privilege Escalation'
  url: https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
related:
- hunt: suid-helper-abuse
  reason: Focuses on the SUID helpers themselves rather than the path of execution.
  relation: sibling
scenario:
  stages:
  - name: Execution from Writable Path
    observables:
    - /tmp/*
    - /var/tmp/*
    - /dev/shm/*
    - /run/user/*
    - /var/run/user/*
    - /home/*/*
    - 'interpreter: python'
    - 'interpreter: perl'
    - 'interpreter: ruby'
    - 'interpreter: lua'
    - 'interpreter: php'
    - 'interpreter: node'
    slug: initial-foothold-execution
    tactic: execution
    techniques:
    - T1190
    - T1059.004
  - name: Exploitation of SUID Helpers or Kernel Interfaces
    observables:
    - su
    - sudo
    - pkexec
    - passwd
    - umount
    - mount
    - chsh
    - chfn
    - gpasswd
    - newgrp
    - socket
    - splice
    - bind
    - pedit COW
    - RefluXFS
    - OVSwrap
    - Copy Fail
    - DirtyFrag
    - Fragnesia
    - DirtyDecrypt
    - DirtyClone
    slug: privilege-escalation-trigger
    tactic: privilege-escalation
    techniques:
    - T1548.001
    - T1068
  - name: Privilege Transition to Root
    observables:
    - 'user_name: root'
    - process.user.id == 0
    - process.real_user.id != 0
    - uid_change to 0
    slug: privilege-transition-to-root
    tactic: privilege-escalation
    techniques:
    - T1548.001
  - name: Root Status Verification
    observables:
    - whoami
    - id
    - logname
    slug: post-escalation-verification
    tactic: discovery
    techniques:
    - T1033
  summary: Exploit binaries are executed from writable Linux directories like /tmp
    or /dev/shm to trigger kernel memory bugs or abuse SUID-root helpers. This results
    in a privilege transition where an unprivileged process lineage gains root access,
    often followed by diagnostic commands like whoami.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Linux LPE via Writable Path Execution

Local privilege escalation (LPE) in Linux often involves a predictable lifecycle: a binary is dropped into a world-writable directory like /tmp or /dev/shm, executed, and leverages a kernel vulnerability or SUID helper to gain root status. This hunt identifies this transition by monitoring processes launched from suspicious paths that eventually run as root, baselining their prevalence across the fleet to identify unique exploit payloads, and corroborating these with post-escalation discovery commands like whoami.

## identify-vulnerable-linux-hosts
<!-- Identify potentially vulnerable Linux hosts -->
Scope the hunt to Linux hosts that have reported privilege escalation vulnerabilities or general Linux devices by joining vulnerability findings with device inventory.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with known LPE vulnerabilities. This narrows the scope
  for more intensive telemetry analysis.
reads:
- device_uid
- cve_uid
- title
- status
- provider
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT d.hostname AS device_hostname, f.cve_uid, f.title FROM hb_vulnerability_finding f JOIN hb_devices d ON f.device_uid = d.device_uid WHERE (LOWER(f.title) LIKE '%privilege escalation%' OR LOWER(f.title) LIKE '%kernel%') AND f.status != 'suppressed' AND f.provider IN ('wiz', 'aws', 'vanta')
```

## parallel-evidence-gathering
<!-- Gather behavioural evidence side-by-side -->
parallel:
- → root-processes-in-writable-paths
- → rare-writable-binaries
- → post-escalation-discovery
join: → triage-escalation

## root-processes-in-writable-paths
<!-- Root processes launched from writable paths -->
Identify processes running as root whose image resides in world-writable directories, a core indicator of LPE.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A row indicates a process that achieved root privileges while running from
  a directory normally restricted for system binaries.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, parent_process_name, time FROM hb_process_activity WHERE user_name = 'root' AND (process_path LIKE '/tmp/%' OR process_path LIKE '/var/tmp/%' OR process_path LIKE '/dev/shm/%' OR process_path LIKE '/run/user/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-writable-binaries
<!-- Rare binaries in writable paths -->
Identify one-off exploit payloads by baselining the prevalence of all binaries executing from world-writable paths.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique or rare paths/binaries in /tmp or /dev/shm. Routine scripts appear
  on many hosts; exploits are typically rare.
prevalence:
  by: device_hostname
  key:
  - full_path
  - proc_name
  rare_below: 3
reads:
- process_path
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) AS full_path, LOWER(process_name) AS proc_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (process_path LIKE '/tmp/%' OR process_path LIKE '/dev/shm/%' OR process_path LIKE '/var/tmp/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY full_path, proc_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## post-escalation-discovery
<!-- Post-escalation discovery by root -->
Find root-owned discovery processes to corroborate that a privilege transition was successful and followed by verification.

```sqlite target=endpoint role=enrichment params=(discovery_tools=discovery_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A 'whoami' or 'id' command running as root. This is the 'finishing move'
  that confirms the exploit worked.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE user_name = 'root' AND instr(',' || '{{discovery_tools}}' || ',', ',' || REPLACE(REPLACE(LOWER(process_name), '/usr/bin/', ''), '/bin/', '') || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-escalation
<!-- Triage escalation evidence -->
```agent target=hunter
cite: required
context:
- root-processes-in-writable-paths
- rare-writable-binaries
- post-escalation-discovery
max_iterations: 3
objective: Determine if any host shows a rare binary running from a writable path
  that successfully transitioned to root UID, followed by discovery tools like 'whoami'.
  Cite the specific process and time of transition.
success_criteria: A verdict citing specific rows that confirm the LPE lifecycle.
tools:
- endpoint
```

## decision-route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host showing the writable-to-root flow" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → analyst-review

## contain-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the binary identified in the writable directory for reverse engineering.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the process lineage to identify the initial entry point (e.g., a vulnerable web service). Validate the rare binary and check for signs of credential theft or persistence.
```
→ end
