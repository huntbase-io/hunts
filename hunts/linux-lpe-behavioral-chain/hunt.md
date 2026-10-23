---
analysis: 'A simple detection rule might fire on whoami run by root, but this hunt
  correlates the three-stage chain: unprivileged execution from a writable path, the
  rarity of that binary, and the eventual transition from a non-root parent to a root
  process. This context allows for a high-fidelity verdict where a single rule would
  be too noisy.'
blind_spots:
- id: short-lived-processes
  question: Can we see an exploit binary that executes and immediately deletes itself?
  requires: Real-time process event stream
  risk: A snapshot-based surface like hb_process_activity may miss the foothold binary
    if it runs between snapshots, leaving only the root shell as evidence.
  stage: payload-execution-from-writable-path
- id: in-memory-kernel-modification
  question: Did the exploit modify kernel task structures directly without spawning
    new processes?
  requires: Kernel-level auditing (auditd/eBPF)
  risk: Direct kernel memory modification that changes the UID of an existing process
    would be invisible to process launch telemetry.
  stage: kernel-exploit-privilege-gain
coverage:
- stage: payload-execution-from-writable-path
  status: covered
  steps:
  - execution-from-writable
  - rare-writable-binaries
- stage: suid-sgid-helper-abuse
  status: covered
  steps:
  - privilege-transition
- reason: While the kernel-level memory race is not visible, the resulting outcome
    (an unprivileged lineage becoming root) is tracked.
  stage: kernel-exploit-privilege-gain
  status: covered
  steps:
  - privilege-transition
  - final-assessment
- stage: post-escalation-identity-discovery
  status: covered
  steps:
  - privilege-transition
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Local privilege escalation is the critical pivot in a Linux intrusion.
    Because modern kernel exploits often share behavioral characteristics regardless
    of the bug class, a behavioral hunt is the only durable defense against undisclosed
    zero-days.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is exploiting a kernel vulnerability or a misconfigured SUID
  helper to transition from a low-privilege foothold in a writable directory to root
  privileges.
labels:
- hunt
- attack.t1190
- attack.t1548.001
- attack.t1033
- attack.t1059.004
name: Linux Local Privilege Escalation Behavior
parameters:
  discovery_commands:
    default:
    - whoami
    - id
    - logname
    description: Commands run post-escalation to verify root status.
    from:
      kind: article
      observed: '2026-09-11'
      ref: elastic-security-labs
    type: list[string]
  interpreter_parents:
    default:
    - python
    - python3
    - perl
    - ruby
    - lua
    - php
    - node
    - bash
    - sh
    description: Interpreters and shells that often spawn SUID helpers or root shells
      during exploitation.
    from:
      kind: article
      observed: '2026-09-11'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-11'
      ref: Default setting
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus the hunt; leave empty to scan all Linux
      hosts.
    from:
      kind: manual
      observed: '2026-09-11'
      ref: Analyst input
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
rationale: Start with internet-facing Linux servers and multi-user systems. Narrow
  by the active state in hb_devices to ensure telemetry is expected.
references:
- name: "Elastic Security Labs \u2014 Linux Privilege Escalation Detection Framework"
  url: https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
related:
- hunt: container-escape-to-host
  reason: Escaping a container to the host kernel is a distinct escalation path requiring
    container-specific telemetry.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Execution from Writable Path
    observables:
    - Execution from /tmp
    - Execution from /var/tmp
    - Execution from /dev/shm
    - Execution from /run/user
    - Execution from /var/run/user
    - Execution from /home
    - Parent process is an interpreter (python, perl, ruby, lua, php, node, deno,
      bun, java)
    - Parent process is a shell with command flags (-c, -cl, -lc, --command, -ic,
      -ci)
    slug: payload-execution-from-writable-path
    tactic: execution
    techniques:
    - T1105
    - T1059.004
  - name: SUID/SGID Helper Abuse
    observables:
    - su
    - sudo
    - pkexec
    - passwd
    - umount
    - process.args_count <= 2 for su
    - process.args_count == 1 for sudo or pkexec
    - stringcontains(process.executable, process.command_line)
    - Helper binary passed as an argument to another privileged binary (proxy execution)
    slug: suid-sgid-helper-abuse
    tactic: privilege-escalation
    techniques:
    - T1548.001
  - name: Kernel Exploit Privilege Escalation
    observables:
    - Copy Fail
    - DirtyFrag
    - Fragnesia
    - DirtyDecrypt
    - DirtyClone
    - pedit COW
    - RefluXFS
    - OVSwrap
    - process.user.id == 0 and process.real_user.id != 0
    - process.group.id == 0 and process.real_group.id != 0
    slug: kernel-exploit-privilege-gain
    tactic: privilege-escalation
    techniques:
    - T1548.001
  - name: Post-Escalation Identity Discovery
    observables:
    - whoami
    - id
    - logname
    slug: post-escalation-identity-discovery
    tactic: discovery
    techniques:
    - T1033
  summary: This research outlines a consistent behavioral flow in Linux local privilege
    escalation (LPE) exploits, focusing on kernel copy-on-write vulnerabilities and
    SUID/SGID helper abuse. Defenders can identify these attacks by monitoring for
    unprivileged processes executing payloads from writable directories that subsequently
    transition to root privileges (UID 0) and execute identity discovery commands.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Linux Local Privilege Escalation Behavior

This hunt identifies the behavioral signature of Linux local privilege escalation (LPE). It tracks the chain from initial execution of rare binaries in writable paths like /tmp or /dev/shm through to the moment a process transitions to root privileges, followed by standard identity discovery commands. By focusing on the privilege transition and process lineage rather than specific exploit signatures, this hunt remains effective against the Copy Fail family of kernel bugs and LLM-assisted exploit variants.

## scope-linux-hosts
<!-- Scope Linux hosts -->
Identify active Linux endpoints to narrow the search space for behavioral telemetry.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence means no Linux hosts are currently reporting
  inventory.
reads:
- hostname
- device_uid
- os_name
- platform
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname AS device_hostname, device_uid, os_name, platform FROM hb_devices WHERE (LOWER(platform) = 'linux' OR LOWER(os_name) LIKE '%ubuntu%' OR LOWER(os_name) LIKE '%debian%') AND lifecycle_state = 'active' AND time >= datetime('now', '-{{lookback_days}} days')
```

## foothold-parallel
<!-- Parallel search for suspicious footholds -->
parallel:
- → execution-from-writable
- → rare-writable-binaries
join: → triage-foothold

## execution-from-writable
<!-- Unprivileged execution from writable paths -->
Identify non-root users running binaries from /tmp, /dev/shm, or /var/tmp, which are common staging areas for exploits.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes run by normal users from writable directories. Binaries in /tmp
  are high-interest.
reads:
- device_hostname
- user_name
- process_name
- process_path
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_name, process_path, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE user_name != 'root' AND (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%' OR LOWER(process_path) LIKE '/var/tmp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-writable-binaries
<!-- Rare binaries in writable paths -->
Stack-count binaries in writable paths to highlight outliers that may be unique exploit payloads.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries running from writable paths seen on only one or two hosts across
  the fleet.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%' OR LOWER(process_path) LIKE '/var/tmp/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING host_count <= 2
```

## triage-foothold
<!-- Triage potential footholds -->
```agent target=hunter
cite: required
context:
- execution-from-writable
- rare-writable-binaries
max_iterations: 3
objective: Identify rare, non-root processes in /tmp, /dev/shm, or /var/tmp that are
  likely exploit payloads. Identify processes where the process_name does not match
  the process_path basename, which may indicate masquerading such as an sshd process
  running from /tmp.
success_criteria: A verdict for each candidate foothold, citing the rarity, path,
  and any masquerading indicators.
tools:
- endpoint
```

## privilege-transition
<!-- Privilege transition and discovery -->
Search for the second half of the LPE chain: a process becoming root or running discovery tools from an interpreter or suspicious lineage.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, interpreter_parents=interpreter_parents, discovery_commands=discovery_commands)
~~~yaml
expected: Root processes spawned by non-privileged parents or root users running discovery
  commands.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE ((user_name = 'root' AND instr(',' || '{{interpreter_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) OR (user_name = 'root' AND instr(',' || '{{discovery_commands}}' || ',', ',' || LOWER(process_name) || ',') > 0)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-assessment
<!-- Evaluate full escalation chain -->
```agent target=hunter
cite: required
context:
- triage-foothold
- privilege-transition
max_iterations: 5
objective: Link the unprivileged execution from a writable path to the subsequent
  root-level process and discovery activity on the same host.
success_criteria: A final verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## escalation-decision
<!-- Route on escalation verdict -->
if~: "the final-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → remediate-incident
unavailable: → remediate-incident (blind_spot: short-lived-processes)
else: → close-hunt

## isolate-endpoint
<!-- Isolate compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR. Preserve the contents of the identified writable directory for forensics.
```
→ remediate-incident

## remediate-incident
<!-- Incident investigation and remediation -->
```manual target=analyst
Review the process lineage on the host. Look for the binary in /tmp or /dev/shm. Check kernel logs for crashes or audit logs for SUID helper abuse. Update the kernel if a known vulnerability was used.
```
→ close-hunt

## close-hunt
<!-- Close out hunt -->
```manual target=analyst
If the result was negative, archive the hunt. If legitimate scripts triggered the rare binary baseline, add them to a local exclusion list for future runs.
```
→ end
