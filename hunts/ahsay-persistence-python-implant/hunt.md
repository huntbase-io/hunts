---
analysis: A simple detection rule for the 'kvm' task may exist, but this hunt correlates
  persistence (task/registry) with the execution of a custom implant and its C2 network
  traffic across two distinct phases. This multi-surface context is necessary to distinguish
  an intrusion from remnants of an un-remediated compromise.
blind_spots:
- id: no-process-visibility
  question: Was the Python implant executed without a corresponding process start
    event?
  requires: EDR process logging on all backup servers
  risk: A host without EDR coverage will contribute no process rows, potentially missing
    an active implant.
  stage: execution-python-implant
- id: machine-guid-hash-marker
  question: Can we identify the marker file without knowing the MachineGuid in advance?
  requires: hb_file_activity
  risk: The marker file name is unique per host; while we hunt for it, the lack of
    a known list of hashes makes detection dependent on finding the activity rather
    than the file itself.
  stage: execution-python-implant
coverage:
- stage: persistence-scheduled-task
  status: covered
  steps:
  - scheduled-task-persistence
- stage: persistence-registry-run
  status: covered
  steps:
  - registry-run-persistence
- stage: execution-python-implant
  status: covered
  steps:
  - python-implant-activity
- stage: command-and-control-https
  status: covered
  steps:
  - c2-communications
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: exploitation-ahsay-rce
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: persistence-webshells
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: defense-evasion-impair-protection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: credential-access-veeam
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: persistence-remote-access-tools
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: c2-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside an AhsayCBS Intrusion: Hidden Webshells,
    a CryptoMiner, and a C2 Implant'' series.'
  stage: impact-resource-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Backup servers are high-value targets for persistence and data theft.
    A confirmed persistent implant on these servers represents an immediate risk of
    data exfiltration or ransomware deployment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has maintained access to an exploited backup server using
  a scheduled task for a miner and a Registry Run key for a custom Python implant
  that communicates with known C2 infrastructure.
labels:
- hunt
- attack.t1053.005
- attack.t1547.001
- attack.t1059.006
- attack.t1620
- attack.t1480.001
- attack.t1071.001
- command and control
- credential access
- defense evasion
- execution
- impact
- initial access
- persistence
name: AhsayCBS Persistence and Python Implant
parameters:
  c2_domains:
    default:
    - creepexplosiondarknight.com
    - updatereceivers.do
    description: C2 domains observed in Python implant and exploit communications.
    from:
      kind: article
      observed: '2026-11-09'
      ref: huntress-ahsay-post
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-09'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: 'Optional: List of known AhsayCBS server hostnames to narrow the
      hunt.'
    from:
      kind: manual
      observed: '2026-11-09'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ahsaycbs-webshells
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers running Ahsay backup software first. Use the software
  inventory to identify targets, then broaden the search to look for the 'kvm' task
  across all servers if the initial results are sparse.
references:
- name: 'Inside an AhsayCBS Intrusion: Hidden Webshells, a CryptoMiner, and a C2 Implant'
  url: https://www.huntress.com/blog/ahsaycbs-webshells
related:
- hunt: ahsay-webshell-exploitation
  reason: Initial exploitation and the presence of webshells are handled in a separate
    hunt focused on web server directories.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AhsayCBS Remote Code Execution
    observables:
    - POST request to /rps/api/json/UpdateReceivers.do
    slug: exploitation-ahsay-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: JSP Webshell Deployment
    observables:
    - AhsayCBS.jsp
    - nsmind.jsp
    - a2b59a4bb296604b.jsp
    - status_*.jsp
    - st_*.jsp
    - Hardcoded key parameter p with hex characters followed by P
    - Payload hidden in PNG pixel data
    slug: persistence-webshells
    tactic: persistence
    techniques:
    - T1505.003
    - T1027.003
  - name: Defender Security Evasion
    observables:
    - Defender exclusions for system paths
    - Defender exclusions for .exe and .dll extensions
    - Defender exclusion for AhsayCBS service process
    slug: defense-evasion-impair-protection
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Cryptominer Task Persistence
    observables:
    - Scheduled task named kvm
    - Task running every minute as SYSTEM
    - Task XML with backdated start time
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Registry Run Key Persistence
    observables:
    - Registry Run key for main.py
    slug: persistence-registry-run
    tactic: persistence
    techniques:
    - T1547.001
  - name: Python Reflective Implant Execution
    observables:
    - main.py script
    - Embedded Python distribution
    - Reflective x64 DLL loader
    - Marker file named with SHA-256 of MachineGuid
    slug: execution-python-implant
    tactic: execution
    techniques:
    - T1059.006
    - T1620
    - T1480.001
  - name: Veeam Credential Harvesting
    observables:
    - Commands matching NetExec Veeam module for stored credentials
    slug: credential-access-veeam
    tactic: credential-access
    techniques:
    - T1555
  - name: Remote Access Software
    observables:
    - AnyDesk installation
    - Atera installation
    - Splashtop installation
    slug: persistence-remote-access-tools
    tactic: persistence
    techniques:
    - T1219
  - name: Protocol Tunneling
    observables:
    - chisel executable
    - gost executable
    - wust*a.exe and wust*b.exe in .st* folders
    slug: c2-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: HTTPS Implant C2
    observables:
    - creepexplosiondarknight.com
    - hxxps://creepexplosiondarknight.com/d
    slug: command-and-control-https
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: XMRig Resource Hijacking
    observables:
    - kvm-agent.exe
    - pool.supportxmr.com:443
    - pool-fr.supportxmr.com:443
    - 104.243.43.115:443
    slug: impact-resource-hijacking
    tactic: impact
    techniques:
    - T1496.001
  summary: Threat actors exploited unauthenticated RCE and auth bypass flaws in AhsayCBS
    backup servers to deploy multiple JSP webshell families and persistent implants.
    The intrusion involved defense evasion via Defender exclusions, a custom Python
    reflective loader communicating with creepexplosiondarknight[.]com, and the use
    of tunneling tools (Chisel, Gost) alongside XMRig cryptominers and Veeam credential
    harvesting.
series:
  index: 2
  slug: inside-an-ahsaycbs-intrusion-hidden-webshells-a-cryptominer-and-a-c2-implant
  title: 'Inside an AhsayCBS Intrusion: Hidden Webshells, a CryptoMiner, and a C2
    Implant'
  total: 3
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


# AhsayCBS Persistence and Python Implant

This hunt identifies OS-level persistence and post-exploitation activity following an AhsayCBS intrusion. It targets the 'kvm' scheduled task and the 'main.py' Python implant. The hunt follows a phased approach: first identifying the persistence mechanisms established during the 'patience' phase of the attack, then corroborating these with behavioral evidence of active implant execution and network C2 traffic. This ensures that persistence evidence is weighed against active malicious communication before containment is recommended.

## scope-ahsay-hosts
<!-- Identify hosts with Ahsay software -->
Identify potential target hosts by finding those with Ahsay software installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running Ahsay backup software. Silence indicates
  no such software is managed in inventory.
reads:
- package_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%ahsay%'
```

## find-persistence
<!-- Search for persistence mechanisms -->
parallel:
- → scheduled-task-persistence
- → registry-run-persistence
join: → evaluate-persistence

## scheduled-task-persistence
<!-- Search for the kvm cryptominer task -->
Find the scheduled task named 'kvm' used to relaunch the miner every minute.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A task named kvm or a command line running kvm-agent.exe, often as SYSTEM.
reads:
- job_name
- job_cmd_line
- device_hostname
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'kvm' OR LOWER(job_cmd_line) LIKE '%kvm-agent%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## registry-run-persistence
<!-- Search for Registry Run persistence -->
Identify the Run key established for the Python implant script.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A registry value pointing to a Python interpreter launching main.py.
reads:
- reg_target
- reg_value_data
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\\currentversion\\run%' OR LOWER(reg_target) LIKE '%\\currentversion\\runonce%') AND LOWER(reg_value_data) LIKE '%python.exe%main.py%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-persistence
<!-- Evaluate persistence evidence -->
```agent target=hunter
cite: required
context:
- scheduled-task-persistence
- registry-run-persistence
max_iterations: 3
objective: Identify hosts where the 'kvm' task or 'main.py' run key exists. Mark these
  as high-interest for activity analysis.
success_criteria: A list of hosts with confirmed persistence artifacts.
tools:
- endpoint
```

## detect-active-implant
<!-- Detect active implant activity -->
parallel:
- → python-implant-activity
- → c2-communications
join: → final-triage

## python-implant-activity
<!-- Rare Python script execution -->
Identify rare invocations of 'main.py' or Python from unusual paths to isolate the implant execution.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare command lines involving main.py, specifically those not residing in
  Program Files.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%python.exe%main.py%' OR LOWER(process_cmd_line) LIKE '%\\main.py%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3
```

## c2-communications
<!-- DNS activity for known C2 -->
Identify network resolutions to the specific C2 domains identified in the research.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any resolution of creepexplosiondarknight.com by a host already identified
  with persistence artifacts.
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## final-triage
<!-- Final triage of compromise -->
```agent target=hunter
cite: required
context:
- evaluate-persistence
- python-implant-activity
- c2-communications
max_iterations: 5
objective: Determine which hosts are compromised by correlating the earlier persistence
  findings with active process execution and C2 communications.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing persistence
  rows and activity rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Gather the 'main.py' script and identify the marker file (named with the SHA-256 of the MachineGuid) before remediation.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows for the 'kvm' task and Python execution. Verify that the Python script is not part of a legitimate administrative tool.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the identified artifacts and whether any were deleted (self-deletion). Finalize the hunt report.
```
→ end
