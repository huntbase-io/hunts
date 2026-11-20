---
analysis: This hunt correlates vulnerability state with behavioral file and script
  execution and follow-on persistence. A single rule on scheduled tasks is too noisy;
  this hunt provides the forensic triage required to link disparate stages into a
  single intrusion chain.
blind_spots:
- id: appliance-visibility-gap
  question: whether the initial bypass was executed on the appliance
  requires: EDR agent on the appliance itself
  risk: Compromise of the appliance that does not immediately result in follow-on
    activity on a monitored endpoint will be missed.
  stage: appliance-vulnerability-exploitation
- id: encrypted-reverse-shell
  question: whether the outbound traffic on common ports contains reverse shell commands
  requires: TLS decryption / PCAP
  risk: A custom shell using TLS on port 443 might be mistaken for normal web traffic
    without content inspection.
  stage: reverse-shell-c2
coverage:
- stage: appliance-vulnerability-exploitation
  status: covered
  steps:
  - vulnerability-scope
- stage: document-and-archive-delivery
  status: covered
  steps:
  - file-indicators
- stage: script-download-and-execution
  status: covered
  steps:
  - github-scripts
- stage: persistence-via-tasks-and-startup
  status: covered
  steps:
  - rare-tasks
- stage: reverse-shell-c2
  status: covered
  steps:
  - powershell-c2
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: UAT-6275 is actively targeting regional government and critical infrastructure
    with custom reverse shells; identifying these intrusions before exfiltration occurs
    is a high-priority defensive objective.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An espionage actor has established a beachhead via edge appliance exploitation
  or archive delivery, established persistence through scheduled tasks, and is maintaining
  access via a PowerShell-based reverse shell.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1133
- attack.t1190
- attack.t1204.002
- attack.t1547.001
- attack.t1071.001
- command and control
- execution
- initial access
- persistence
name: Regional Government and Infrastructure Espionage Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the behavioral queries.
    type: list[host]
  uat_filenames:
    default:
    - sample.exe
    - f_00478d.exe
    - kmsauto net.exe
    description: Filenames reported in UAT-6275 activity.
    from:
      kind: article
      observed: '2026-10-15'
      ref: talos-uat-6275-espionage
    type: list[string]
  uat_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f
    - 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
    - fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
    description: Malware hashes associated with UAT-6275 payloads.
    from:
      kind: article
      observed: '2026-10-15'
      ref: talos-uat-6275-espionage
    type: list[hash]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-q3-vulnerability-pulse-discovery-exploitation/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing Windows servers and infrastructure in the CIS
  region first. Expand to workstations if the GitHub-hosted scripts are detected on
  any beachhead host.
references:
- name: "Talos \u2014 The Q3 Vulnerability Pulse: Discovery \u2260 Exploitation"
  url: https://blog.talosintelligence.com/the-q3-vulnerability-pulse-discovery-exploitation/
related:
- hunt: winrar-vulnerability-hygiene
  reason: General WinRAR patching is a hygiene concern; this hunt specifically looks
    for the espionage actor's usage.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Edge Appliance Exploitation
    observables:
    - CVE-2026-104935
    - Ivanti Connect Secure authentication bypass
    - SonicWall SMA maximum-severity SSRF
    - unintended alternate access path
    slug: appliance-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1133
  - name: Malicious Document and Archive Delivery
    observables:
    - macro-enabled documents
    - WinRAR vulnerability exploit
    - sample.exe
    - f_00478d.exe
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f
    slug: document-and-archive-delivery
    tactic: execution
    techniques:
    - T1204.002
    - T1566.001
  - name: Script Payload Download and Execution
    observables:
    - GitHub-hosted scripts
    - PowerShell activity
    - payload downloads from public services
    - powershell.exe
    slug: script-download-and-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1105
  - name: Persistence via Tasks and Startup Folder
    observables:
    - Windows Startup folder changes
    - suspicious scheduled tasks
    - schtasks.exe
    slug: persistence-via-tasks-and-startup
    tactic: persistence
    techniques:
    - T1053.005
    - T1547.001
  - name: Reverse Shell Command and Control
    observables:
    - custom reverse shells
    - lightweight reverse shells
    slug: reverse-shell-c2
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1095
  summary: UAT-6275 is conducting an espionage campaign against government and critical
    infrastructure in the CIS region using custom reverse shells. The group utilizes
    diverse initial access vectors including phishing with macro-enabled documents,
    WinRAR exploits, and the exploitation of vulnerabilities in Ivanti and SonicWall
    appliances, maintaining persistence through scheduled tasks and the Windows Startup
    folder.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Regional Government and Infrastructure Espionage Activity

This hunt follows the tradecraft of UAT-6275, an actor targeting government and critical infrastructure for diplomatic and economic intelligence. The hunt identifies vulnerable edge appliances such as Ivanti or SonicWall, then parallels searches for malicious file drops and GitHub-hosted script execution. Following an initial triage, it shifts to finding follow-on persistence in the task scheduler and outbound reverse-shell traffic, correlating these disparate stages into a high-confidence intrusion verdict.

## vulnerability-scope
<!-- Hosts with appliance vulnerabilities -->
Scope the hunt to hosts where the environment has found appliance-based vulnerabilities like the Ivanti bypass or SonicWall SSRF.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of device UIDs affected by edge appliance vulnerabilities. Silence
  means no appliances in scope are flagged as vulnerable to these specific CVEs.
reads:
- device_uid
- cve_uid
- title
- severity
- first_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_uid, cve_uid, title, severity, first_seen FROM hb_vulnerability_finding WHERE (cve_uid = 'CVE-2026-104935' OR LOWER(title) LIKE '%ivanti%' OR LOWER(title) LIKE '%sonicwall%')
```

## initial-execution
<!-- Check for initial delivery and execution -->
parallel:
- → file-indicators
- → github-scripts
join: → early-triage

## file-indicators
<!-- Search for malicious file indicators -->
Search for specific hashes and rare files dropped by suspicious parent processes like WinRAR.

```sqlite target=endpoint role=enrichment params=(uat_hashes=uat_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any row showing known malicious hashes or files dropped by archive utilities.
  Silence means no suspicious drops were observed.
reads:
- device_hostname
- file_name
- file_path
- file_hash_sha256
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, file_name, file_hash_sha256, process_name, time FROM hb_file_activity WHERE (instr(',' || '{{uat_hashes}}' || ',', ',' || file_hash_sha256 || ',') > 0 OR LOWER(process_name) LIKE '%\\winrar.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## github-scripts
<!-- PowerShell scripts from GitHub -->
Identify PowerShell execution that pulls payloads from GitHub, a common UAT-6275 delivery method.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: PowerShell script blocks containing GitHub URLs and execution keywords,
  indicating external payload retrieval.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%github%' AND (LOWER(script_content) LIKE '%iex%' OR LOWER(script_content) LIKE '%invoke-expression%' OR LOWER(script_content) LIKE '%downloadstring%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage
<!-- Assess early infection likelihood -->
```agent target=hunter
cite: required
context:
- vulnerability-scope
- file-indicators
- github-scripts
max_iterations: 3
objective: Determine if any host in scope shows evidence of being successfully compromised
  by UAT-6275 based on the vulnerability findings and execution markers.
success_criteria: A per-host verdict citing specific vulnerability findings or script
  content.
tools:
- endpoint
- network
```

## persistence-and-c2
<!-- Check for persistence and C2 -->
parallel:
- → rare-tasks
- → powershell-c2
join: → final-triage

## rare-tasks
<!-- Rare scheduled tasks -->
Stack-count scheduled jobs to find rare persistence entries created by the actor.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Scheduled tasks with rare command lines that appear on only one or two hosts.
  Silence means no rare tasks were identified.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- job_name
- job_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT job_name, job_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_cmd_line HAVING hosts <= 2
```

## powershell-c2
<!-- PowerShell reverse-shell connections -->
Monitor for outbound TCP connections from PowerShell or known binaries to detect reverse-shell activity.

```sqlite target=network role=triage params=(uat_filenames=uat_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound connections from PowerShell or suspect binaries. Silence means
  no outbound traffic matching these patterns was found.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%\\powershell.exe' OR instr(',' || '{{uat_filenames}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Intrusion assessment -->
```agent target=hunter
cite: required
context:
- early-triage
- rare-tasks
- powershell-c2
max_iterations: 6
objective: Determine if any host showing early-stage signals also displays persistence
  (rare tasks) or C2 (outbound PowerShell), confirming the UAT-6275 espionage chain.
success_criteria: A final verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- network
```

## route-assessment
<!-- Route on assessment -->
if~: "the final triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: appliance-visibility-gap)
else: → close-out

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the endpoint agent. Collect the identified payloads for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Examine the cited rows for the PowerShell scripts and rare tasks. Verify the destination IPs for reverse-shell traffic. Escalate if persistence is confirmed.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the results. If no activity was found, verify if any new GitHub repositories have been identified for UAT-6275 and update the parameters for the next run.
```
→ end
