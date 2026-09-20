---
analysis: A standard rule may flag Node.js execution, but this hunt correlates the
  execution with fleet-wide rarity, reconnaissance-themed scripts, and internal WinRM
  traffic to distinguish an intruder from a legitimate developer.
blind_spots:
- id: encrypted-c2-tasks
  question: What specific JavaScript instructions are being sent over the randomized
    HTTPS polling?
  requires: Network TLS inspection or in-memory script capture
  risk: The intruder can change their reconnaissance patterns in memory without producing
    new on-disk artifacts, making it difficult to fully scope their actions.
  stage: node-js-implant-c2
- id: winrm-over-non-standard-ports
  question: Did the attacker move laterally over WinRM using a non-standard port?
  requires: Deep packet inspection for administrative protocols
  risk: The query specifically targets port 5985; movement on custom ports would not
    be visible here.
  stage: lateral-movement-winrm
coverage:
- stage: node-js-implant-c2
  status: covered
  steps:
  - node-execution-scoping
  - rare-node-paths
- stage: host-and-domain-reconnaissance
  status: covered
  steps:
  - recon-script-activity
- stage: lateral-movement-winrm
  status: covered
  steps:
  - winrm-internal-connections
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: it-support-social-engineering
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: malicious-msi-installation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: edge-update-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Human-operated intrusions that pivot toward identity infrastructure
    represent a critical risk of enterprise-wide compromise; identifying interactive
    implants early is essential to prevent ransomware deployment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is maintaining interactive control via a Node.js implant staged
  in a user profile, performing Active Directory reconnaissance and moving laterally
  via WinRM.
labels:
- hunt
- attack.t1071
- attack.t1090.003
- attack.t1041
- attack.t1059.001
- attack.t1218.011
- attack.t1555
name: Persistent Node.js Backdoor Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: A list of hostnames to focus the search; leave empty to hunt across
      the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hosts where users have LocalAppData execution rights and where
  external Microsoft Teams collaboration is permitted.
references:
- name: 'MSRC Blog: Impersonating IT support: how threat actors turn a remote session
    into enterprise-wide access'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: it-support-social-engineering-teams
  reason: The initial social engineering and remote session setup stage is a separate
    point of visibility.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: IT Support Social Engineering
    observables:
    - quickassist.exe
    - Microsoft Teams external contact prompts
    - Accept/Block control prompts
    slug: it-support-social-engineering
    tactic: initial-access
    techniques:
    - T1566.003
  - name: Malicious MSI Installation
    observables:
    - msiexec.exe /qn
    - devfix.msi
    - Hotfix.msi
    - PowerShell downloading from cloud storage
    slug: malicious-msi-installation
    tactic: execution
    techniques:
    - T1059.001
  - name: Implant Persistence
    observables:
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdate
    - EdgeUpdate.lnk in user Startup folder
    - WScript launching Node.js
    slug: edge-update-persistence
    tactic: persistence
    techniques:
    - T1059.001
  - name: Node.js Implant C2
    observables:
    - node.exe executing from LocalAppData
    - randomized HTTPS long-polling
    - JS loaders with .tmp, .ini, .dat, .bin, or .cfg extensions
    slug: node-js-implant-c2
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
    - T1041
  - name: Host and Domain Reconnaissance
    observables:
    - ADSI queries for domain enumeration
    - AV and VM discovery checks
    - rundll32.exe loading actor-supplied DLLs
    - Base64 encoded screenshots in temp files
    slug: host-and-domain-reconnaissance
    tactic: discovery
    techniques:
    - T1059.001
    - T1218.011
    - T1555
  - name: Lateral Movement via WinRM
    observables:
    - WinRM connections over TCP port 5985
    - Pivoting toward Domain Controllers and CAs
    slug: lateral-movement-winrm
    tactic: lateral-movement
    techniques:
    - T1059.001
  summary: Threat actors use Microsoft Teams to impersonate helpdesk personnel, tricking
    users into allowing remote control and installing a persistent Node.js implant.
    This implant enables persistent command-and-control, host discovery, and lateral
    movement via WinRM toward high-value infrastructure.
series:
  index: 2
  slug: impersonating-it-support-how-threat-actors-turn-a-remote-session-into-enterprise-wide-access
  title: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
  total: 2
severity: medium
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


# Persistent Node.js Backdoor Activity

This hunt targets the post-exploitation behavior of an adversary who has gained access through social engineering. It focuses on the unusual execution of a legitimate Node.js runtime from LocalAppData, a pattern used to evade binary-based detections. The hunt correlates this execution with rare file paths, reconnaissance-themed script blocks (ADSI, AV/VM discovery), and internal network pivoting over the WinRM protocol to identify hands-on-keyboard activity.

## node-execution-scoping
<!-- Node.js execution from user-writable paths -->
Identify hosts where the Node.js runtime or renamed copies are executing from LocalAppData, which is the primary execution pattern for this implant.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts where Node.js is running from a user profile. Legitimate development
  often uses specific paths; outliers here warrant investigation.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_original_file_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\local\%' OR LOWER(process_path) LIKE '%\users\%\appdata\%') AND (LOWER(process_name) LIKE '%node.exe' OR LOWER(process_original_file_name) = 'node.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate on multiple surfaces -->
parallel:
- → rare-node-paths
- → recon-script-activity
- → winrm-internal-connections
join: → triage-agent

## rare-node-paths
<!-- Prevalence of Node.js execution paths -->
Stack-count the execution paths to find rare, randomly named directories used for implant staging.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A path seen on only one or two hosts, which is highly characteristic of
  the randomly named staging directories in this campaign.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_original_file_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\local\%' OR LOWER(process_path) LIKE '%\users\%\appdata\%') AND (LOWER(process_name) LIKE '%node.exe' OR LOWER(process_original_file_name) = 'node.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING hosts <= 3 ORDER BY hosts ASC
```

## recon-script-activity
<!-- Discovery and reconnaissance script blocks -->
Find evidence of domain enumeration and defensive checks performed through the Node.js implant.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing ADSI search queries or WMI checks for AV and VMs.
  This is a high-confidence signal for post-exploitation discovery.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%adsisearcher%' OR LOWER(script_content) LIKE '%antivirusproduct%' OR LOWER(script_content) LIKE '%win32_videocontroller%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## winrm-internal-connections
<!-- Lateral movement over WinRM -->
Identify internal connections on port 5985, which the operator uses to pivot from the beachhead toward identity servers.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A Node.js process initiating WinRM connections to other internal hosts.
  This confirms lateral movement intent.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%node.exe' OR LOWER(process_path) LIKE '%\appdata\local\%') AND dst_endpoint_port = 5985 AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage implant behavior -->
```agent target=hunter
cite: required
context:
- node-execution-scoping
- rare-node-paths
- recon-script-activity
- winrm-internal-connections
max_iterations: 5
objective: Determine whether the Node.js activity in user profiles, the rare execution
  paths, and the subsequent WinRM or discovery behavior indicates an active hands-on-keyboard
  intrusion.
success_criteria: A per-host verdict citing the specific process paths and script
  contents that indicate malicious intent.
tools:
- endpoint
- network
```

## routing-decision
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-c2-tasks)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the Node.js binary and any .js or .tmp files found in the LocalAppData directory identified by the agent.
```
→ analyst-review

## analyst-review
<!-- Analyst verification -->
```manual target=analyst
Review the WinRM destination IPs to identify which other hosts may have been accessed. Check authentication logs for any failed or successful logons following the implant activity.
```
→ close-out

## close-out
<!-- Hunt documentation -->
```manual target=analyst
Summarize the affected user and hosts. Consider promoting the reconnaissance script query to a permanent detection rule if the false positive rate is low.
```
→ end
