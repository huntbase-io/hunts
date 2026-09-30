---
analysis: A standard rule might fire on PowerShell with an encoded command, but this
  hunt correlates persistence with rare application paths and network traffic, reducing
  noise from legitimate headless conhost use.
blind_spots:
- id: no-process-visibility
  question: whether the BrowserWindow methods were overwritten in memory
  requires: EDR memory-map or runtime introspection
  risk: The hunt relies on file paths and parent processes because static analysis
    of the obfuscated JavaScript in app.asar is not performed on the endpoint.
  stage: defense-evasion-ui-suppression
- id: webdav-execution-gap
  question: whether the payload was executed from a remote WebDAV share via search-ms
  requires: hb_network_connection with WebDAV protocol details
  risk: If the attacker uses the us05.org WebDAV route, file creation events on the
    local disk are absent, leaving only network and process start events.
  stage: command-and-control-network-activity
coverage:
- stage: defense-evasion-ui-suppression
  status: covered
  steps:
  - rare-exodus-paths
- stage: persistence-headless-scheduled-task
  status: covered
  steps:
  - headless-powershell-tasks
- stage: command-and-control-network-activity
  status: covered
  steps:
  - c2-network-traffic
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: initial-access-masqueraded-javascript-dropper
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: execution-silent-msi-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: persistence-tampered-app-installation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Exodus RAT uses a legitimate, signed runtime and valid wallet
    code to bypass traditional security controls. A negative result confirms that
    these stealthy installers haven't compromised the user estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed a tampered Exodus wallet that suppresses its
  UI and maintains persistence through a headless PowerShell scheduled task while
  communicating with a hardcoded C2 IP.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1564.003
- attack.t1027
- attack.t1071.001
name: Tampered Exodus Wallet Persistence and C2
parameters:
  c2_ips:
    default:
    - 35.212.159.20
    description: Hardcoded C2 IP addresses observed in the report.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress-exodus-rat
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  task_names:
    default:
    - INetHealth
    description: Names of scheduled tasks used for persistence.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress-exodus-rat
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations where users might manage crypto assets or open documents.
  Exclude servers that do not perform user-driven web activities.
references:
- name: "Huntress \u2014 The Crypto Wallet That Never Opened"
  url: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
related:
- hunt: javascript-dropper-initial-access
  reason: The masqueraded JavaScript dropper (.pdf.js) and the initial MSI execution
    are handled by a separate hunt focused on delivery.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Masqueraded JavaScript Dropper
    observables:
    - .pdf.js
    - Update_GS_7G0N-254V38L2350.zip
    - Update_GS_7G0N-254V38L2350.js
    - storyblok.com
    - law.georgetown.edu
    - search-ms:displayname=Search Results in update (\\us05.org@8080)
    slug: initial-access-masqueraded-javascript-dropper
    tactic: initial-access
    techniques:
    - T1566.001
    - T1036.007
    - T1027.006
  - name: Silent MSI Installer Execution
    observables:
    - msiexec /i "%TEMP%\jn0101.msi" /quiet /norestart
    - msiexec /i "%TEMP%\jg0384.msi"
    - jn0101.msi
    - jg0384.msi
    slug: execution-silent-msi-installer
    tactic: execution
    techniques:
    - T1218.007
    - T1204.002
  - name: Tampered Application Installation
    observables:
    - '%APPDATA%\ExdBackupTool\'
    - Exodus.exe
    - app.asar
    - Manufacturer Apple Inc
    - ProductName Background Service
    slug: persistence-tampered-app-installation
    tactic: persistence
    techniques:
    - T1547.001
    - T1036
  - name: Electron UI Suppression
    observables:
    - exodus_patch.js
    - BrowserWindow.prototype.show
    - BrowserWindow.prototype.focus
    - BrowserWindow.prototype.center
    - explorer.exe "[INSTALLDIR]Exodus.exe"
    slug: defense-evasion-ui-suppression
    tactic: defense-evasion
    techniques:
    - T1564.003
    - T1027
  - name: Headless PowerShell Scheduled Task
    observables:
    - INetHealth
    - conhost.exe --headless
    - powershell -e
    slug: persistence-headless-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
    - T1059.001
  - name: C2 Network Activity
    observables:
    - 35.212.159.20
    - fiat.a.exodus.io
    - assets-gateway-clarity-api.a.exodus.io
    slug: command-and-control-network-activity
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Threat actors are delivering tampered Exodus cryptocurrency wallet installers
    via malicious JavaScript droppers disguised as PDF documents or software updates.
    The malicious wallet suppresses its user interface while running a modular RAT
    that maintains persistence through scheduled tasks and steals browser credentials
    while mimicking legitimate network traffic.
series:
  index: 2
  slug: the-crypto-wallet-that-never-opened-tampered-exodus-installer-hides-a-modular-rat
  title: 'The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular
    RAT'
  total: 2
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


# Tampered Exodus Wallet Persistence and C2

This hunt targets the stealthy persistence and communication phases of a modular RAT masquerading as the Exodus crypto wallet. It identifies the INetHealth scheduled task and conhost.exe headless execution patterns used to hide PowerShell scripts. It corroborates these findings by identifying rare Exodus.exe process paths in user profiles and network connections to known malicious infrastructure.

## headless-powershell-tasks
<!-- Headless PowerShell scheduled tasks -->
Identify hosts where a scheduled task uses conhost to hide a PowerShell command, matching the campaign lead.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, task_names=task_names)
~~~yaml
expected: Any scheduled task using --headless with PowerShell is suspicious. Matches
  on INetHealth are high-confidence indicators of this campaign.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (instr(',' || '{{task_names}}' || ',', ',' || job_name || ',') > 0 OR (LOWER(job_cmd_line) LIKE '%powershell%' AND LOWER(job_cmd_line) LIKE '%--headless%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Correlate execution and network activity -->
parallel:
- → rare-exodus-paths
- → c2-network-traffic
join: → triage-agent

## rare-exodus-paths
<!-- Rare Exodus paths in user profiles -->
Find instances where Exodus.exe runs from the tampered ExdBackupTool directory and stack-count to find anomalies.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The presence of Exodus.exe in AppData\ExdBackupTool is an anomaly. Legitimate
  installs typically use standard Program Files or predictable AppData paths that
  appear fleet-wide.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 5
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS exec_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\exdbackuptool\exodus.exe' OR LOWER(process_path) LIKE '%\appdata\roaming\exdbackuptool\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING host_count <= 5
```

## c2-network-traffic
<!-- Direct connections to C2 IP -->
Detect network traffic from the endpoint to the hardcoded C2 infrastructure identified in the report.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Direct connections to the C2 IP from any process, especially Exodus or PowerShell,
  indicate active communication.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage wallet threat evidence -->
```agent target=hunter
cite: required
context:
- headless-powershell-tasks
- rare-exodus-paths
- c2-network-traffic
max_iterations: 4
objective: Determine if any host shows a complete chain of headless PowerShell persistence,
  tampered application execution in ExdBackupTool, and communication with the malicious
  IP.
success_criteria: Verdicts for every host with cited evidence rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the %APPDATA%\ExdBackupTool\ directory for forensics, focusing on app.asar.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the scheduled tasks and process command lines for any hosts marked suspicious. Check for web browser history related to JavaScript spam as noted in the report.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the number of hosts identified with tampered wallet installations. Recommend promoting the INetHealth task and headless PowerShell patterns to standing rules.
```
→ end
