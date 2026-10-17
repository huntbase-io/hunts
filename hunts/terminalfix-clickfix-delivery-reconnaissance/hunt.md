---
analysis: A single rule for the Run key can be evaded with randomized naming; this
  hunt pivots from delivery lures (script content) to local staging (ProgramData)
  to discovery bursts, requiring an analyst to weigh the full chain of evidence.
blind_spots:
- id: no-script-logging
  question: whether the lure was executed in a terminal
  requires: hb_script_activity with Script Block Logging (ID 4104)
  risk: Without script block logging, the pasted multi-line PowerShell command will
    not be visible in telemetry.
  stage: defense-evasion-steganography
- id: endpoint-visibility
  question: whether the Run key exists on unmanaged hosts
  requires: hb_registry_activity (Sysmon) or osquery hive snapshot
  risk: If the host is not reporting registry events, the persistence mechanism remains
    hidden.
  stage: persistence-mechanisms
coverage:
- blind_spot: no-script-logging
  reason: Detection shifted to initial delivery interaction (ClickFix T1115/T1059.001)
    per design review to prioritize high-fidelity social engineering lures.
  stage: defense-evasion-steganography
  status: not_visible
- stage: persistence-mechanisms
  status: covered
  steps:
  - scoping-programdata-activity
- stage: discovery-domain-reconnaissance
  status: covered
  steps:
  - reconnaissance-baseline
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: execution-powershell-launcher
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: defense-evasion-dll-sideloading
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: command-and-control-asynchronous-shell
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: command-and-control-reverse-tunnel
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: TerminalFix infections lead to persistent network-level proxy access;
    identifying the transition from social engineering to reconnaissance is critical
    to stop the intruder before they reach internal databases or domain controllers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a fake Cloudflare verification lure to trick a user
  into pasting a PowerShell command, facilitating local directory staging and automated
  domain discovery.
labels:
- hunt
- attack.t1115
- attack.t1059.001
- attack.t1547.001
- attack.t1053.005
- attack.t1018
- attack.t1087.002
- attack.t1482
name: TerminalFix ClickFix Delivery and Automated Reconnaissance
parameters:
  lookback_days:
    default: '14'
    description: Days of telemetry to examine.
    from:
      kind: manual
      observed: '2026-08-29'
      ref: standard-retention
    type: number
  programdata_target:
    default: f47f2a8c21c9df4e
    description: Randomized folder name used in the campaign summary.
    from:
      kind: article
      observed: '2026-08-29'
      ref: msrc-blog
    type: string
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step.
    from:
      kind: manual
      observed: '2026-08-29'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with user workstations; focus on hosts with activity in the randomized
  ProgramData directory or those running nltest and net group commands.
references:
- name: 'MSRC Blog: TerminalFix campaign deploys a reverse tunnel through multistage
    intrusion'
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-tunnel-detection
  reason: This hunt targets the delivery and discovery phases; a sibling hunt targets
    the Python reverse tunnel deployment.
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Fake CAPTCHA
    observables:
    - Cloudflare Turnstile verification overlay
    - Verification command copied to clipboard
    - Instructions to open Windows Terminal or PowerShell
    - Fake Cloudflare-themed terminal output messages
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1204.001
  - name: Malicious PowerShell Launcher
    observables:
    - C:\ProgramData\f47f2a8c21c9df4e
    - 1.bat
    - ZIP archive download with custom User-Agent
    - 'I am not a robot - Cloudflare ID: f47f2a8c21c9df4e'
    slug: execution-powershell-launcher
    tactic: execution
    techniques:
    - T1059.001
    - T1105
  - name: DLL Sideloading via LockScreenContentServer
    observables:
    - LockScreenContentServer.exe
    - dui70.dll (unsigned, forged timestamp 2104)
    - LockScreenContentServer.exe loading dui70.dll from ProgramData
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
  - name: Steganographic Payload Extraction
    observables:
    - p1.png
    - p2.png
    - p3.png
    - gitnow.dev
    - Extract-RawFileFromImage PowerShell function
    - Reassembling DLL fragments from PNG pixel data
    slug: defense-evasion-steganography
    tactic: defense-evasion
    techniques:
    - T1027.003
  - name: Redundant Persistence
    observables:
    - LockScreenContentServer_MuODG5yBM
    - 'Registry Run Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    - Scheduled Task running every 60 minutes
    - attrib +h +s folder hiding on C:\ProgramData subfolders
    slug: persistence-mechanisms
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Extensive Domain Discovery
    observables:
    - nltest /domain_trusts
    - net group "domain admins" /domain
    - get-aduser
    - get-adcomputer
    - Ping sweeps of dc, db, backup, gateway, mail servers
    slug: discovery-domain-reconnaissance
    tactic: discovery
    techniques:
    - T1018
    - T1087.002
    - T1482
  - name: Asynchronous File-Watch Command Loop
    observables:
    - PowerShell file-watch loop monitoring text files
    - Invoke-Expression (IEX) on watched file content
    - Command output written to disk files
    slug: command-and-control-asynchronous-shell
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Reverse WebSocket Tunneling
    observables:
    - pythonw.exe
    - client.py
    - gitnow.dev:443
    - Reverse WebSocket tunnel providing SOCKS proxy access
    slug: command-and-control-reverse-tunnel
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  summary: The TerminalFix campaign employs fake Cloudflare CAPTCHA prompts to trick
    users into executing malicious PowerShell commands that initiate a multi-stage
    infection. The attack leverages DLL sideloading and steganography to deploy a
    persistent Python-based reverse tunnel, enabling attackers to conduct extensive
    Active Directory reconnaissance and maintain encrypted SOCKS-style proxy access
    to the victim's internal network.
series:
  index: 2
  slug: terminalfix-campaign-deploys-a-reverse-tunnel-through-multistage-intrusion
  title: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
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


# TerminalFix ClickFix Delivery and Automated Reconnaissance

This hunt targets the early-to-mid stages of a TerminalFix intrusion, focusing on the transition from social engineering (ClickFix) to environment mapping. It identifies the interaction where clipboard-pasted PowerShell lures are executed, staged in unique ProgramData paths, and followed by a rapid burst of Active Directory and infrastructure discovery commands. By correlating these distinct behavioural surfaces, the hunt identifies compromised hosts acting as network pivot points before the deployment of reverse tunnels.

## scoping-programdata-activity
<!-- Identify campaign-specific directory activity -->
Find hosts where files are being executed from or paths are established in the unique ProgramData folder mentioned in the campaign.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, programdata_target=programdata_target)
~~~yaml
expected: A list of hosts running processes from the campaign's staging directory.
  Silence means this specific path has not been used.
reads:
- device_hostname
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\programdata\{{programdata_target}}\%' OR LOWER(process_cmd_line) LIKE '%\programdata\{{programdata_target}}\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## investigation-fan-out
<!-- Parallel investigation of delivery and discovery -->
parallel:
- → clickfix-delivery-interaction
- → reconnaissance-baseline
join: → triage-agent

## clickfix-delivery-interaction
<!-- Detect ClickFix PowerShell interaction -->
Identify PowerShell script blocks that match the fake Cloudflare verification lure pasted into the terminal.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing fake verification messages. Silence proves the
  lure was not executed via a script-block logging interface.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (instr(LOWER(script_content), 'cloudflare') > 0 AND (instr(LOWER(script_content), 'verification') > 0 OR instr(LOWER(script_content), 'not a robot') > 0)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## reconnaissance-baseline
<!-- Monitor for automated AD discovery -->
Identify hosts performing a burst of domain and infrastructure discovery commands often seen in TerminalFix campaigns.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A cluster of discovery commands on one host that are rare across the fleet.
  Multiple matches in a short window indicate automated mapping.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, COUNT(*) as cmd_count, MIN(time) as first_seen FROM hb_process_activity WHERE (instr(LOWER(process_cmd_line), '/domain_trusts') > 0 OR instr(LOWER(process_cmd_line), 'domain admins') > 0 OR instr(LOWER(process_cmd_line), 'get-aduser') > 0 OR (LOWER(process_name) LIKE '%ping.exe%' AND (LOWER(process_cmd_line) LIKE '%dc%' OR LOWER(process_cmd_line) LIKE '%db%' OR LOWER(process_cmd_line) LIKE '%backup%'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line
```

## triage-agent
<!-- Weigh campaign evidence -->
```agent target=hunter
cite: required
context:
- scoping-programdata-activity
- clickfix-delivery-interaction
- reconnaissance-baseline
max_iterations: 4
objective: Determine if the host shows a complete chain from ClickFix interaction
  to campaign-specific staging and automated environment discovery.
success_criteria: A verdict of malicious | suspicious | benign per host with citations
  of script content matching the Cloudflare lure.
tools:
- endpoint
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-logging)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the contents of the ProgramData campaign directory for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Verify the cited script blocks. Pivot to network traffic for connections to gitnow.dev or unexpected pythonw.exe activity on port 443.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Ensure the registry persistence keys and scheduled tasks are removed. Record any new infrastructure pings identified in the triage process.
```
→ end
