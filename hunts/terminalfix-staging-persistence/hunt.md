---
analysis: A single rule on the Run key might fire, but this hunt provides the context
  of the DLL sideloading and the script-based extraction logic that proves the intrusion's
  intent. It uses an agent to weigh multiple independent behavioral indicators.
blind_spots:
- id: incomplete-module-logging
  question: whether the sideloading occurred on hosts without real-time module load
    logging
  requires: hb_module_activity from Sysmon Event ID 7
  risk: A point-in-time snapshot might miss the load if the process executes and exits
    quickly.
  stage: defense-evasion-dll-sideloading
- id: obfuscated-script-logic
  question: whether the extraction logic was hidden using standard PowerShell obfuscation
    techniques
  requires: hb_script_activity with deobfuscated content
  risk: A simple string match on 'pixel' or 'RGBA' may miss variants of the script
    logic.
  stage: steganographic-payload-extraction
coverage:
- stage: initial-access-fake-captcha-execution
  status: covered
  steps:
  - file-staging-check
- stage: defense-evasion-dll-sideloading
  status: covered
  steps:
  - sideloading-behavior
- stage: steganographic-payload-extraction
  status: covered
  steps:
  - steganography-logic
- stage: persistence-registry-and-task
  status: covered
  steps:
  - persistence-baseline
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: discovery-ad-and-network-recon
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: c2-reverse-websocket-tunnel
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The TerminalFix campaign bypasses traditional security controls by
    using signed binaries and steganography. A hunt is necessary to pivot across file,
    module, and script surfaces to identify the coordinated behavior before it reaches
    the network-tunneling stage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a fake CAPTCHA lure to trick users into running
  PowerShell commands that establish persistence and deploy a DLL-sideloaded payload
  from ProgramData.
labels:
- hunt
- attack.t1566.002
- attack.t1574.001
- attack.t1027.003
- attack.t1547.001
- attack.t1053.005
- attack.t1115
- attack.t1059.001
name: TerminalFix Staging and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-config
    type: number
  persistence_key:
    default: LockScreenContentServer_MuODG5yBM
    description: The specific masquerading name used for Run keys and scheduled tasks.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: string
  scope_hosts:
    default: []
    description: Restrict the hunt to specific hosts; leave empty for the entire estate.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-entry
    type: list[host]
  staging_folder:
    default: f47f2a8c21c9df4e
    description: Unique folder identifier used for staging in ProgramData.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: string
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
rationale: Start with general Windows workstations. If results are found, pivot to
  all hosts using the same staging path identifier.
references:
- name: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-discovery-and-tunneling
  reason: This hunt covers the beachhead; the subsequent reconnaissance and reverse-tunnel
    deployment are handled by the next hunt in this series.
  relation: follows
scenario:
  stages:
  - name: Fake CAPTCHA PowerShell Execution
    observables:
    - Fake Cloudflare Turnstile overlay 'Verify you are human'
    - Clipboard manipulation to stage PowerShell command
    - powershell.exe downloading ZIP archive from gitnow.dev
    - Extraction to C:\ProgramData\f47f2a8c21c9df4e
    - Execution of 1.bat
    slug: initial-access-fake-captcha-execution
    tactic: initial-access
    techniques:
    - T1566.002
    - T1115
    - T1059.001
  - name: DLL Sideloading via LockScreenContentServer
    observables:
    - LockScreenContentServer.exe loading malicious dui70.dll
    - dui70.dll with forged future timestamp 2104
    - Masquerading DLL name 'Windows DirectUI Engine'
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
    - T1574.002
  - name: Steganographic Payload Extraction
    observables:
    - PowerShell function Extract-RawFileFromImage
    - POST requests to content domains for PNG images
    - DLL fragments extracted from pixel RGBA channels
    - Reassembly of executables from PNG data
    slug: steganographic-payload-extraction
    tactic: execution
    techniques:
    - T1059.001
    - T1027.003
  - name: Persistent Execution Loop
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM
    - Scheduled task re-executing LockScreenContentServer.exe every 60 minutes
    - Folder hidden via attrib +s +h C:\ProgramData\f47f2a8c21c9df4e
    slug: persistence-registry-and-task
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Active Directory and Network Reconnaissance
    observables:
    - nltest /domain_trusts
    - net group 'domain admins' /domain
    - Ping sweeps of 'dc', 'backup', 'mail', 'gateway' servers
    - Active Directory user description harvesting
    - System information collection (English, Spanish, German)
    slug: discovery-ad-and-network-recon
    tactic: discovery
    techniques:
    - T1018
    - T1087.002
    - T1482
  - name: Reverse WebSocket Tunneling
    observables:
    - pythonw.exe executing client.py
    - Encrypted WebSocket tunnel to gitnow.dev:443
    - FileSystemWatcher asynchronous command loop
    - SOCKS-style TCP proxy access
    slug: c2-reverse-websocket-tunnel
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  summary: The TerminalFix campaign uses social engineering with fake CAPTCHA overlays
    to trick users into executing PowerShell scripts that deploy a multi-stage infection.
    The attack leverages DLL sideloading of a signed binary and steganographic payload
    extraction to establish persistent access and deploy a Python-based reverse tunnel
    for encrypted WebSocket C2.
series:
  index: 1
  slug: terminalfix-campaign-deploys-a-reverse-tunnel-through-multistage-intrusion
  title: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
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
tlp: clear
type: investigation
---


# TerminalFix Staging and Persistence

This hunt targets the initial infection and persistence phases of the TerminalFix campaign. It identifies the unique staging directory in ProgramData, the abuse of a legitimate Windows binary (LockScreenContentServer.exe) to sideload a malicious DLL (dui70.dll), and the extraction of steganographic payloads from PNG images. Finally, it corroborates these activities against redundant persistence mechanisms in the registry and task scheduler.

## scope-windows-hosts
<!-- Scope Windows Hosts -->
Identify all Windows-based hosts in the estate where TerminalFix might execute, filtered by time to avoid scanning historical inventory.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to the active Windows estate. Silence indicates
  no Windows systems are reporting in the window.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE platform = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Parallel Activity Corroboration -->
parallel:
- → file-staging-check
- → sideloading-behavior
- → steganography-logic
- → persistence-baseline
join: → agent-triage

## file-staging-check
<!-- Initial Staging in ProgramData -->
Identify hosts where the unique TerminalFix staging folder or the initial batch file exists.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, staging_folder=staging_folder, scope_hosts=scope_hosts)
~~~yaml
expected: Creation or access of the specific campaign folder or batch file. Silence
  may mean a different staging directory was used.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\\' || '{{staging_folder}}' || '\\%' OR LOWER(file_name) = '1.bat') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## sideloading-behavior
<!-- DLL Sideloading via LockScreenContentServer -->
Detect the illegitimate loading of dui70.dll from the staging directory instead of the Windows system path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: LockScreenContentServer.exe loading a DLL from a non-standard path. This
  is a high-confidence indicator of the campaign's defense evasion.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE LOWER(module_name) = 'dui70.dll' AND LOWER(process_name) LIKE '%lockscreencontentserver.exe' AND LOWER(module_path) NOT LIKE '%\\windows\\system32\\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## steganography-logic
<!-- Steganographic Extraction Logic -->
Identify PowerShell execution that contains keywords related to the campaign's steganography routines.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing the logic to reassemble executables from image
  pixel data. Silence suggests the logic is either missing or heavily obfuscated.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%extract-rawfilefromimage%' OR (LOWER(script_content) LIKE '%pixel%' AND LOWER(script_content) LIKE '%rgba%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-baseline
<!-- Rare Persistence Mechanisms -->
Identify instances of the campaign's persistence key across the fleet and isolate rare occurrences.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, persistence_key=persistence_key)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts possessing the specific Run key value. Silence indicates
  the campaign name has changed or the key was not set.
prevalence:
  by: device_hostname
  key:
  - reg_value_name
  rare_below: 5
reads:
- reg_value_name
- device_hostname
- reg_target
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT reg_value_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\currentversion\\run%' AND LOWER(reg_value_name) LIKE '%' || LOWER('{{persistence_key}}') || '%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_value_name HAVING hosts < 5
```

## agent-triage
<!-- Agent Triage TerminalFix Chain -->
```agent target=hunter
cite: required
context:
- file-staging-check
- sideloading-behavior
- steganography-logic
- persistence-baseline
max_iterations: 5
objective: Determine if the events on any single host constitute the TerminalFix campaign.
  Weigh the overlap between the staging path, the sideloaded DLL, the script logic,
  and the registry persistence.
success_criteria: A verdict of malicious | suspicious | benign per host citing the
  specific rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-module-logging)
else: → close-out

## isolate-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Preserve the contents of C:\ProgramData\{{staging_folder}} for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Tuning -->
```manual target=analyst
Review the cited rows from the triage agent. Check for subsequent discovery commands or network connections to gitnow.dev or other suspicious domains. Record tuning notes for the sideloading detection-candidate.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
No coordinated TerminalFix activity was found. Record the estate coverage and lookback window.
```
→ end
