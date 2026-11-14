---
analysis: A single rule might miss transient files or the specific sequence of macro-execution
  leading to Startup folder persistence. This hunt links vulnerability context with
  behavioral pivots to provide a high-confidence narrative for containment.
blind_spots:
- id: missing-script-telemetry
  question: whether the PowerShell loader executed its base64-encoded logic
  requires: hb_script_activity (PowerShell Event 4104)
  risk: Without script block logging, the in-memory execution phase of the Prime loader
    remains a blind spot.
  stage: dropper-execution-vba-ps
- id: ephemeral-tool-cleanup
  question: whether the harvester has already deleted itself from ProgramData
  requires: hb_file_activity deletion events
  risk: Gorbag tools are designed for rapid harvesting and cleanup. payloads may only
    be visible as historical file creation events.
coverage:
- stage: spearphishing-delivery
  status: covered
  steps:
  - specific-lure-detection
  - agent-delivery-read
- stage: exploit-winrar-traversal
  status: covered
  steps:
  - scoping-vulnerable-winrar
  - rare-programdata-drops
- stage: dropper-execution-vba-ps
  status: covered
  steps:
  - rare-programdata-drops
  - powershell-loader-logic
- stage: startup-persistence
  status: covered
  steps:
  - startup-lnk-persistence
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: browser-intel-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: network-c2-and-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: post-intrusion-cleanup
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Gorbag APT targets strategic Ukrainian entities for rapid intelligence
    harvesting. Credential theft and VPN configuration compromise can occur before
    standard alerts are reviewed; a phased hunt for the deployment chain is required
    for early containment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed the Gorbag compromise chain by exploiting a WinRAR
  vulnerability or using macro-enabled lures to drop transient harvesters into ProgramData
  and establish startup folder persistence.
labels:
- hunt
- attack.t1566.001
- attack.t1203
- attack.t1059.001
- attack.t1547.001
- attack.t1027.009
- command and control
- credential access
- defense evasion
- execution
- initial access
- persistence
name: Gorbag APT Rapid Harvester Deployment
parameters:
  cve_id:
    default: CVE-2025-8088
    description: The WinRAR path traversal vulnerability identifier used by Gorbag.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_names:
    default:
    - "\u0434\u043E\u0434\u0430\u0442\u043E\u043A \u043F\u043E\u0434\u0430\u0442\u043A\
      \u043E\u0432\u0430.xlsm"
    - "\u041F\u043E\u0432\u0456\u0434\u043E\u043C\u043B\u0435\u043D\u043D\u044F 4726-49.rar"
    description: Filenames of the malicious lures identified in the report.
    from:
      kind: article
      observed: '2026-11-03'
      ref: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the behavioral queries, usually
      provided after the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize endpoints in the defense, law enforcement, and local administration
  sectors. Focus on hosts with identified vulnerabilities to CVE-2025-8088.
references:
- name: 'Gorbag: Orcs at the border harvesting intelligence from Ukraine'
  url: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/
related:
- hunt: gorbag-intelligence-exfiltration
  reason: This hunt targets deployment; a follow-on hunt handles the network exfiltration
    and browser data theft.
  relation: follows
scenario:
  stages:
  - name: Spearphishing with Malicious Lures
    observables:
    - "\u0434\u043E\u0434\u0430\u0442\u043E\u043A \u043F\u043E\u0434\u0430\u0442\u043A\
      \u043E\u0432\u0430.xlsm"
    - "\u041F\u043E\u0432\u0456\u0434\u043E\u043C\u043B\u0435\u043D\u043D\u044F 4726-49.rar"
    - Email subjects regarding administrative fines or taxes
    slug: spearphishing-delivery
    tactic: initial-access
    techniques:
    - T1566.001
    - T1199
  - name: WinRAR Path Traversal Exploitation
    observables:
    - CVE-2025-8088
    - Extraction of alternate data streams outside directory
    - LNK file written to Startup folder
    slug: exploit-winrar-traversal
    tactic: execution
    techniques:
    - T1203
  - name: Macro or PowerShell Dropper Execution
    observables:
    - VBA decoding base64 from Excel cells
    - Payload dropped into %ProgramData%
    - PowerShell loader in %ProgramData%
    slug: dropper-execution-vba-ps
    tactic: execution
    techniques:
    - T1059.001
    - T1027.009
  - name: Persistence via Startup Folder
    observables:
    - LNK file in %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
    slug: startup-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Rapid Browser and VPN Data Theft
    observables:
    - BeautyStealer access to browser profile databases
    - Collection of VPN configurations
    - Staging of documents for exfiltration
    slug: browser-intel-harvesting
    tactic: credential-access
    techniques:
    - T1555.003
    - T1539
    - T1217
    - T1005
  - name: C2 and Telegram Exfiltration
    observables:
    - HTTPS connection to 89.44.9.186 (Prime ReverseShell)
    - Exfiltration to 142.111.194.73
    - Data exfiltration via Telegram API
    - RC4 encrypted payloads
    slug: network-c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1567
    - T1048.001
  - name: Self-Deletion Cleanup
    observables:
    - Malware binary removal from %ProgramData% after single pass execution
    slug: post-intrusion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: Gorbag is a Russia-aligned threat actor targeting Ukrainian law enforcement
    and defense sectors since 2025. They utilize spearphishing with macro-enabled
    spreadsheets or WinRAR exploits (CVE-2025-8088) to deploy BeautyStealer for rapid
    credential and file harvesting and Prime ReverseShell for command and control
    before performing self-deletion.
series:
  index: 1
  slug: gorbag-orcs-at-the-border-harvesting-intelligence-from-ukraine
  title: 'Gorbag: Orcs at the border harvesting intelligence from Ukraine'
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


# Gorbag APT Rapid Harvester Deployment

This hunt targets the initial deployment phase of the Russia-aligned Gorbag group. The actor uses spearphishing lures or weaponized archives exploiting CVE-2025-8088 to drop payloads like BeautyStealer or Prime ReverseShell. The hunt follows a phased approach: first, it identifies vulnerable hosts and examines the file surface for lure delivery and rare dropper activity in ProgramData; second, it corroborates these findings by looking for Startup folder persistence and PowerShell loader script blocks. This sequence allows an analyst to distinguish between routine file activity and the specific, multi-stage delivery pattern of an ephemeral intelligence harvester that removes itself after execution.

## scoping-vulnerable-winrar
<!-- Identify hosts vulnerable to WinRAR traversal -->
Find endpoints currently reporting the WinRAR vulnerability (CVE-2025-8088) to prioritize the behavioral hunt.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: Rows identify devices with vulnerable versions of WinRAR. Silence means
  the specific vulnerability was not detected by scanners in this estate.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, title FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status != 'suppressed'
```

## parallel-delivery
<!-- Early delivery fan-out -->
parallel:
- → specific-lure-detection
- → rare-programdata-drops
join: → agent-delivery-read

## specific-lure-detection
<!-- Detection of specific spearphishing lures -->
Match the exact filenames used in the Gorbag campaign in recent file activity.

```sqlite target=endpoint role=triage params=(lure_names=lure_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A file matching a lure name landing on a host. Silence means these specific
  file names were not observed.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{lure_names}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-programdata-drops
<!-- Rare file drops in ProgramData from suspect parents -->
Identify behavioral indicators where Excel or WinRAR drop rare files into the ProgramData directory.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare file created in ProgramData by a productivity or archiving application.
  Silence suggests no such drops occurred within the window.
prevalence:
  by: device_hostname
  key:
  - dropped_file
  - process_name
  rare_below: 3
reads:
- file_name
- process_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT LOWER(file_name) AS dropped_file, process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(process_name) LIKE '%excel.exe' OR LOWER(process_name) LIKE '%winrar.exe') AND LOWER(file_path) LIKE '%\programdata\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dropped_file, process_name HAVING hosts <= 3
```

## agent-delivery-read
<!-- Evaluate delivery evidence -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-winrar
- specific-lure-detection
- rare-programdata-drops
max_iterations: 3
objective: Decide whether any host shows evidence of a successful Gorbag delivery
  based on lure file presence or anomalous ProgramData dropper behavior.
success_criteria: A suspicious/malicious verdict if specific lures are found or if
  Office/WinRAR drop rare payloads on vulnerable hosts.
tools:
- endpoint
```

## parallel-follow-on
<!-- Persistence and loader fan-out -->
parallel:
- → startup-lnk-persistence
- → powershell-loader-logic
join: → agent-follow-on-read

## startup-lnk-persistence
<!-- Creation of Startup folder LNK files -->
Identify persistence established via the Windows Startup folder, dropped by WinRAR or PowerShell.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A LNK file landing in the Startup directory. Silence is expected if the
  threat actor only performed one-time harvesting.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND LOWER(file_path) LIKE '%\start menu\programs\startup\%' AND LOWER(file_name) LIKE '%.lnk' AND (LOWER(process_name) LIKE '%winrar.exe' OR LOWER(process_name) LIKE '%powershell.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-loader-logic
<!-- PowerShell loader script patterns -->
Find script blocks that decode base64 content and reference the ProgramData directory, matching the Prime loader behavior.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A PowerShell script block performing decoding to stage a payload from ProgramData.
  Silence means no such script patterns were logged.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, script_content, script_path, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%frombase64string%' AND LOWER(script_content) LIKE '%programdata%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-follow-on-read
<!-- Full intrusion chain triage -->
```agent target=hunter
cite: required
context:
- agent-delivery-read
- startup-lnk-persistence
- powershell-loader-logic
max_iterations: 6
objective: Determine if the early delivery evidence combined with follow-on persistence
  or loader script blocks indicates a full Gorbag compromise chain.
success_criteria: A verdict of malicious for any host where early stage drops are
  followed by Startup persistence or specific PowerShell loader script patterns.
tools:
- endpoint
```

## intrusion-decision
<!-- Decide on intrusion status -->
if~: "the agent-follow-on-read verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-verification-task
unavailable: → analyst-verification-task (blind_spot: missing-script-telemetry)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint from the network and preserve the ProgramData and Startup folder artifacts for forensic analysis.
```
→ analyst-verification-task

## analyst-verification-task
<!-- Analyst forensic verification -->
```manual target=analyst
Examine the LNK file and payloads in ProgramData. Confirm if they match the RC4-encrypted patterns or the PowerShell loader behavior described in the ESET article. Check the USN journal if files have been deleted.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the results. If malicious activity was confirmed, escalate to Incident Response. Promote the rare ProgramData drop query to a standing detection rule.
```
→ end
