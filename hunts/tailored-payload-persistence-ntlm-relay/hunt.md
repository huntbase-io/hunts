---
analysis: "A simple detection rule for Python or headless Edge would be noisy. This\
  \ hunt uses a multi-surface approach\u2014correlating process flags, binary rarity,\
  \ specific paths, and destination port mapping\u2014to isolate the Campaign B pattern\
  \ with high confidence."
blind_spots:
- id: no-smb-visibility
  question: whether the SMB traffic is a specific PetitPotam coercion attempt or general
    scanning
  requires: Network-layer SMB protocol analysis or DC auditing
  risk: Legitimate administrative Python scripts may trigger false positives without
    protocol-level inspection.
  stage: ntlm-relay-lateral-movement
- id: extension-content-analysis
  question: what the malicious browser extension is actually doing (e.g., credential
    theft, further delivery)
  requires: Endpoint file content logging
  risk: A hunt can see that an extension was loaded, but not what the extension's
    code does, requiring manual file collection.
  stage: headless-browser-extension-sideloading
coverage:
- stage: tailored-executable-persistence
  status: covered
  steps:
  - identify-suspicious-hosts
  - temp-persistence
- stage: headless-browser-extension-sideloading
  status: covered
  steps:
  - headless-browser-evasion
- stage: ntlm-relay-lateral-movement
  status: covered
  steps:
  - ntlm-relay-smb
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: teams-external-vishing-lure
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: user-initiated-remote-support-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: host-and-domain-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: powershell-rat-delivery-and-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: amsi-bypass-evasion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Spring Ring Campaign B demonstrates a high-impact transition from
    vishing to domain takeover. Detecting these advanced persistence and lateral movement
    techniques is essential for preventing the compromise of core identity infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is establishing persistence using tailored executables in
  the Temp directory and initiating a Python-based NTLM relay attack to achieve domain-level
  takeover.
labels:
- hunt
- attack.t1204.002
- attack.t1547.001
- attack.t1564.003
- attack.t1574.002
- attack.t1557.001
- attack.t1210
name: Tailored Payload Persistence and NTLM Relay
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  python_relay_path:
    default: C:\ProgramData\IntegrityData\python.exe
    description: Specific malicious Python path observed in the report.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
    type: path
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for all hosts.
    type: list[host]
  temp_prefixes:
    default:
    - vhlp-
    - scnr-
    description: Prefixes for persistence executables found in Temp.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start the hunt on all user endpoints. Focus specifically on hosts with
  Python installed or where Temp folder execution is common for users.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: teams-vishing-initial-access
  reason: Detection of the initial Teams chat creation is best handled via M365/Entra
    audit logs in a dedicated hunt.
  relation: out-of-scope-alternative
- hunt: spring-ring-powershell-rat-evasion
  relation: follows
scenario:
  stages:
  - name: External Teams Vishing Lure
    observables:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    - 'Teams display names: help desk, IT assistance, support staff'
    - Voice calls lasting 10-15 minutes
    slug: teams-external-vishing-lure
    tactic: initial-access
    techniques:
    - T1566.003
    - T1566.004
  - name: User-initiated Remote Support Execution
    observables:
    - Quick Assist
    - Third-party RMM software downloads
    slug: user-initiated-remote-support-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Host and Domain Enumeration
    observables:
    - whoami /groups
    - net group /dom
    slug: host-and-domain-enumeration
    tactic: discovery
    techniques:
    - T1033
    - T1069.002
  - name: PowerShell RAT Delivery and C2
    observables:
    - san-sid.com
    - PowerShell command line download from external domain
    - Encrypted host data beacons
    slug: powershell-rat-delivery-and-c2
    tactic: command-and-control
    techniques:
    - T1105
    - T1071.001
  - name: AMSI Bypass Evasion
    observables:
    - amsiInitFailed flag manipulation
    - Obfuscated 9-line C2 stager script
    slug: amsi-bypass-evasion
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1059.001
  - name: Tailored Executable Persistence
    observables:
    - s3.us-west-2.amazonaws.com
    - <company_name>-org-filters-update-<victim_name>.exe
    - 'Files: vhlp-*.exe, scnr-*.exe'
    - 'Path: \Temp\'
    slug: tailored-executable-persistence
    tactic: persistence
    techniques:
    - T1204.002
    - T1547.001
  - name: Headless Browser Extension Sideloading
    observables:
    - Headless Microsoft Edge execution
    - Sideloaded Edge extension
    slug: headless-browser-extension-sideloading
    tactic: defense-evasion
    techniques:
    - T1564.003
    - T1574.002
  - name: NTLM Relay Lateral Movement
    observables:
    - C:\ProgramData\IntegrityData\python.exe
    - SMB scanning on port 445
    - PetitPotam coercion attempts against Domain Controllers
    slug: ntlm-relay-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1557.001
    - T1210
  summary: 'Spring Ring is a vishing operation where attackers use external Microsoft
    Teams accounts to impersonate IT support and coerce employees into executing remote
    management tools or custom malware. The campaign employs two distinct paths: one
    using an obfuscated PowerShell-based RAT with AMSI bypasses, and another using
    tailored executables and browser hijacking to perform NTLM relay attacks via PetitPotam
    against domain controllers.'
series:
  index: 3
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Tailored Payload Persistence and NTLM Relay

This hunt targets the sophisticated second-stage behaviors of the Spring Ring Campaign B. It focuses on the deployment of persistence mechanisms in user Temp folders, the use of headless browsers for defense evasion via extension sideloading, and the execution of PetitPotam-style NTLM relay attacks from a Python interpreter staged in ProgramData. The hunt correlates these endpoint and network behaviors to identify high-impact intrusions that bypass standard security monitoring.

## identify-suspicious-hosts
<!-- Identify candidate compromised hosts -->
Locate hosts running the specific malicious Python interpreter or staging binaries with known campaign prefixes in Temp.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, python_relay_path=python_relay_path, temp_prefixes=temp_prefixes)
~~~yaml
expected: A list of hostnames where initial indicators were observed. Silence indicates
  these specific IOCs are not present.
reads:
- device_hostname
- process_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_path) = LOWER('{{python_relay_path}}') OR (LOWER(process_path) LIKE '%\temp\%' AND instr(',' || '{{temp_prefixes}}' || ',', ',' || substr(LOWER(process_name), 1, 5) || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## campaign-b-behavior
<!-- Gather multi-surface artifacts -->
parallel:
- → headless-browser-evasion
- → temp-persistence
- → ntlm-relay-smb
join: → triage-agent

## headless-browser-evasion
<!-- Headless Edge with sideloaded extensions -->
Detect Microsoft Edge running in headless mode with an extension loaded from a local path, a common defense evasion technique.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process execution rows showing headless browser flags. This is a high-confidence
  signal for browser manipulation.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%msedge.exe' AND LOWER(process_cmd_line) LIKE '%--headless%' AND LOWER(process_cmd_line) LIKE '%--load-extension%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## temp-persistence
<!-- Rare persistence binaries in Temp -->
Identify binaries matching the campaign's naming convention in user Temp directories, filtered by fleet rarity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, temp_prefixes=temp_prefixes, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts running rare binaries in Temp folders. Rarity helps distinguish
  attacker tools from standard updaters.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- process_name
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) as p_name, device_hostname, process_path, MIN(time) as first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\temp\%' AND (instr(',' || '{{temp_prefixes}}' || ',', ',' || substr(LOWER(process_name), 1, 5) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY p_name, device_hostname, process_path HAVING COUNT(DISTINCT device_hostname) <= 5
```

## ntlm-relay-smb
<!-- SMB scanning from staged Python -->
Detect network connections to port 445 (SMB) originating specifically from the malicious Python interpreter location.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, python_relay_path=python_relay_path, scope_hosts=scope_hosts)
~~~yaml
expected: Network connections from the staged Python interpreter to multiple internal
  IPs over port 445, indicative of NTLM relay attempts.
reads:
- device_hostname
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as connection_count FROM hb_network_connection WHERE (LOWER(process_path) = LOWER('{{python_relay_path}}') AND dst_endpoint_port = 445) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_path, dst_endpoint_ip, dst_endpoint_port
```

## triage-agent
<!-- Triage Campaign B intrusion -->
```agent target=hunter
cite: required
context:
- identify-suspicious-hosts
- headless-browser-evasion
- temp-persistence
- ntlm-relay-smb
max_iterations: 5
objective: 'Determine if any host shows multiple artifacts of Spring Ring Campaign
  B: Python-based SMB scanning, headless Edge extension loading, and rare binaries
  in Temp.'
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  evidence.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on correlated artifacts" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-smb-visibility)
else: → analyst-manual-review

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the binary from the Temp folder and the Edge extension path for further analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Examine the extension directory sideloaded by Edge. Verify if the SMB scanning activity aligns with PetitPotam coercion against known Domain Controllers.
```
→ end
