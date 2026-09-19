---
analysis: A static rule for 'amsiInitFailed' is easily bypassed by obfuscation. This
  hunt uses multi-surface corroboration (DNS, process, and script blocks) and prevalence
  baselining for PowerShell connections to find the threat even when the code is obfuscated.
blind_spots:
- id: no-script-logging
  question: whether the 'amsiInitFailed' manipulation occurred inside a script block
  requires: hb_script_activity (PowerShell Event ID 4104)
  risk: Without script block logging, attackers can execute obfuscated in-memory commands
    that never appear in process command lines.
  stage: amsi-bypass-evasion
- id: tls-blind-spot
  question: the specific content and payloads being sent over C2 beacons
  requires: TLS inspection for hb_http_activity
  risk: We can see the destination (san-sid.com) but not the data being exfiltrated
    or the secondary payloads being fetched after the stager runs.
  stage: powershell-rat-delivery-and-c2
coverage:
- stage: powershell-rat-delivery-and-c2
  status: covered
  steps:
  - dns-scoping
  - powershell-downloads
  - rare-powershell-beacons
- stage: amsi-bypass-evasion
  status: covered
  steps:
  - amsi-bypass-detection
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
  stage: tailored-executable-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: headless-browser-extension-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: ntlm-relay-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Spring Ring successfully compromised 150+ targets across 10 companies.
    Detecting the PowerShell delivery and evasion phase is critical as it represents
    the first step of technical control after the social engineering lure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using vishing to deliver a PowerShell RAT and is bypassing
  AMSI in-memory via the amsiInitFailed flag to evade detection, followed by beaconing
  to the campaign's C2 domain.
labels:
- hunt
- attack.t1105
- attack.t1071.001
- attack.t1562.001
- attack.t1059.001
name: 'Spring Ring: PowerShell RAT Delivery and Defensive Evasion'
parameters:
  c2_domains:
    default:
    - san-sid.com
    description: Known C2 domains from the Spring Ring campaign research.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to narrow the investigation; leave empty to hunt
      across the full estate.
    type: list[host]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with user workstations where Microsoft Teams is standard. Focus on
  users whose roles might be targeted by IT help desk impersonation.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: spring-ring-campaign-b-lateral-movement
  reason: Campaign B uses NTLM relaying and tailored executables, which is handled
    in its own hunt.
  relation: out-of-scope-alternative
- hunt: spring-ring-teams-vishing-rmm
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
  index: 2
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


# Spring Ring: PowerShell RAT Delivery and Defensive Evasion

This hunt targets the execution phase of Campaign A in the Spring Ring operation. It focuses on identifying hosts that resolved the campaign's C2 domains, then corroborates that with behavioral evidence of PowerShell-based remote content downloads, in-memory AMSI flag manipulation (amsiInitFailed), and rare outbound network connections from PowerShell processes. An agent evaluates these signals to identify compromised workstations following a vishing interaction.

## dns-scoping
<!-- Identify hosts resolving Spring Ring C2 -->
Identify any host in the fleet that has attempted to resolve the campaign's C2 domains within the lookback window.

```sqlite target=endpoint role=scoping params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames that resolved known C2 domains. These hosts should be
  the primary focus for subsequent steps.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## parallel-corroboration
<!-- Corroborate with Process, Script, and Network Evidence -->
parallel:
- → powershell-downloads
- → amsi-bypass-detection
- → rare-powershell-beacons
join: → triage-agent

## powershell-downloads
<!-- PowerShell Remote Content Download -->
Identify PowerShell execution that uses download keywords like 'iwr' or 'downloadstring' to fetch remote payloads, characteristic of the Spring Ring RAT delivery.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Command lines where PowerShell is used to download files. Benign administrative
  scripts may appear, requiring triage context.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%powershell.exe' OR LOWER(process_name) LIKE '%pwsh.exe') AND (LOWER(process_cmd_line) LIKE '%iwr%' OR LOWER(process_cmd_line) LIKE '%downloadstring%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## amsi-bypass-detection
<!-- AMSI Bypass Flag Manipulation -->
Identify script blocks that manipulate the 'amsiInitFailed' flag in memory to disable scanning, as observed in Campaign A's C2 stager.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing the specific AMSI bypass string. This is a high-fidelity
  indicator of defensive evasion.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(script_content, 'amsiInitFailed') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-powershell-beacons
<!-- Rare Outbound PowerShell Connections -->
Identify outbound network connections from PowerShell to destinations that are rare across the environment, which may indicate C2 beaconing.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small list of destinations PowerShell connected to. Malicious C2 destinations
  like san-sid.com will typically have very low host counts.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
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
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%powershell.exe' OR LOWER(process_name) LIKE '%pwsh.exe') AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 3
```

## triage-agent
<!-- Triage PowerShell RAT Evidence -->
```agent target=hunter
cite: required
context:
- dns-scoping
- powershell-downloads
- amsi-bypass-detection
- rare-powershell-beacons
max_iterations: 5
objective: Review the DNS resolution for san-sid.com, the PowerShell download activity,
  the AMSI bypass script content, and rare outbound connections. Determine if these
  signals overlap on a single host to indicate a Spring Ring infection.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  rows from the query results.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage agent found malicious PowerShell activity corroborated by C2 resolution for at least one host." (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-logging)
else: → close-out

## contain-and-revoke
<!-- Isolate Host and Revoke Credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host(s) identified as malicious. Revoke active sessions and force a password reset for the associated user accounts in Entra ID/Active Directory to neutralize the vishing outcome.
```
→ analyst-review

## analyst-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the cited rows and forensics. Confirm if the 'amsiInitFailed' manipulation occurred. Check Microsoft Teams chat/call history for the vishing lure. Document any additional enumeration commands found on the host.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record that no malicious PowerShell activity related to san-sid.com was observed for the selected window. If legitimate admin scripts were identified, mark them for tuning the AMSI detection rule.
```
→ end
