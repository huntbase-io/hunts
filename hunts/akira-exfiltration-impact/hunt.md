---
analysis: A single rule might alert on vssadmin usage, but this hunt pivots between
  original binary names, rare destination stacking, and network volume across three
  different telemetry surfaces to distinguish a ransomware incident from administrative
  maintenance.
blind_spots:
- id: missing-byte-counters
  question: Was 75GB of data actually exfiltrated?
  requires: hb_network_connection with traffic_bytes from flow logs
  risk: Without byte counters, we can see the connection to the Ukrainian destination
    but cannot confirm the magnitude of the data breach.
  stage: data-exfiltration-sftp
- id: api-shadow-deletion
  question: Was shadow deletion performed without using the command line?
  requires: Endpoint monitoring for COM/WMI API calls
  risk: Advanced ransomware using direct API calls (e.g., IVssBackupComponents) to
    delete shadows will bypass process command-line monitoring.
  stage: impact-ransomware-encryption
coverage:
- stage: data-exfiltration-sftp
  status: covered
  steps:
  - identify-suspect-processes
  - bulk-exfiltration-stacking
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - identify-suspect-processes
  - shadow-copy-removal
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: initial-access-seo-redirection
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: execution-dll-side-loading
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: c2-establishment-adaptix
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: internal-discovery-and-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: lateral-movement-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: credential-access-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Akira ransomware results in total business disruption; detecting
    the terminal exfiltration phase and backup destruction provides the final opportunity
    for intervention before catastrophic data loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exfiltrating bulk data via SFTP using FileZilla and executing
  Akira ransomware, evidenced by massive outbound network transfers and the destruction
  of Volume Shadow Copies.
labels:
- hunt
- attack.t1048.003
- attack.t1020
- attack.t1486
- attack.t1490
- attack.t1047
- command and control
- credential access
- discovery
- execution
- exfiltration
- impact
- initial access
- lateral movement
name: Akira Ransomware Exfiltration and Impact
parameters:
  exfil_tools:
    default:
    - filezilla.exe
    - sftp.exe
    description: Original file names of common exfiltration tools.
    from:
      kind: article
      observed: '2025-07-01'
      ref: dfir-report-akira
    type: list[string]
  impact_admin_tools:
    default:
    - vssadmin.exe
    - wmic.exe
    - powershell.exe
    - pwsh.exe
    - powershell_ise.exe
    description: Legitimate administrative tools often abused for shadow copy deletion.
    from:
      kind: article
      observed: '2025-07-01'
      ref: dfir-report-akira
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  ransomware_binaries:
    default:
    - locker.exe
    - akira.exe
    description: Original file names associated with the Akira payload.
    from:
      kind: article
      observed: '2025-07-01'
      ref: dfir-report-akira
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to scan the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on file servers, domain controllers, and backup infrastructure
  (e.g., Veeam servers), as these were specifically targeted for bulk data theft and
  encryption in this scenario.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
related:
- hunt: bumblebee-loader-behavior
  reason: The initial delivery and C2 establishment phases are handled in the first
    hunt of this series.
  relation: out-of-scope-alternative
- hunt: bumblebee-persistence-and-ad-credential-harvesting
  relation: follows
scenario:
  stages:
  - name: SEO Poisoning Redirection
    observables:
    - opmanager.pro
    - download-center.online
    - ip-scanner.org
    - download-server.online
    - soft-server.online
    - soft-hub.pro
    - netml.shop
    - /Get?q=
    slug: initial-access-seo-redirection
    tactic: initial-access
    techniques:
    - T1189
    - T1583.008
  - name: Bumblebee DLL Side-Loading
    observables:
    - ManageEngine-OpManager.msi
    - consent.exe
    - msimg32.dll
    - '%TEMP%\ApplicationInstallationFolder_11'
    - ApplicationInstallationFolder_11
    slug: execution-dll-side-loading
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: AdaptixC2 Infrastructure Setup
    observables:
    - AdgNsy.exe
    - 4.239.95.1:8080
    - 84.32.84.32
    slug: c2-establishment-adaptix
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1568.002
    - T1055
  - name: Internal Reconnaissance and Persistence
    observables:
    - systeminfo
    - nltest
    - RustDesk
    - Enterprise Admin accounts
    slug: internal-discovery-and-persistence
    tactic: discovery
    techniques:
    - T1082
    - T1016
    - T1136.002
    - T1543.003
  - name: SSH Tunneling and RDP Pivot
    observables:
    - reverse SSH tunnel
    - RDP proxy traffic
    slug: lateral-movement-tunneling
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1572
  - name: Active Directory and Veeam Credential Harvesting
    observables:
    - wbadmin.exe
    - ntds.dit
    - lsassy
    - Veeam credential dumping script
    slug: credential-access-harvesting
    tactic: credential-access
    techniques:
    - T1003.003
    - T1003.001
    - T1552.004
  - name: Data Exfiltration via SFTP
    observables:
    - FileZilla.exe
    - 75GB exfiltrated
    - Ukrainian IP space
    slug: data-exfiltration-sftp
    tactic: exfiltration
    techniques:
    - T1048.003
    - T1020
  - name: Akira Ransomware Impact
    observables:
    - locker.exe
    - delete Volume Shadow Copies
    - WMI
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
    - T1490
    - T1047
  summary: Threat actors utilized Bing SEO poisoning to deliver Bumblebee malware
    via trojanized software installers, leading to the deployment of AdaptixC2 for
    network discovery. The attackers leveraged RDP over SSH tunnels to move laterally
    and harvest credentials from NTDS.dit and LSASS before exfiltrating 75GB of data
    and deploying Akira ransomware.
series:
  index: 3
  slug: from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
  total: 3
severity: critical
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


# Akira Ransomware Exfiltration and Impact

This hunt identifies the final, high-impact phase of an Akira ransomware intrusion. It scopes for the execution of known exfiltration tools and the ransomware binary itself (locker.exe), then corroborates this with behavioral evidence: bulk network transfers to rare destinations—matching the 75GB volume reported—and the deletion of system recovery options via shadow copy removal. An agent triages these signals to confirm if a host has reached the final stage of encryption, enabling immediate containment before widespread business disruption occurs.

## identify-suspect-processes
<!-- Identify Suspect Processes -->
Locate execution of the reported exfiltration tools or ransomware binaries by matching original file names to bypass renaming evasion.

```sqlite target=endpoint role=scoping params=(exfil_tools=exfil_tools, ransomware_binaries=ransomware_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A hit names the host and binary (e.g., locker.exe renamed or FileZilla).
  Silence suggests these specific binaries did not run in the lookback window.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{ransomware_binaries}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate Exfiltration and Impact -->
parallel:
- → bulk-exfiltration-stacking
- → shadow-copy-removal
join: → triage-final-stage

## bulk-exfiltration-stacking
<!-- Bulk Exfiltration Stacking -->
Identify hosts pushing massive outbound volume (over 100MB) to destinations seen on very few hosts, characteristic of data theft.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One or two hosts pushing huge volume to a unique IP, especially on port
  22 (SFTP). Benign noise includes backup servers; outliers represent potential exfiltration.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- traffic_bytes
- time
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, SUM(traffic_bytes) AS total_bytes, MIN(time) AS first_seen FROM hb_network_connection WHERE state_kind = 'log' AND traffic_bytes > 104857600 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count < 3 ORDER BY total_bytes DESC
```

## shadow-copy-removal
<!-- Shadow Copy Removal -->
Detect the final precursor to ransomware impact: the deletion of Volume Shadow Copies using administrative tools.

```sqlite target=endpoint role=detection-candidate params=(impact_admin_tools=impact_admin_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process rows showing tools like vssadmin or wmic used to delete shadows.
  This is a high-confidence indicator of ransomware preparation.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{impact_admin_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{impact_admin_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND LOWER(process_cmd_line) LIKE '%shadow%' AND LOWER(process_cmd_line) LIKE '%delete%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-final-stage
<!-- Triage Final Stage -->
```agent target=hunter
cite: required
context:
- identify-suspect-processes
- bulk-exfiltration-stacking
- shadow-copy-removal
max_iterations: 4
objective: Determine if the presence of suspect binaries (FileZilla/locker.exe), bulk
  outbound transfers, and shadow deletion together indicate an active ransomware intrusion.
success_criteria: A per-host verdict citing specific rows from process and network
  surfaces.
tools:
- endpoint
- network
```

## route-remediation
<!-- Route Remediation -->
if~: "the triage verdict is malicious for at least one host based on correlated exfiltration and impact signals" (confidence: high, judge=hunter)
then: → isolate-affected-host
indeterminate: → analyst-impact-review
unavailable: → analyst-impact-review (blind_spot: missing-byte-counters)
else: → close-out-hunt

## isolate-affected-host
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all active sessions for users observed executing exfiltration tools or the ransomware binary.
```
→ analyst-impact-review

## analyst-impact-review
<!-- Analyst Impact Review -->
```manual target=analyst
Verify the destination IP in the Ukraine IP space; check the host for the .akira extension on critical file shares and backup drives.
```
→ close-out-hunt

## close-out-hunt
<!-- Hunt Close-out -->
```manual target=analyst
Record the total bytes exfiltrated per host. If no activity was found, ensure the exfiltration tools are included in software restriction policies.
```
→ end
