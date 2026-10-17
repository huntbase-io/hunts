---
analysis: While a rule might flag wbadmin, this hunt correlates the discovery commands,
  the rare SSH/RDP connection pairs, and the resulting credential harvesting events
  to build a high-confidence narrative of an intrusion in progress.
blind_spots:
- id: no-clipboard-telemetry
  question: whether FileZilla was introduced via RDP clipboard
  requires: EDR clipboard audit logs
  risk: An adversary can move tools onto a server via clipboard without generating
    a file-transfer network log.
  stage: lateral-movement-tunneling
- id: obfuscated-script-truncation
  question: whether custom credential-decryption scripts were used
  requires: hb_script_activity with high block counts
  risk: Mixed-case obfuscation and script-block fragmentation can make automated detection
    difficult.
  stage: credential-access-harvesting
coverage:
- stage: internal-discovery-and-persistence
  status: covered
  steps:
  - discovery-and-tunneling-lead
  - triage-intrusion-activity
- stage: lateral-movement-tunneling
  status: covered
  steps:
  - rare-network-peers
  - triage-intrusion-activity
- stage: credential-access-harvesting
  status: covered
  steps:
  - credential-harvesting-events
  - script-forensics-review
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
  stage: data-exfiltration-sftp
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: impact-ransomware-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries targeting Active Directory and Veeam credentials can
    cripple an organization's recovery capability before deploying ransomware. Hunting
    these precursors is critical for prevention.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established internal persistence through unauthorized
  remote access tools like RustDesk and is performing Active Directory credential
  harvesting by dumping the NTDS database and LSASS memory.
labels:
- hunt
- attack.t1082
- attack.t1016
- attack.t1136.002
- attack.t1543.003
- attack.t1021.001
- attack.t1572
- attack.t1003.003
- attack.t1003.001
- attack.t1552.004
- command and control
- credential access
- discovery
- execution
- exfiltration
- impact
- initial access
- lateral movement
name: Bumblebee Persistence and AD Credential Harvesting
parameters:
  credential_tools:
    default:
    - wbadmin.exe
    - lsassy.exe
    description: Tools used to harvest credentials or dump databases.
    from:
      kind: article
      observed: '2026-06-29'
      ref: dfir-report-bumblebee-akira
    type: list[string]
  discovery_tools:
    default:
    - systeminfo.exe
    - nltest.exe
    - rustdesk.exe
    description: Legitimate tools often repurposed for discovery and persistence.
    from:
      kind: article
      observed: '2026-06-29'
      ref: dfir-report-bumblebee-akira
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for persistence and discovery.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: The suspected beachhead hosts identified in the lead step; leave
      empty to scan the entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-scoping
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
rationale: Focus on Domain Controllers, backup servers, and the initial beachhead
  host. Prioritize servers running PowerShell or harboring standard IT tools in AppData
  folders.
references:
- name: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
  url: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
related:
- hunt: bumblebee-initial-access-and-sideloading
  reason: This hunt focuses on the post-infection stage after Bumblebee has been deployed.
  relation: precedes
- hunt: akira-ransomware-impact-and-exfiltration
  reason: Data exfiltration and encryption are the final stages after credential harvesting
    is complete.
  relation: follows
- hunt: bumblebee-delivery-and-c2-establishment
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
  index: 2
  slug: from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
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


# Bumblebee Persistence and AD Credential Harvesting

This hunt identifies post-initial-access activities following a Bumblebee infection, specifically focusing on internal reconnaissance, persistent remote access, and high-value credential harvesting. It follows a funnel flow: starting with a lead query for common discovery tools and SSH tunneling parameters, then fanning out to stack-count rare RDP/SSH destinations and search for Active Directory database extraction artifacts. An agent triages the results to distinguish between legitimate IT maintenance and the Akira ransomware attack chain.

## discovery-and-tunneling-lead
<!-- Discovery Tools and SSH Tunneling Lead -->
Identify hosts running reconnaissance tools or showing signs of reverse SSH tunnel configurations.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, discovery_tools=discovery_tools)
~~~yaml
expected: Execution of systeminfo, nltest, or RustDesk, or an SSH client configured
  with reverse/local port forwarding.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{discovery_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR ((LOWER(process_name) = 'ssh.exe' OR LOWER(process_name) = 'plink.exe') AND (LOWER(process_cmd_line) LIKE '% -r %:%:%' OR LOWER(process_cmd_line) LIKE '% -l %:%:%'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## fan-out-corroboration
<!-- Corroborate with Prevalence and Credential Access -->
parallel:
- → rare-network-peers
- → credential-harvesting-events
join: → triage-intrusion-activity

## rare-network-peers
<!-- Identify Rare RDP and SSH Peers -->
Stack-count network connections on ports 3389 and 22 to find rare destinations, scoped to suspected beachhead hosts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An IP address receiving RDP or SSH traffic from only one or two hosts, which
  is atypical for centralized management gateways.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (dst_endpoint_port = 22 OR dst_endpoint_port = 3389) AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2 ORDER BY host_count ASC
```

## credential-harvesting-events
<!-- Credential Harvesting and AD Dumping -->
Search for direct evidence of Active Directory database dumping or LSASS memory harvesting, scoped to suspected beachhead hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, credential_tools=credential_tools, scope_hosts=scope_hosts)
~~~yaml
expected: Usage of wbadmin to export the NTDS database or lsassy to dump memory, often
  on a Domain Controller.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{credential_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%ntds.dit%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-intrusion-activity
<!-- Triage Intrusion Indicators -->
```agent target=hunter
cite: required
context:
- discovery-and-tunneling-lead
- rare-network-peers
- credential-harvesting-events
max_iterations: 5
objective: Determine whether the evidence across discovery, network peers, and credential
  access indicates an active threat actor in the post-initial-access stage.
success_criteria: Verdicts must distinguish between legitimate IT tool usage and unauthorized
  activity like NTDS dumping or reverse SSH tunneling.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict identifies malicious activity on a domain controller or backup server" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → script-forensics-review
unavailable: → script-forensics-review (blind_spot: no-clipboard-telemetry)
else: → close-out

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke any Enterprise Admin group changes observed in the last 48 hours.
```
→ script-forensics-review

## script-forensics-review
<!-- Script Forensics Review -->
```manual target=analyst
Query hb_script_activity for the host in question; look for blocks decrypting DPAPI or referencing Veeam password paths.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record all found accounts and hosts. Note any gaps in script telemetry where mixed-case obfuscation was observed.
```
→ end
