---
analysis: A simple rule might catch consent.exe in a user path, but this hunt correlates
  that event with search-engine poisoning infrastructure and rare persistence tools
  like RustDesk, reducing false positives from legitimate software testing while providing
  full breach context.
blind_spots:
- id: no-process-logs
  question: whether consent.exe was executed on hosts missing an agent
  requires: hb_process_activity on all servers
  risk: A host without an agent contributes no process rows, allowing the side-loading
    execution to go unnoticed.
  stage: execution-sideloaded-loader
- id: no-dns-logs
  question: whether connection attempts to SEO domains occurred
  requires: hb_dns_activity covering endpoint resolvers
  risk: If DNS is encrypted or bypasses the monitored resolver, the initial lure connection
    will be invisible.
  stage: initial-access-seo-poisoning
- id: no-inventory-visibility
  question: whether all potential targets of the campaign were scoped
  requires: hb_software_inventory coverage for the entire server estate
  risk: If inventory is incomplete, the hunt may miss hosts that are running the impersonated
    management tools.
coverage:
- stage: initial-access-seo-poisoning
  status: covered
  steps:
  - campaign-dns-activity
- stage: execution-sideloaded-loader
  status: covered
  steps:
  - detect-sideloading-lead
- stage: persistence-c2-establishment
  status: covered
  steps:
  - rare-persistence-prevalence
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: discovery-credential-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: lateral-movement-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: data-exfiltration-filezilla
  status: out_of_scope
- reason: 'Belongs to another part of the ''From Bing Search to Ransomware: Bumblebee
    and AdaptixC2 Deliver Akira'' series.'
  stage: impact-ransomware-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Bumblebee is a precursor to Akira ransomware and large-scale data
    exfiltration (75GB+ observed). Identifying it during initial side-loading and
    persistence prevents catastrophic domain-wide encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has delivered Bumblebee malware through a trojanized MSI installer
  via SEO poisoning, using DLL side-loading of consent.exe and establishing persistence
  with remote management tools like RustDesk.
labels:
- hunt
- attack.t1566.002
- attack.t1583.008
- attack.t1204.002
- attack.t1574.002
- attack.t1136.002
- attack.t1543.003
- attack.t1105
name: Bumblebee Delivery and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step to narrow subsequent behavioral
      queries; leave empty to hunt the whole estate.
    type: list[host]
  seo_c2_domains:
    default:
    - opmanager.pro
    - zenmap.pro
    - download-center.online
    - soft-hub.pro
    - download-server.online
    - soft-server.online
    - netml.shop
    - ip-scanner.org
    description: Known impersonation and C2 domains identified in the campaign.
    from:
      kind: article
      observed: '2025-07-01'
      ref: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
    type: list[domain]
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
rationale: The hunt focuses on hosts running ManageEngine or Advanced IP Scanner,
  typically servers or IT administrator workstations. The infection chain begins with
  a user search, so start by identifying hosts with these software packages in the
  scoping query.
references:
- name: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
  url: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
related:
- hunt: discovery-credential-dumping
  reason: Once persistence is established, Bumblebee operators typically move to dumping
    NTDS.dit and harvesting credentials.
  relation: follows
scenario:
  stages:
  - name: SEO Poisoning for Trojanized Installers
    observables:
    - opmanager.pro
    - zenmap.pro
    - download-center.online
    - soft-hub.pro
    - download-server.online
    - soft-server.online
    - ip-scanner.org
    - 84.32.84.32
    - url_path contains '/Get?q='
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1566.002
    - T1583.008
  - name: DLL Side-loading of Bumblebee Loader
    observables:
    - ManageEngine-OpManager.msi
    - Advanced-IP-Scanner.msi
    - consent.exe executed from AppData
    - msimg32.dll side-loaded
    - ApplicationInstallationFolder_11
    - 'Signer: LLC Resource+'
    - 'Signer: LLC Vector'
    slug: execution-sideloaded-loader
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: Persistent C2 and Access Management
    observables:
    - 14-char .org DGA domains
    - AdgNsy.exe (renamed wab.exe)
    - RustDesk service installation
    - New Enterprise Admin accounts
    slug: persistence-c2-establishment
    tactic: persistence
    techniques:
    - T1136.002
    - T1543.003
    - T1105
  - name: Network Discovery and Credential Harvesting
    observables:
    - systeminfo
    - nltest
    - wbadmin.exe to extract ntds.dit
    - lsassy utility
    - pOWerShELl.exE (mixed-case obfuscation)
    - PowerShell scripts for Veeam credential decryption
    slug: discovery-credential-dumping
    tactic: credential-access
    techniques:
    - T1003.001
    - T1003.003
    - T1082
    - T1018
    - T1059.001
  - name: Lateral Movement and Tunneling
    observables:
    - Reverse SSH tunnel
    - RDP proxying over SSH
    - BYOVD driver usage to neutralize EDR
    slug: lateral-movement-tunneling
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1572
    - T1562.010
  - name: Data Exfiltration via SFTP
    observables:
    - FileZilla execution
    - SFTP traffic to Ukrainian server
    - 75GB of data exfiltrated
    - SYSVOL and file share exfiltration
    slug: data-exfiltration-filezilla
    tactic: exfiltration
    techniques:
    - T1048.003
  - name: Akira Ransomware Deployment
    observables:
    - locker.exe (Akira binary)
    - WMI shadow copy deletion
    - Volume Shadow Copy deletion via vssadmin
    slug: impact-ransomware-deployment
    tactic: impact
    techniques:
    - T1486
    - T1490
  summary: Bumblebee malware was delivered via SEO poisoning using trojanized installers
    for enterprise software like ManageEngine OpManager. The threat actor established
    persistence with RustDesk and AdaptixC2, performed deep credential harvesting
    (NTDS.dit and Veeam), and exfiltrated over 75GB of data before deploying Akira
    ransomware.
series:
  index: 1
  slug: from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
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


# Bumblebee Delivery and Persistence

This hunt identifies the initial stages of a Bumblebee infection. The hunt first scopes the environment for vulnerable software, then identifies a behavioral lead: the adversary executing consent.exe from AppData. If a lead is confirmed, the hunt fans out to search for campaign-specific C2/SEO infrastructure and rare persistence mechanisms, including renamed Windows utilities and unauthorized remote access services. An analyst then weighs the evidence to confirm the breach.

## find-vulnerable-software
<!-- Scope hosts with target management software -->
Identify hosts running the management software that was impersonated in the SEO poisoning campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that use these management tools, making them high-fidelity
  targets for this campaign. Silence means no known targets exist in current inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%manageengine opmanager%' OR LOWER(package_name) LIKE '%advanced ip scanner%'
```

## detect-sideloading-lead
<!-- Anomalous consent.exe side-loading -->
Find the primary execution signal for the Bumblebee loader: consent.exe running from non-system paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any execution of consent.exe outside the System32 directory, which strongly
  indicates a DLL side-loading attempt. Silence proofs the specific binary lure was
  not seen.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) = 'consent.exe' AND LOWER(process_path) NOT LIKE 'c:\\windows\\system32\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate side-loading lead -->
```agent target=hunter
cite: required
context:
- detect-sideloading-lead
max_iterations: 3
objective: Determine if the execution of consent.exe indicates an unauthorized Bumblebee
  loader execution by checking the path and parent process context.
success_criteria: A verdict of suspicious or malicious for any host exhibiting anomalous
  path behavior.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on lead confirmation -->
if~: "the evaluate-lead verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → investigation-fanout
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-logs)
else: → close-out

## investigation-fanout
<!-- Parallel investigation of infrastructure and persistence -->
parallel:
- → campaign-dns-activity
- → rare-persistence-prevalence
join: → final-triage

## campaign-dns-activity
<!-- Campaign SEO and delivery DNS hits -->
Identify connections to the impersonation domains used for SEO poisoning and initial payload delivery.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, seo_c2_domains=seo_c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolutions of known malicious delivery domains, confirming the host
  was lured by the SEO campaign.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{seo_c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## rare-persistence-prevalence
<!-- Rare persistence binaries and renamed tools -->
Stack-count rare binaries in AppData and identify renamed utilities like AdgNsy.exe or unauthorized RustDesk activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Identification of AdgNsy.exe or RustDesk on scoped hosts, or rare binaries
  residing in AppData paths used by Bumblebee.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- device_hostname
- process_path
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, LOWER(process_path) AS path, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\appdata\\%' OR LOWER(process_name) = 'adgnsy.exe' OR LOWER(process_cmd_line) LIKE '%rustdesk%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, LOWER(process_path) ORDER BY runs ASC
```

## final-triage
<!-- Synthesize Bumblebee infection evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- campaign-dns-activity
- rare-persistence-prevalence
max_iterations: 6
objective: Confirm if any host has been successfully compromised by correlating the
  anomalous execution of consent.exe with subsequent network infrastructure matches
  and rare binary persistence.
success_criteria: A verdict citing specific rows from at least two surfaces for any
  host determined to be malicious, explicitly correlating the host identified in detect-sideloading-lead
  with the findings from subsequent steps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final triage -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-logs)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the contents of ApplicationInstallationFolder_11 and dump the memory of any anomalous consent.exe processes for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Forensic review of accounts and tunnels -->
```manual target=analyst
Review the cited rows. Search hb_auth_signin for unauthorized Enterprise Admin accounts. Verify hb_network_connection for reverse SSH tunnels (e.g., port 22 to non-standard external IPs) used to proxy RDP.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the findings. If no malicious activity was found, record the lookback window and the specific domains searched. Recommend promoting the consent.exe path check to a standing detection rule.
```
→ end
