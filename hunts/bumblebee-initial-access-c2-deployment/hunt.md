---
analysis: A standard rule might detect one known C2 IP or a specific hash. This hunt
  correlates the target software context (IT lures), the side-loading behavior (msimg32.dll),
  and the statistical rarity of DGA domains to find the breach even as hashes and
  IPs rotate.
blind_spots:
- id: module-visibility-gap
  question: Whether msimg32.dll was side-loaded into consent.exe
  requires: hb_module_activity (endpoint telemetry for module loads)
  risk: Without module load events, the primary behavioral indicator for Bumblebee
    execution is invisible, forcing total reliance on network indicators.
  stage: execution-bumblebee-sideloading
- id: dns-dga-noise
  question: Whether rare .org domains are DGA or rare legitimate web services
  requires: hb_dns_activity with query history
  risk: High potential for false positives if internal tools use randomized domain
    patterns.
  stage: c2-bumblebee-and-adaptix
coverage:
- stage: initial-access-seo-poisoning
  status: covered
  steps:
  - scope-hosts-by-software
  - msi-download-activity
- stage: execution-bumblebee-sideloading
  status: covered
  steps:
  - sideloading-msimg32
- stage: c2-bumblebee-and-adaptix
  status: covered
  steps:
  - c2-ip-connections
  - dga-dns-prevalence
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: discovery-built-in-utilities
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: persistence-accounts-and-remote-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: credential-access-ntds-and-lsass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: collection-and-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: impact-akira-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Bumblebee is a high-volume initial access tool for ransomware affiliates.
    Identifying the breach at the first stage on the beachhead host is critical to
    stopping the 9-44 hour path to full enterprise encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised an IT administrator via SEO poisoning, leading
  to the execution of a trojanized installer that side-loads Bumblebee and establishes
  AdaptixC2 connectivity.
labels:
- hunt
- attack.t1189
- attack.t1566.002
- attack.t1574.002
- attack.t1204.002
- attack.t1071.001
- attack.t1568.002
name: Bumblebee Initial Access and C2 Deployment
parameters:
  c2_ips:
    default:
    - 109.205.195.211
    - 188.40.187.145
    - 172.96.137.160
    - 170.130.55.223
    - 193.242.184.150
    - 185.174.100.203
    - 83.229.17.60
    description: Known C2 and infrastructure IPs associated with Bumblebee and AdaptixC2.
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_msi_filenames:
    default:
    - manageengine-opmanager.msi
    - advanced-ip-scanner.msi
    - ip-scanner.msi
    description: Specific MSI filenames used in the SEO poisoning campaign.
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying IT administrators and systems where management
  tools are already installed, as these are the primary targets for SEO poisoning
  lures like 'ManageEngine'. If no specific hosts are provided, it runs fleet-wide
  with a focus on user-writable directories.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: akira-discovery-and-lateral-recon
  reason: This hunt focuses on initial access; the follow-up hunt examines the domain
    reconnaissance and lateral movement phase.
  relation: follows
scenario:
  stages:
  - name: Trojanized Installer via SEO Poisoning
    observables:
    - opmanager.pro
    - angryipscanner.org
    - axiscamerastation.org
    - ip-scanner.org
    - ManageEngine-OpManager.msi
    - Advanced-IP-Scanner.msi
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1189
    - T1566.002
  - name: Bumblebee Loader Side-loading
    observables:
    - msimg32.dll
    - consent.exe
    slug: execution-bumblebee-sideloading
    tactic: execution
    techniques:
    - T1574.002
    - T1204.002
  - name: Multi-Stage C2 Establishment
    observables:
    - 109.205.195.211
    - 188.40.187.145
    - 172.96.137.160
    - 170.130.55.223
    - ev2sirbd269o5j.org
    - 2rxyt9urhq0bgj.org
    - AdgNsy.exe
    slug: c2-bumblebee-and-adaptix
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1568.002
  - name: Internal Network Discovery
    observables:
    - systeminfo
    - 'nltest /dclist:'
    - whoami /groups
    - net group "domain admins" /dom
    - Invoke-ShareFinder
    - Export-DnsServerZone
    slug: discovery-built-in-utilities
    tactic: discovery
    techniques:
    - T1082
    - T1016
    - T1069.002
    - T1087.002
  - name: Persistence and Reverse Tunnelling
    observables:
    - backup_DA
    - backup_EA
    - RustDesk
    - ssh.exe -R *:10400 -p22
    - 193.242.184.150
    - 83.229.17.60
    slug: persistence-accounts-and-remote-access
    tactic: persistence
    techniques:
    - T1136.002
    - T1219
    - T1572
  - name: Domain Credential Dumping
    observables:
    - wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include":C:\windows\NTDS\ntds.dit
    - 'comsvcs.dll, #+000024'
    - psql.exe -U postgres --csv -d VeeamBackup -c "SELECT user_name,password..."
    slug: credential-access-ntds-and-lsass
    tactic: credential-access
    techniques:
    - T1003.003
    - T1003.001
    - T1552.002
  - name: Data Staging and SFTP Exfiltration
    observables:
    - FileZilla
    - 185.174.100.203
    - C:\ProgramData\shares.txt
    slug: collection-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1048.003
    - T1560.001
  - name: Akira Ransomware Deployment
    observables:
    - locker.exe
    - win.exe
    slug: impact-akira-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: A threat actor used SEO poisoning on Bing to deliver trojanized IT management
    installers, leading to Bumblebee and AdaptixC2 infections. The intrusion escalated
    to a full network compromise where the actor performed credential dumping, established
    persistent remote access via RustDesk, exfiltrated data, and ultimately deployed
    Akira ransomware.
series:
  index: 1
  slug: flash-alert-from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'Flash Alert: From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver
    Akira'
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


# Bumblebee Initial Access and C2 Deployment

This hunt identifies the initial entry point and command-and-control establishment of the Bumblebee malware. We start by scoping hosts with IT management tools typically targeted in SEO poisoning campaigns, then look for the specific MSI installers used as lures. The hunt pivots to detect the sideloading of msimg32.dll into legitimate system processes like consent.exe and corroborates this with network connections to known C2 infrastructure and DGA-patterned DNS lookups. An agent triages the multiple evidence streams to identify active infections before they move to lateral movement.

## scope-hosts-by-software
<!-- Scope hosts with targeted IT tools -->
Identify hosts that have IT management tools installed, as these users are likely the primary targets for SEO poisoning campaigns targeting admins.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to IT staff. If empty, the hunt continues
  unscoped.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE instr(LOWER(package_name), 'manageengine') > 0 OR instr(LOWER(package_name), 'opmanager') > 0
```

## msi-download-activity
<!-- MSI activity in user directories -->
Detect the download or presence of trojanized installers identified in the report, or any MSI in user-writable paths.

```sqlite target=endpoint role=triage params=(lure_msi_filenames=lure_msi_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: MSI file interaction in user profile folders like Downloads or Desktop.
  This provides the primary entry lead.
reads:
- device_hostname
- file_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, actor_user_name, time FROM hb_file_activity WHERE (instr(',' || '{{lure_msi_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR (LOWER(file_path) LIKE '%\\users\\%' AND LOWER(file_name) LIKE '%.msi')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate infection signals -->
parallel:
- → sideloading-msimg32
- → c2-ip-connections
- → dga-dns-prevalence
join: → triage-agent

## sideloading-msimg32
<!-- Bumblebee DLL side-loading -->
Detect the side-loading of msimg32.dll from non-system directories, a core behavioral indicator for Bumblebee execution.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A module load for msimg32.dll where the path is within a user directory
  or C:\ProgramData. This is the primary behavioral detection candidate.
reads:
- device_hostname
- process_name
- module_path
- module_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_path, time FROM hb_module_activity WHERE LOWER(module_name) = 'msimg32.dll' AND module_path IS NOT NULL AND LOWER(module_path) NOT LIKE 'c:\\windows\\system32\\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-ip-connections
<!-- Outbound traffic to C2 IPs -->
Identify connections to the Adaptix and Bumblebee IPs associated with this campaign.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Network connections to known-bad infrastructure from hosts that also showed
  suspicious MSI or DLL activity.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dga-dns-prevalence
<!-- Rare DGA-patterned .org domains -->
Search for randomized .org domains matching the 8-14 character Bumblebee DGA pattern and filter for fleet rarity.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One or two randomized domains found on only one host. These represent the
  DGA signals that survive IP rotation.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.org' AND length(replace(LOWER(query_hostname), '.org', '')) BETWEEN 8 AND 14 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-agent
<!-- Triage Bumblebee infection -->
```agent target=hunter
cite: required
context:
- msi-download-activity
- sideloading-msimg32
- c2-ip-connections
- dga-dns-prevalence
max_iterations: 4
objective: Determine if a host has been compromised via the reported SEO poisoning
  campaign. Weigh the presence of lure MSI files against the side-loading of msimg32.dll
  and communication with the listed infrastructure.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  evidence rows.
tools:
- endpoint
- network
```

## route-infection
<!-- Route on verdict -->
if~: "The triage verdict is malicious for any host where side-loading or known C2 traffic was confirmed." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: module-visibility-gap)
else: → forensic-review

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified endpoint. Revoke all active cloud and SSO sessions for the user account identified in the activity.
```
→ forensic-review

## forensic-review
<!-- Forensic review and scoping -->
```manual target=analyst
Review the host's C:\ProgramData and user profile directories for recently created .exe files with random names (potential AdaptixC2). Verify if consent.exe spawned any unusual child processes.
```
→ close-hunt

## close-hunt
<!-- Close hunt and record tuning -->
```manual target=analyst
Record the findings. If benign, document the legitimate MSI software paths for tuning future behavioral rules.
```
→ end
