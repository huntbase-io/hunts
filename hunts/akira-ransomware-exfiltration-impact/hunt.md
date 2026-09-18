---
analysis: A simple rule might alert on 'locker.exe', but this hunt pivots between
  the installation of FileZilla, the creation of staging files in ProgramData, and
  connections to specific exfiltration IPs, providing a narrative context an individual
  rule lacks.
blind_spots:
- id: no-process-attribution-on-network
  question: Which process initiated the connection to the exfiltration IP?
  requires: Endpoint telemetry with socket-to-process mapping
  risk: In environments where only network flow logs are available (e.g., AWS VPC
    flows), we see the traffic to the exfil IP but cannot confirm if it was FileZilla
    or another tool.
  stage: collection-and-exfiltration
- id: file-content-not-visible
  question: Does shares.txt actually contain sensitive data?
  requires: DLP or Data Forensics
  risk: The hunt identifies the creation of the file, but without content inspection,
    an analyst cannot immediately confirm the volume or sensitivity of exfiltrated
    data.
  stage: collection-and-exfiltration
coverage:
- stage: collection-and-exfiltration
  status: covered
  steps:
  - scoping-filezilla-installation
  - network-exfiltration-events
  - file-staging-activity
- stage: impact-akira-ransomware
  status: covered
  steps:
  - ransomware-process-prevalence
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: initial-access-seo-poisoning
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: execution-bumblebee-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: c2-bumblebee-and-adaptix
  status: out_of_scope
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
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Data exfiltration is the primary motivation for many actors, and
    Akira ransomware is the final destructive impact. Identifying staging and exfiltration
    attempts allows for intervention before the final encryption phase.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has staged reconnaissance data in ProgramData, exfiltrated
  it via FileZilla/SFTP, and deployed Akira ransomware binaries (locker.exe/win.exe)
  for environment-wide encryption.
labels:
- hunt
- attack.t1048.003
- attack.t1560.001
- attack.t1486
name: 'Akira Ransomware: Data Exfiltration and Impact'
parameters:
  exfil_ips:
    default:
    - 185.174.100.203
    description: Known SFTP exfiltration servers identified in research.
    from:
      kind: article
      observed: '2025-08-05'
      ref: DFIR Report Akira
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  ransomware_binaries:
    default:
    - locker.exe
    - win.exe
    description: Binary names associated with the Akira payload.
    from:
      kind: article
      observed: '2025-08-05'
      ref: DFIR Report Akira
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt (from scoping step).
    type: list[host]
  staging_paths:
    default:
    - c:\programdata\shares.txt
    description: Observed paths for data staging.
    from:
      kind: article
      observed: '2025-08-05'
      ref: DFIR Report Akira
    type: list[path]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers, particularly backup and file servers, as these were
  targeted for data exfiltration and database credential dumping.
references:
- name: "DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: akira-credential-access-recovery
  reason: This hunt focuses on the end-stage; credential access (NTDS dumping, LSASS)
    is handled in the previous hunt in the series.
  relation: out-of-scope-alternative
- hunt: bumblebee-discovery-creds
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
  index: 3
  slug: flash-alert-from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'Flash Alert: From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver
    Akira'
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


# Akira Ransomware: Data Exfiltration and Impact

This hunt focuses on the final stages of the Bumblebee/AdaptixC2 attack chain. It investigates evidence of data staging (specifically 'shares.txt' in ProgramData), network exfiltration to identified attacker infrastructure using SFTP, and the presence of Akira ransomware payloads. By correlating file system artifacts, network connections, and rare process execution, this hunt identifies hosts where the impact is imminent or has already occurred.

## scoping-filezilla-installation
<!-- Scope hosts with FileZilla installation -->
Identify hosts where FileZilla, the tool used for exfiltration in this campaign, has been installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts with FileZilla installed. While legitimate in some contexts, installation
  on servers or by non-admins during a suspected incident is high signal.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%filezilla%' OR LOWER(vendor_name) LIKE '%filezilla%'
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → network-exfiltration-events
- → file-staging-activity
- → ransomware-process-prevalence
join: → triage-impact

## network-exfiltration-events
<!-- SFTP network exfiltration to identified IPs -->
Find network connections to the SFTP exfiltration servers identified in the research.

```sqlite target=network role=detection-candidate params=(exfil_ips=exfil_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Connections to known bad IPs, likely associated with FileZilla or other
  SFTP clients.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{exfil_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-staging-activity
<!-- Data staging in ProgramData -->
Detect the creation of the specific 'shares.txt' staging file or other suspicious file activity in ProgramData.

```sqlite target=endpoint role=triage params=(staging_paths=staging_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of shares.txt or a sudden cluster of text files in ProgramData,
  indicative of reconnaissance staging.
reads:
- activity_id
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (instr(',' || '{{staging_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR (LOWER(file_path) LIKE '%\programdata\%.txt' AND activity_id = 1)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransomware-process-prevalence
<!-- Prevalence of Akira binaries and ProgramData processes -->
Identify rare binaries matching Akira payload names or any process executing from ProgramData, which is a common staging ground.

```sqlite target=endpoint role=baseline params=(ransomware_binaries=ransomware_binaries, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes (seen on < 3 hosts) running from staging paths or matching
  Akira filenames like 'locker.exe'.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{ransomware_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR (LOWER(process_path) LIKE '%\programdata\%' AND LOWER(process_path) NOT LIKE '%\malwarebytes\%' AND LOWER(process_path) NOT LIKE '%\microsoft\%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## triage-impact
<!-- Triage exfiltration and ransomware activity -->
```agent target=hunter
cite: required
context:
- network-exfiltration-events
- file-staging-activity
- ransomware-process-prevalence
max_iterations: 3
objective: Determine if the evidence supports a full ransomware intrusion (Akira)
  following data exfiltration.
success_criteria: A per-host verdict (malicious/suspicious/benign) citing specific
  staging files and C2/Exfil IPs.
tools:
- endpoint
- network
```

## impact-decision
<!-- Route on ransomware/exfiltration verdict -->
if~: "The triage verdict is malicious for Akira ransomware or confirmed exfiltration." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-process-attribution-on-network)
else: → manual-review

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and initiate full incident response.
```
→ manual-review

## manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the identified staging files and network connections. Confirm if the rare processes observed are legitimate or malicious. If confirmed, continue with isolation and cleanup.
```
→ end
