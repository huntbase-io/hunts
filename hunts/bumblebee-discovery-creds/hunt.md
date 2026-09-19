---
analysis: A single rule on 'net.exe' or 'wbadmin' causes noise; this hunt correlates
  discovery sequences with rare parent processes and subsequent credential theft activity
  to confirm an intrusion.
blind_spots:
- id: script-transcription-gap
  owner: Security Operations
  question: What obfuscated scripts were run during discovery?
  remediation: Enable PowerShell Script Block Logging (GPO).
  requires: hb_script_activity (PowerShell transcription)
  risk: Adversaries using Invoke-ShareFinder in memory would not be caught by process
    command-line monitoring.
  stage: discovery-built-in-utilities
- id: tunnel-ip-rotation
  owner: Threat Intelligence
  question: Are connections to new, unlisted SSH tunnel IPs occurring?
  remediation: Integrate a live C2 feed into the tunnel_ips parameter.
  requires: Threat Intel Feed
  risk: A hunt relying only on article IPs will miss infrastructure that rotated after
    the report.
  stage: persistence-accounts-and-remote-access
coverage:
- stage: discovery-built-in-utilities
  status: covered
  steps:
  - discovery-and-account-leads
  - powershell-discovery-scripts
  - baseline-discovery-parents
- stage: persistence-accounts-and-remote-access
  status: covered
  steps:
  - discovery-and-account-leads
  - reverse-tunnel-connections
- stage: credential-access-ntds-and-lsass
  status: covered
  steps:
  - credential-harvesting-activity
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
  justification: Detecting the pivot from initial access to domain-wide discovery
    is the highest-value window for preventing ransomware impact. These actions (AD
    database dumping and enterprise admin account creation) have low false-positive
    rates for non-admin accounts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has pivoted from an initial workstation to domain discovery
  using built-in utilities, creating high-privilege service-style accounts, and staging
  NTDS.dit or LSASS dumps for credential harvesting.
labels:
- hunt
- attack.t1003.003
- attack.t1003.001
- attack.t1082
- attack.t1016
- attack.t1069.002
- attack.t1087.002
- attack.t1136.002
- attack.t1572
- attack.t1021.001
name: Bumblebee discovery and domain credential harvesting
parameters:
  discovery_binaries:
    default:
    - nltest.exe
    - whoami.exe
    - net.exe
    - net1.exe
    - systeminfo.exe
    description: Common binaries used for internal discovery.
    from:
      kind: manual
      observed: '2025-08-05'
      ref: common-living-off-the-land
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Narrow to specific hostnames (e.g. Domain Controllers); leave empty
      for all.
    type: list[host]
  tunnel_ips:
    default:
    - 193.242.184.150
    - 83.229.17.60
    description: Known external IP addresses used for SSH tunneling in this campaign.
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with domain controllers and critical infrastructure servers. If no
  hits, widen to the entire server estate and workstations using 'backup_' in user
  profiles.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: bumblebee-initial-access
  reason: This hunt picks up after the Bumblebee delivery and sideloading phase.
  relation: follows
- hunt: akira-ransomware-impact
  reason: This hunt aims to stop the intrusion before the Akira locker is deployed.
  relation: precedes
- hunt: bumblebee-initial-access-c2-deployment
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Bumblebee discovery and domain credential harvesting

This hunt focuses on the critical escalation phase of an Akira ransomware intrusion. After gaining access via Bumblebee, threat actors typically perform noisy network discovery and create 'backup' themed administrator accounts to maintain access and dump credentials. We look for a sequence of built-in utility executions (nltest, net, whoami) followed by the use of wbadmin to backup the Active Directory database (NTDS.dit) and the use of comsvcs.dll to dump LSASS memory. The hunt also monitors for reverse SSH tunnels used for persistent re-entry and stack-counts the parents of discovery tools to isolate AdaptixC2 beacons.

## server-inventory-scope
<!-- Identify Windows Servers -->
Narrows the hunt focus to servers and domain controllers where AD discovery and credential dumping are most impactful.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames representing the server estate within the lookback window.
reads:
- hostname
- os_name
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE LOWER(os_name) LIKE '%server%' AND lifecycle_state = 'active' AND time >= datetime('now', '-{{lookback_days}} days')
```

## discovery-and-account-leads
<!-- Noisy discovery and suspicious account creation -->
Identify hosts running domain discovery tools or creating service-style admin accounts (e.g. backup_EA).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes like nltest.exe, net.exe, or whoami.exe being run with discovery
  flags, or net user commands creating 'backup_' accounts. Silence means no such commands
  were captured.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/dclist:%' OR LOWER(process_cmd_line) LIKE '%domain admins%' OR LOWER(process_cmd_line) LIKE '%/groups%' OR LOWER(process_cmd_line) LIKE '%/add /dom%' OR LOWER(process_cmd_line) LIKE '%backup_ea%' OR LOWER(process_cmd_line) LIKE '%backup_da%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with credentials, tunnels, and scripts -->
parallel:
- → credential-harvesting-activity
- → reverse-tunnel-connections
- → powershell-discovery-scripts
- → baseline-discovery-parents
join: → triage-tactic-progression

## credential-harvesting-activity
<!-- Dumping NTDS.dit and LSASS memory -->
Corroborate discovery with specific credential dumping techniques using wbadmin, comsvcs, or psql.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: A hit indicates a high-severity attempt to harvest domain or database credentials.
  Silence means no such command strings were captured.
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
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE ((LOWER(process_cmd_line) LIKE '%wbadmin%' AND LOWER(process_cmd_line) LIKE '%ntds.dit%') OR (LOWER(process_cmd_line) LIKE '%comsvcs.dll%' AND LOWER(process_cmd_line) LIKE '%#+000024%') OR (LOWER(process_cmd_line) LIKE '%psql%' AND LOWER(process_cmd_line) LIKE '%veeambackup%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## reverse-tunnel-connections
<!-- Network connections to tunneling infrastructure -->
Detect network traffic to external IPs identified in the campaign or unusual SSH patterns.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, tunnel_ips=tunnel_ips)
~~~yaml
expected: Outbound connections to campaign IPs. Silence means no connections to these
  specific IPs occurred.
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
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{tunnel_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-discovery-scripts
<!-- Domain discovery script execution -->
Detect script-based discovery (Invoke-ShareFinder) which may not be visible in process command lines.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Rows showing domain enumeration scripts. Silence suggests these specific
  scripts were not executed.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%invoke-sharefinder%' OR LOWER(script_content) LIKE '%export-dnsserverzone%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-discovery-parents
<!-- Prevalence of discovery tool parents -->
Stack-count the parents of built-in discovery tools to isolate those launched by non-standard processes like Adaptix beacons.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, discovery_binaries=discovery_binaries)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare parent processes (e.g., a random alphanumeric EXE) launching system
  discovery tools. Benign parents like explorer.exe or SCCM should count high.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  rare_below: 3
reads:
- parent_process_name
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT parent_process_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS execs, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{discovery_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY parent_process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-tactic-progression
<!-- Triage tactic progression -->
```agent target=hunter
cite: required
context:
- discovery-and-account-leads
- credential-harvesting-activity
- reverse-tunnel-connections
- powershell-discovery-scripts
- baseline-discovery-parents
max_iterations: 4
objective: Decide if the observed activity indicates a move from initial access to
  domain-level compromise by correlating discovery, account creation, and dumping.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  evidence for each phase.
tools:
- endpoint
- network
```

## decision-route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for any host exhibiting discovery followed by account creation or credential dumping." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: script-transcription-gap)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR. Revoke credentials for any identified 'backup_' accounts and disable the SSH tunnel process if found.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage citations. If verified as an intrusion, initiate the Akira ransomware response playbook. If a false positive by a legit admin, tune the discovery leads query.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Log the negative result or benign findings. Note any visibility gaps encountered.
```
→ end
