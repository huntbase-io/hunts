---
analysis: This hunt pivots across three telemetry surfaces (DNS, Process, and Network)
  to connect a user's web activity to an execution anomaly and subsequent C2 callout,
  providing the full context needed to differentiate an admin performing a legitimate
  install from an intruder using a trojanized decoy.
blind_spots:
- id: no-dns-retention
  question: whether a host visited the malicious domains outside the current retention
    window
  requires: long-term hb_dns_activity logs
  risk: A host infected weeks ago would be missed if the redirection event is no longer
    in the logs.
  stage: initial-access-seo-redirection
- id: no-process-visibility
  question: whether consent.exe was executed from a non-standard path
  requires: endpoint auditing of System32 binaries running from user-writable paths
  risk: Without path-aware process auditing, the side-loading of msimg32.dll goes
    unobserved.
  stage: execution-dll-side-loading
coverage:
- stage: initial-access-seo-redirection
  status: covered
  steps:
  - lead-dns-lookups
- stage: execution-dll-side-loading
  status: covered
  steps:
  - detect-sideloading
  - rare-binaries-in-user-paths
- stage: c2-establishment-adaptix
  status: covered
  steps:
  - detect-c2-activity
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
  justification: Bumblebee is a high-confidence precursor to Akira ransomware; identifying
    it at the delivery and C2 stage prevents catastrophic data exfiltration and encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has lured an administrator to a look-alike download page via
  SEO poisoning, leading to a trojanized installer that side-loads Bumblebee via consent.exe
  and establishes AdaptixC2.
labels:
- hunt
- attack.t1189
- attack.t1583.008
- attack.t1204.002
- attack.t1574.002
- attack.t1071.001
- attack.t1568.002
- attack.t1055
- command and control
- credential access
- discovery
- execution
- exfiltration
- impact
- initial access
- lateral movement
name: Bumblebee Delivery and C2 Establishment
parameters:
  c2_ips:
    default:
    - 84.32.84.32
    - 4.239.95.1
    description: Known C2 and staging IPs associated with this Bumblebee/Adaptix wave.
    from:
      kind: article
      observed: '2025-07-01'
      ref: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to narrow the expensive fan-out queries; populate
      from the lead query results.
    type: list[host]
  seo_domains:
    default:
    - opmanager.pro
    - download-center.online
    - ip-scanner.org
    - download-server.online
    - soft-server.online
    - soft-hub.pro
    - zenmap.pro
    - netml.shop
    description: Look-alike and delivery domains identified in the Bumblebee campaign.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-privileged IT administrator workstations and management servers,
  as these are the primary targets for ManageEngine look-alike decoys.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
related:
- hunt: bumblebee-discovery-and-persistence
  reason: Once established, Bumblebee performs discovery and installs RustDesk for
    persistence.
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
  index: 1
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


# Bumblebee Delivery and C2 Establishment

The adversary lulls administrators into a false sense of security with high-fidelity lookalike download pages for tools like ManageEngine OpManager. This hunt first searches for the cheap lead: DNS lookups to known SEO-poisoned redirection infrastructure. If a lead is found, it fans out to examine host-level process anomalies: the legitimate Windows binary consent.exe executed from unusual user-writable paths like AppData or Temp, and the prevalence of rare binaries in those same paths. The hunt then corroborates these hits with network connections to AdaptixC2 infrastructure or traffic from the renamed Address Book utility used for shellcode injection.

## lead-dns-lookups
<!-- Lead: DNS lookups to SEO look-alike domains -->
Identify hosts that interacted with the reported SEO poisoning infrastructure to narrow the hunt scope.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, seo_domains=seo_domains)
~~~yaml
expected: A host resolving one of the lookalike domains. Silence means no recorded
  interaction with the known delivery infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{seo_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## gate-read
<!-- Examine DNS lead -->
```agent target=hunter
cite: required
context:
- lead-dns-lookups
max_iterations: 3
objective: Determine if any host in the lead query results resolved the malicious
  SEO domains during the lookback window.
success_criteria: Confirm the presence of relevant DNS resolutions.
tools:
- endpoint
- network
```

## gate-decision
<!-- Decide to proceed with deeper investigation -->
if~: "the gate-read verdict finds at least one host resolved a malicious SEO domain" (confidence: high, judge=hunter)
then: → investigate-infection
indeterminate: → close-out
unavailable: → close-out (blind_spot: no-dns-retention)
else: → close-out

## investigate-infection
<!-- Fan-out investigation -->
parallel:
- → detect-sideloading
- → rare-binaries-in-user-paths
- → detect-c2-activity
join: → final-triage

## detect-sideloading
<!-- Detect side-loading of consent.exe from AppData or Temp -->
Identify the execution of a legitimate Windows binary from a non-standard, user-writable path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row showing consent.exe executing from a folder like ApplicationInstallationFolder_11
  under AppData.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(process_name) LIKE '%\consent.exe' AND (LOWER(process_name) LIKE '%\appdata\%' OR LOWER(process_name) LIKE '%\temp\%') AND LOWER(process_name) NOT LIKE 'c:\windows\system32\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-binaries-in-user-paths
<!-- Rare binaries in AppData or Temp -->
Stack-count processes running from user-writable paths to find rare Bumblebee-related binaries like AdgNsy.exe or dropped loaders.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process seen on only one or two hosts in the fleet, specifically targeting
  user-writable directories.
prevalence:
  by: device_hostname
  key:
  - name
  - path
  rare_below: 3
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT LOWER(process_name) AS name, LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\temp\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY name, path HAVING hosts <= 3 ORDER BY hosts ASC
```

## detect-c2-activity
<!-- Detect AdaptixC2 and Bumblebee C2 traffic -->
Corroborate the execution lead with network traffic to known malicious IPs or from the injected Address Book process.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Network connections to reported Azure C2 IPs or outbound traffic from AdgNsy.exe.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR LOWER(process_name) LIKE '%\adgnsy.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final infection triage -->
```agent target=hunter
cite: required
context:
- gate-read
- detect-sideloading
- rare-binaries-in-user-paths
- detect-c2-activity
max_iterations: 6
objective: Determine if any host shows the complete chain of SEO redirection followed
  by suspicious consent.exe execution and C2 network activity. Check for Bumblebee
  patterns such as the system locale check and specific ApplicationInstallationFolder_11
  paths.
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the available telemetry.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on infection verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → quarantine-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## quarantine-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR. Capture a memory dump of the AdgNsy.exe process if possible.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited DNS lookups and process execution paths for consent.exe. Check for signs of ManageEngine-OpManager.msi execution on the desktop or downloads folder.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the hosts examined and reasons for closing. Document any new SEO domains found during analysis.
```
→ end
