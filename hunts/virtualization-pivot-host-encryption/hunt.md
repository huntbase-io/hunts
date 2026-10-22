---
analysis: A single detection rule cannot distinguish between administrative maintenance
  and a coordinated ransomware pivot to the hypervisor. This hunt joins early reconnaissance
  tools with lateral movement toward virtualization management and follow-on hypervisor
  configuration changes, providing the context necessary to confirm a sophisticated
  multi-stage intrusion.
blind_spots:
- id: esxi-visibility-gap
  question: What specifically was run after execInstalledOnly was disabled?
  requires: Direct hypervisor audit logs or host-based agent on ESXi
  risk: Attackers can run custom compiled tools on the hypervisor that are invisible
    to guest-level EDR.
  stage: defense-evasion-esxi-security
- id: veeam-database-access
  question: Was the Veeam configuration database queried directly?
  requires: hb_datastore_activity with full SQL auditing
  risk: CVE-2023-27532 allows direct credential extraction; without DB logs, the extraction
    itself is invisible, only the subsequent use of those credentials is seen.
  stage: credential-access-offline-vmdk
coverage:
- stage: lateral-movement-vcenter-pivot
  status: covered
  steps:
  - infrastructure-pivots
- stage: defense-evasion-esxi-security
  status: covered
  steps:
  - esxi-security-changes
- stage: credential-access-offline-vmdk
  status: covered
  steps:
  - identify-vulnerable-targets
  - vmdk-offline-access
- stage: discovery-rmm-recon
  status: covered
  steps:
  - rare-rmm-activity
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - ransomware-impact
- reason: 'Belongs to another part of the ''Threat Brief: Active Exploitation of PAN-OS
    CVE-2026-0257 (Updated October 19)'' series.'
  stage: initial-access-pan-os-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''Threat Brief: Active Exploitation of PAN-OS
    CVE-2026-0257 (Updated October 19)'' series.'
  stage: unauthorized-vpn-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The adversary exploits PAN-OS vulnerabilities to breach the perimeter,
    directly threatening critical virtualization and backup assets. A negative result
    across these high-value systems provides the business with assurance that the
    most impactful stages of a ransomware campaign are not currently active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: The adversary has exploited a VPN gateway to breach the perimeter and
  is now pivoting to the virtualization layer to disable security controls and deploy
  ransomware via virtual disk manipulation.
labels:
- hunt
- attack.t1190
- attack.t1021.001
- attack.t1562.001
- attack.t1003
- attack.t1046
- attack.t1486
- credential access
- defense evasion
- discovery
- impact
- initial access
- lateral movement
- persistence
name: Virtualization Pivot and Host Encryption
parameters:
  infra_keywords:
    default:
    - vcenter
    - vpxd
    - esxi
    - backup
    - veeam
    - domain-controller
    - dc01
    description: Keywords identifying critical infrastructure targets.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of telemetry to examine.
    type: number
  rmm_tools:
    default:
    - anydesk.exe
    - screenconnect.exe
    - atera.exe
    - splashtop.exe
    - rustdesk.exe
    - teamviewer.exe
    - logmein.exe
    description: Common dual-use RMM executable names used for persistence and recon.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: common-rmm-list
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty to scan
      the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers, domain controllers, and backup infrastructure (Veeam).
  Use the vulnerability scoping step to identify the most likely beachheads before
  fanning out.
references:
- name: "Unit 42 \u2014 Active Exploitation of PAN-OS CVE-2026-0257"
  url: https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/
related:
- hunt: initial-access-pan-os-exploit
  reason: Initial access occurs via the PAN-OS VPN gateway before the virtualization
    pivot.
  relation: precedes
- hunt: vpn-gateway-exploitation-unauthorized-auth
  relation: follows
scenario:
  stages:
  - name: PAN-OS GlobalProtect Exploitation
    observables:
    - CVE-2026-0257
    - 23.128.228.6
    - 104.207.144.154
    - 146.19.216.119
    - 146.19.216.120
    - 146.19.216.125
    - 179.43.172.213
    - 185.195.232.139
    - 198.12.106.60
    - 202.144.192.47
    slug: initial-access-pan-os-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized VPN Session Establishment
    observables:
    - aa:bb:cc:dd:ee:ff
    - 00:11:22:33:44:55
    - WINDOWS-LAPTOP-001
    - DESKTOP-GP01
    - GP-CLIENT
    - Microsoft Windows 10 Pro 64-bit
    slug: unauthorized-vpn-persistence
    tactic: persistence
    techniques:
    - T1133
  - name: Pivot to Virtualization Layer
    observables:
    - RDP to vCenter management appliance
    - SMB lateral movement
    slug: lateral-movement-vcenter-pivot
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Disabling ESXi Security Controls
    observables:
    - execInstalledOnly disabled on ESXi hypervisors
    slug: defense-evasion-esxi-security
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Offline Virtual Disk Credential Dumping
    observables:
    - Custom tool for VMDK dumping
    - Dumping Domain Controller virtual disks
    - CVE-2023-27532
    - Veeam backup infrastructure exploitation
    slug: credential-access-offline-vmdk
    tactic: credential-access
    techniques:
    - T1003
  - name: Internal Reconnaissance with RMM
    observables:
    - Dual-use RMM tools
    slug: discovery-rmm-recon
    tactic: discovery
    techniques:
    - T1046
  - name: Data Encryption for Impact
    observables:
    - Qilin ransomware
    - Inc ransomware
    - Settra ransomware
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Ransomware operators including Qilin and Inc exploit CVE-2026-0257 to bypass
    authentication on Palo Alto Networks GlobalProtect gateways, establishing unauthorized
    VPN sessions. Attackers then pivot to the virtualization layer (vCenter/ESXi)
    to disable security controls and perform offline credential dumping against domain
    controller virtual disks before deploying ransomware.
series:
  index: 2
  slug: threat-brief-active-exploitation-of-pan-os-cve-2026-0257-updated-october-19
  title: 'Threat Brief: Active Exploitation of PAN-OS CVE-2026-0257 (Updated October
    19)'
  total: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Virtualization Pivot and Host Encryption

The adversary exploits PAN-OS and pivots from the VPN gateway to the virtualization and backup infrastructure. This hunt targets the sophisticated post-access tradecraft observed following this exploitation. It examines the use of dual-use RMM tools for reconnaissance, identifies lateral movement toward vCenter and backup infrastructure, and detects the pivot to the ESXi hypervisor layer where security controls are disabled. Finally, it looks for the characteristic file encryption patterns of ransomware families like Qilin and Inc that occur after credentials have been harvested from virtual disks. The analyst reviews these correlated signals to stop the impact before it reaches the full fleet.

## identify-vulnerable-targets
<!-- Identify vulnerable backup infrastructure -->
Find Veeam infrastructure hosts affected by CVE-2023-27532 that serve as primary targets for credential theft.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows identify specific hosts running vulnerable Veeam components. Silence
  means the estate is patched or not running Veeam.
reads:
- device_uid
- resource_uid
- affected_package_name
- affected_package_version
- severity
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_uid, resource_uid, affected_package_name, affected_package_version, severity FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2023-27532' AND status != 'suppressed'
```

## parallel-early-evidence
<!-- Gather early-stage beachhead evidence -->
parallel:
- → rare-rmm-activity
- → infrastructure-pivots
join: → triage-early-beachhead

## rare-rmm-activity
<!-- Rare RMM tool activity -->
Detect dual-use RMM tools that are rare across the fleet, suggesting they were dropped by an attacker for persistence or recon.

```sqlite target=endpoint role=baseline params=(rmm_tools=rmm_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts running an RMM tool that is not part of standard IT operations.
  Silence means no known RMM binaries were executed.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT LOWER(process_name) AS rmm_bin, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## infrastructure-pivots
<!-- Lateral logons to virtualization infrastructure -->
Identify RDP or Network logons from unexpected source workstations to sensitive infrastructure like vCenter or domain controllers.

```sqlite target=identity role=enrichment params=(infra_keywords=infra_keywords, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Logon events to servers containing infrastructure keywords. Silence proofs
  no remote interactive sessions occurred to these targets within the window.
reads:
- device_hostname
- actor_user_name
- dst_endpoint_hostname
- logon_type
- src_endpoint_ip
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, actor_user_name, dst_endpoint_hostname, logon_type, src_endpoint_ip, time FROM hb_auth_signin WHERE (logon_type_id IN (3, 10)) AND (instr(',' || '{{infra_keywords}}' || ',', LOWER(dst_endpoint_hostname)) > 0 OR instr(',' || '{{infra_keywords}}' || ',', LOWER(device_hostname)) > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-beachhead
<!-- Triage early-stage beachhead -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-targets
- rare-rmm-activity
- infrastructure-pivots
max_iterations: 4
objective: Determine if the combination of rare RMM tools and lateral movement to
  infrastructure indicates a high-confidence intrusion on specific hosts.
success_criteria: Verdicts (Malicious | Suspicious | Benign) per host with citations.
tools:
- endpoint
- identity
```

## parallel-follow-on
<!-- Search for follow-on virtualization and impact behavior -->
parallel:
- → vmdk-offline-access
- → esxi-security-changes
- → ransomware-impact
join: → full-chain-analysis

## vmdk-offline-access
<!-- Offline virtual disk access and dumping -->
Detect the use of tools or commands aimed at mounting or dumping virtual disks (VMDKs) to harvest credentials offline.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Commands linking virtual disk files to credential storage locations. Silence
  proofs no such shell commands were executed.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vmdk%' OR LOWER(process_cmd_line) LIKE '%mount%' OR LOWER(process_cmd_line) LIKE '%vmtools%') AND (LOWER(process_cmd_line) LIKE '%ntds%' OR LOWER(process_cmd_line) LIKE '%sam%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## esxi-security-changes
<!-- ESXi security control modification -->
Search syslog records for modifications to ESXi security settings like execInstalledOnly that attackers use to run custom tooling.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A log message indicating a security control on the hypervisor was disabled.
  Silence suggests no such configuration change was logged to this syslog collector.
reads:
- device_hostname
- message
- syslog_tag
- time
silence: not_evidence_of_absence
source: hb_syslog
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, message, syslog_tag, time FROM hb_syslog WHERE (LOWER(message) LIKE '%execinstalledonly%' AND LOWER(message) LIKE '%disabled%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransomware-impact
<!-- Mass file renaming (Ransomware behavior) -->
Identify high-frequency file modification or renaming activity typical of Qilin or Inc ransomware deployment.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts where a single process has touched dozens of files with ransom extensions.
  None means no such large-scale encryption was visible.
reads:
- device_hostname
- process_name
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, process_name, COUNT(*) AS file_ops, MIN(time) AS start_time FROM hb_file_activity WHERE activity_id IN (3, 5) AND (LOWER(file_path) LIKE '%.locked' OR LOWER(file_path) LIKE '%.inc' OR LOWER(file_path) LIKE '%.qilin' OR LOWER(file_path) LIKE '%recovery%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_ops > 50
```

## full-chain-analysis
<!-- Full chain analysis -->
```agent target=hunter
cite: required
context:
- triage-early-beachhead
- vmdk-offline-access
- esxi-security-changes
- ransomware-impact
max_iterations: 6
objective: Integrate findings from RMM usage, lateral movement, vCenter access, VMDK
  dumping, and ransomware encryption patterns to confirm a full-scale compromise.
success_criteria: A detailed verdict citing the full path from initial internal pivot
  to impact.
tools:
- endpoint
- identity
```

## threat-routing
<!-- Decision: Active ransomware chain detected -->
if~: "the full-chain-analysis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → containment
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: esxi-visibility-gap)
else: → analyst-validation

## containment
<!-- Isolate compromised hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the hosts identified by the agent and revoke any credentials used from those systems.
```
→ analyst-validation

## analyst-validation
<!-- Analyst review and tuning -->
```manual target=analyst
Review the RMM and lateral movement citations. Confirm if the RMM usage is sanctioned and document the source of any virtualization-layer modifications.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the hunt results. If Ransomware behavior was confirmed, transition to the full Ransomware Incident Response playbook.
```
→ end
