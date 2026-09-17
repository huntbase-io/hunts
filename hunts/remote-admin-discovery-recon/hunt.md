---
analysis: A single detection rule might alert on 'PsExec' or 'vssadmin', but those
  are frequently used by IT. This hunt is distinct because it correlates the *sequence*
  of remote execution, session discovery, and specific DNS lookups for backup infrastructure
  across three surfaces, using fleet prevalence to filter out legitimate admin activity.
blind_spots:
- id: incomplete-process-telemetry
  question: Can we see short-lived processes spawned by remote services?
  requires: EDR process logging on all target servers
  risk: If a server lacks process monitoring, an attacker can move laterally and run
    recon tools without generating any rows in hb_process_activity.
  stage: lateral-movement-psexec
- id: non-dns-discovery
  question: Are attackers performing IP-based scanning without DNS resolution?
  requires: hb_network_connection
  risk: The DNS step targets reconnaissance for named backup infra; a direct IP scan
    for SMB/RDP would not be caught by the DNS query.
  stage: host-and-session-discovery
coverage:
- stage: lateral-movement-psexec
  status: covered
  steps:
  - psexec-lateral-movement
- stage: host-and-session-discovery
  status: covered
  steps:
  - session-and-vss-discovery
  - dns-enumeration-anomalies
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: vss-creation-for-credentials
  status: out_of_scope
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: vss-deletion-and-inhibition
  status: out_of_scope
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: data-encryption-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries rely on discovery and lateral movement to identify high-value
    targets. Detecting this behavior provides an early-warning signal for credential
    theft and ransomware campaigns before VSS deletion or encryption occurs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using PsExec to move laterally to Windows servers and
  executing session or network discovery to identify high-value targets, including
  backup infrastructure, before attempting VSS manipulation.
labels:
- hunt
- attack.t1021.002
- attack.t1021.001
- attack.t1018
- attack.t1033
- attack.t1490
name: Remote Administration and Discovery Reconnaissance
parameters:
  backup_keywords:
    default:
    - backup
    - veeam
    - synology
    - nas
    - storage
    - rubrik
    - cohesity
    description: Keywords associated with backup infrastructure and storage devices.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: backup-infra-recon
    type: list[string]
  discovery_tools:
    default:
    - qwinsta.exe
    - query.exe
    - nslookup.exe
    - net.exe
    - nltest.exe
    - vssadmin.exe
    description: Common binaries used for session and network discovery.
    from:
      kind: article
      observed: '2026-09-14'
      ref: huntress-vss-abuse
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of process and network history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: hunt-standard
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/vss-abuse-explained
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets Windows servers and domain controllers, as these are the
  primary targets for large-scale ransomware impact and credential theft through NTDS.dit
  extraction.
references:
- name: How Attackers Abuse VSS, and How Huntress Detects It
  url: https://www.huntress.com/blog/vss-abuse-explained
related:
- hunt: vss-creation-credentials
  reason: This hunt identifies the reconnaissance that precedes the creation of a
    VSS shadow for credential theft.
  relation: follows
- hunt: vss-deletion-inhibition
  reason: This hunt identifies precursors to the actual deletion of shadow copies.
  relation: follows
scenario:
  stages:
  - name: Lateral Movement via PsExec
    observables:
    - PsExec spawning SYSTEM-level command shell
    - psexec.exe
    - cmd.exe
    slug: lateral-movement-psexec
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: Session and Network Reconnaissance
    observables:
    - Enumeration of active Remote Desktop sessions
    - DNS enumeration commands
    - Reconnaissance against remote hosts
    - qwinsta.exe
    slug: host-and-session-discovery
    tactic: discovery
    techniques:
    - T1021.001
  - name: Shadow Copy Creation
    observables:
    - vssadmin create shadow
    - ntds.dit extraction
    - vssadmin.exe
    slug: vss-creation-for-credentials
    tactic: credential-access
    techniques:
    - T1003.003
  - name: Inhibit System Recovery
    observables:
    - vssadmin delete shadows /all /quiet
    - vssadmin.exe
    - Blocked attempts to delete shadow copies
    slug: vss-deletion-and-inhibition
    tactic: impact
    techniques:
    - T1490
  - name: Data Encrypted for Impact
    observables:
    - Encryption of local files
    - Ransomware detonation
    slug: data-encryption-impact
    tactic: impact
    techniques:
    - T1486
  summary: Attackers exploit Windows Volume Shadow Copy (VSS) for both credential
    theft and ransomware protection. By creating shadow copies, they can perform offline
    extraction of sensitive files like the Active Directory database (ntds.dit), and
    by deleting them, they prevent victims from using local snapshots to recover from
    ransomware encryption.
series:
  index: 1
  slug: how-attackers-abuse-vss-and-how-huntress-detects-it
  title: How Attackers Abuse VSS, and How Huntress Detects It
  total: 2
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Remote Administration and Discovery Reconnaissance

This hunt identifies the early stages of a Volume Shadow Copy (VSS) abuse campaign. It focuses on the use of PsExec to establish a foothold and the subsequent execution of reconnaissance tools like qwinsta and vssadmin to map the environment and shadow copy configuration. While these tools are common in administrative workflows, their appearance in a specific sequence—spawning from remote execution services on sensitive hosts like Domain Controllers—is a high-fidelity indicator of malicious intent. The hunt also correlates these behaviors with DNS lookups for backup infrastructure, which attackers often target for deletion.

## scope-windows-servers
<!-- Identify Windows Servers -->
Identify potential target hosts where administrative lateral movement and VSS abuse are most impactful.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing servers or Domain Controllers. Silence
  means no Windows servers are currently enrolled.
reads:
- hostname
- device_uid
- os_name
- os_version
- platform
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT hostname, device_uid, os_name, os_version FROM hb_devices WHERE LOWER(COALESCE(platform, '')) = 'windows' AND (LOWER(COALESCE(hostname, '')) LIKE '%dc%' OR LOWER(COALESCE(hostname, '')) LIKE '%srv%' OR LOWER(COALESCE(os_name, '')) LIKE '%server%') AND activity_id = 2
```

## parallel-recon-detection
<!-- Execute Parallel Behavior Queries -->
parallel:
- → psexec-lateral-movement
- → session-and-vss-discovery
- → dns-enumeration-anomalies
join: → triage-recon-activity

## psexec-lateral-movement
<!-- PsExec Service Execution on Servers -->
Detect the execution of the PsExec service (PSEXESVC) or command shells spawned by it on the scoped Windows servers.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Process events showing PSEXESVC or child processes like cmd.exe. These are
  often used by attackers to gain SYSTEM-level access remotely on critical infrastructure.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(COALESCE(process_name, '')) = 'psexesvc.exe' OR LOWER(COALESCE(parent_process_name, '')) LIKE '%psexesvc.exe') AND (LOWER(COALESCE(device_hostname, '')) LIKE '%dc%' OR LOWER(COALESCE(device_hostname, '')) LIKE '%srv%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## session-and-vss-discovery
<!-- Discovery and VSS Tool Baseline -->
Stack-count the execution of discovery tools and VSS manipulation commands to find rare usage patterns.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, discovery_tools=discovery_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of discovery or VSS tools executed on a small number of hosts. Benign
  backup agents would typically appear fleet-wide.
prevalence:
  by: device_hostname
  key:
  - tool
  rare_below: 5
reads:
- process_name
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT LOWER(COALESCE(process_name, 'unknown')) AS tool, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{discovery_tools}}' || ',', ',' || LOWER(COALESCE(process_name, '')) || ',') > 0 OR LOWER(COALESCE(process_cmd_line, '')) LIKE '%vssadmin%' OR LOWER(COALESCE(process_cmd_line, '')) LIKE '%delete shadows%' OR LOWER(COALESCE(process_cmd_line, '')) LIKE '%resize shadowstorage%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY tool HAVING host_count <= 5 ORDER BY host_count ASC
```

## dns-enumeration-anomalies
<!-- Backup Infrastructure Recon -->
Identify anomalous DNS query patterns targeting backup servers or storage devices.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: DNS lookups suggest reconnaissance against backup infrastructure. AXFR (zone
  transfer) queries are particularly high-fidelity signals of discovery.
reads:
- device_hostname
- process_name
- query_hostname
- query_type
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_name, query_hostname, query_type, COUNT(*) AS lookup_count FROM hb_dns_activity WHERE (LOWER(COALESCE(query_hostname, '')) LIKE '%backup%' OR LOWER(COALESCE(query_hostname, '')) LIKE '%veeam%' OR LOWER(COALESCE(query_hostname, '')) LIKE '%synology%' OR LOWER(COALESCE(query_hostname, '')) LIKE '%nas%' OR LOWER(COALESCE(query_hostname, '')) LIKE '%storage%' OR query_type = 'AXFR') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname, query_type ORDER BY lookup_count DESC
```

## triage-recon-activity
<!-- Triage Reconnaissance and Lateral Movement -->
```agent target=hunter
cite: required
context:
- scope-windows-servers
- psexec-lateral-movement
- session-and-vss-discovery
- dns-enumeration-anomalies
max_iterations: 4
objective: Determine if the sequence of PsExec execution, VSS/session discovery, and
  DNS reconnaissance for backup assets indicates a malicious lateral movement campaign.
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  specific rows where PsExec and VSS tools appeared together.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for any host showing psexec and reconnaissance activity" (confidence: high, judge=hunter)
then: → isolate-beachhead
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: incomplete-process-telemetry)
else: → close-recon-hunt

## isolate-beachhead
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host to prevent further lateral movement and potential VSS deletion. Proceed to manual incident investigation.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the cited process lineages and DNS lookups. Investigate if the user account responsible for the activity typically performs remote administration on backups. If not, treat as a high-severity precursor to ransomware.
```
→ end

## close-recon-hunt
<!-- Close and Document -->
```manual target=analyst
Document the absence of malicious PsExec or recon activity. Record any legitimate RMM or backup tools found to refine future prevalence-based hunts.
```
→ end
