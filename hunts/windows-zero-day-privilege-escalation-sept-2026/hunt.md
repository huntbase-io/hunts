---
analysis: A vulnerability scanner only reports the missing patch. This hunt pivots
  to look for the rare SYSTEM-integrity processes and symbolic link artifacts that
  prove the vulnerability is being actively weaponized in this environment, using
  a prevalence baseline to filter out legitimate system activity.
blind_spots:
- id: kernel-memory-telemetry
  owner: Endpoint Security Team
  question: whether the ALPC buffer overflow occurred without causing a process launch
  remediation: Deploy EDR policies with kernel-level exploit protection and enable
    advanced auditing for ALPC events.
  requires: Kernel-mode memory access monitoring
  risk: The hunt only sees the aftermath of elevation; a failed exploit attempt or
    one that stays in-kernel would be missed.
  stage: privilege-escalation-alpc-overflow
- id: encrypted-traffic-payloads
  owner: Network Engineering
  question: whether specific exploit strings were delivered via HTTPS to internet-facing
    services
  remediation: Enable SSL/TLS inspection for inbound traffic to critical servers and
    monitored web endpoints.
  requires: HTTPS decryption on edge proxies
  risk: Initial exploitation attempts against Windows web services are invisible to
    endpoint logs without traffic inspection.
  stage: initial-access-exploit-public-facing
coverage:
- blind_spot: encrypted-traffic-payloads
  reason: Exploit payloads for zero-days in network services are generally not visible
    in standard hb_http_activity or hb_network_connection without deep packet inspection.
  stage: initial-access-exploit-public-facing
  status: not_visible
- stage: privilege-escalation-alpc-overflow
  status: covered
  steps:
  - vulnerable-endpoints
  - rare-system-processes
- stage: privilege-escalation-update-stack-link
  status: covered
  steps:
  - vulnerable-endpoints
  - junction-link-creation
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - high-volume-file-writes
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The September 2026 Patch Tuesday includes 999 vulnerabilities, with
    confirmed zero-day exploitation of ALPC and Update Stack mechanisms. Identifying
    unpatched hosts and verifying they are clean of exploitation is a critical requirement
    given the high potential for automated ransomware deployment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are exploiting unpatched Windows ALPC or Update Stack vulnerabilities
  to escalate to SYSTEM integrity and deploy ransomware, leaving traces of rare process
  elevations and specific link-resolution artifacts.
labels:
- hunt
- attack.t1190
- attack.t1068
- attack.t1486
- impact
- initial access
- privilege escalation
name: Windows Zero-Day Privilege Escalation and Ransomware
parameters:
  cve_ids:
    default:
    - CVE-2026-81963
    - CVE-2026-85880
    description: Vulnerability identifiers for the September zero-days.
    from:
      kind: article
      observed: '2026-09-08'
      ref: "rapid7 \u2014 https://www.rapid7.com/blog/post/em-patch-tuesday-september-2026"
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Limit behavioral checks to these hostnames; leave empty to hunt across
      the entire estate.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: scoping-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/em-patch-tuesday-september-2026
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize domain controllers and internet-facing application servers.
  Use device_uid from the first query to identify the specific assets before widening
  the search to the entire workstation fleet.
references:
- name: "Rapid7 \u2014 Patch Tuesday September 2026"
  url: https://www.rapid7.com/blog/post/em-patch-tuesday-september-2026
related:
- hunt: print-spooler-eop-baseline
  reason: Adversaries frequently use similar privilege escalation patterns across
    different Windows services like the Print Spooler or Fax Service.
  relation: sibling
scenario:
  stages:
  - name: Exploit Public-Facing Application
    observables:
    - Inbound exploitation attempts against internet-facing Windows services
    - Crashes in network-accessible service processes
    slug: initial-access-exploit-public-facing
    tactic: initial-access
    techniques:
    - T1190
  - name: ALPC Buffer Overflow Elevation
    observables:
    - CVE-2026-85880
    - Buffer overflow in Advanced Local Procedure Call (ALPC) mechanism
    - Out-of-bounds write activity
    - Process integrity escalation to SYSTEM from user-mode processes
    slug: privilege-escalation-alpc-overflow
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Update Stack Link Resolution Elevation
    observables:
    - CVE-2026-81963
    - Improper link resolution in Windows Update Stack
    - Creation of symbolic links or junctions in update paths by low-privileged users
    - Elevation to SYSTEM privileges
    slug: privilege-escalation-update-stack-link
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Ransomware Data Encryption
    observables:
    - Bulk file write and rename operations
    - Encryption of common user files (Office docs, PDFs, images)
    - Presence of ransomware notes
    - System-wide file markers or new extensions
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: The September 2026 Patch Tuesday released 999 CVEs, featuring two zero-day
    elevation of privilege vulnerabilities in the Windows ALPC (CVE-2026-85880) and
    Update Stack (CVE-2026-81963) exploited in the wild. Attackers use these flaws
    to escalate to SYSTEM privileges on Windows systems, often as a precursor to ransomware
    deployment and bulk file encryption.
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


# Windows Zero-Day Privilege Escalation and Ransomware

This hunt targets the zero-day exploits published in September 2026 (CVE-2026-85880 and CVE-2026-81963). The ALPC buffer overflow and Update Stack link resolution flaws allow low-privileged attackers to gain SYSTEM access. Once elevated, the adversary is expected to deploy ransomware. The hunt identifies vulnerable assets, baselines rare SYSTEM-integrity processes, and triages specific file system behaviors such as suspicious symbolic link creation in update directories and high-volume file encryption markers.

## vulnerable-endpoints
<!-- Identify vulnerable Windows endpoints -->
The hunt identifies unpatched Windows endpoints missing fixes for the ALPC and Update Stack zero-days to establish the scope of exposed assets.

```sqlite target=endpoint role=scoping params=(cve_ids=cve_ids)
~~~yaml
expected: A list of device_uids that are unpatched. Silence means the estate is fully
  patched against these specific CVEs.
reads:
- device_uid
- cve_uid
- severity
- status
silence: evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_uid, cve_uid, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{cve_ids}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed' AND status != 'fixed'
```

## rare-system-processes
<!-- Baseline rare SYSTEM-integrity processes -->
This hunt pivots to look for the rare SYSTEM-integrity processes and symbolic link artifacts that prove the vulnerability is being actively weaponized.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small set of processes running with System privileges on only 1-3 hosts.
  Legitimate system utilities will show high host counts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 4
reads:
- process_name
- device_hostname
- integrity_level
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(integrity_level) = 'system' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## parallel-behaviour-check
<!-- Check for exploitation and impact -->
parallel:
- → junction-link-creation
- → high-volume-file-writes
join: → agent-triage

## junction-link-creation
<!-- Update stack symbolic link creation -->
The hunt detects the specific 'improper link resolution' behavior where an adversary creates symbolic links in Windows Update paths to gain SYSTEM privileges.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any symbolic links created within the Windows Update paths (SoftwareDistribution)
  by non-system processes.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- file_type
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE file_type = 'symlink' AND LOWER(file_path) LIKE '%\windows\softwaredistribution%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## high-volume-file-writes
<!-- High-volume file encryption activity -->
The hunt identifies high-volume file encryption and rename markers that indicate a successful ransomware impact following the privilege escalation.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts showing multiple file writes with known ransomware extensions or note
  filenames.
reads:
- device_hostname
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, COUNT(*) AS write_count, MAX(time) AS last_write FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_name) LIKE '%.crypt%' OR LOWER(file_name) LIKE '%.locked%' OR LOWER(file_name) LIKE 'read_me%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING write_count > 5
```

## agent-triage
<!-- Assess exposure and exploitation -->
```agent target=hunter
cite: required
context:
- vulnerable-endpoints
- rare-system-processes
- junction-link-creation
- high-volume-file-writes
max_iterations: 4
objective: Analyze the combination of unpatched status, rare system processes, and
  suspicious file activity to determine if an adversary has compromised any exposed
  host.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing specific
  process launches or file paths.
tools:
- endpoint
```

## decision-route
<!-- Route based on compromise -->
if~: "the agent-triage verdict indicates active exploitation or ransomware activity on any exposed host" (confidence: high, judge=hunter)
then: → task-patch-and-verify
indeterminate: → task-patch-and-verify
unavailable: → task-patch-and-verify (blind_spot: kernel-memory-telemetry)
else: → task-close-out

## task-patch-and-verify
<!-- Patch and Verify Remediation -->
```manual target=analyst
For hosts identified as vulnerable or compromised: 1. Deploy the September 2026 security updates for Windows ALPC and Update Stack. 2. Verify patch installation via hb_vulnerability_finding. 3. If the agent identified malicious behavior, escalate to the Incident Response team for host forensic imaging.
```
→ task-close-out

## task-close-out
<!-- Close-out and reporting -->
```manual target=analyst
Record the percentage of the estate currently patched against CVE-2026-85880 and CVE-2026-81963. Document any false positives from the rare-process baseline for future tuning of standing detection rules.
```
→ end
