---
analysis: This hunt correlates three distinct attack phases across five telemetry
  surfaces. A single rule might flag mass file modifications but produce false positives
  for backup software; this hunt requires the presence of vulnerability context, initial
  access anomalies, and rare process execution to confirm a malicious intrusion.
blind_spots:
- id: unmanaged-assets
  question: Whether unmanaged servers or IoT devices were the entry point.
  requires: comprehensive endpoint agent coverage
  risk: Attacks starting on unmanaged assets remain invisible to endpoint-based process
    and file monitoring.
- id: encrypted-egress
  question: Whether sensitive data was exfiltrated via HTTPS to common cloud storage.
  requires: SSL/TLS inspection or network proxy logs
  risk: Without traffic inspection, data exfiltration over standard web channels is
    indistinguishable from normal user activity.
  stage: exfiltration-of-stolen-data
coverage:
- stage: initial-access-phishing-and-exploitation
  status: covered
  steps:
  - identify-vulnerable-hosts
  - web-exploitation-signs
  - auth-anomaly-check
- stage: execution-of-malicious-code
  status: covered
  steps:
  - rare-writable-processes
- blind_spot: encrypted-egress
  reason: Requires specialized egress inspection or proxy telemetry not currently
    listed in the available surfaces.
  stage: exfiltration-of-stolen-data
  status: not_visible
- stage: ransomware-impact
  status: covered
  steps:
  - mass-file-ops
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SMBs are increasingly targeted by automated ransomware. A negative
    result over the scoped vulnerable estate confirms that these assets are not currently
    undergoing a high-speed encryption campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated adversary is exploiting high-severity vulnerabilities or
  weak credentials to gain initial access, subsequently executing rare processes from
  writable paths to encrypt files for extortion.
labels:
- hunt
- attack.t1041
- attack.t1190
- attack.t1486
- attack.t1566
- execution
- exfiltration
- impact
- initial access
name: AI-Driven Ransomware and Data Extortion
parameters:
  critical_severity_id:
    default: '4'
    description: Minimum severity ID for vulnerability findings (4=High, 5=Critical).
    from:
      kind: manual
      observed: '2024-10-26'
      ref: vulnerability-threshold
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-26'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search; if empty, the whole
      estate is searched.
    from:
      kind: manual
      observed: '2024-10-26'
      ref: scoping-parameter
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/quest-simplicity-why-smbs-want-advanced-protection-without-complexity/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope the hunt starting with hosts that show high-severity CVEs in hb_vulnerability_finding.
  Use the results from the first query to populate the scope_hosts parameter if focusing
  on specific assets.
references:
- name: 'The quest for simplicity: Why SMBs want advanced protection without the complexity'
  url: https://www.welivesecurity.com/en/business-security/quest-simplicity-why-smbs-want-advanced-protection-without-complexity/
related:
- hunt: lateral-movement-smb-rdp
  reason: This hunt focuses on the vertical path from initial access to ransomware
    impact; lateral movement is a distinct phase requiring separate authentication
    and network audit logs.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and Application Exploitation
    observables:
    - Personalized phishing messages
    - Exploitation of internet-facing vulnerabilities
    - Exploitation of weak passwords
    slug: initial-access-phishing-and-exploitation
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Malicious Code Execution
    observables:
    - Deployment of malicious code
    - Autonomous AI agents exploiting passwords and creating personas
    - Execution of AI-assisted workflows and chatbots
    slug: execution-of-malicious-code
    tactic: execution
  - name: Data Exfiltration
    observables:
    - Exfiltration over existing C2 channels
    - Data theft extortion
    slug: exfiltration-of-stolen-data
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Encryption
    observables:
    - Ransomware encryption of files
    - Data encrypted for impact
    slug: ransomware-impact
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors targeting SMBs, including state-backed and financially motivated
    groups, are utilizing AI to accelerate attack chains from initial reconnaissance
    to impact. These campaigns typically involve personalized phishing or vulnerability
    exploitation followed by the deployment of malicious code, leading to data exfiltration
    and ransomware encryption.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI-Driven Ransomware and Data Extortion

This hunt identifies the progression of high-speed ransomware attacks starting from initial access attempts via application exploitation or credential abuse. It scopes the hunt to vulnerable assets, correlates those vulnerabilities with anomalous sign-ins and web traffic, and then pivots to find evidence of malicious execution and bulk file impact. This phased approach is designed to catch automated threats before they complete the encryption phase.

## identify-vulnerable-hosts
<!-- Identify vulnerable hosts -->
Locate hosts with high-severity vulnerabilities to establish the probable initial attack surface.

```sqlite target=endpoint role=scoping params=(critical_severity_id=critical_severity_id, lookback_days=lookback_days)
~~~yaml
expected: A list of host identifiers and their vulnerabilities; this establishes where
  exploitation is most likely to occur.
reads:
- device_uid
- cve_uid
- title
- affected_package_name
- affected_package_version
- severity_id
- status
- last_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_uid, cve_uid, title, affected_package_name, affected_package_version FROM hb_vulnerability_finding WHERE severity_id >= {{critical_severity_id}} AND status != 'suppressed' AND last_seen >= datetime('now', '-{{lookback_days}} days')
```

## initial-access-parallel
<!-- Gather initial access evidence -->
parallel:
- → web-exploitation-signs
- → auth-anomaly-check
join: → early-stage-triage

## web-exploitation-signs
<!-- Web exploitation attempts -->
Detect automated probing by finding high-severity web errors targeting sensitive application files.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Clusters of 403 or 500 errors targeting PHP, JSP, or configuration files,
  indicating automated exploitation probes.
prevalence:
  by: device_hostname
  key:
  - url_path
  - status_code
  rare_below: 5
reads:
- device_hostname
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, url_path, status_code, COUNT(*) as counts, MIN(time) as first_seen FROM hb_http_activity WHERE status_code IN (403, 500) AND (LOWER(url_path) LIKE '%.php%' OR LOWER(url_path) LIKE '%.jsp%' OR LOWER(url_path) LIKE '%.env%' OR LOWER(url_path) LIKE '%.config%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path, status_code HAVING counts > 5
```

## auth-anomaly-check
<!-- Auth anomaly check -->
Identify high-volume sign-in failures that indicate password exploitation or brute force attempts.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Specific user accounts or source IPs exhibiting excessive authentication
  failures consistent with credential stuffing.
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT actor_user_name, device_hostname, src_endpoint_ip, COUNT(*) as failures FROM hb_auth_signin WHERE status_id = 2 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname, src_endpoint_ip HAVING failures > 20
```

## early-stage-triage
<!-- Early-stage triage -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-hosts
- web-exploitation-signs
- auth-anomaly-check
max_iterations: 4
objective: Identify hosts that are both vulnerable and showing signs of active exploitation
  or credential abuse. Prioritize hosts that appear in the results of identify-vulnerable-hosts
  AND at least one of web-exploitation-signs or auth-anomaly-check.
success_criteria: A per-host verdict of malicious | suspicious for initial access,
  citing matching vulnerability and anomaly data.
tools:
- endpoint
- identity
- web
```

## follow-on-parallel
<!-- Gather execution and impact evidence -->
parallel:
- → rare-writable-processes
- → mass-file-ops
join: → follow-on-triage

## rare-writable-processes
<!-- Rare writable processes -->
Detect malicious code deployment by finding rare binaries running from user-writable directories.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes with low fleet prevalence running from suspicious, user-writable
  locations.
prevalence:
  by: device_hostname
  key:
  - process_name
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
verified_at: '2026-10-08'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) as fleet_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\appdata\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING fleet_count <= 2
```

## mass-file-ops
<!-- High-speed file impact -->
Detect ransomware encryption activity by identifying processes with extreme bursts of file touches.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts)
~~~yaml
expected: A single process modifying or renaming over 1,000 files in a single hour,
  consistent with high-speed encryption.
reads:
- device_hostname
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, COUNT(*) as file_touches FROM hb_file_activity WHERE activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-1 hours') GROUP BY device_hostname, process_name HAVING file_touches > 1000
```

## follow-on-triage
<!-- Follow-on triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- rare-writable-processes
- mass-file-ops
max_iterations: 6
objective: Determine if any host identified as suspicious in early-stage-triage is
  also exhibiting malicious execution and mass file modification consistent with ransomware.
  Cite the relationship between the vulnerable state, the initial access anomaly,
  and the follow-on impact.
success_criteria: A definitive verdict for each host citing evidence from at least
  three surfaces to confirm a full attack chain.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-deep-dive
unavailable: → analyst-deep-dive (blind_spot: unmanaged-assets)
else: → close-out-hunt

## contain-host
<!-- Contain host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the binary identified in the rare-writable-processes step.
```
→ analyst-deep-dive

## analyst-deep-dive
<!-- Analyst deep dive -->
```manual target=analyst
Review the full process tree on the compromised host, check for signs of lateral movement via SMB or RDP, and update the vulnerability management plan.
```
→ end

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Log the examined period and confirm whether any indicators of high-speed ransomware were detected.
```
→ end
