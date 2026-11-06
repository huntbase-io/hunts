---
analysis: A standard detection rule might fire on a single rare process or a large
  file modification. This hunt correlates those signals across the entire attack lifecycle
  (Phishing -> Supply Chain -> Exfiltration -> Encryption) and uses clinical inventory
  context to distinguish maintenance from an intrusion.
blind_spots:
- id: missing-process-ancestry
  owner: Endpoint Security
  question: Did a legitimate clinical updater spawn the malicious child process?
  remediation: Increase EDR process telemetry depth and ensure full command line capture
    for clinical binaries.
  requires: EDR process tree depth exceeding 10 levels
  risk: Short process command lines or truncated ancestry may hide the original injection
    point of a supply chain compromise.
  stage: initial-access-supply-chain
- id: encrypted-exfiltration-visibility
  owner: Network Engineering
  question: Is sensitive patient data being leaked via AI prompts in encrypted HTTPS
    requests?
  remediation: Deploy TLS inspection on clinical segments to monitor for PII/PHI leakage
    via web services.
  requires: hb_http_activity with decrypted payload visibility
  risk: The current network connection surface only shows volume; it cannot see the
    content of HTTPS POST requests to AI service providers.
  stage: exfiltration-data-leakage
coverage:
- stage: initial-access-phishing-and-bec
  status: covered
  steps:
  - phishing-signin-check
- stage: initial-access-supply-chain
  status: covered
  steps:
  - supply-chain-process-check
- stage: exfiltration-data-leakage
  status: covered
  steps:
  - exfiltration-network-check
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - ransomware-file-burst
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Cyber disruption to healthcare operations directly threatens patient
    safety. This hunt provides assurance that critical systems are not currently subject
    to the high-impact attack patterns (Ransomware, BEC, Supply Chain) highlighted
    in the 2026 report.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained access to clinical systems via phishing or supply
  chain compromise and is now exfiltrating patient data or preparing to deploy ransomware.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1041
- attack.t1486
- exfiltration
- impact
- initial access
name: Healthcare Service Disruption and Data Exfiltration
parameters:
  clinical_software_keywords:
    default:
    - epic
    - cerner
    - meditech
    - allscripts
    - pacs
    - dicom
    description: Exact package names of clinical software to identify sensitive hosts.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: healthcare-software-list
    type: list[string]
  large_transfer_threshold:
    default: '100000000'
    description: Threshold in bytes (default 100MB) for outbound network traffic volume.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: network-policy
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: hunt-standard-config
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step; leave empty for a full-estate
      hunt.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: scoping-output
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/press-releases/cyber-insecurity-in-healthcare-report-2026
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts identified by the clinical_software_keywords list. Focus
  on Electronic Health Record (EHR) servers and diagnostic workstations. Ensure that
  domain controllers are included when assessing MFA-less sign-ins.
references:
- name: "Proofpoint \u2014 Healthcare Sees No Relief from Cyberattacks Disrupting\
    \ Patient Care"
  url: https://www.proofpoint.com/us/newsroom/press-releases/cyber-insecurity-in-healthcare-report-2026
related:
- hunt: clinical-data-access-audit
  reason: This hunt looks for mass exfiltration behavior; a sibling hunt is needed
    to audit individual credential access to database tables via application logs.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Business Email Compromise and Phishing
    observables:
    - Business email compromise (BEC) attempts
    - AI-generated phishing
    - Social engineering lures
    - Unauthorized cloud account access
    slug: initial-access-phishing-and-bec
    tactic: initial-access
    techniques:
    - T1566
  - name: Supply Chain Compromise
    observables:
    - Compromised AI vendors
    - Malicious software dependencies
    - Untrusted third-party service integration
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: Data Exfiltration and Leakage
    observables:
    - Data leakage through AI prompts
    - Exfiltration of sensitive healthcare information
    - High-volume outbound network traffic
    - Unauthorized file access
    slug: exfiltration-data-leakage
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Data Encryption
    observables:
    - Mass file encryption
    - Deployment of ransomware payloads
    - Disruption of clinical applications
    - Encryption of patient records
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: "Healthcare organizations are facing a surge in cyberattacks\u2014including\
    \ ransomware, supply chain compromises, and business email compromise\u2014that\
    \ increasingly disrupt patient care and cause significant financial and operational\
    \ strain. The rise of unsanctioned AI tools and vulnerable cloud accounts has\
    \ further expanded the attack surface, leading to frequent data exfiltration and\
    \ clinical service delays."
severity: medium
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


# Healthcare Service Disruption and Data Exfiltration

This hunt follows the attack lifecycle identified in the 2026 Cyber Insecurity in Healthcare report. It identifies critical healthcare assets and then monitors for signs of initial access, such as Business Email Compromise and supply chain anomalies. The hunt then pivots to detect high-volume exfiltration and the mass file encryption characteristic of ransomware, providing a phased assessment of the intrusion's progression on clinical hosts.

## discover-clinical-assets
<!-- Discover clinical assets -->
Identify hosts running healthcare applications to focus the hunt on systems where disruption would impact patient care.

```sqlite target=endpoint role=scoping params=(clinical_software_keywords=clinical_software_keywords)
~~~yaml
expected: A list of hosts running clinical software. Silence means no matching packages
  were found in inventory.
reads:
- device_hostname
- package_name
- package_version
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE instr(',' || '{{clinical_software_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## parallel-access-check
<!-- Parallel initial access check -->
parallel:
- → phishing-signin-check
- → supply-chain-process-check
join: → early-stage-triage

## phishing-signin-check
<!-- Phishing and BEC sign-in check -->
Identify successful sign-ins to clinical hosts that bypassed MFA or originated from unusual sources.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A concentration of MFA-less logins on a single host. Rare source countries
  indicate potential account takeover.
prevalence:
  by: src_location_country
  key:
  - actor_user_name
  rare_below: 2
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- mfa
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, mfa, time FROM hb_auth_signin WHERE status_id = 1 AND (mfa = 'false' OR mfa IS NULL) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## supply-chain-process-check
<!-- Clinical supply chain process check -->
Find rare processes on the scoped clinical hosts, which may indicate a supply-chain compromise where malware is disguised as normal system operations.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare binary path on a host that belongs to the clinical scope. Absence
  suggests only common fleet-wide binaries are running.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- process_name
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, process_path, process_name, parent_process_name, process_cmd_line, COUNT(*) as occurrence_count FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_path HAVING occurrence_count < 3 ORDER BY occurrence_count ASC
```

## early-stage-triage
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- discover-clinical-assets
- phishing-signin-check
- supply-chain-process-check
max_iterations: 4
objective: Determine if any host in the clinical scope shows signs of BEC or supply
  chain tampering based on the sign-in and process evidence.
success_criteria: A per-host verdict of suspicious | benign for initial access stages.
tools:
- endpoint
- identity
- network
```

## parallel-impact-check
<!-- Parallel impact and exfiltration check -->
parallel:
- → exfiltration-network-check
- → ransomware-file-burst
join: → final-intrusion-assessment

## exfiltration-network-check
<!-- Exfiltration network check -->
Identify high-volume outbound network traffic to rare destinations from clinical hosts that may indicate data exfiltration.

```sqlite target=network role=enrichment params=(large_transfer_threshold=large_transfer_threshold, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound flows exceeding 100MB to rare destination IPs. Absence of rows
  means no single flow met the threshold or all targets are fleet-wide common.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 2
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, dst_endpoint_ip, traffic_bytes, process_name, time FROM hb_network_connection WHERE direction = 'outbound' AND traffic_bytes > {{large_transfer_threshold}} AND state_kind = 'log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY traffic_bytes DESC
```

## ransomware-file-burst
<!-- Ransomware file burst -->
Detect mass file modifications (renames or deletions) on clinical hosts that indicate ransomware encryption activity.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A single process modifying thousands of files. A hit suggests active encryption
  or data wiping.
reads:
- device_hostname
- process_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, process_name, activity_name, COUNT(*) as file_count, MIN(time) as burst_start FROM hb_file_activity WHERE activity_id IN (3, 4, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, activity_name HAVING file_count > 1000 ORDER BY file_count DESC
```

## final-intrusion-assessment
<!-- Final intrusion assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- exfiltration-network-check
- ransomware-file-burst
max_iterations: 6
objective: Synthesize findings from initial access triage with follow-on network exfiltration
  and ransomware file bursts to determine the severity and status of the intrusion.
success_criteria: A final verdict of malicious | suspicious | benign per host, with
  a description of the attack stage.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-intrusion-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: missing-process-ancestry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve its memory state for forensic analysis. Notify clinical operations of the system downtime.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation -->
```manual target=analyst
Review the clinical hosts identified. Verify if the network traffic and file activity are legitimate clinical operations or malicious behavior. Document tuning recommendations for the sign-in and file burst queries.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record what was examined and what was not visible. If no intrusion was found, highlight the clinical systems that were verified as secure.
```
→ end
