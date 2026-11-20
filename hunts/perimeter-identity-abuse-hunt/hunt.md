---
analysis: A simple rule on HTTP 500s or high API usage is too noisy. This hunt uses
  the funnel approach to scope the perimeter, look for new crash patterns on specific
  paths, and correlate them with identity search anomalies that match the Danish CPR
  breach profile.
blind_spots:
- id: limited-cloud-audit-retention
  question: whether high-volume searching occurred outside the current 14-day window
  requires: Extended retention of hb_cloud_api_activity
  risk: A breach that occurred earlier would be invisible to the API search query.
  stage: lawful-access-identity-abuse
- id: application-level-query-logging
  question: what specific data was retrieved during the searches
  requires: Application-specific logs for the CPR or record system
  risk: API activity shows that a search happened, but not which specific records
    were viewed, making impact assessment difficult.
  stage: lawful-access-identity-abuse
- id: encrypted-perimeter-payloads
  question: the specific exploitation strings used in the memory overflow attack
  requires: SSL/TLS decryption or appliance-local logs
  risk: Without payload inspection, the hunt relies on service crashes as a secondary
    indicator rather than seeing the exploit itself.
  stage: citrix-netscaler-exploitation
coverage:
- stage: citrix-netscaler-exploitation
  status: covered
  steps:
  - citrix-inventory-scope
  - netscaler-service-crashes
- stage: lawful-access-identity-abuse
  status: covered
  steps:
  - identity-search-anomalies
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: trojanized-utility-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: ai-analysis-evasion-obfuscation
  status: out_of_scope
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: kernel-driver-edr-impairment
  status: out_of_scope
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: ransomware-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The exploitation of perimeter devices and the abuse of valid credentials
    for large-scale data theft are high-impact events that often bypass automated
    rules. A hunt is required to correlate these disparate signals into a single intrusion
    narrative.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting a memory overflow in Citrix NetScaler to gain
  initial access or disrupt services, while simultaneously abusing lawful identity
  access to perform high-volume, unauthorized searches against sensitive record systems.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1530
- defense evasion
- execution
- impact
- initial access
name: Perimeter Vulnerabilities and Identity Access Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of NetScaler hostnames to focus on after the scoping
      step.
    type: list[host]
  sensitive_search_ops:
    default:
    - search
    - read
    - list
    - get
    - query
    description: API operations associated with data retrieval and searching.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/making-sure-the-checks-get-printed/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Begin by identifying all Citrix NetScaler appliances in the environment
  using software inventory. If vulnerability scan data is available, prioritize those
  with active CVE-2026-88779 findings.
references:
- name: "Talos \u2014 Making sure the checks get printed"
  url: https://blog.talosintelligence.com/making-sure-the-checks-get-printed/
related:
- hunt: netscaler-webshell-persistence
  reason: Once initial access is gained via NetScaler, adversaries often drop webshells;
    this hunt focuses only on the exploit and identity abuse.
  relation: follows
scenario:
  stages:
  - name: Citrix NetScaler Vulnerability Exploitation
    observables:
    - CVE-2026-88779
    - Memory overflow in Citrix NetScaler
    slug: citrix-netscaler-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Abuse of Lawful Identity Access
    observables:
    - Abuse of Danish company lawful access to CPR system
    slug: lawful-access-identity-abuse
    tactic: initial-access
    techniques:
    - T1078
  - name: Trojanised Software Execution
    observables:
    - KMSAuto Net.exe
    - SECOH-QAD.exe
    - PulseBrowser.29kh.in12.Talos
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    - 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
    slug: trojanized-utility-execution
    tactic: execution
    techniques:
    - T1195
  - name: AI-Analysis Evasion (A3)
    observables:
    - Plaintext imperative language instructions in binaries
    - Template spraying designed to trick LLMs
    - Instructions telling AI to ignore files
    slug: ai-analysis-evasion-obfuscation
    tactic: defense-evasion
    techniques:
    - T1027
  - name: Kernel driver EDR Impairment
    observables:
    - Abusing vulnerable drivers to disable EDR from kernel space
    - MANTLEMAZE driver abuse
    slug: kernel-driver-edr-impairment
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1068
  - name: Ransomware Encryption
    observables:
    - Warlock ransomware activity
    - Encryption of water utility and telecom systems
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Mantlemaze and other threat actors are employing 'AI-Analysis Evasion'
    (A3) by embedding natural-language instructions in malware to trick automated
    scrutiny, often pairing it with kernel-level driver abuse to disable EDR. These
    techniques are observed alongside high-impact threats including vulnerabilities
    in Citrix NetScaler and ransomware attacks by groups like Warlock.
series:
  index: 1
  slug: making-sure-the-checks-get-printed
  title: Making sure the checks get printed
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Perimeter Vulnerabilities and Identity Access Abuse

This hunt examines two critical exposure points: the exploitation of the Citrix NetScaler perimeter (CVE-2026-88779) and the abuse of valid accounts for large-scale data harvesting. The hunt first scopes the environment for vulnerable Citrix instances, then fans out to monitor for service instability and anomalous spikes in identity search API calls. By correlating perimeter crashes with identity search behavior, the hunt identifies successful intrusions that leverage lawful access to bypass traditional MFA and alerting.

## citrix-inventory-scope
<!-- Identify Citrix NetScaler inventory -->
Scope the estate to find Citrix NetScaler instances that may be vulnerable to the reported memory overflow.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running Citrix software. Silence suggests no managed
  NetScaler instances are visible in inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%netscaler%' OR LOWER(vendor_name) LIKE '%citrix%')
```

## parallel-assessment
<!-- Assess perimeter stability and identity usage -->
parallel:
- → netscaler-service-crashes
- → identity-search-anomalies
join: → triage-incidents

## netscaler-service-crashes
<!-- NetScaler HTTP service crashes -->
Detect server-side errors on NetScaler hosts that suggest a memory overflow or denial of service attack occurred.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A spike in HTTP 500 errors on specific paths. Silence suggests the NetScaler
  service is stable.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- device_hostname
- status_code
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, url_path, status_code, COUNT(*) AS crash_count, MIN(time) AS first_error, MAX(time) AS last_error FROM hb_http_activity WHERE status_code >= 500 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path, status_code
```

## identity-search-anomalies
<!-- Anomalous identity search volume -->
Find users performing an excessive number of search or read operations, which may indicate the abuse of lawful access to extract sensitive records.

```sqlite target=endpoint role=detection-candidate params=(sensitive_search_ops=sensitive_search_ops, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Identities with hundreds of search API calls from single IPs. Silence means
  no high-volume read patterns were detected in the audit log.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  - api_operation
  rare_below: 5
reads:
- actor_user_name
- api_operation
- api_service_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT actor_user_name, api_operation, api_service_name, src_endpoint_ip, COUNT(*) AS call_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_cloud_api_activity WHERE (instr(',' || '{{sensitive_search_ops}}' || ',', ',' || LOWER(api_operation) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation, api_service_name, src_endpoint_ip HAVING call_count > 100
```

## triage-incidents
<!-- Triage perimeter and identity findings -->
```agent target=hunter
cite: required
context:
- citrix-inventory-scope
- netscaler-service-crashes
- identity-search-anomalies
max_iterations: 6
objective: Determine whether the HTTP crashes on NetScaler hosts and the high-volume
  API searches by specific users together indicate active exploitation and data theft
  via lawful access abuse.
success_criteria: A verdict of malicious | suspicious | benign citing specific row
  counts and temporal proximity between service errors and identity spikes.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route based on agent verdict -->
if~: "the triage-incidents verdict is malicious for at least one host or user account" (confidence: medium, judge=hunter)
then: → isolate-compromised-assets
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: limited-cloud-audit-retention)
else: → close-out

## isolate-compromised-assets
<!-- Isolate compromised assets -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected NetScaler host and revoke the credentials for any user account identified as participating in anomalous search activity.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation and verification -->
```manual target=analyst
Review the cited rows from HTTP and API logs. Verify if the identified searches are consistent with legitimate administrative tasks or if they match the Danish CPR breach pattern of abusing lawful access.
```
→ vulnerability-remediation

## vulnerability-remediation
<!-- Remediate NetScaler vulnerability -->
```manual target=analyst
Coordinate with the infrastructure team to apply patches to the identified vulnerable NetScaler instances and verify the service stability post-patch.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings, update any detections for high-volume API calls, and document the hosts that were patched during this hunt cycle.
```
→ end
