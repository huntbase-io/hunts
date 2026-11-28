---
analysis: This hunt correlates exposure (unpatched vulnerability) with behavioral
  anomalies (rare sign-ins, geographic shifts, and successful HTTP probes) across
  three distinct surfaces. A single rule might alert on a CVE or a malicious IP, but
  this hunt provides the cross-surface context an analyst needs to confirm a successful
  breach versus a failed scan.
blind_spots:
- id: encrypted-perimeter-traffic
  question: whether exploit payloads are present in HTTPS traffic
  requires: TLS decryption at the perimeter or web-server log auditing
  risk: Without decryption, hb_http_activity cannot see the URL parameters or body
    content where many exploits reside.
  stage: initial-access-exploit-perimeter
- id: stale-vulnerability-data
  question: whether a host is currently vulnerable
  requires: Real-time vulnerability scanning
  risk: If the vulnerability scanner hasn't run recently, the scoping step will miss
    hosts patched yesterday or newly vulnerable today.
  stage: initial-access-exploit-perimeter
coverage:
- stage: initial-access-ai-phishing
  status: covered
  steps:
  - anomalous-signins
  - triage-initial-access
- stage: initial-access-exploit-perimeter
  status: covered
  steps:
  - vulnerable-perimeter-inventory
  - perimeter-exploitation-probes
  - triage-initial-access
- reason: Belongs to another part of the 'Unit 42 Threat Intelligence Highlights -
    Nov. 2, 2026' series.
  stage: evasion-and-execution-lotl
  status: out_of_scope
- reason: Belongs to another part of the 'Unit 42 Threat Intelligence Highlights -
    Nov. 2, 2026' series.
  stage: credential-access-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'Unit 42 Threat Intelligence Highlights -
    Nov. 2, 2026' series.
  stage: collection-exfiltration-staging
  status: out_of_scope
- reason: Belongs to another part of the 'Unit 42 Threat Intelligence Highlights -
    Nov. 2, 2026' series.
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
  justification: Adversaries use AI for high-fidelity social engineering and exploit
    perimeter vulnerabilities for initial access. This hunt provides assurance that
    the external attack surface is not currently compromised by these advanced methods.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries target unpatched perimeter assets or use AI-generated personas
  for initial access, indicated by high-severity vulnerabilities on internet-facing
  hosts coupled with anomalous sign-ins and successful unauthorized web requests.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1555
- attack.t1041
- credential access
- defense evasion
- exfiltration
- impact
- initial access
name: Perimeter Access and Identity Fraud
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the scoping step to focus the behavioral
      analysis.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/u42-threat-intelligence-highlights-oct-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing web servers, cloud gateways, and remote access
  servers identified via exposed asset scans. Use the hostnames from the first step
  to populate the scope_hosts parameter. If the vulnerability inventory is empty,
  run the behavioral queries without scoping to detect generic identity fraud.
references:
- name: Unit 42 Threat Intelligence Highlights - Nov. 2, 2026
  url: https://unit42.paloaltonetworks.com/u42-threat-intelligence-highlights-oct-2026/
related:
- hunt: evasion-and-execution-lotl
  reason: If initial access is confirmed, the adversary will likely transition to
    using living-off-the-land binaries for persistence and execution.
  relation: follows
scenario:
  stages:
  - name: AI-Enhanced Phishing
    observables:
    - context-tailored social engineering lures
    - synthetic personas
    - deepfakes
    - executive impersonation
    slug: initial-access-ai-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Perimeter Application Exploitation
    observables:
    - unpatched perimeter assets
    - zero-day vulnerabilities
    - internet-facing web applications
    slug: initial-access-exploit-perimeter
    tactic: initial-access
    techniques:
    - T1190
  - name: Living-off-the-Land and Scripting
    observables:
    - LotL binaries
    - built-in administration tools
    - AI-assisted scripting
    - payload debugging
    - code obfuscation
    slug: evasion-and-execution-lotl
    tactic: defense-evasion
  - name: Credential Harvesting
    observables:
    - infostealer logs
    - exposed credentials
    - access to password storage locations
    slug: credential-access-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Staging and Exfiltration
    observables:
    - low-and-slow data staging
    - exfiltration over C2 channel
    - public exposure threats
    slug: collection-exfiltration-staging
    tactic: exfiltration
    techniques:
    - T1041
  - name: Data Encryption and Extortion
    observables:
    - ransomware deployment
    - multi-extortion models
    - systemic data compromise
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors are employing AI-enhanced social engineering and Large Language
    Model (LLM) assisted scripting to refine initial access through targeted phishing
    and perimeter application exploitation. Once inside, they utilize living-off-the-land
    (LotL) binaries for credential harvesting and low-and-slow data staging, culminating
    in strategic data theft or multi-extortion ransomware attacks.
series:
  index: 1
  slug: unit-42-threat-intelligence-highlights-nov-2-2026
  title: Unit 42 Threat Intelligence Highlights - Nov. 2, 2026
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


# Perimeter Access and Identity Fraud

This hunt focuses on the external-facing attack surface by identifying vulnerable assets and monitoring for subsequent signs of exploitation or identity-based deception. It uses a scoping step to identify hosts with high-severity vulnerabilities that are confirmed to be internet-exposed. The hunt simultaneously evaluates identity-based anomalies (such as rare user agents, geographic shifts, and MFA bypass patterns) and behavioral web probes. An agent weighs these independent indicators per host to identify successful initial access via unpatched services or sophisticated phishing lures.

## vulnerable-perimeter-inventory
<!-- High-severity perimeter vulnerabilities -->
Identify internet-facing assets with high-severity vulnerabilities that could serve as initial entry points by joining vulnerability findings with device inventory and external exposure data.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames currently exposed to high-severity vulnerabilities on
  the perimeter. These hosts should be provided in the scope_hosts parameter for subsequent
  steps.
reads:
- device_uid
- severity_id
- status
- resource_type
- cve_uid
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT DISTINCT d.hostname AS device_hostname, v.cve_uid, v.severity, v.title FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid JOIN hb_exposed_assets e ON (d.hostname = e.domain_or_ip OR d.ip_address = e.ip_address) WHERE v.severity_id >= 4 AND v.status != 'suppressed' AND v.resource_type = 'device'
```

## parallel-corroboration
<!-- Parallel Corroboration -->
parallel:
- → anomalous-signins
- → perimeter-exploitation-probes
join: → triage-initial-access

## anomalous-signins
<!-- Anomalous sign-ins and identity risk -->
Detect sign-ins that may indicate executive impersonation or session hijacking, focusing on rare user-agents, geographic anomalies, and unusual authentication requirements.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Login events from rare combinations of location, user-agent, and auth protocol,
  especially those flagged as proxies. Silence indicates no anomalous logins were
  captured for the specified hosts.
prevalence:
  by: device_hostname
  key:
  - user_agent
  - actor_user_name
  - src_location_country
  rare_below: 3
reads:
- actor_user_name
- user_agent
- is_proxy
- risk_state
- src_location_country
- mfa
- auth_requirement
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT actor_user_name, user_agent, is_proxy, risk_state, src_location_country, mfa, auth_requirement, device_hostname, COUNT(*) as signin_count, MIN(time) as first_seen FROM hb_auth_signin WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, user_agent, is_proxy, risk_state, src_location_country, mfa, auth_requirement, device_hostname HAVING signin_count <= 3 ORDER BY signin_count ASC
```

## perimeter-exploitation-probes
<!-- Perimeter exploitation behavioral probes -->
Identify successful web requests targeting sensitive files or attempting command injection on vulnerable assets by filtering for successful HTTP response codes.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests with directory traversal or command execution patterns that
  returned a 2xx success code. Silence indicates no successful probe-like requests
  were captured.
reads:
- device_hostname
- url_full
- status_code
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, url_full, status_code, user_agent, time FROM hb_http_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND status_code BETWEEN 200 AND 299 AND (LOWER(url_full) LIKE '%etc/passwd%' OR LOWER(url_full) LIKE '%/bin/sh%' OR LOWER(url_full) LIKE '%/cgi-bin/%' OR LOWER(url_full) LIKE '%.env%' OR LOWER(url_full) LIKE '%/wp-config%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-initial-access
<!-- Triage initial access evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-perimeter-inventory
- anomalous-signins
- perimeter-exploitation-probes
max_iterations: 5
objective: Determine if any host with high-severity vulnerabilities shows evidence
  of successful exploitation or unauthorized sign-in using geographic, MFA, or user-agent
  anomalies.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing relevant
  telemetry rows.
tools:
- endpoint
- identity
- web
```

## decision-on-access
<!-- Decision on Initial Access -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: encrypted-perimeter-traffic)
else: → close-out-hunt

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any active session tokens for the affected accounts in the identity provider.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the cited sign-in anomalies and HTTP traffic; verify if the requests correlate with known vulnerability exploits. Document any AI-generated phishing indicators observed in user-agent strings or source IPs.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Document hosts that were unpatched and prioritize them for immediate remediation. If suspicious activity was found, pivot to investigations of post-compromise behavior.
```
→ end
