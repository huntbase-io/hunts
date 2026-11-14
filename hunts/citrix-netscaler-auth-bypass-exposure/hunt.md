---
analysis: "A standard signature-based detection for this CVE might be evaded by minor\
  \ adjustments in the exploit payload; this hunt instead looks for the behavioral\
  \ aftermath\u2014successful, rare authentications and anomalous web patterns on\
  \ vulnerable perimeter systems."
blind_spots:
- id: missing-appliance-telemetry
  question: Are the appliances configured to forward HTTP and authentication logs?
  requires: Syslog ingestion from NetScaler to hb_http_activity and hb_auth_signin
  risk: If logs are not centralized, the prevalence and behavioral queries will return
    zero results even if exploitation is occurring.
  stage: authentication-bypass-exploitation
- id: ephemeral-auth-sessions
  question: Can the bypass establish a session without a recorded logon event?
  requires: hb_auth_signin session tracking
  risk: If the bypass occurs purely at the protocol level (e.g., SAML assertion injection)
    and the appliance does not log it as a standard 'logon', the auth prevalence query
    will miss it.
  stage: external-remote-access
coverage:
- stage: vulnerable-service-exposure
  status: covered
  steps:
  - identify-vulnerable-netscaler
- stage: authentication-bypass-exploitation
  status: covered
  steps:
  - suspicious-web-access-patterns
- stage: external-remote-access
  status: covered
  steps:
  - rare-auth-source-ips
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: NetScaler appliances are high-value perimeter targets; an unauthenticated
    bypass (CVE-2026-19490) allows direct internal access, making a negative result
    a critical security requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthenticated attacker has exploited CVE-2026-19490 on an internet-facing
  NetScaler appliance to bypass authentication and gain unauthorized remote access.
labels:
- hunt
- attack.t1190
- attack.t1133
name: Citrix NetScaler Authentication Bypass and Exposure
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames or resource IDs for the identified vulnerable NetScaler
      appliances.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed appliances first by cross-referencing vulnerability
  scans with external asset inventory. Use the hostnames from the vulnerability findings
  to populate the scope_hosts parameter for the behavioral queries.
references:
- name: "Rapid7 \u2014 CVE-2026-19490: Critical Vulnerability Affecting Citrix NetScaler\
    \ ADC and NetScaler Gateway"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway
related:
- hunt: citrix-netscaler-shell-exploitation
  reason: This hunt focuses on the authentication bypass; post-exploitation shell
    activity on the underlying Linux OS requires different telemetry surfaces.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exposed Vulnerable NetScaler Service
    observables:
    - NetScaler ADC versions prior to 14.1-73.32
    - NetScaler Gateway versions prior to 13.1-63.21
    - NetScaler ADC FIPS
    - NetScaler ADC NDcPP
    slug: vulnerable-service-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: NetScaler Authentication Bypass
    observables:
    - Unauthenticated remote network access
    - SAML action configuration (add authentication samlAction)
    - VPN vserver configuration (add vpn vserver)
    - Auth vserver configuration (add authentication vserver)
    slug: authentication-bypass-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized External Remote Access
    observables:
    - Successful gateway login without valid credential record
    - Bypassed authentication session via SAML
    slug: external-remote-access
    tactic: initial-access
    techniques:
    - T1133
  summary: Attackers can bypass authentication on Citrix NetScaler ADC and NetScaler
    Gateway appliances via CVE-2026-19490, a critical vulnerability affecting systems
    configured with SAML or VPN virtual servers. This allows unauthenticated remote
    access to the perimeter device, providing a foothold for initial access into the
    corporate network.
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


# Citrix NetScaler Authentication Bypass and Exposure

This hunt identifies Citrix NetScaler ADC and Gateway appliances vulnerable to CVE-2026-19490 and evaluates signs of exploitation. It first scopes the estate using vulnerability findings for the specific CVE. It then analyzes authentication patterns and HTTP traffic targeting sensitive SAML and VPN endpoints on those systems to identify rare source IPs and anomalous access that indicate a successful authentication bypass.

## identify-vulnerable-netscaler
<!-- Identify vulnerable NetScaler appliances -->
Find systems with active, unresolved findings for CVE-2026-19490.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows identify specific vulnerable appliances. No rows means no confirmed
  vulnerabilities are present in the vulnerability management data.
reads:
- device_uid
- resource_uid
- severity
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, resource_uid, severity, collected_at FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-19490' AND status = 'unresolved'
```

## rare-auth-source-ips
<!-- Prevalence of successful authentication by source IP -->
Identify rare external IP addresses successfully authenticating to NetScaler services, which may indicate bypassed authentication.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs that have only successfully logged into one or two appliances
  stand out from regular corporate VPN users.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- device_hostname
- time
- status_id
- metadata_product
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS login_events, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE (LOWER(metadata_product) LIKE '%citrix%' OR LOWER(provider) LIKE '%citrix%') AND status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING host_count <= 2 ORDER BY host_count ASC, login_events DESC
```

## suspicious-web-access-patterns
<!-- Anomalous web access to SAML and VPN endpoints -->
Identify unusual HTTP request patterns targeting sensitive NetScaler authentication and gateway paths.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Access to SAML or VPN endpoints from IPs identified as rare in the prevalence
  step, or requests that return successful status codes without typical precursor
  sessions.
reads:
- device_hostname
- url_path
- url_query
- src_endpoint_ip
- user_agent
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_path, url_query, src_endpoint_ip, user_agent, status_code, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/logon/%' OR LOWER(url_path) LIKE '%/saml/%' OR LOWER(url_path) LIKE '%/vpn/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## agent-triage
<!-- Examine exposure and traffic for exploitation signs -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-netscaler
- rare-auth-source-ips
- suspicious-web-access-patterns
max_iterations: 5
objective: Determine if CVE-2026-19490 has been exploited by evaluating anomalous
  access to vulnerable NetScaler appliances.
success_criteria: A clear verdict of malicious, suspicious, or benign for each host
  in scope.
tools:
- endpoint
- identity
- web
```

## exploitation-decision
<!-- Route based on exploitation verdict -->
if~: "the agent-triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → remediation-task
indeterminate: → remediation-task
unavailable: → remediation-task (blind_spot: missing-appliance-telemetry)
else: → close-out-task

## remediation-task
<!-- Remediation and Incident Response Review -->
```manual target=analyst
1. Confirm that all NetScaler appliances identified in the scoping step are updated to at least the fixed versions (14.1-73.32 or 13.1-63.21). 2. For hosts with malicious activity, verify if SAML configurations were tampered with. 3. Review internal access logs from the compromised appliance IPs to determine lateral movement.
```
→ close-out-task

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document the resolution of the vulnerability findings. Ensure any suspicious source IPs identified are added to watchlists for future monitoring.
```
→ end
