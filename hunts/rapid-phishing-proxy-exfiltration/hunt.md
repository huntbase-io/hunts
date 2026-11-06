---
analysis: A single rule fires on high-volume traffic; this hunt correlates that signal
  with identity-layer anomalies (new source IP for a user) and rare DNS frequency
  to distinguish data theft from authorized administrative tasks.
blind_spots:
- id: no-okta-logs
  owner: SaaS Platform Team
  question: whether the initial authentication attempt occurred
  remediation: Audit and onboard all Okta tenants to the SIEM.
  requires: hb_auth_signin (Okta connector)
  risk: An authentication event outside the monitored SaaS provider will not trigger
    the lead query.
  stage: initial-access-phishing-mfa
- id: no-network-telemetry
  owner: Cloud Infrastructure
  question: how much data was exfiltrated
  remediation: Enable flow logs for critical VPC subnets.
  requires: hb_network_connection with traffic_bytes
  risk: Without network fabric logs (like VPC flow logs), endpoint-only data may lack
    reliable byte counts for exfiltration estimation.
  stage: exfiltration-over-c2
- id: direct-ip-c2
  owner: SOC Engineering
  question: whether the adversary bypassed DNS by using hard-coded IPs
  remediation: Implement an IP reputation baseline for outbound connections.
  requires: hb_dns_activity
  risk: The proxy-c2-signals query relies on DNS; a direct IP connection to a tunnel
    endpoint would only be caught by the exfiltration volume query.
  stage: c2-multi-hop-proxy
coverage:
- stage: initial-access-phishing-mfa
  status: covered
  steps:
  - okta-signins-unusual-ips
  - assess-initial-access
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - proxy-c2-signals
- stage: exfiltration-over-c2
  status: covered
  steps:
  - outlier-exfiltration-bytes
  - final-triage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Rapid exfiltration following identity compromise can occur in hours.
    Automating the correlation between identity outliers and network exfiltration
    volume reduces the exposure window before isolation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed phishing-resistant MFA to gain initial access
  via a SaaS provider and is now using a multi-hop proxy or tunnel to exfiltrate data
  from an internal host.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1041
name: Rapid Phishing and Proxy-based Exfiltration
parameters:
  lookback_days:
    default: '7'
    description: Days of history to examine for initial access and exfiltration.
    type: number
  min_exfil_bytes:
    default: '104857600'
    description: Minimum outbound traffic in bytes (default 100MB) to flag as potential
      exfiltration.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the investigation.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-elastic-workflows
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on administrative users or high-value accounts first. Use the bridge
  identification from the first agent to restrict network queries to relevant subnets.
references:
- name: Inside Elastic InfoSec's agentic SOC
  url: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-elastic-workflows
related:
- hunt: mfa-bypass-session-token-theft
  reason: Adversaries may steal session tokens rather than phishing, requiring cookie
    analysis in hb_http_activity.
  relation: alternative
scenario:
  stages:
  - name: Phishing with MFA Bypass
    observables:
    - source.ip
    - user.email
    - event.action == 'policy.evaluate_sign_on'
    - Okta authentication events
    - phishing-resistant MFA session evaluation
    slug: initial-access-phishing-mfa
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-hop Proxy Command and Control
    observables:
    - DNS queries for .onion domains
    - ngrok tunnel hostnames (e.g., tunnel.us.ngrok.com)
    - outbound network connections to known proxy endpoints
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Exfiltration Over C2 Channel
    observables:
    - high outbound traffic_bytes to proxy/C2 IPs
    - source.ip activity across AWS, Azure, and SaaS audit logs
    - exfiltration via established tunnel
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: This attack chain describes a compressed intrusion timeline where attackers
    gain initial access via phishing, establish command-and-control through multi-hop
    proxies like Tor or ngrok, and rapidly exfiltrate data. The scenario focuses on
    the speed of AI-assisted attacks and the defensive automation required to triage
    such events.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Rapid Phishing and Proxy-based Exfiltration

This hunt detects high-speed intrusions where identity compromise is immediately followed by proxy-based command-and-control. The adversary bypasses phishing-resistant MFA to gain initial access via a SaaS provider and then uses a multi-hop proxy or tunnel to exfiltrate data from an internal host. The hunt identifies successful Okta logins from rare source IPs, then gates an expensive investigation into DNS queries for hidden services and high-volume outbound network traffic. An AI agent correlates the identity lead with network signals to identify active data theft.

## okta-signins-unusual-ips
<!-- Rare Okta Sign-ins by User and IP -->
Identify successful logins from unusual source IPs that may indicate phished credentials, excluding IPs the user has successfully used in the prior month.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicating a successful login from a source IP not previously associated
  with a specific user in the 30 days prior to the search window.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- provider
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT t1.actor_user_name, t1.src_endpoint_ip, t1.dst_endpoint_name, COUNT(*) AS login_count, MIN(t1.time) AS first_seen FROM hb_auth_signin t1 WHERE t1.provider = 'okta' AND t1.status_id = 1 AND t1.time >= datetime('now', '-{{lookback_days}} days') AND NOT EXISTS (SELECT 1 FROM hb_auth_signin t2 WHERE t2.actor_user_name = t1.actor_user_name AND t2.src_endpoint_ip = t1.src_endpoint_ip AND t2.status_id = 1 AND t2.time >= datetime('now', '-{{lookback_days}} - 30 days') AND t2.time < datetime('now', '-{{lookback_days}} days')) GROUP BY t1.actor_user_name, t1.src_endpoint_ip ORDER BY login_count ASC
```

## assess-initial-access
<!-- Assess Initial Access Leads -->
```agent target=hunter
cite: required
context:
- okta-signins-unusual-ips
max_iterations: 3
objective: Determine if any rare Okta sign-ins represent potential MFA bypass or session
  theft. Identify the bridge between the Okta login and the internal fleet, such as
  a VPN endpoint session or an OIDC-integrated server login, to avoid querying network
  data for the entire fleet in the next phase.
success_criteria: A prioritized list of suspicious IPs and their associated internal
  bridge endpoints.
tools:
- endpoint
- identity
- network
```

## gate-on-suspicious-auth
<!-- Gate on Suspicious Authentication -->
if~: "The assessment for at least one IP or user is suspicious or malicious." (confidence: high, judge=hunter)
then: → investigate-network-anomalies
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-okta-logs)
else: → close-out-triage

## investigate-network-anomalies
<!-- Investigate Proxy C2 and Exfiltration -->
parallel:
- → proxy-c2-signals
- → outlier-exfiltration-bytes
join: → final-triage

## proxy-c2-signals
<!-- High-Frequency Rare DNS Activity -->
Identify hosts querying for rare domains at high frequency, potentially indicating a multi-hop proxy or tunnel endpoint.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host resolving rare domains at high frequency, which is a common behavior
  of tunnel or proxy clients.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS query_frequency, GROUP_CONCAT(DISTINCT process_name) AS processes FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY query_hostname HAVING host_count < 3 AND query_frequency > 20 ORDER BY query_frequency DESC
```

## outlier-exfiltration-bytes
<!-- Outlier Outbound Traffic by Process -->
Stack-count outbound traffic bytes per process to identify rare, high-volume data transfers.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, min_exfil_bytes=min_exfil_bytes, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process pushing significant data to an external IP. The analyst or agent
  must distinguish legitimate sync tools like OneDrive from exfiltration tools.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- traffic_bytes
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, SUM(traffic_bytes) AS bytes_out, COUNT(*) AS connection_count FROM hb_network_connection WHERE state_kind = 'log' AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name, dst_endpoint_ip HAVING bytes_out > {{min_exfil_bytes}} ORDER BY bytes_out DESC
```

## final-triage
<!-- Final Alert Triage -->
```agent target=hunter
cite: required
context:
- assess-initial-access
- proxy-c2-signals
- outlier-exfiltration-bytes
max_iterations: 5
objective: Confirm if the suspicious Okta login was used to gain access to an internal
  host that subsequently established a proxy tunnel and exfiltrated data. Use process_name
  to distinguish legitimate backup tools (OneDrive, rclone) from potential exfiltration.
success_criteria: A final verdict citing specific rows from identity, DNS, and network
  connection logs.
tools:
- endpoint
- identity
- network
```

## route-on-threat
<!-- Route on Threat Confirmation -->
if~: "The triage verdict is malicious for at least one host and indicates exfiltration." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host cited in the malicious verdict and initiate credential reset for the affected user.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the exfiltration volume and process name. Use hb_file_activity to determine which files the process accessed during the exfiltration window.
```
→ end

## close-out-triage
<!-- Close Triage -->
```manual target=analyst
Document the triage path. If the session was benign (e.g., an authorized remote developer), record the IP and user for tuning.
```
→ end
