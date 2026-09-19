---
analysis: A standard rule alerts on any Ngrok or Tor domain; this hunt asks whether
  the activity is rare for the host and whether it matches a high-risk user profile
  (new hire, sensitive role), using an agent to weigh the context.
blind_spots:
- id: no-identity-role-metadata
  owner: Identity Engineering
  question: Does the user's professional role justify the use of tunneling tools?
  remediation: Sync job_family and department data from Workday/HRIS into the identity
    surface.
  requires: hb_users with job_title or department fields
  risk: Without role metadata, the hunt relies on tenure (new hires), missing seasoned
    insiders in high-privilege roles.
  stage: high-risk-identity-correlation
- id: ip-based-tunneling
  owner: Network Engineering
  question: Is the user connecting to proxies without performing a DNS lookup first?
  remediation: Ingest and tag known proxy/VPN IP ranges in flow logs for direct correlation.
  requires: hb_network_connection with direct IP correlation against Tor/Ngrok nodes
  risk: DNS-based detection is bypassed if the proxy IP is hard-coded or known via
    out-of-band channels.
  stage: multi-hop-proxy-tunneling
coverage:
- stage: multi-hop-proxy-tunneling
  status: covered
  steps:
  - rare-ngrok-tunnels
  - tor-dns-gateways
- stage: high-risk-identity-correlation
  status: covered
  steps:
  - high-risk-host-identification
  - identity-risk-context
  - agentic-brainstorm
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Multi-hop proxies and reverse tunnels (T1090.003) are common precursors
    to data exfiltration and persistent C2. Correlating technical signals with identity
    lifecycles provides a high-confidence way to detect these without the noise of
    standard static rules.
  methodology: model-assisted
  trigger: intel-report
hypothesis: High-risk users, such as new hires or those in sensitive roles, are using
  multi-hop proxies (Ngrok, Tor) to bypass network controls, which an agentic triage
  process can distinguish from legitimate developer activity.
labels:
- hunt
- attack.t1090.003
- attack.t1078
name: Agentic Proxy and Identity Risk Correlation
parameters:
  high_risk_emails:
    default: []
    description: List of high-risk user emails (e.g., from HR leaver lists or security
      researchers).
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  ngrok_domains:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - tunnel.sa.ngrok.com
    description: Known ngrok tunnel endpoints.
    from:
      kind: article
      observed: '2026-08-25'
      ref: elastic-security-labs
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to restrict the hunt to (pasted from the scoping step).
    type: list[host]
  tor_gateways:
    default:
    - hiddenservice.net
    - onion.link
    - onion.to
    - onion.nu
    - onion.city
    - onion.cab
    - onion.casa
    description: Common Tor-to-Web gateways and suffixes.
    from:
      kind: manual
      observed: '2026-08-25'
      ref: common-tor-gateways
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by scoping to 'new hires' (hb_users created_at < 90 days) or users
  from a known HR leaver list. Paste these emails into high_risk_emails.
references:
- name: 'Inside Elastic''s agentic SOC: How we took AI alert triage from 60% to 92%
    accuracy'
  url: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents
related:
- hunt: ssh-reverse-tunneling-detection
  reason: SSH-specific tunneling (T1572) involves distinct process and protocol indicators
    not covered by domain matching.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-hop Proxy Tunneling
    observables:
    - .onion DNS queries
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - tunnel.sa.ngrok.com
    - source_ip
    - host_name
    slug: multi-hop-proxy-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: High-Risk Identity Correlation
    observables:
    - user.email
    - user_name
    - user_id
    - job titles in security research or help desk
    - new hire status (joined < 90 days)
    - leaving soon status (leaving < 90 days)
    - cost_center risk
    slug: high-risk-identity-correlation
    tactic: initial-access
    techniques:
    - T1078
  summary: The campaign involves the use of multi-hop proxies, such as Tor and Ngrok,
    to establish command-and-control tunnels and obfuscate malicious traffic. These
    activities are triaged by correlating network alerts with identity-based risk
    factors, including user employment status and job roles, to identify high-risk
    anomalies.
severity: medium
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


# Agentic Proxy and Identity Risk Correlation

Inspired by the Elastic 'Agentic SOC' model, this hunt correlates technical indicators of anonymization with identity risk markers. It identifies hosts used by high-risk accounts (newly created or manually scoped) and then hunts for rare tunneling behavior (Ngrok) and Tor-related DNS lookups. An agent weighs the tenure and role of the user against these technical signals to reach a high-fidelity verdict, mirroring the self-correcting triage logic used by advanced security teams to reduce false positives from developer workflows.

## high-risk-host-identification
<!-- Identify Hosts for High-Risk Users -->
Identify endpoints associated with high-risk users to scope technical analysis to specific identities.

```sqlite target=identity role=scoping params=(high_risk_emails=high_risk_emails, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames mapped to the user identities of interest. Silence means
  no auth events were recorded for these users in the window.
reads:
- dst_endpoint_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT dst_endpoint_name AS device_hostname, actor_user_name FROM hb_auth_signin WHERE ('{{high_risk_emails}}' = '' OR instr(',' || '{{high_risk_emails}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gather-evidence
<!-- Gather Technical and Identity Evidence -->
parallel:
- → rare-ngrok-tunnels
- → tor-dns-gateways
- → identity-risk-context
join: → agentic-brainstorm

## rare-ngrok-tunnels
<!-- Rare Ngrok Tunnel Connections -->
Identify established network connections to ngrok tunneling infrastructure that are rare across the fleet, suggesting unauthorized proxy usage.

```sqlite target=network role=detection-candidate params=(ngrok_domains=ngrok_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to tunnel endpoints. The total_host_hits column allows for identifying
  rare connections (e.g., < 3).
prevalence:
  by: device_hostname
  key:
  - tunnel_domain
  rare_below: 3
reads:
- dst_endpoint_hostname
- device_hostname
- user_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(dst_endpoint_hostname) AS tunnel_domain, device_hostname, user_name, MIN(time) AS first_seen, COUNT(*) OVER (PARTITION BY dst_endpoint_hostname) AS total_host_hits FROM hb_network_connection WHERE instr(',' || '{{ngrok_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## tor-dns-gateways
<!-- Tor and Onion DNS Gateways -->
Find DNS queries for common Tor-to-Web gateways used to obfuscate traffic, avoiding standard .onion resolver noise.

```sqlite target=endpoint role=triage params=(tor_gateways=tor_gateways, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions indicative of Tor network access via gateways. Any row on
  a corporate endpoint is suspicious.
reads:
- device_hostname
- query_hostname
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, actor_user_name, time FROM hb_dns_activity WHERE instr(',' || '{{tor_gateways}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## identity-risk-context
<!-- User Risk Context and Tenure -->
Retrieve identity metadata to determine if users are 'new hires' or carry high-risk flags, which weights the technical signals.

```sqlite target=identity role=baseline params=(high_risk_emails=high_risk_emails)
~~~yaml
baseline:
  compare: first_seen
  window: 90d
expected: Identity records including a 'new hire' flag. New accounts (created < 90
  days ago) increase the risk weight.
reads:
- email
- name
- created_at
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT email, name, created_at, status, (CASE WHEN created_at >= datetime('now', '-90 days') THEN 1 ELSE 0 END) AS is_new_hire FROM hb_users WHERE ('{{high_risk_emails}}' = '' OR instr(',' || '{{high_risk_emails}}' || ',', ',' || email || ',') > 0)
```

## agentic-brainstorm
<!-- Agentic Brainstorm Triage -->
```agent target=hunter
cite: required
context:
- high-risk-host-identification
- rare-ngrok-tunnels
- tor-dns-gateways
- identity-risk-context
max_iterations: 5
objective: Determine if the observed proxy behavior is unauthorized by correlating
  it with high-risk user status (new hire or sensitive email). Reach a verdict of
  malicious, suspicious, or benign per host.
success_criteria: A verdict citing specific rows for user risk and technical signals.
tools:
- endpoint
- identity
- network
```

## verdict-routing
<!-- Route by Brainstorm Verdict -->
if~: "The triage verdict is malicious for a user with 'is_new_hire' = 1 or a manually scoped high-risk email." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: no-identity-role-metadata)
else: → analyst-triage

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the triage report to prevent further unauthorized communication.
```
→ analyst-triage

## analyst-triage
<!-- Analyst Review of Findings -->
```manual target=analyst
Verify the agent's verdict against the DNS and Network rows. If the user is in a 'Security' or 'Dev' job family, confirm if this is an authorized test or legitimate proxy usage for local development.
```
→ close-hunt

## close-hunt
<!-- Close and Document -->
```manual target=analyst
Document the hosts found and any false positives related to specific user job families. Provide these notes to detection engineering for agent prompt tuning.
```
→ end
