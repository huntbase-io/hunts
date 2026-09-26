---
analysis: A single detection rule can trigger on a known Tor IP or a specific discovery
  command, but it cannot verify if that IP was used for a successful Okta login that
  then led to discovery activity on an internal host. This hunt pivots between Identity,
  DNS, Network, and Process surfaces to confirm the behavioral link.
blind_spots:
- id: missing-endpoint-telemetry
  question: Did the user execute commands on hosts where no EDR agent is installed?
  requires: hb_process_activity from all endpoints
  risk: An adversary could authenticate via proxy and access unmanaged infrastructure
    without detection.
  stage: endpoint-identity-execution
- id: ephemeral-proxy-nodes
  question: Was the authentication from a newly stood-up VPS not yet in our IP lists?
  requires: Up-to-date threat intelligence on Tor exit nodes
  risk: Static IP lists will miss private relays or fresh VPS infrastructure.
  stage: okta-authentication-via-proxy
coverage:
- stage: proxy-infrastructure-resolution
  status: covered
  steps:
  - dns-proxy-infra
- stage: okta-authentication-via-proxy
  status: covered
  steps:
  - auth-suspicious-ips
- stage: multi-hop-network-egress
  status: covered
  steps:
  - network-proxy-egress
- stage: endpoint-identity-execution
  status: covered
  steps:
  - endpoint-discovery
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Linking identity-provider events to specific host-based activity
    is the primary way to deanonymize sessions arriving via multi-hop proxies; this
    hunt provides that correlation across siloed telemetry surfaces.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxy infrastructure to authenticate via
  Okta and subsequently execute discovery commands on an endpoint, obscured by network
  egress to proxy relay ports.
labels:
- hunt
- attack.t1090.003
- attack.t1078
- attack.t1059
name: Correlating Proxy-Obscured Identity and Endpoint Activity
parameters:
  discovery_commands:
    default:
    - whoami
    - hostname
    - ipconfig
    - net user
    description: Discovery commands often run by adversaries immediately after gaining
      access.
    from:
      kind: article
      observed: '2026-06-11'
      ref: red-canary
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_domains:
    default:
    - torproject.org
    - bridge.torproject.org
    - check.torproject.org
    description: Known proxy infrastructure domains.
    from:
      kind: article
      observed: '2026-06-11'
      ref: red-canary
    type: list[domain]
  proxy_ips:
    default:
    - 185.220.101.0
    - 176.10.99.200
    description: Known Tor exit node or VPS IP addresses.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: threat-intel
    type: list[ip]
  scope_hosts:
    default: []
    description: Specific hostnames to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/threat-hunting-scaled/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with high-privilege users in the Okta logs. Focus on authentication
  events where the source IP does not match the user's typical office or VPN range.
references:
- name: "How threat hunting evolves at scale \u2014 Red Canary"
  url: https://redcanary.com/blog/threat-detection/threat-hunting-scaled/
related:
- hunt: okta-mfa-fatigue-triage
  reason: This hunt focuses on proxy-obscured source attribution rather than authentication
    mechanism exploitation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Proxy Infrastructure DNS Resolution
    observables:
    - 'query_hostname: torproject.org'
    - 'query_hostname: *.hiddenservice.net'
    - 'query_hostname: bridge.torproject.org'
    slug: proxy-infrastructure-resolution
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Identity Authentication via Multi-hop Proxy
    observables:
    - src_endpoint_ip belonging to VPS or known Tor exit node ranges
    - 'auth_protocol: SAML'
    - 'auth_protocol: OAuth'
    - 'provider: okta'
    slug: okta-authentication-via-proxy
    tactic: initial-access
    techniques:
    - T1078
    - T1090.003
  - name: Network Egress to Proxy Nodes
    observables:
    - 'dst_endpoint_port: 9001'
    - 'dst_endpoint_port: 9050'
    - 'dst_endpoint_ip: known Tor relays'
    - 'protocol: tcp'
    slug: multi-hop-network-egress
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Identity-Correlated Process Execution
    observables:
    - 'process_cmd_line: whoami'
    - 'process_cmd_line: hostname'
    - user_name matching actor_user_name from Okta authentication events
    slug: endpoint-identity-execution
    tactic: execution
    techniques:
    - T1059
  summary: Adversaries leverage multi-hop proxies to obscure their origin while authenticating
    to identity providers like Okta, subsequently performing unauthorized actions
    on endpoints. Detection relies on the difficult task of correlating proxy-anonymized
    sign-in events with subsequent host-level process and network telemetry.
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


# Correlating Proxy-Obscured Identity and Endpoint Activity

This hunt bridges identity telemetry with endpoint behavior to deanonymize sessions arriving through multi-hop proxies. It starts by identifying successful Okta logins and correlating them with hosts resolving known proxy infrastructure. The hunt then pivots to find network egress to standard proxy ports (9001, 9050) and the execution of post-authentication discovery commands on those same hosts. By linking these disparate surfaces, the analyst can identify compromised credentials even when the source IP is obscured.

## scope-okta-logins
<!-- Scope Okta Authentication Activity -->
Establish a baseline of successful Okta logins to identify active users and potential beachhead IPs.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of successful Okta logins. Silence indicates no Okta telemetry is
  available for the period.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- provider
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, time FROM hb_auth_signin WHERE provider = 'okta' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-evidence-gathering
<!-- Parallel Early Evidence Gathering -->
parallel:
- → dns-proxy-infra
- → auth-suspicious-ips
join: → early-stage-triage

## dns-proxy-infra
<!-- DNS Resolutions for Proxy Infrastructure -->
Detect endpoints resolving domains associated with proxy services like Tor or onion routing.

```sqlite target=endpoint role=enrichment params=(proxy_domains=proxy_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving Tor-related domains. Silence suggests no active use of these
  proxy gateways via DNS.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.hiddenservice.net') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## auth-suspicious-ips
<!-- Suspicious Okta Login Source IPs -->
Identify Okta logins from known proxy IPs or IPs used by very few users across the fleet.

```sqlite target=identity role=baseline params=(proxy_ips=proxy_ips, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Successful logins from known proxy exit nodes or highly unique IPs. Silence
  suggests no anomalous authentication source IPs.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- provider
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_count FROM hb_auth_signin WHERE provider = 'okta' AND status_id = 1 AND (instr(',' || '{{proxy_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR src_endpoint_ip IN (SELECT src_endpoint_ip FROM hb_auth_signin WHERE provider = 'okta' GROUP BY src_endpoint_ip HAVING COUNT(DISTINCT actor_user_name) <= 3)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip
```

## early-stage-triage
<!-- Early Stage Evidence Triage -->
```agent target=hunter
cite: required
context:
- scope-okta-logins
- dns-proxy-infra
- auth-suspicious-ips
max_iterations: 3
objective: Identify if any Okta login session from a rare or known proxy IP (auth-suspicious-ips)
  occurred on a host that was also resolving proxy infrastructure domains (dns-proxy-infra).
success_criteria: A verdict citing specific hosts and users where both signals occurred
  in close proximity.
tools:
- endpoint
- identity
- network
```

## follow-on-evidence-gathering
<!-- Parallel Follow-on Evidence Gathering -->
parallel:
- → network-proxy-egress
- → endpoint-discovery
join: → follow-on-triage

## network-proxy-egress
<!-- Network Egress to Proxy Relay Ports -->
Detect TCP connections to standard proxy ports like 9001 and 9050 that often signal Tor or multi-hop traffic.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Established connections to proxy relay ports. Silence means no egress to
  these specific ports was observed.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE dst_endpoint_port IN (9001, 9050) AND protocol = 'tcp' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## endpoint-discovery
<!-- Endpoint Discovery Command Execution -->
Find discovery commands executed on the host that correlate with the suspected proxy session.

```sqlite target=endpoint role=detection-candidate params=(discovery_commands=discovery_commands, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process execution of common discovery tools. Silence suggests no discovery
  activity was logged.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{discovery_commands}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{discovery_commands}}' || ',', ',' || LOWER(process_cmd_line) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Follow-on Evidence Triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- network-proxy-egress
- endpoint-discovery
max_iterations: 6
objective: Confirm whether the suspect users and hosts from early-stage-triage showed
  subsequent network egress to proxy nodes or discovery command execution on the same
  endpoint.
success_criteria: A final malicious | suspicious verdict citing the temporal link
  between auth, network, and process events.
tools:
- endpoint
- identity
- network
```

## route-verdict
<!-- Route Based on Intrusion Chain -->
if~: "the follow-on-triage verdict is malicious for at least one host and user" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: missing-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host and Revoke Identity -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint in the EDR console and revoke all active Okta sessions for the identified user.
```
→ analyst-validation

## analyst-validation
<!-- Analyst Final Validation -->
```manual target=analyst
Verify the link between the Okta login IP and the endpoint network/process activity. Investigate any lateral movement (e.g. RDP/SSH) from this host within the same window.
```
→ close-out

## close-out
<!-- Close Out and Record ROI -->
```manual target=analyst
Document the findings and update any baseline filters if the activity was determined to be authorized administrative work. Record the detection of a proxy-obscured session as a successful hunt ROI.
```
→ end
