---
analysis: "While static rules flag ngrok domains, this hunt differentiates legitimate\
  \ use from C2 by correlating across four surfaces: rare connection patterns, Tor\
  \ DNS gateways, user account status, and process listener state\u2014context a single\
  \ rule cannot weigh."
blind_spots:
- id: missing-host-on-listener
  question: Which specific host is running the listening process?
  requires: device_hostname column on hb_network_listener
  risk: Without a host column, an analyst must manually correlate process names and
    PIDs across steps, which is prone to misattribution in large environments.
  stage: multi-hop-proxy-c2
- id: tor-direct-ip
  question: Did the host connect directly to a Tor entry node by IP?
  requires: hb_network_connection IP reputation feed
  risk: Direct IP-based Tor connections bypass DNS-based gateway detection, leaving
    only the process name as a signal.
  stage: multi-hop-proxy-c2
- id: no-hr-linkage
  question: Is the user a developer or a security researcher?
  requires: Workday or HR linkage in hb_users
  risk: If the identity provider doesn't include job titles or cost centers, the agent
    cannot determine if the activity is aligned with the user's role, increasing false
    positives.
  stage: multi-hop-proxy-c2
coverage:
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - tunnel-lead
  - dns-onion-check
  - user-status
  - process-listeners
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Multi-hop proxies and tunnels are primary techniques for C2 obfuscation;
    a negative result over high-risk users confirms that these obfuscation paths are
    not currently being used by adversaries.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using a multi-hop proxy or tunneling service to obfuscate
  C2 traffic, which can be distinguished from legitimate researcher activity by correlating
  network leads with user risk profiles and local port bindings.
labels:
- hunt
- attack.t1090.003
name: Multi-hop proxy and tunnel triage via identity context
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  onion_gateways:
    default:
    - onion.link
    - onion.pet
    - onion.ws
    - onion.casa
    - onion.direct
    description: Public DNS gateways used to resolve Tor .onion addresses without
      a local Tor client.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: Tor DNS Gateways
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hostnames to narrow the search; leave empty for the full
      estate.
    type: list[host]
  tunnel_domains:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - ngrok-free.app
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - tunnel.sa.ngrok.com
    description: Known domains for tunneling services used to obfuscate C2.
    from:
      kind: article
      observed: '2026-08-25'
      ref: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents
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
rationale: Focus on endpoints first, then expand to cloud jump boxes if the DNS surface
  shows .onion gateway activity.
references:
- name: 'Inside Elastic''s agentic SOC: How we took AI alert triage from 60% to 92%
    accuracy'
  url: https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents
related:
- hunt: unauthorized-vpn-usage
  reason: Standard VPNs use different protocol and process signals than the focused
    tunnels (ngrok/socat) targeted here.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-hop Proxy and Tunneling Communication
    observables:
    - query_hostname ending in .onion
    - dst_endpoint_hostname containing ngrok.com
    - user.email
    - kibana.alert.rule.uuid
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This scenario covers the detection and triage of multi-hop proxy and tunneling
    traffic, such as Tor and ngrok, which adversaries use to obfuscate command-and-control
    communication. Defenders enhance alert accuracy by correlating network indicators
    with user identity profiles and historical triage decisions through an automated
    AI pipeline.
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


# Multi-hop proxy and tunnel triage via identity context

This hunt identifies potential C2 obfuscation by looking for rare outbound tunnels and multi-hop proxies. Following the agentic SOC pattern, it enriches network leads with user identity status and host listener data to differentiate between malicious actors and legitimate developers or researchers. An agent evaluates the combined evidence—prevalence, account risk, and proxy-like behavior—to decide whether to isolate the host.

## tunnel-lead
<!-- Detect rare tunneling and proxy connections -->
Find connections to known tunneling providers or outbound traffic from proxy-like processes to identify potential beachheads.

```sqlite target=network role=detection-candidate params=(tunnel_domains=tunnel_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare outbound connections to tunnel providers or proxy binaries. Benign
  hits often come from authorized developers; malicious hits often lack business context.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_hostname
  rare_below: 3
reads:
- device_hostname
- user_name
- process_name
- dst_endpoint_hostname
- time
- direction
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_name, dst_endpoint_hostname, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR (direction = 'outbound' AND (LOWER(process_name) LIKE '%tunnel%' OR LOWER(process_name) LIKE '%proxy%' OR LOWER(process_name) LIKE '%socat%'))) AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, user_name, process_name, dst_endpoint_hostname HAVING connection_count < 50
```

## parallel-enrichment
<!-- Enrich with DNS gateways, user risk, and listener state -->
parallel:
- → dns-onion-check
- → user-status
- → process-listeners
join: → agent-triage

## dns-onion-check
<!-- Look for Tor DNS gateway usage -->
Identify if the same hosts are resolving .onion domains via web gateways, which confirms multi-hop proxy intent.

```sqlite target=endpoint role=enrichment params=(onion_gateways=onion_gateways, lookback_days=lookback_days)
~~~yaml
expected: DNS queries for .onion gateways on the fleet. Silence here does not rule
  out direct Tor traffic.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{onion_gateways}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## user-status
<!-- Check user identity risk factors -->
Retrieve account status and MFA state for all corporate users to correlate with the network leads.

```sqlite target=identity role=enrichment
~~~yaml
expected: User account details. An inactive or non-MFA user establishing a tunnel
  is a high-confidence indicator of session theft or beachhead activity.
reads:
- email
- name
- status
- mfa_enabled
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT email, name, status, mfa_enabled FROM hb_users
```

## process-listeners
<!-- Check for local port bindings by proxy binaries -->
Verify if suspicious processes are binding to local ports, a key characteristic of active proxies and reverse tunnels.

```sqlite target=network role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: A process from the lead step that is also listening on a port. This confirms
  the multi-hop proxy role of the binary.
reads:
- process_name
- port
- protocol
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_network_listener
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, port, protocol, process_cmd_line, time FROM hb_network_listener WHERE (LOWER(process_name) LIKE '%tunnel%' OR LOWER(process_name) LIKE '%proxy%' OR LOWER(process_name) LIKE '%socat%' OR LOWER(process_name) LIKE '%ngrok%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Identity and behavior triage -->
```agent target=hunter
cite: required
context:
- tunnel-lead
- dns-onion-check
- user-status
- process-listeners
max_iterations: 4
objective: Determine if the tunneling activity represents a legitimate administrative
  session or a malicious C2 channel. Correlate the user_name from the network lead
  with the user status from identity data. Match process names from the lead with
  listener activity to confirm proxy behavior. Weigh the presence of Tor gateway DNS
  lookups as a high-risk factor.
success_criteria: A per-host verdict of malicious, suspicious, or benign with specific
  citations of rows.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-host-on-listener)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke active sessions for the involved user account.
```
→ analyst-review

## analyst-review
<!-- Analyst verification -->
```manual target=analyst
Review the agent reasoning and the cited rows. Confirm whether the user's role justifies the tunneling activity.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the outcome of the triage and document any blind spots encountered.
```
→ end
