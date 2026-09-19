---
analysis: A rule identifies a proxy IP; this hunt uses entity resolution to pivot
  from that IP to a cloud user and then to specific discovery activity by a 'local'
  user on a gateway host, bridging three logical namespaces.
blind_spots:
- id: incomplete-identity-logs
  question: Whether the SIEM has successfully resolved the 'local' user to the 'provider'
    user.
  remediation: Implement the Entity Store Maintainer logic as a real-time enrichment
    for ingestion.
  requires: Unified EUID field across all hb_ surfaces
  risk: Without resolution metadata on raw events, the analyst must manually correlate
    usernames and IPs, increasing time-to-detect.
  stage: cloud-identity-authentication
- id: dga-evasion
  question: Whether the proxy exit node uses a low-entropy domain that bypasses the
    length filter.
  remediation: Integrate an IP-based ORB/Proxy reputation list into hb_network_connection.
  requires: Proxy IP reputation feed
  risk: Proxy nodes using common domains will not be captured by the behavioral DNS
    lead.
  stage: multi-hop-proxy-c2
coverage:
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - proxy-dns-leads
- stage: cloud-identity-authentication
  status: covered
  steps:
  - auth-from-proxy-ips
- stage: host-and-service-discovery
  status: covered
  steps:
  - local-host-discovery
  - gateway-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries targeting cloud gateways via multi-hop proxies bypass
    geographic security controls. Confirming the absence of proxy-derived sign-ins
    across resolved identities validates the perimeter's integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies to mask their origin while authenticating
  to cloud identity providers and performing discovery on target hosts using accounts
  that appear as 'local' identities.
labels:
- hunt
- attack.t1090.003
- attack.t1078.004
- attack.t1087.004
name: Identity-Resolved Multi-hop Proxy Activity
parameters:
  correlated_users:
    default: []
    description: Usernames discovered authenticating from proxy-linked IPs.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_ips:
    default: []
    description: Source IPs identified as proxy exit nodes from DNS leads.
    from:
      kind: article
      observed: '2026-08-24'
      ref: https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security
    type: list[ip]
  scope_hosts:
    default: []
    description: Hostnames of targeted gateways or API services identified in the
      scoping step.
    type: list[host]
  scope_ips:
    default: []
    description: IP addresses of targeted gateways identified in the scoping step.
    from:
      kind: article
      observed: '2026-08-24'
      ref: https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security
    type: list[ip]
  target_tlds:
    default:
    - check.torproject.org
    - exit.torproject.org
    - api.ipify.org
    description: Common domains resolved by multi-hop proxies or ORB infrastructure
      to check connectivity.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: common-proxy-check-domains
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scoping must first identify assets with 'gateway' or 'api' in their hostname
  to narrow the search. Proxy leads rely on DNS activity and should be matched against
  authentication logs regardless of host scope.
references:
- name: How a team of entity maintainers monitors, connects and scores entities in
    Elastic Security
  url: https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security
related:
- hunt: tor-exit-node-signins
  reason: Focuses strictly on known Tor databases rather than behavioral multi-hop
    proxy patterns like ORBs.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-hop Proxy C2
    observables:
    - Tor network traffic
    - Connection to Operational Relay Box (ORB) networks
    - DNS queries for .onion domains
    - Network activity targeting service:api-gateway
    - Use of VPS-based proxies
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Cloud Identity Authentication
    observables:
    - Sign-ins to okta provider namespace
    - Sign-ins to entra_id provider namespace
    - 'User identifier: jane.doe@example.com'
    - Authentication events from proxy-derived source IPs
    slug: cloud-identity-authentication
    tactic: initial-access
    techniques:
    - T1078.004
  - name: Host and Service Discovery
    observables:
    - Interaction with host:9f86d081-1e0c-4b3f-8a2d-2c1e7bed425e
    - Access to EC2 instances and Kubernetes clusters
    - Process activity attributed to user:jdoe in the local namespace
    - Resource access involving service:api-gateway
    slug: host-and-service-discovery
    tactic: discovery
    techniques:
    - T1087.004
  summary: The campaign involves the use of multi-hop proxies and tunneling services
    to obfuscate the origin of unauthorized access to cloud identity providers and
    infrastructure. By leveraging entity resolution, the attack tracks an adversary's
    progression from masked network connections to impersonated sign-ins and subsequent
    interaction with resolved host and service entities.
severity: high
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


# Identity-Resolved Multi-hop Proxy Activity

This hunt correlates network-layer proxy indicators with identity-provider authentication and host-level discovery commands. Following the logic of entity resolution, we identify internal hosts communicating with known multi-hop proxy networks (ORBs and Tor), pivot to cloud sign-ins from those same source IPs, and then corroborate with activity from 'local' scoped users on high-value infrastructure identified during scoping.

## scoping-entities
<!-- Locate targeted hosts and services -->
Identify the actual hostnames and IPs for services containing 'gateway' or 'api' to provide dynamic targets for the hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Identifies the specific internal infrastructure to be used as destination
  targets in network and host queries.
reads:
- hostname
- ip_address
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_uid, hostname, ip_address, os_name, provider FROM hb_devices WHERE (LOWER(hostname) LIKE '%gateway%' OR LOWER(hostname) LIKE '%api%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## proxy-dns-leads
<!-- Behavioral multi-hop proxy DNS leads -->
Identify internal hosts resolving unusual TLDs (.onion) or known proxy check domains.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, target_tlds=target_tlds)
~~~yaml
expected: Internal hosts resolving domains characteristic of proxy networks. Use these
  IPs to populate 'proxy_ips'.
reads:
- src_endpoint_ip
- query_hostname
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, src_endpoint_ip, COUNT(*) AS lookup_count FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.onion%' OR instr(',' || '{{target_tlds}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## parallel-corroboration
<!-- Corroborate identity and behavior -->
parallel:
- → auth-from-proxy-ips
- → local-host-discovery
- → gateway-access
join: → triage-resolved-identity

## auth-from-proxy-ips
<!-- Cloud authentication from proxy source IPs -->
Filter sign-ins by the source IPs identified in the proxy DNS activity to find correlated identities.

```sqlite target=identity role=baseline params=(proxy_ips=proxy_ips, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Users authenticating from IPs used for multi-hop proxy DNS lookups. Resulting
  usernames should populate 'correlated_users'.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- actor_user_name
- src_endpoint_ip
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, actor_user_name, provider, status_id, COUNT(*) AS login_count FROM hb_auth_signin WHERE ('{{proxy_ips}}' = '' OR instr(',' || '{{proxy_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND provider IN ('okta', 'aws', 'm365') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4
```

## local-host-discovery
<!-- Discovery commands by correlated users -->
Identify discovery commands run by users identified in the previous authentication step.

```sqlite target=endpoint role=enrichment params=(correlated_users=correlated_users, lookback_days=lookback_days)
~~~yaml
expected: Process activity linking the high-confidence cloud identity to specific
  host-level discovery actions.
reads:
- user_name
- process_cmd_line
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{correlated_users}}' = '' OR instr(',' || '{{correlated_users}}' || ',', ',' || user_name || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%whoami%' OR LOWER(process_cmd_line) LIKE '%hostname%' OR LOWER(process_cmd_line) LIKE '%net user%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## gateway-access
<!-- Constrained access to Gateway services -->
Monitor network connections targeting the destination infrastructure identified in scoping.

```sqlite target=network role=triage params=(scope_hosts=scope_hosts, scope_ips=scope_ips, lookback_days=lookback_days)
~~~yaml
expected: Inbound connections to established gateway infrastructure from internal
  hosts resolving proxy DNS.
reads:
- dst_endpoint_hostname
- dst_endpoint_ip
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_ip, process_name, time FROM hb_network_connection WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_hostname || ',') > 0) OR ('{{scope_ips}}' = '' OR instr(',' || '{{scope_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-resolved-identity
<!-- Resolve identities across surfaces -->
```agent target=hunter
cite: required
context:
- scoping-entities
- proxy-dns-leads
- auth-from-proxy-ips
- local-host-discovery
- gateway-access
max_iterations: 6
objective: Determine if the IP addresses from 'proxy-dns-leads' match 'src_endpoint_ip'
  in 'auth-from-proxy-ips', and if those users performed discovery in 'local-host-discovery'.
success_criteria: A per-host verdict citing specific rows that resolve these disparate
  identifiers into one intrusion path.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on resolved identity verdict -->
if~: "the triage verdict is malicious for a user linked to proxy source IPs who then performed discovery." (confidence: high, judge=hunter)
then: → contain-intrusion
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-identity-logs)
else: → close-out

## contain-intrusion
<!-- Contain Intrusion -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in 'local-host-discovery' and revoke all active MFA sessions for the user identified in 'auth-from-proxy-ips'.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the agent's resolution of 'local' user activity back to the cloud sign-in. Confirm or overturn the verdict and record a tuning note for future runs.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document the absence of proxy-derived sign-ins and discovery behavior for this window.
```
→ end
