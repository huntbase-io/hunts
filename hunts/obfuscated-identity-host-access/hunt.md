---
analysis: This hunt connects proxy-related DNS activity specifically from auth processes
  to authoritative cloud sign-ins and subsequent rare internal movement, providing
  the multi-plane context and temporal correlation needed to verify a breach that
  single rules miss.
blind_spots:
- id: missing-auth-context
  question: Was MFA challenged and satisfied for the suspicious login?
  requires: hb_auth_signin with full MFA disposition
  risk: A login from a proxy might be benign if MFA is verified; without it, the hunt
    may over-alert on legitimate remote work.
  stage: cloud-identity-authentication
- id: short-dns-retention
  question: When was the tunneling infrastructure first contacted by this host?
  requires: hb_dns_activity with 30+ day retention
  risk: If the beachhead was established beyond the retention window, the proxy activity
    will be invisible, breaking the correlation chain.
  stage: proxy-tunneling-obfuscation
coverage:
- stage: proxy-tunneling-obfuscation
  status: covered
  steps:
  - proxy-dns-check
- stage: cloud-identity-authentication
  status: covered
  steps:
  - idp-auth-scoping
  - external-ip-prevalence
- stage: internal-host-service-access
  status: covered
  steps:
  - internal-access-pivot
- stage: endpoint-process-execution
  status: covered
  steps:
  - rare-local-execution
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries use proxies to blend into administrative login traffic;
    a phased hunt linking external obfuscation to internal access is required to distinguish
    this activity from legitimate remote work.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies or tunnels to mask their origin
  during authentication to cloud identity providers, subsequently using that access
  to reach internal hosts and execute local commands.
labels:
- hunt
- attack.t1090.003
- attack.t1078
- attack.t1021.001
- attack.t1059
name: Obfuscated Identity and Host Access
parameters:
  admin_ports:
    default:
    - '22'
    - '445'
    - '3389'
    - '5985'
    description: Administrative ports associated with lateral movement.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: standard-admin-ports
    type: list[string]
  auth_providers:
    default:
    - okta
    - entra_id
    - microsoft_365
    - active_directory
    description: Authoritative identity providers to monitor.
    from:
      kind: article
      observed: '2024-05-22'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: default
    type: number
  proxy_indicators:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - onion.city
    - onion.direct
    - hiddenservice.net
    - onion.ca
    - onion.cab
    - onion.casa
    description: Proxy and tunneling domains identified in the research.
    from:
      kind: article
      observed: '2024-05-22'
      ref: elastic-security-labs
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hostnames to focus on for the follow-on phase.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: analyst-defined
    type: list[host]
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
rationale: Start with logins from authoritative providers (Okta, Entra ID) and focus
  on source IPs that authenticate very few users. Widen the search if no tunneling
  DNS matches are found initially.
references:
- name: How a team of entity maintainers monitors, connects and scores entities in
    Elastic Security
  url: https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security
related:
- hunt: internal-management-port-misuse
  reason: Focuses on management protocol abuse without the origin-masking correlation.
  relation: sibling
scenario:
  stages:
  - name: Multi-hop Proxy and Tunneling
    observables:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - .onion.city
    - .onion.direct
    - Tor exit nodes
    slug: proxy-tunneling-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Identity Provider Authentication
    observables:
    - jane.doe@example.com
    - okta
    - entra_id
    - microsoft_365
    slug: cloud-identity-authentication
    tactic: initial-access
    techniques:
    - T1078
  - name: Access to Hosts and Services
    observables:
    - host:9f86d081-1e0c-4b3f-8a2d-2c1e7bed425e
    - service:api-gateway
    - host.name
    - host.hostname
    slug: internal-host-service-access
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Local Host Activity
    observables:
    - user:jdoe@local
    - process_cmd_line
    - host.id
    slug: endpoint-process-execution
    tactic: execution
    techniques:
    - T1059
  summary: The campaign involves an adversary utilizing multi-hop proxies and tunneling
    services like ngrok or Tor to obfuscate their origin while authenticating to corporate
    identity providers such as Okta or Entra ID. Once authenticated, the actor accesses
    specific internal hosts and services, establishing a local presence that is tracked
    through entity resolution and risk scoring.
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


# Obfuscated Identity and Host Access

This hunt correlates network obfuscation with identity provider authentication and subsequent internal host activity. It follows a phased flow: first, it identifies proxy usage by authentication processes and authoritative sign-in events from identity providers; second, it pivots to observe rare internal network connections on administrative ports and suspicious process execution in the local context. This traces the full chain from an external proxy-originating login to local host execution, providing the context necessary to distinguish a breach from normal administrative access.

## idp-auth-scoping
<!-- Identify authoritative IDP sign-ins -->
Narrow the hunt to users and source IPs associated with successful logins through authoritative identity providers.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, auth_providers=auth_providers)
~~~yaml
expected: A list of successful cloud/SaaS logins. This identifies the active identities
  and source IPs that form the basis of the hunt.
reads:
- actor_user_name
- provider
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT actor_user_name, provider, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{auth_providers}}' || ',', ',' || LOWER(provider) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Monitor proxies and login prevalence -->
parallel:
- → proxy-dns-check
- → external-ip-prevalence
join: → early-triage-agent

## proxy-dns-check
<!-- Auth process DNS to proxy domains -->
Detect DNS queries for proxy infrastructure originating specifically from authentication-related processes like lsass.exe or securityd.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, proxy_indicators=proxy_indicators)
~~~yaml
expected: DNS resolutions from sensitive processes to known proxy domains. This is
  a high-fidelity indicator of a host being used as a masked point of origin.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (LOWER(process_name) LIKE '%lsass.exe' OR LOWER(process_name) LIKE '%securityd') AND instr(',' || '{{proxy_indicators}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## external-ip-prevalence
<!-- Rare source IP logins -->
Stack-rank source IPs for successful logins to identify anomalous or new locations for authoritative users.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IPs that have successfully authenticated only a few users. Silence suggests
  all logins come from known, high-prevalence infrastructure.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING user_count <= 2 ORDER BY user_count ASC
```

## early-triage-agent
<!-- Triage early obfuscation and identity -->
```agent target=hunter
cite: required
context:
- idp-auth-scoping
- proxy-dns-check
- external-ip-prevalence
max_iterations: 4
objective: Determine if any identity provider login originated from a source IP associated
  with proxy DNS activity or is otherwise anomalous within the scope.
success_criteria: The agent identifies high-risk logins and potential beachhead hosts
  for the follow-on phase.
tools:
- endpoint
- identity
- network
```

## follow-on-parallel
<!-- Hunt follow-on access and execution -->
parallel:
- → internal-access-pivot
- → rare-local-execution
join: → phased-synthesis-agent

## internal-access-pivot
<!-- Pivot to rare admin connections -->
Identify outbound connections to internal networks on administrative ports that are rare across the fleet.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, admin_ports=admin_ports)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Internal administrative access (SSH, RDP, SMB) performed by a small number
  of hosts, suggesting lateral movement rather than routine noise.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND instr(',' || '{{admin_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 3 ORDER BY host_count ASC
```

## rare-local-execution
<!-- Rare local context execution -->
Identify process execution in a 'local' user context that is rare across the fleet, avoiding hardcoded user names.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Shell or tool execution within a local context that is unique to a few hosts.
  This matches the behavior of a user with host-scoped local activity.
prevalence:
  by: device_hostname
  key:
  - process_path
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- user_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_path, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(user_name) LIKE '%local%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path, process_cmd_line HAVING host_count <= 3
```

## phased-synthesis-agent
<!-- Synthesize full intrusion chain -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- internal-access-pivot
- rare-local-execution
max_iterations: 5
objective: Determine if the rare internal connections and local shell execution constitute
  a direct continuation of a suspect identity compromise. Specifically, verify if
  the proxy-related DNS activity and the identity provider authentication occurred
  within 60 minutes of each other.
success_criteria: The agent provides a verdict citing the timing and linkage between
  network obfuscation, authentication, and internal activity.
tools:
- endpoint
- identity
- network
```

## route-decision
<!-- Route on intrusion verdict -->
if~: "the phased-synthesis-agent confirms a malicious intrusion where proxy-related DNS activity and identity provider authentication occur within 60 minutes of each other, followed by rare internal access or local execution" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-auth-context)
else: → analyst-review

## isolate-host
<!-- Isolate suspect host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified by the triage agent. Rotate credentials for the involved identity provider account and revoke any active OAuth sessions.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the process activity and network logs for the suspect hosts. Confirm if the local user execution aligns with the timing of the identity provider sign-in. Review the EUID derivation logic to see if multiple accounts were resolved into the same malicious actor.
```
→ close-out

## close-out
<!-- Close out and reporting -->
```manual target=analyst
Document the Entity Unique IDs (EUIDs) involved across providers. Record any tuning notes regarding the baseline of internal connections or local context execution. Provide feedback on proxy domain efficacy.
```
→ end
