---
analysis: A static detection rule would only trigger on a known Tor IP list. This
  hunt baselines administrative behavior to find rare IPs first, then pivots into
  DNS activity from related endpoints and identity security posture to provide a contextual
  risk score that reduces false positives from authorized remote administration.
blind_spots:
- id: no-cloud-audit-logs
  question: What discovery operations (ListBuckets, ListRoles) did the identity perform?
  requires: Normalized hb_cloud_audit surface
  risk: We can identify the login anomaly but not the subsequent actions taken within
    the cloud console.
  stage: cloud-resource-discovery
- id: no-ip-reputation-data
  question: Does the source IP belong to a known Tor exit node or VPN provider?
  requires: External IP reputation feed
  risk: The hunt must rely on behavioral rarity and DNS queries from managed hosts,
    potentially missing Tor logins from unmanaged devices.
  stage: multi-hop-proxy-obfuscation
coverage:
- stage: cloud-identity-authentication
  status: covered
  steps:
  - rare-admin-signins-lead
  - evaluate-risk-of-lead
  - identity-posture-check
- blind_spot: no-cloud-audit-logs
  reason: Cloud discovery API calls (e.g., ListBuckets) are not recorded in the provided
    endpoint or auth surfaces; they require CloudTrail-style logs.
  stage: cloud-resource-discovery
  status: not_visible
- stage: multi-hop-proxy-obfuscation
  status: covered
  steps:
  - network-obfuscation-dns
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: exploit-public-application
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: client-side-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromise of administrative cloud identities allows for full environment
    takeover. Identifying anomalous behavioral clusters (rare IP + proxy usage) is
    an essential control where MFA may be bypassed or not enforced.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised an administrative cloud identity and is accessing
  the environment through multi-hop proxies or Tor to perform discovery and initial
  access.
labels:
- hunt
- attack.t1090.003
- attack.t1190
- attack.t1078.004
name: Anomalous Cloud Identity Behavior
parameters:
  admin_patterns:
    default:
    - awsreservedsso_administratoraccess_
    - admin
    - superuser
    - root
    description: Naming patterns associated with administrative roles.
    from:
      kind: article
      observed: '2026-09-14'
      ref: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of activity to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to limit the DNS search to; leave empty to scan the entire
      estate.
    type: list[host]
  tor_domains:
    default:
    - torproject.org
    - check.torproject.org
    - exitlist.torproject.org
    description: Domains linked to Tor network infrastructure.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: T1090.003
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on AWS and Azure cloud tenants. Prioritize accounts that exhibit
  'ConsoleLogin' activity without MFA from non-corporate IP ranges.
references:
- name: "Unit 42 \u2014 Unmasking Cloud Identities: From Behavioral Clustering to\
    \ Automated Detection"
  url: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
related:
- hunt: cloud-api-discovery-clustering
  reason: This hunt establishes the login anomaly; a follow-on hunt should examine
    clustered API discovery patterns once cloud audit logs are available.
  relation: follows
- hunt: public-app-exploitation-cloud-identity-drift
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Application
    observables:
    - Inbound exploitation attempts against internet-facing web servers
    - Unauthorized HTTP POST requests to vulnerable endpoints
    slug: exploit-public-application
    tactic: initial-access
    techniques:
    - T1190
  - name: User Execution of Malicious File
    observables:
    - Execution of downloaded suspicious documents or binaries
    - Process spawning from browser or email client
    - Malicious file creation in temporary directories
    slug: client-side-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Cloud Identity Authentication
    observables:
    - ConsoleLogin events
    - GetSigninToken activity
    - Identity naming patterns containing 'admin'
    - AWSReservedSSO_AdministratorAccess_ prefix usage
    slug: cloud-identity-authentication
    tactic: initial-access
  - name: Cloud Resource Discovery
    observables:
    - ListBuckets
    - ListRoles
    - ListNotificationHubs
    - GetCostAndUsage
    - GetCostForecast
    slug: cloud-resource-discovery
    tactic: discovery
  - name: Multi-hop Proxy Obfuscation
    observables:
    - Sign-in activity from known Tor exit nodes
    - Network connections to multi-hop VPS or ORB networks
    - Anomalous source IP addresses for administrative sessions
    slug: multi-hop-proxy-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Attackers leverage exploited applications or social engineering to gain
    access to over-privileged cloud identities, which are then used to perform resource
    enumeration and discovery within AWS Management Console. To evade detection, actors
    masquerade using benign permission profiles and mask their activity source through
    multi-hop proxies or Tor, requiring behavioral clustering to distinguish malicious
    reconnaissance from legitimate administrative activity.
series:
  index: 2
  slug: unmasking-cloud-identities-from-behavioral-clustering-to-automated-detection
  title: 'Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection'
  total: 2
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
tlp: clear
type: investigation
---


# Anomalous Cloud Identity Behavior

This hunt implements behavioral clustering logic to identify administrative identities operating outside of their normal baseline. It starts by identifying privileged sign-ins from rare source IP addresses. A gated evaluation determines if these logins warrant deeper investigation. If they do, the hunt fans out to look for evidence of network obfuscation, such as Tor DNS resolutions, and verifies the identity's security posture. An agent then synthesizes these results to detect credential abuse masked by multi-hop proxies.

## rare-admin-signins-lead
<!-- Identify rare administrative sign-ins -->
Establish a lead by finding privileged logins from source IPs that have appeared fewer than five times in the lookback window.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, admin_patterns=admin_patterns)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rows showing a privileged user logging into a service from an IP they do
  not typically use. Silence proves no rare administrative logins were recorded for
  these patterns.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- mfa
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, mfa, COUNT(*) AS login_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE activity_id = 1 AND status_id = 1 AND (instr(',' || '{{admin_patterns}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 OR LOWER(actor_user_name) LIKE '%admin%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name, mfa HAVING login_count < 5 ORDER BY login_count ASC
```

## evaluate-risk-of-lead
<!-- Evaluate risk of the sign-in lead -->
```agent target=hunter
cite: required
context:
- rare-admin-signins-lead
max_iterations: 3
objective: Review the rare sign-ins and identify users who logged in from rare IPs
  without MFA, or users whose names strongly match the sensitive administrative patterns.
success_criteria: A clear list of suspicious users and source IPs that require further
  investigation.
tools:
- endpoint
- identity
```

## gate-decision
<!-- Gate deeper analysis -->
if~: "the evaluate-risk-of-lead agent identifies at least one high-risk administrative sign-in from a rare IP address" (confidence: high, judge=hunter)
then: → corroborate-anomalies
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-ip-reputation-data)
else: → close-out

## corroborate-anomalies
<!-- Corroborate anomalies -->
parallel:
- → network-obfuscation-dns
- → identity-posture-check
join: → triage-verdict

## network-obfuscation-dns
<!-- Network obfuscation via Tor DNS -->
Search for DNS lookups to Tor-related domains from the endpoints associated with the suspicious logins.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, tor_domains=tor_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Rows mapping a host or user to Tor domain resolutions. Any hit confirms
  the use of anonymity software.
reads:
- device_hostname
- query_hostname
- actor_user_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, actor_user_name, src_endpoint_ip, time FROM hb_dns_activity WHERE (instr(',' || '{{tor_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.onion%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## identity-posture-check
<!-- Identity security posture -->
Verify the current status and MFA configuration of identities identified in the lead.

```sqlite target=identity role=baseline
~~~yaml
expected: Identity records showing users without MFA enabled or in a non-active status.
  This context increases the likelihood that a login anomaly is malicious.
reads:
- name
- email
- mfa_enabled
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT name, email, provider, mfa_enabled, status, created_at FROM hb_users WHERE status != 'active' OR mfa_enabled = 'false'
```

## triage-verdict
<!-- Triage the behavioral anomalies -->
```agent target=hunter
cite: required
context:
- evaluate-risk-of-lead
- network-obfuscation-dns
- identity-posture-check
max_iterations: 5
objective: Determine if the anomalous administrative sign-ins indicate account compromise
  by correlating the rare IP results from the lead with any Tor DNS activity or weak
  identity posture found in the fan-out.
success_criteria: A per-host and per-user verdict citing specific DNS queries or login
  timestamps.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route based on triage -->
if~: "the triage-verdict agent identifies at least one administrative user as malicious due to the intersection of rare IPs and Tor activity" (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-audit-logs)
else: → analyst-review

## revoke-sessions
<!-- Revoke identity sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identified administrative users and force an immediate password reset and MFA rotation.
```
→ analyst-review

## analyst-review
<!-- Post-incident cloud audit -->
```manual target=analyst
Examine native cloud audit logs (e.g., AWS CloudTrail) for the users identified in this hunt. Search for discovery operations like ListBuckets, ListRoles, or GetCostAndUsage. Verify if the rare source IP belongs to a known administrative jump box or a public proxy/Tor node.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings and update the admin_patterns list if legitimate administrative accounts were flagged. If any Tor activity was benign (e.g., research), document the exemption.
```
→ end
