---
analysis: 'A single detection rule triggers on ''s3 ls''. This hunt asks: is the identity
  an admin? Is the source IP rare? Is there concurrent proxy activity? It weights
  these three surfaces to identify functional role masquerading.'
blind_spots:
- id: no-cloud-audit-integration
  question: Are we seeing authentication events from regions we do not actively monitor?
  requires: Direct CloudTrail/Audit integration for every cloud region
  risk: Adversaries often use unmonitored regions for stealthy discovery and C2 infrastructure.
  stage: cloud-identity-authentication
- id: unmanaged-endpoint-cloud-access
  question: Is cloud discovery occurring from a non-managed/shadow IT device?
  requires: Endpoint agent coverage on all potential management hosts
  risk: A host without an agent running CLI commands won't appear in hb_process_activity,
    leaving only the cloud-native auth signal.
  stage: cloud-discovery-enumeration
coverage:
- stage: cloud-identity-authentication
  status: covered
  steps:
  - admin-console-logins
  - rare-auth-source-ips
- stage: cloud-discovery-enumeration
  status: covered
  steps:
  - cloud-discovery-commands
- stage: c2-network-obfuscation
  status: covered
  steps:
  - proxy-network-activity
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: initial-access-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: execution-malicious-file
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Over-privileged cloud identities represent a significant blast-radius
    risk. Validating that identities with administrative labels are not showing anomalous
    behavioral footprints (discovery + proxy C2) is a business-critical audit requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using over-privileged cloud identities masquerading as
  administrative roles to perform environment discovery while routing traffic through
  multi-hop proxies to evade IP-based detection.
labels:
- hunt
- attack.t1078.004
- attack.t1036
- attack.t1580
- attack.t1087.004
- attack.t1090.003
name: Cloud Identity Masquerading and Obfuscated C2
parameters:
  discovery_keywords:
    default:
    - list-roles
    - list-buckets
    - get-cost-and-usage
    - get-cost-forecast
    - list-notification-hubs
    description: API operations associated with cloud discovery.
    from:
      kind: article
      observed: '2024-09-14'
      ref: Unit 42
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-09-14'
      ref: default
    type: number
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: We focus on hosts with cloud management software (AWS CLI, kubectl) as
  they are the primary conduits for identity-based discovery. The time window is critical
  as behavioral clusters emerge over days.
references:
- name: "Unit 42 \u2014 Unmasking Cloud Identities: From Behavioral Clustering to\
    \ Automated Detection"
  url: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
related:
- hunt: aws-imds-abuse-detection
  reason: Abuse of IMDS for token theft is a related mechanism but focuses on instance
    metadata, not user-identity clustering.
  relation: out-of-scope-alternative
- hunt: initial-access-execution-exposed-writable-paths
  relation: follows
scenario:
  stages:
  - name: Exploit Public-Facing Application
    observables:
    - exploited web servers
    - vulnerable internet-facing databases
    - open sockets on management protocols
    - misconfigured cloud assets
    slug: initial-access-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious File Execution
    observables:
    - execution of .doc, .exe, .lnk, .iso, or .scr files
    - social engineering for code execution
    - launch of malicious payloads on endpoint
    slug: execution-malicious-file
    tactic: execution
    techniques:
    - T1204.002
  - name: Cloud Authentication and Masquerading
    observables:
    - ConsoleLogin events
    - GetSigninToken requests
    - identities with 'admin' substring in name
    - AWSReservedSSO_AdministratorAccess_ prefix usage
    - login from anomalous source IPs
    slug: cloud-identity-authentication
    tactic: initial-access
    techniques:
    - T1078.004
    - T1036
  - name: Cloud Resource Discovery
    observables:
    - ListBuckets API calls
    - ListRoles API calls
    - GetCostAndUsage
    - GetCostForecast
    - ListNotificationHubs
    - aws s3 ls command execution
    - aws iam list-roles command execution
    slug: cloud-discovery-enumeration
    tactic: discovery
    techniques:
    - T1580
    - T1087.004
  - name: Multi-hop Proxy Obfuscation
    observables:
    - traffic to Tor exit nodes
    - DNS queries for .onion domains
    - connections to ORB (Operational Relay Box) networks
    - VPS-based proxy chains
    slug: c2-network-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Attackers gain initial access by exploiting vulnerabilities in public-facing
    applications or by tricking users into executing malicious files on endpoints.
    Once inside, they leverage over-privileged cloud identities to perform resource
    discovery while masquerading as legitimate administrative users. The intrusion
    is further concealed using multi-hop proxies and Tor to obfuscate the origin of
    their cloud API activity.
series:
  index: 2
  slug: unmasking-cloud-identities-from-behavioral-clustering-to-automated-detection
  title: 'Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection'
  total: 2
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
tlp: clear
type: investigation
---


# Cloud Identity Masquerading and Obfuscated C2

This hunt identifies the behavioral markers of cloud identity abuse by clustering authentication events, resource discovery patterns, and network obfuscation. We begin by scoping the estate to hosts with cloud management tools, then identify administrative 'ConsoleLogin' events from anomalous sources. We corroborate this by searching for common discovery commands (ListBuckets, ListRoles) and network evidence of multi-hop proxy usage like Tor, mapping functional identity roles rather than just static indicators.

## scoping-cloud-hosts
<!-- Scope to Cloud Management Hosts -->
Find hosts that manage cloud infrastructure or run containerized workloads.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely to interact with cloud APIs. Silence means no such
  software is inventoried, which narrows the hunt to cloud-native actors not observed
  on endpoints.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%aws-cli%' OR LOWER(package_name) LIKE '%kubectl%' OR LOWER(package_name) LIKE '%amazon-ssm-agent%' OR LOWER(package_name) LIKE '%kubelet%')
```

## admin-console-logins
<!-- Administrative Console Sign-ins -->
Identify logins to the AWS console using identities with 'admin' substrings or SSO administrator roles.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows showing privileged identities logging into the management console.
  This is the primary behavioral marker of human or masqueraded human activity.
reads:
- actor_user_name
- src_endpoint_ip
- provider
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT actor_user_name, src_endpoint_ip, provider, auth_protocol, time FROM hb_auth_signin WHERE provider = 'aws' AND (activity_id = 1 OR activity_name = 'ConsoleLogin') AND (LOWER(actor_user_name) LIKE '%admin%' OR LOWER(actor_user_name) LIKE '%awsreservedss%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-identity-behavior
<!-- Corroborate on Multiple Surfaces -->
parallel:
- → cloud-discovery-commands
- → rare-auth-source-ips
- → proxy-network-activity
join: → triage-cloud-abuse

## cloud-discovery-commands
<!-- Cloud Resource Discovery Behavior -->
Find process command lines matching the discovery operations identified in the research.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and users executing discovery commands. If these correlate
  with 'admin' console logins from anomalous IPs, the risk is critical.
reads:
- device_hostname
- user_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, user_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%s3 %' OR LOWER(process_cmd_line) LIKE '%iam %' OR LOWER(process_cmd_line) LIKE '%kubectl %') AND (LOWER(process_cmd_line) LIKE '%ls%' OR LOWER(process_cmd_line) LIKE '%list-%' OR LOWER(process_cmd_line) LIKE '%get-cost%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-auth-source-ips
<!-- Rare AWS Auth Source IPs -->
Identify administrative logins from source IPs that are rare across the fleet.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IP addresses used sparingly for cloud authentication, suggesting a VPN,
  VPS, or proxy exit point.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE provider = 'aws' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING login_count <= 3 ORDER BY login_count ASC
```

## proxy-network-activity
<!-- Evidence of Multi-hop Proxy C2 -->
Find network evidence of proxying, such as Tor or known onion-routing behavior, corroborating the identity abuse.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Any DNS request for .onion domains or Tor infrastructure. While some existing
  rules cover this, this step provides the C2 context for the specific identities
  found earlier.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%.torproject.org%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-cloud-abuse
<!-- Weigh Cloud Identity Abuse Evidence -->
```agent target=hunter
cite: required
context:
- admin-console-logins
- cloud-discovery-commands
- rare-auth-source-ips
- proxy-network-activity
max_iterations: 4
objective: Determine if any identities with 'admin' names are showing anomalous login
  locations followed by cloud discovery or proxy-routing behavior.
success_criteria: A verdict of malicious | suspicious | benign per host/identity,
  citing the specific rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host or identity" (confidence: high, judge=hunter)
then: → isolate-cloud-identity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-audit-integration)
else: → close-out

## isolate-cloud-identity
<!-- Isolate Cloud Identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identity and apply a temporary 'DenyAll' policy in the cloud provider.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Verification -->
```manual target=analyst
Examine the cited rows. Verify if the rare source IPs belong to a known proxy network. Check if the 'admin' naming is consistent with legitimate internal patterns or if it appears to be a masquerading attempt.
```
→ end

## close-out
<!-- Close and Record Negative Result -->
```manual target=analyst
Document the identities and IPs examined. Note any over-privileged roles found for cleanup, even if they were benign.
```
→ end
