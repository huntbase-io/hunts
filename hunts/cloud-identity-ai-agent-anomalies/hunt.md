---
analysis: A standard detection rule might alert on any Kubernetes login, but this
  hunt uses a gated flow to correlate those logins with fleet-wide prevalence and
  rare behavioral pivots in the cloud control plane.
blind_spots:
- id: limited-identity-context
  question: whether the successful login was preceded by multiple MFA fatigue or password
    spray attempts
  requires: hb_auth_signin with detailed logon types and MFA failure reasons
  risk: The lead query focuses on successful entry; the precursor brute-force activity
    may be invisible.
  stage: initial-access-social-engineering
- id: metadata-visibility
  question: whether an unmanaged cloud instance accessed the metadata service
  requires: VPC flow logs for all cloud subnets
  risk: A network pivot from a host without an agent will not appear in hb_network_connection,
    leaving a blind spot for unmanaged compute.
  stage: exploitation-public-facing-apps
coverage:
- stage: initial-access-social-engineering
  status: covered
  steps:
  - suspicious-sensitive-logins
  - evaluate-login-lead
- stage: exploitation-public-facing-apps
  status: covered
  steps:
  - suspicious-sensitive-logins
  - rare-orchestration-connections
- stage: ai-agent-discovery-c2
  status: covered
  steps:
  - agentic-api-patterns
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: unauthorized-rmm-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: credential-harvesting-lsass
  status: out_of_scope
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: data-encrypted-for-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are targeting cloud control planes and using automated
    agents to manipulate infrastructure. Identifying anomalous logins followed by
    rare management port access provides effective detection for these advanced techniques.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used social engineering or exploited public-facing remote
  services to compromise an administrative identity, then used that access to manipulate
  cloud repositories or orchestration layers via automated agents.
labels:
- hunt
- attack.t1133
- attack.t1190
- attack.t1204.002
- attack.t1003.001
- credential access
- discovery
- impact
- initial access
- persistence
name: Cloud Identity and AI Agent Anomalies
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  metadata_ip:
    default: 169.254.169.254
    description: Cloud Instance Metadata Service IP address.
    type: ip
  scope_hosts:
    default: []
    description: Paste the device_hostname values from the lead query here to narrow
      the second stage.
    type: list[host]
  sensitive_resources:
    default:
    - kubernetes
    - vpn-gateway
    - admin-console
    - azure-portal
    - aws-console
    - okta
    description: Critical resource names to monitor in sign-in logs.
    from:
      kind: manual
      observed: '2024-10-01'
      ref: architectural-critical-assets
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on administrative identities and service accounts used for automation.
  This hunt is particularly valuable in hybrid environments with high Kubernetes adoption.
references:
- name: "Cisco Talos \u2014 The Fine Art of Frustrating the Adversary"
  url: https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/
related:
- hunt: unauthorized-rmm-persistence
  reason: Persistence through RMM tools uses endpoint process and file telemetry,
    which is handled in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and Social Engineering
    observables:
    - Lures sent from expired domains
    - Communication with fictional employee profiles
    - Urgency-based messaging (unpaid taxes, injured relatives)
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1204.002
  - name: Exploitation of Public-Facing Apps
    observables:
    - Unauthorized sign-ins to critical servers
    - Connections to Kubernetes API servers
    - Access to exposed VPN gateways
    slug: exploitation-public-facing-apps
    tactic: initial-access
    techniques:
    - T1190
    - T1133
  - name: Persistence via RMM Software
    observables:
    - Zoho Unattended Agent
    - AnyDesk
    - ScreenConnect
    - Atera
    - Unauthorized remote technician sessions
    slug: unauthorized-rmm-persistence
    tactic: persistence
    techniques:
    - T1133
  - name: LSASS Credential Access
    observables:
    - Mimikatz
    - comsvcs.dll
    - procdump -ma lsass.exe
    - Direct access to LSASS memory
    slug: credential-harvesting-lsass
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Agentic Malactivity and Discovery
    observables:
    - Unexpected writes to package registries
    - Repository creation and dataset commits
    - API calls to Kubernetes interfaces
    - DNS-over-HTTPS relays usage
    - Access to cloud metadata services
    slug: ai-agent-discovery-c2
    tactic: discovery
    techniques:
    - T1190
  - name: Ransomware Encryption
    observables:
    - Execution of ransomware encryptor
    - High-volume file modification / renaming
    slug: data-encrypted-for-impact
    tactic: impact
    techniques:
    - T1486
  summary: This scenario outlines the diverse set of adversary behaviors described
    by Cisco Talos, moving from initial access via social engineering or service exploitation
    to persistence using legitimate remote-management tools. It concludes with credential
    harvesting from LSASS memory, data encryption for impact, and emerging malicious
    activity from misconfigured AI agents targeting cloud infrastructure.
series:
  index: 1
  slug: the-fine-art-of-frustrating-the-adversary
  title: The Fine Art of Frustrating the Adversary
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Cloud Identity and AI Agent Anomalies

This hunt identifies unauthorized access to critical cloud management interfaces and orchestration systems. It uses a gated flow, starting with a lightweight audit of logins to sensitive resources like Kubernetes API servers or VPN gateways. If the lead is suspicious, the hunt expands to examine rare cloud API operations and rare network connections to orchestration management ports, stack-counting these behaviors to separate manual or agentic intrusions from fleet-wide administrative noise.

## suspicious-sensitive-logins
<!-- Suspicious logins to sensitive interfaces -->
Identify successful sign-ins to critical services that manage the cloud or network perimeter as a lead for further investigation.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, sensitive_resources=sensitive_resources)
~~~yaml
expected: Login events from unusual IPs or countries targeting sensitive infrastructure;
  the presence of these rows triggers the next read.
reads:
- actor_user_name
- device_hostname
- dst_endpoint_name
- mfa
- src_endpoint_ip
- src_location_country
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, dst_endpoint_name, src_endpoint_ip, src_location_country, mfa, device_hostname, time FROM hb_auth_signin WHERE status_id = 1 AND (instr(',' || '{{sensitive_resources}}' || ',', ',' || LOWER(dst_endpoint_name) || ',') > 0 OR LOWER(dst_endpoint_name) LIKE '%kube%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-login-lead
<!-- Evaluate sign-in lead -->
```agent target=hunter
cite: required
context:
- suspicious-sensitive-logins
max_iterations: 3
objective: Determine if any sign-in to sensitive infrastructure shown in the lead
  query is anomalous based on source IP, geography, or lack of MFA.
success_criteria: A verdict of suspicious or benign for each identified session.
tools:
- endpoint
- identity
- network
```

## auth-gate
<!-- Gate: Proceed to behavioral analysis? -->
if~: "the login-lead verdict is suspicious for at least one session" (confidence: high, judge=hunter)
then: → behavioral-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-identity-context)
else: → close-out

## behavioral-fan-out
<!-- Fan-out to behavioral surfaces -->
parallel:
- → agentic-api-patterns
- → rare-orchestration-connections
join: → triage-synthesis

## agentic-api-patterns
<!-- Agentic Cloud API and Repository activity -->
Identify repository creation, EKS manipulation, or unusual data staging operations consistent with automated agents.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Unexpected writes to package registries or repository creation performed
  by the identities flagged in the lead query.
reads:
- actor_user_name
- api_operation
- api_service_name
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, api_operation, api_service_name, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%repository%' OR LOWER(api_operation) LIKE '%putbucket%' OR LOWER(api_service_name) LIKE '%eks%' OR LOWER(api_service_name) LIKE '%kubernetes%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-orchestration-connections
<!-- Rare orchestration and metadata connections -->
Stack-count network connections to management ports and the metadata service to find rare access from scoped hosts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, metadata_ip=metadata_ip, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A connection to a Kubernetes management port or metadata service appearing
  on only one or two hosts, indicating non-standard activity.
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
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_ip = '{{metadata_ip}}' OR dst_endpoint_port IN (6443, 8443, 10250)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2 ORDER BY host_count ASC
```

## triage-synthesis
<!-- Synthesize and Triage -->
```agent target=hunter
cite: required
context:
- evaluate-login-lead
- agentic-api-patterns
- rare-orchestration-connections
max_iterations: 6
objective: Assess whether the suspicious login from Step 1 is corroborated by the
  rare cloud API activity or orchestration network pivots found in the fan-out queries.
success_criteria: A malicious | suspicious | benign verdict per host or identity.
tools:
- endpoint
- identity
- network
```

## final-route
<!-- Route on final triage -->
if~: "the triage-synthesis verdict is malicious for at least one identity" (confidence: high, judge=hunter)
then: → revoke-and-isolate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: metadata-visibility)
else: → close-out

## revoke-and-isolate
<!-- Revoke credentials and isolate -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identified user account, rotate any long-lived cloud keys (AKIA/ASIA), and disable the account in the primary identity provider.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Verify the cloud API operations and rare network connections. If the activity was a legitimate, approved automated process, tune the sensitive resource list.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hunt results. Document any service accounts found accessing orchestration layers for inclusion in future whitelists.
```
→ end
