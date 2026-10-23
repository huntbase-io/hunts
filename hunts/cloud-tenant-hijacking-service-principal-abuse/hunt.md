---
analysis: A standard detection rule can flag the PnP Management Shell, but this hunt
  correlates proxy-based sign-in anomalies, application-level authentication flows,
  and the high-volume manipulation of accounts by new principals to confirm a systematic
  takeover that a single-event rule would miss.
blind_spots:
- id: cloud-audit-retention-limit
  question: whether the initial app secret was stolen months before the manipulation
    began
  requires: hb_cloud_api_activity with retention exceeding 90 days
  risk: The initial takeover event may be outside the current telemetry window, leaving
    only the later-stage manipulation visible.
  stage: persistence-account-manipulation
- id: app-secret-visibility
  question: which specific secret for a multi-secret app was used
  requires: The specific client secret ID used in hb_auth_signin
  risk: Without the secret ID, an analyst cannot confirm if a legitimate secret was
    rotated or a stolen one was used until the app is audited.
  stage: initial-access-app-only-auth
coverage:
- stage: reconnaissance-automated-cloud-profiling
  status: covered
  steps:
  - proxy-signins-m365
- stage: initial-access-app-only-auth
  status: covered
  steps:
  - app-only-auth-flow
- stage: persistence-account-manipulation
  status: covered
  steps:
  - rare-admin-operations
- stage: privilege-escalation-graph-abuse
  status: covered
  steps:
  - graph-privesc-pnp
- reason: The Graph escalation to AppCatalog and SharePoint control enables the bulk
    hosting abuse described in the research.
  stage: collection-resource-hosting-abuse
  status: covered
  steps:
  - graph-privesc-pnp
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: command-and-control-dns-routing
  status: out_of_scope
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: exfiltration-interactive-credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Hijacked cloud environments are the primary infrastructure for global
    phishing campaigns; a single compromised tenant can be used to send millions of
    phishing emails, causing significant reputational and financial damage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses stolen application secrets for application-only authentication
  to hijack M365 tenants, subsequently escalating privileges via the Graph API to
  host phishing infrastructure on SharePoint and OneDrive.
labels:
- hunt
- attack.t1078.004
- attack.t1098.003
- attack.t1090.003
- attack.t1560
- attack.t1098
- collection
- command and control
- exfiltration
- initial access
- persistence
- privilege escalation
- reconnaissance
name: Cloud Tenant Hijacking and Service Principal Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Target cloud account UIDs or actor domains; leave empty for all.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on tenants with education (.edu) or non-profit (.org) identifiers,
  as these are specifically marketed in the YAM Store ecosystem. Look for activity
  originating from known proxy exit nodes.
references:
- name: "Microsoft \u2014 The hidden network: Inside the phishing infrastructure ecosystem\
    \ powering global cybercrime"
  url: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/
related:
- hunt: phishing-kit-interactive-harvesting
  reason: This hunt focuses on the supply-side tenant hijacking; the actual interactive
    credential harvesting occurs on the downstream phishing sites.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Automated Cloud Tenant Reconnaissance
    observables:
    - Flask-based reconnaissance tooling
    - Tor infrastructure for anonymity
    - Profiling of M365 tenant enrollment opportunities
    - Discovery of Azure cloud information
    slug: reconnaissance-automated-cloud-profiling
    tactic: reconnaissance
    techniques:
    - T1090.003
    - T1595
  - name: Application-Level Environment Takeover
    observables:
    - Application-only authentication flows
    - Usage of stolen client secrets
    - PHP, Java/Spring, and Cloudflare Workers admin panels
    - Client secret-based directory control
    slug: initial-access-app-only-auth
    tactic: initial-access
    techniques:
    - T1078.004
  - name: Silent Password Resets and License Assignment
    observables:
    - Silent password resets (without force-change requirement)
    - Assignment of education licenses
    - Granting of privileged account attributes
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1098
  - name: Graph API Privilege Escalation
    observables:
    - Self-provisioning of PnP Management Shell service principal
    - Granting AppCatalog.ReadWrite.All permission
    - Broad Microsoft Graph permissions grant
    - Full control over SharePoint API
    slug: privilege-escalation-graph-abuse
    tactic: privilege-escalation
    techniques:
    - T1098.003
  - name: SharePoint and OneDrive Storage Abuse
    observables:
    - Abuse of SharePoint as bulk hosting platform
    - Abuse of OneDrive for phishing content hosting
    - Conversion of hijacked storage into sellable products
    slug: collection-resource-hosting-abuse
    tactic: collection
    techniques:
    - T1560
  - name: DNS Management and Domain Routing
    observables:
    - Custom DNS management platform
    - Cloudflare domain-routing configurations
    - jewishchoice.org
    - AI-generated nonprofit web presence
    slug: command-and-control-dns-routing
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1568
  - name: Real-time Phishing and Exfiltration
    observables:
    - WebSocket connections for real-time victim interaction
    - Telegram bot tokens and chat IDs for exfiltration
    - Iron Man System phishing kit
    - Credential harvesting (usernames, passwords, credit card info)
    slug: exfiltration-interactive-credential-harvesting
    tactic: exfiltration
    techniques:
    - T1566
    - T1041
  summary: Storm-3119 (YAM Store) functions as an infrastructure broker that hijacks
    Microsoft 365 and Azure environments through automated reconnaissance and application-level
    credential abuse. These compromised environments and PaaS phishing kits (Storm-2990)
    are then used by downstream actors to conduct large-scale credential and financial
    theft, leveraging real-time victim interaction via WebSockets and Telegram.
series:
  index: 1
  slug: the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime
  title: 'The hidden network: Inside the phishing infrastructure ecosystem powering
    global cybercrime'
  total: 2
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
tlp: clear
type: investigation
---


# Cloud Tenant Hijacking and Service Principal Abuse

This hunt identifies the lifecycle of cloud tenant hijacking as observed in the Storm-3119 ecosystem. It begins by identifying anomalous application-level authentication flows and sign-ins from proxy infrastructure (T1090.003). It then follows the chain to find privilege escalation through the self-provisioning of the PnP Management Shell and the abuse of sensitive directory permissions like AppCatalog.ReadWrite.All (T1098.003). By correlating initial access with follow-on resource manipulation, the hunt distinguishes between routine automation and the systematic hijacking of organizational storage for global phishing operations.

## identify-active-tenants
<!-- Identify active M365 tenants -->
Find the M365 tenant IDs currently active in the API logs to narrow the investigation.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of cloud account UIDs representing active tenants. Silence suggests
  no M365 activity.
reads:
- api_service_name
- cloud_account_uid
- provider
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT DISTINCT cloud_account_uid, api_service_name FROM hb_cloud_api_activity WHERE provider = 'm365' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-access-discovery
<!-- Discover anomalous access -->
parallel:
- → proxy-signins-m365
- → app-only-auth-flow
join: → early-takeover-assessment

## proxy-signins-m365
<!-- Proxy and Anonymized sign-ins -->
Identify sign-ins coming from known proxies or anonymizing infrastructure.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Sign-in events flagged as originating from proxy infrastructure. Silence
  proves no such logins were detected.
reads:
- actor_user_domain
- actor_user_name
- is_proxy
- provider
- src_endpoint_ip
- src_location_country
- time
- user_agent
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_domain, actor_user_name, src_endpoint_ip, user_agent, src_location_country, time FROM hb_auth_signin WHERE provider = 'm365' AND is_proxy = 'true' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || actor_user_domain || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## app-only-auth-flow
<!-- Application-only authentication flows -->
Identify logins using application secrets rather than user sessions, a prerequisite for the Storm-3119 takeover pipeline.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful application-only logins. Benign service accounts will appear,
  but new or unexpected principals are suspicious.
reads:
- activity_id
- actor_user_domain
- actor_user_name
- auth_protocol
- provider
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_domain, actor_user_name, auth_protocol, src_endpoint_ip, time FROM hb_auth_signin WHERE provider = 'm365' AND activity_id = 1 AND (LOWER(auth_protocol) LIKE '%secret%' OR LOWER(auth_protocol) LIKE '%client_credentials%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || actor_user_domain || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-takeover-assessment
<!-- Assess early access indicators -->
```agent target=hunter
cite: required
context:
- identify-active-tenants
- proxy-signins-m365
- app-only-auth-flow
max_iterations: 3
objective: Identify service principals or accounts that authenticated via proxy infrastructure
  using application-only flows.
success_criteria: A list of suspected compromised service principals for follow-on
  analysis.
tools:
- endpoint
- identity
```

## abuse-and-persistence-discovery
<!-- Discover resource abuse and persistence -->
parallel:
- → graph-privesc-pnp
- → rare-admin-operations
join: → full-chain-analysis

## graph-privesc-pnp
<!-- Graph escalation and PnP Shell -->
Find the specific privilege escalation tradecraft: self-provisioning the PnP Management Shell and granting sensitive directory permissions.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Granting of sensitive AppCatalog or Graph roles to the PnP Shell or new
  apps. Silence suggests no documented privesc attempt.
reads:
- actor_user_name
- api_operation
- cloud_account_uid
- provider
- resource_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT api_operation, resource_name, actor_user_name, cloud_account_uid, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (LOWER(resource_name) LIKE '%pnp management shell%' OR LOWER(api_operation) LIKE '%addapproleassignment%' OR LOWER(resource_name) LIKE '%appcatalog%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || cloud_account_uid || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-admin-operations
<!-- Rare silent password and license changes -->
Identify high-volume manipulation of accounts and licenses by service principals that are new to the environment.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A service principal performing password resets or license assignments that
  is new or rare in the environment.
prevalence:
  by: cloud_account_uid
  key:
  - actor_user_name
  - api_operation
  rare_below: 2
reads:
- actor_user_name
- api_operation
- cloud_account_uid
- provider
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, api_operation, MIN(time) AS first_seen, COUNT(DISTINCT cloud_account_uid) AS tenant_count, COUNT(*) AS total_ops FROM hb_cloud_api_activity WHERE provider = 'm365' AND (LOWER(api_operation) LIKE '%resetpassword%' OR LOWER(api_operation) LIKE '%assignlicense%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation HAVING tenant_count <= 1 ORDER BY total_ops DESC
```

## full-chain-analysis
<!-- Analyze full attack chain -->
```agent target=hunter
cite: required
context:
- early-takeover-assessment
- graph-privesc-pnp
- rare-admin-operations
max_iterations: 5
objective: Determine if the service principals identified in the first stage have
  proceeded to escalate privileges and perform bulk account or license changes.
success_criteria: A final verdict citing the specific actor, the authentication anomalies,
  and the administrative abuse.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on takeover verdict -->
if~: "the full-chain-analysis verdict is malicious for an identified service principal or tenant" (confidence: high, judge=hunter)
then: → revoke-app-access
indeterminate: → analyst-remediation-task
unavailable: → analyst-remediation-task (blind_spot: cloud-audit-retention-limit)
else: → close-out-task

## revoke-app-access
<!-- Revoke App Access -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the compromised service principal in Entra ID and rotate or revoke its client secrets.
```
→ analyst-remediation-task

## analyst-remediation-task
<!-- Remediate and Audit -->
```manual target=analyst
Verify any accounts that underwent silent password resets. Audit SharePoint and OneDrive for unexpected public hosting or bulk phishing templates.
```
→ close-out-task

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document the identified service principals and IP addresses. Record a tuning note for any high-volume administrative service accounts that appeared in the prevalence count.
```
→ end
