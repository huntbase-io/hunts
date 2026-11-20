---
analysis: A simple spray detection rule fires on volume but lacks the context of 'app-only'
  authentication transitions. This hunt specifically correlates the high-volume noise
  of AI agents with the quiet, privileged modifications they make to service principals,
  which a single rule cannot easily join across audit and sign-in surfaces.
blind_spots:
- id: limited-entra-retention
  question: whether activity occurred more than 30 days ago
  requires: Extended Entra ID logging
  risk: Standard Entra ID sign-in logs are often limited to 30 days; activity from
    early September might be unavailable if the hunt is delayed.
  stage: ai-automated-password-spraying
- id: proxy-rotation
  question: whether the adversary rotated to residential proxies for successful logons
  requires: Cross-tenant IP enrichment
  risk: If the AI framework uses the reported IP for high-volume spraying but switches
    to residential proxies for the actual application abuse, the correlation in the
    parallel step will fail.
  stage: compromised-application-abuse
coverage:
- stage: ai-automated-password-spraying
  status: covered
  steps:
  - infrastructure-scoping
  - high-volume-spraying
- stage: compromised-application-abuse
  status: covered
  steps:
  - app-credential-activity
  - triage-automated-activity
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: connectwise-supply-chain-compromise
  status: out_of_scope
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: graph-api-recon-and-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: privilege-and-group-modification
  status: out_of_scope
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: mailbox-and-file-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The use of agentic AI frameworks like ARTEX allows nation-state actors
    to compress the window between reconnaissance and privileged access to under 3
    hours; identifying the authentication lead immediately is critical to preventing
    downstream supply chain data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using agentic AI to automate high-volume password spraying
  and service principal authentication from a known infrastructure range to bypass
  interactive sign-ins.
labels:
- hunt
- attack.t1110.003
- attack.t1190
- attack.t1195
- credential access
- exfiltration
- initial access
- persistence
name: Storm-0940 AI-Accelerated Authentication
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step to narrow the focus.
    type: list[host]
  storm_ips:
    default:
    - 144.172.64.99
    description: Known Storm-0940 infrastructure IPs reported in the campaign.
    from:
      kind: article
      observed: '2026-10-21'
      ref: msrc-blog-storm-0940
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on external identity planes (Entra ID, Microsoft 365). The reporting
  devices for these authentications are typically Domain Controllers or Identity Proxies.
  Use the 'infrastructure-scoping' results to narrow the spray search.
references:
- name: Storm-0940 uses ARTEX agentic AI ConnectWise supply chain compromise
  url: https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
related:
- hunt: storm-0940-graph-api-reconnaissance
  reason: Once an application is confirmed compromised, a second hunt must examine
    the Microsoft Graph API activity for data theft and further persistence.
  relation: follows
scenario:
  stages:
  - name: AI-Automated Password Spraying
    observables:
    - IP address 144.172.64.99
    - 2,900 authentication attempts per minute
    - 151,000+ failed logon events
    - 98% lockout responses
    - Targeting Microsoft 365 and Exchange Online
    - Peak activity on October 11, 2026
    slug: ai-automated-password-spraying
    tactic: credential-access
    techniques:
    - T1110.003
  - name: ConnectWise Supply Chain Compromise
    observables:
    - ConnectWise Cloud Backup application
    - Multi-tenant application compromise
    - Stolen application credentials/identities
    slug: connectwise-supply-chain-compromise
    tactic: initial-access
    techniques:
    - T1195
  - name: Compromised Application Authentication
    observables:
    - Service principal sign-ins from 144.172.64.x IP range
    - ARTEX framework (Next.js frontend)
    - Use of stolen app credentials to bypass interactive sign-in
    - Authentication to 2,250+ tenants
    slug: compromised-application-abuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Microsoft Graph Reconnaissance and Persistence
    observables:
    - Microsoft Graph API calls
    - Listing directories, permissions, and approvals
    - Modification of OAuth application credentials
    - Adding new application owners or service principals
    - Modifying app-role assignments
    slug: graph-api-recon-and-persistence
    tactic: persistence
    techniques:
    - T1087
    - T1098
  - name: Privilege and Group Modification
    observables:
    - Changes to privileged roles
    - Modification of group memberships
    - Conditional Access policy changes
    - Identity-related directory operations
    slug: privilege-and-group-modification
    tactic: persistence
    techniques:
    - T1098
  - name: Mailbox and File Exfiltration
    observables:
    - Unusual mail or file access and downloads
    - Creation of inbox or transport rules
    - Delegated mailbox permission changes
    - Forwarding rule creation
    slug: mailbox-and-file-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: Storm-0940 used the ARTEX agentic AI framework to automate large-scale
    password spraying and a supply chain compromise of the ConnectWise multi-tenant
    application. The actor abused stolen application credentials to perform high-speed
    reconnaissance via Microsoft Graph, modify application credentials for persistence,
    and exfiltrate mailbox data from Microsoft 365 environments.
series:
  index: 1
  slug: ai-driven-large-scale-nation-state-campaign-using-artex-enables-supply-chain-compromise
  title: AI-driven, large-scale nation-state campaign using ARTEX enables supply chain
    compromise
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


# Storm-0940 AI-Accelerated Authentication

This hunt identifies automated authentication campaigns linked to Storm-0940 and the ARTEX AI framework. It focuses on the machine-speed transition from high-volume password spraying to the abuse of compromised service principal credentials. By correlating authentication volume from identity surfaces with application credential changes in cloud audit logs, the hunt identifies tenants where AI-driven agents have achieved initial access and established persistence.

## infrastructure-scoping
<!-- Identify affected reporting hosts -->
Find the reporting devices (domain controllers or gateways) that have logged activity from the known Storm-0940 IP range.

```sqlite target=identity role=scoping params=(storm_ips=storm_ips, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. These are the machines that processed the malicious
  authentication traffic and should be used to populate scope_hosts.
reads:
- device_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT DISTINCT device_hostname FROM hb_auth_signin WHERE instr(',' || '{{storm_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate spray and audit events -->
parallel:
- → high-volume-spraying
- → app-credential-activity
join: → triage-automated-activity

## high-volume-spraying
<!-- Detect machine-speed password spraying -->
Identify IPs exceeding normal human login rates, focusing on those interacting with the scoped identity infrastructure.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs with thousands of failures. Storm-0940 activity peaked at 2,900
  attempts per minute.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
- device_hostname
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT src_endpoint_ip, COUNT(*) as attempts, COUNT(DISTINCT actor_user_name) as unique_users, SUM(CASE WHEN status_id = 2 THEN 1 ELSE 0 END) as failures, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_auth_signin WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING attempts > 500 AND (failures * 1.0 / attempts) > 0.95 ORDER BY attempts DESC
```

## app-credential-activity
<!-- Application and role modifications -->
Identify changes to service principal credentials or role assignments in Entra ID that often follow a successful automated spray.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Audit logs showing credential additions or privilege escalations, particularly
  if the src_endpoint_ip matches one from the spray results.
reads:
- time
- actor_user_name
- api_operation
- target_resource_types
- resource_name
- src_endpoint_ip
- status_detail
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT time, actor_user_name, api_operation, target_resource_types, resource_name, src_endpoint_ip, status_detail FROM hb_cloud_api_activity WHERE provider = 'azure_ad' AND (LOWER(api_operation) LIKE '%credential%' OR LOWER(api_operation) LIKE '%role%' OR LOWER(api_operation) LIKE '%consent%') AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-automated-activity
<!-- Weigh automated intrusion evidence -->
```agent target=hunter
cite: required
context:
- infrastructure-scoping
- high-volume-spraying
- app-credential-activity
max_iterations: 6
objective: Characterize the authentication attempts and correlate them with any successful
  sign-ins or directory changes. Determine if the speed and pattern match an agentic
  AI framework (ARTEX) and if any applications were successfully compromised.
success_criteria: A per-host or per-tenant verdict (malicious, suspicious, benign)
  with citations for the specific spray IPs and affected service principals.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on intrusion probability -->
if~: "The triage verdict is malicious for any successful application authentication or credential modification from a suspect IP." (confidence: high, judge=hunter)
then: → revoke-app-credentials
indeterminate: → analyst-triage-task
unavailable: → analyst-triage-task (blind_spot: limited-entra-retention)
else: → close-out

## revoke-app-credentials
<!-- Revoke compromised app credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all certificates and secrets for the service principals identified by the triage agent. Rotate credentials for any affected administrative accounts.
```
→ analyst-triage-task

## analyst-triage-task
<!-- Analyst verification and scoping -->
```manual target=analyst
Review the identified successful logons and directory changes. Confirm if they match the ConnectWise advisory context. Record the object IDs of compromised apps for use in the 'Storm-0940 Graph API' hunt.
```
→ end

## close-out
<!-- Close out and monitor -->
```manual target=analyst
Log the findings. If spraying was detected but no successful logons occurred, ensure the accounts are monitored for persistent lockouts.
```
→ end
