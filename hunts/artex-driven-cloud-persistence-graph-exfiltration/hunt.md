---
analysis: A single rule on credential addition is often too noisy for dynamic environments.
  This hunt correlates that action with machine-speed API call volumes and rare source
  IP reputation to confirm a high-confidence automated intrusion.
blind_spots:
- id: no-graph-data-events
  question: whether specific mail items were accessed
  requires: Microsoft Purview Audit (Premium)
  risk: Standard audit logs do not capture 'MailItemsAccessed' events, which are the
    primary indicator of data theft via Graph API.
  stage: mailbox-and-file-exfiltration
- id: limited-ip-reputation
  question: whether an IP is truly rare for a specific service principal
  requires: historical src_endpoint_ip baseline
  risk: Legitimate vendor infrastructure may use many IPs; without a long-term baseline,
    AI-driven attacks may be misidentified as normal vendor traffic.
  stage: graph-api-recon-and-persistence
coverage:
- stage: graph-api-recon-and-persistence
  status: covered
  steps:
  - directory-persistence
  - api-volume
- stage: privilege-and-group-modification
  status: covered
  steps:
  - directory-persistence
- stage: mailbox-and-file-exfiltration
  status: covered
  steps:
  - api-volume
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: ai-automated-password-spraying
  status: out_of_scope
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: connectwise-supply-chain-compromise
  status: out_of_scope
- reason: Belongs to another part of the 'AI-driven, large-scale nation-state campaign
    using ARTEX enables supply chain compromise' series.
  stage: compromised-application-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries using ARTEX can move from initial access to full tenant
    persistence in under 3 hours; identifying machine-speed directory changes and
    Graph abuse is essential for timely eviction.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using agentic AI to perform high-velocity reconnaissance,
  credential additions, and data exfiltration within our Microsoft 365 environment
  after compromising a trusted application.
labels:
- hunt
- attack.t1087
- attack.t1098
- attack.t1041
- attack.t1195
- credential access
- exfiltration
- initial access
- persistence
name: ARTEX-Driven Cloud Persistence and Graph Exfiltration
parameters:
  actor_ips:
    default:
    - 144.172.64.99
    description: Known infrastructure used by Storm-0940 agents.
    from:
      kind: article
      observed: '2026-10-21'
      ref: msrc-blog-storm-0940
    type: list[ip]
  connectwise_app_ids:
    default:
    - 00000000-0000-0000-0000-000000000000
    description: Application IDs for the affected ConnectWise applications; refresh
      from advisory.
    from:
      kind: advisory
      observed: '2026-10-16'
      ref: connectwise-october-2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-21'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the directory persistence search.
    from:
      kind: manual
      observed: '2024-10-21'
      ref: analyst-scoping
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Narrow focus to Microsoft 365 tenants with active ConnectWise integrations.
  The window of interest begins on October 10, 2026, when Storm-0940 infrastructure
  was first observed conducting high-volume campaigns.
references:
- name: Storm-0940 uses ARTEX agentic AI in ConnectWise supply chain compromise
  url: https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
related:
- hunt: ai-automated-password-spraying
  reason: This hunt focuses on post-authentication tenant activity, while the password
    spray campaign targets initial access.
  relation: out-of-scope-alternative
- hunt: connectwise-supply-chain-initial-access
  reason: This hunt addresses internal tenant persistence, not the initial exploitation
    of the ConnectWise platform.
  relation: out-of-scope-alternative
- hunt: storm-0940-ai-auth-accelerated
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
  index: 2
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


# ARTEX-Driven Cloud Persistence and Graph Exfiltration

This hunt targets the machine-speed post-authentication activity associated with Storm-0940 and the ARTEX framework. It focuses on identifying automated reconnaissance, unauthorized credential additions to OAuth applications, and high-volume data access via Microsoft Graph. The flow correlates known threat actor infrastructure with sensitive directory changes and uses stack-counting to identify anomalous API call volumes that signify automated exfiltration and persistence.

## signin-lead
<!-- Initial Sign-ins from Actor Infrastructure -->
Identify successful or failed sign-ins from reported actor IP addresses or using the compromised application IDs.

```sqlite target=identity role=scoping params=(actor_ips=actor_ips, connectwise_app_ids=connectwise_app_ids, lookback_days=lookback_days)
~~~yaml
expected: Rows indicate the specific account and IP used to enter the tenant; silence
  provides evidence of absence for these specific IOCs.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- app_id
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, app_id, time FROM hb_auth_signin WHERE (instr(',' || '{{actor_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR instr(',' || '{{connectwise_app_ids}}' || ',', ',' || app_id || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-and-recon-parallel
<!-- Analyze Persistence and API Activity -->
parallel:
- → directory-persistence
- → api-volume
join: → triage-agent

## directory-persistence
<!-- Directory Entity and Role Modifications -->
Identify entity modifications that indicate credential additions or role expansion within the tenant.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: New credentials added to applications or new users added to privileged roles,
  potentially by automated accounts.
reads:
- time
- actor_user_name
- entity_name
- operation_type
- attribute_name
- device_hostname
silence: not_evidence_of_absence
source: hb_entity_management
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT time, actor_user_name, entity_name, operation_type, attribute_name, device_hostname FROM hb_entity_management WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(operation_type) LIKE '%credential%' OR LOWER(operation_type) LIKE '%role%' OR LOWER(operation_type) LIKE '%owner%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## api-volume
<!-- High-Velocity API Call Patterns -->
Stack-count sensitive API calls by source IP to identify automated data exfiltration or reconnaissance.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single IP address or service principal performing over 100 sensitive operations
  in the window, suggesting AI-driven automation.
prevalence:
  by: cloud_account_uid
  key:
  - src_endpoint_ip
  - api_operation
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- api_operation
- time
- provider
- cloud_account_uid
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT src_endpoint_ip, actor_user_name, api_operation, COUNT(*) AS call_count, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE provider IN ('m365', 'azure_ad') AND (LOWER(api_operation) LIKE '%mail%' OR LOWER(api_operation) LIKE '%get%' OR LOWER(api_operation) LIKE '%list%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, api_operation HAVING call_count > 100
```

## triage-agent
<!-- Triage AI-Accelerated Activity -->
```agent target=hunter
cite: required
context:
- signin-lead
- directory-persistence
- api-volume
max_iterations: 5
objective: Determine whether the high-volume API calls and entity modifications correlate
  with the compromised application IDs or the reported actor IPs.
success_criteria: A verdict of malicious | suspicious | benign per host or service
  principal, citing specific rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage-agent verdict is malicious for at least one service principal or account" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-graph-data-events)
else: → close-out

## isolate-identity
<!-- Revoke Identity Access -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identified service principals and rotate their client secrets. Revoke any consent grants created during the intrusion window.
```
→ manual-review

## manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review M365 Unified Audit Logs for the specific principal. Search for MailItemsAccessed and FileDownloaded events. Check for new inbox rules or transport rules created during the intrusion.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Log the identified indicators of compromise. Propose the api-volume query as a permanent detection for high-volume Graph API activity from rare IPs.
```
→ end
