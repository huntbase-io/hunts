---
analysis: A single resource deletion rule is noisy. This hunt correlates a specific
  Python user-agent with a rapid discovery phase and a subsequent multi-service destruction
  sequence, capturing the behavior of automated cloud scripts.
blind_spots:
- id: lack-of-api-version-detail
  question: What specifically caused the SQL deletion failures?
  requires: Cloud audit logs with full request metadata
  risk: If the logs do not record the API version used, the analyst might mistake
    a failed deletion attempt for a simple configuration error.
  stage: impact-resource-deletion
- id: secret-rotation-visibility
  question: Were the retrieved storage keys rotated by the actor?
  requires: hb_account_change for cloud secrets
  risk: We can see the retrieval but not if the actor successfully applied the keys
    to access data without high-fidelity storage logs.
  stage: credential-access-storage-keys
coverage:
- stage: reconnaissance-cloud-discovery
  status: covered
  steps:
  - identify-suspicious-principals
  - recon-volume
  - ua-prevalence
- stage: impact-resource-deletion
  status: covered
  steps:
  - automated-destruction
- stage: inhibit-recovery-lock-removal
  status: covered
  steps:
  - automated-destruction
- stage: credential-access-storage-keys
  status: covered
  steps:
  - automated-destruction
- reason: 'Belongs to another part of the ''Storm-3168: Agentic-driven cloud attacks
    using compromised service principals'' series.'
  stage: initial-access-exposed-secret
  status: out_of_scope
- reason: 'Belongs to another part of the ''Storm-3168: Agentic-driven cloud attacks
    using compromised service principals'' series.'
  stage: reconnaissance-application-probing
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The shift toward agentic cloud attacks allows adversaries to destroy
    infrastructure in minutes; identifying the reconnaissance phase provides the only
    window to prevent catastrophic resource loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A compromised service principal is executing an automated sequence of
  Azure resource discovery, mass deletion, and credential collection to facilitate
  a cloud-native ransomware operation.
labels:
- hunt
- attack.t1087.004
- attack.t1046
- attack.t1580
- attack.t1485
- attack.t1486
- attack.t1490
- attack.t1528
name: 'Storm-3168: Automated Azure Resource Destruction and Recovery Inhibition'
parameters:
  campaign_uas:
    default:
    - python-requests/2.34.2
    description: User agents observed in Storm-3168 activity.
    from:
      kind: article
      observed: '2026-09-25'
      ref: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of cloud API activity to examine.
    type: number
  scope_hosts:
    default: []
    description: List of suspicious Service Principal names identified in the scoping
      phase.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on service principals using Python-based request libraries. The hunt
  starts with Azure authentication logs and pivots to API activity to identify the
  breadth of the impact.
references:
- name: 'Storm-3168: Agentic-driven cloud attacks using compromised service principals'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
related:
- hunt: exposed-secrets-github-history
  reason: Initial access via secrets in GitHub history requires a repository-focused
    hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Service principal credential leak
    observables:
    - plaintext client_id, client_secret, and tenant_id in public GitHub issue history
    slug: initial-access-exposed-secret
    tactic: initial-access
    techniques:
    - T1552.001
  - name: Rapid Azure resource enumeration
    observables:
    - python-requests/2.34.2
    - 300+ successful read operations
    - enumeration of Azure VMs, subscriptions, and resource groups
    - enumeration of App Service configuration stores
    - probing for Azure OpenSearch resources
    slug: reconnaissance-cloud-discovery
    tactic: discovery
    techniques:
    - T1087.004
    - T1046
    - T1580
  - name: Automated resource destruction
    observables:
    - 100+ storage account deletion attempts
    - deletion of Azure Key Vault
    - deletion of Azure Function App
    - deletion of Azure App service plan
    - failed SQL database deletions due to unsupported API version
    slug: impact-resource-deletion
    tactic: impact
    techniques:
    - T1485
    - T1486
  - name: Removal of recovery protections
    observables:
    - attempts to delete Azure Site Recovery locks
    - attempts to delete Azure Backup protection locks
    slug: inhibit-recovery-lock-removal
    tactic: impact
    techniques:
    - T1490
  - name: Storage account key collection
    observables:
    - ListKeys requests against Azure Storage Accounts
    - 30+ successful key retrieval operations
    slug: credential-access-storage-keys
    tactic: credential-access
    techniques:
    - T1528
  - name: Web application vulnerability probing
    observables:
    - GET /api/v1/validate/code
    - WordPress administration path probing
    - PHP-CGI path probing
    slug: reconnaissance-application-probing
    tactic: discovery
    techniques:
    - T1595.002
  summary: Storm-3168 (JADEPUFFER) leverages Azure service principal credentials exposed
    in public GitHub issue histories to perform automated cloud resource destruction.
    The actor executes rapid reconnaissance before bulk-deleting storage accounts,
    key vaults, and databases while attempting to remove backup and recovery locks
    to inhibit restoration.
series:
  index: 1
  slug: storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals
  title: 'Storm-3168: Agentic-driven cloud attacks using compromised service principals'
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


# Storm-3168: Automated Azure Resource Destruction and Recovery Inhibition

This hunt targets the activity of Storm-3168 (JADEPUFFER), an actor using agentic automation to conduct rapid cloud attacks. We analyze Azure control-plane logs for an initial phase of broad resource reconnaissance, followed by a dense sequence of storage, database, and identity resource deletions. The hunt also searches for attempts to remove recovery protection locks and retrieve storage account access keys, identifying the hallmarks of a cloud-native ransomware operation.

## identify-suspicious-principals
<!-- Identify suspicious service principal sign-ins -->
Scope the hunt to Azure service principals using the campaign's specific Python user agent.

```sqlite target=identity role=scoping params=(campaign_uas=campaign_uas, lookback_days=lookback_days)
~~~yaml
expected: A list of service principal names that have authenticated using the suspicious
  Python library. Silence suggests the actor's toolkit is not present.
reads:
- actor_user_name
- src_endpoint_ip
- user_agent
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT actor_user_name, src_endpoint_ip, user_agent, COUNT(*) as login_count, MIN(time) as first_seen FROM hb_auth_signin WHERE provider = 'azure' AND instr(',' || '{{campaign_uas}}' || ',', ',' || user_agent || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, user_agent
```

## parallel-recon-check
<!-- Examine reconnaissance breadth and volume -->
parallel:
- → recon-volume
- → ua-prevalence
join: → triage-reconnaissance

## recon-volume
<!-- Analyze discovery operation volume -->
Find service principals performing a high volume of read operations, typical of automated discovery.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Service principals with hundreds of successful read/list operations across
  multiple subscriptions or resource groups.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 3
reads:
- actor_user_name
- api_operation
- api_service_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT actor_user_name, api_operation, api_service_name, COUNT(*) as op_count FROM hb_cloud_api_activity WHERE activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation, api_service_name HAVING op_count > 50 ORDER BY op_count DESC
```

## ua-prevalence
<!-- Analyze user agent prevalence -->
Stack-count user agents associated with Azure API activity to see if the campaign UA is an outlier.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The Campaign user agent (python-requests/2.34.2) appearing for very few
  service principals, confirming its rarity.
prevalence:
  by: actor_user_name
  key:
  - user_agent
  rare_below: 5
reads:
- user_agent
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT user_agent, COUNT(DISTINCT actor_user_name) as principal_count, COUNT(*) as call_count FROM hb_cloud_api_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent ORDER BY principal_count ASC
```

## triage-reconnaissance
<!-- Assess reconnaissance evidence -->
```agent target=hunter
cite: required
context:
- identify-suspicious-principals
- recon-volume
- ua-prevalence
max_iterations: 3
objective: Determine if any service principal exhibits signs of automated reconnaissance
  against Azure resources, specifically focusing on those using the campaign user
  agent.
success_criteria: A per-principal classification of malicious, suspicious, or benign
  based on reconnaissance patterns.
tools:
- endpoint
- identity
```

## automated-destruction
<!-- Detect automated destruction and key retrieval -->
Search for mass resource deletion and credential collection following the reconnaissance phase.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A dense sequence of deletion operations for storage accounts and key vaults.
  Failed SQL deletions with API errors and multiple ListKeys operations confirm the
  ransomware objective.
reads:
- actor_user_name
- api_operation
- resource_name
- status
- error_code
- activity_id
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT time, actor_user_name, api_operation, resource_name, status, error_code FROM hb_cloud_api_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || actor_user_name || ',') > 0) AND (activity_id = 4 OR LOWER(api_operation) LIKE '%delete%' OR LOWER(api_operation) LIKE '%listkeys%') AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-final-verdict
<!-- Analyze destruction and recovery inhibition -->
```agent target=hunter
cite: required
context:
- triage-reconnaissance
- automated-destruction
max_iterations: 4
objective: Evaluate the combined evidence of discovery, mass resource deletion, failed
  SQL deletions, and storage key collection to confirm a ransomware-aligned campaign.
success_criteria: A comprehensive report naming the malicious service principals and
  the resources affected.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on malicious activity -->
if~: "the agent verdict for triage-final-verdict is malicious and confirms automated resource deletion" (confidence: high, judge=hunter)
then: → revoke-compromised-sp
indeterminate: → impact-assessment
unavailable: → impact-assessment (blind_spot: lack-of-api-version-detail)
else: → close-out

## revoke-compromised-sp
<!-- Revoke compromised service principal -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the service principal(s) identified as malicious and revoke all active OAuth tokens to halt the destructive campaign.
```
→ impact-assessment

## impact-assessment
<!-- Assess destruction and initiate recovery -->
```manual target=analyst
Verify the list of deleted storage accounts, SQL databases, and key vaults. Identify resources where deletion was blocked by locks or protection. Initiate restoration from Azure Backup or Site Recovery.
```
→ close-out

## close-out
<!-- Close hunt and update detections -->
```manual target=analyst
Document the hunt findings. If a confirmed intrusion occurred, escalate to IR. If not, record any benign Python-based automation for exclusion tuning.
```
→ end
