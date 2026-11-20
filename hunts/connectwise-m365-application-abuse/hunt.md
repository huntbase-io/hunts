---
analysis: A static rule for the actor IP is insufficient as the actor rotates infrastructure.
  This hunt pivots from sign-in anomalies to the Unified Audit Log to reconstruct
  a chain of post-exploitation persistence on third-party applications, which requires
  behavioral triage across two distinct surfaces.
blind_spots:
- id: no-cloud-audit-logs
  question: whether the hijacked application modified directory roles or added credentials
  requires: Unified Audit Log (hb_cloud_api_activity) integration
  risk: Without audit log integration, a successful initial sign-in looks like a dead
    end; the persistence phase remains completely invisible.
  stage: privilege-escalation-role-assignment
- id: directory-read-blind-spot
  question: what directory or mailbox data was read by the attacker
  requires: Microsoft Graph Activity Logs
  risk: Microsoft does not log most data-read operations; tokens issued for Graph
    can be used to scrape data without a visible audit trail.
- id: cloud-host-anonymity
  question: which local host initiated the cloud authentication
  requires: Endpoint telemetry with cloud-provider correlation
  risk: Pure cloud-to-cloud sign-ins usually have a NULL device_hostname; the scoping
    step may produce an empty scope_hosts list, making physical-host-based filtering
    ineffective.
coverage:
- stage: credential-access-password-spray
  status: covered
  steps:
  - password-spray-detection
- stage: unauthorized-application-authentication
  status: covered
  steps:
  - app-auth-anomaly
- stage: privilege-escalation-role-assignment
  status: covered
  steps:
  - audit-log-follow-on
- stage: persistence-additional-cloud-credentials
  status: covered
  steps:
  - audit-log-follow-on
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: This hunt addresses a confirmed supply-chain credential compromise
    affecting thousands of tenants. The adversary's ability to establish long-term
    persistence in secondary, trusted applications makes a manual review of all tenants
    with these apps a critical security obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited compromised ConnectWise (SkyKick) vendor credentials
  to access M365 tenants, escalate directory privileges, and persist by adding secrets
  to secondary applications.
labels:
- hunt
- attack.t1098.001
- attack.t1110.003
- attack.t1190
- credential access
- initial access
- persistence
- privilege escalation
name: ConnectWise M365 Application Abuse
parameters:
  actor_ip:
    default: 144.172.64.128
    description: The hosting provider IP address associated with the unauthorized
      sign-ins and password sprays.
    from:
      kind: article
      observed: '2026-10-15'
      ref: huntress-vendor-credential-abuse
    type: ip
  connectwise_app_ids:
    default:
    - b78f6a77-d4e5-46fb-87e5-d1648bd02519
    - 24205314-2b89-4e07-a2a4-579e898a5640
    - b2b55f5b-7758-4719-8d8f-88ae172e6bdb
    description: The Entra application IDs for ConnectWise Exchange Online, MS Teams,
      and SharePoint Online apps.
    from:
      kind: article
      observed: '2026-10-17'
      ref: huntress-vendor-credential-abuse
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty to check
      the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with tenants where ConnectWise Cloud Backup (SkyKick) or Cloud Management
  apps are active. Use a 14-day lookback to cover the initial password sprays (Oct
  13) and the credential abuse window (Oct 15-17).
references:
- name: "Huntress \u2014 Vendor Credential Enables Unauthorized Access"
  url: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access
related:
- hunt: m365-unusual-application-credential-addition
  reason: A general hunt for T1098.001 across all apps, not just the ConnectWise incident.
  relation: sibling
scenario:
  stages:
  - name: Password spraying against law firms
    observables:
    - 'src_endpoint_ip: 144.172.64.128'
    - 'user_agent: curl/7.88.1'
    slug: credential-access-password-spray
    tactic: credential-access
    techniques:
    - T1110.003
  - name: Service principal sign-in via vendor credentials
    observables:
    - 'src_endpoint_ip: 144.172.64.128'
    - 'app_id: b78f6a77-d4e5-46fb-87e5-d1648bd02519 (Exchange Online)'
    - 'app_id: 24205314-2b89-4e07-a2a4-579e898a5640 (MS Teams)'
    - 'app_id: b2b55f5b-7758-4719-8d8f-88ae172e6bdb (SharePoint Online)'
    - 'client_app: Microsoft Graph'
    slug: unauthorized-application-authentication
    tactic: initial-access
    techniques:
    - T1190
  - name: Self-assignment of directory roles
    observables:
    - 'api_operation: Add member to role'
    - 'target_modified_property_new_values: Exchange Administrator'
    - 'target_modified_property_new_values: Global Administrator'
    - 'user_agent: kiota-dotnet'
    - 'actor_app_uid: 24205314-2b89-4e07-a2a4-579e898a5640'
    slug: privilege-escalation-role-assignment
    tactic: privilege-escalation
    techniques:
    - T1098
  - name: New client secrets added to applications
    observables:
    - 'api_operation: Update application'
    - 'user_agent: Python-urllib/3.12'
    - 'resource_name: Huntress Security Platform'
    - 'target_modified_property_names: KeyDescription'
    - 'target_modified_property_new_values: [Client Secret expiry 2028]'
    slug: persistence-additional-cloud-credentials
    tactic: persistence
    techniques:
    - T1098.001
  summary: Threat actors abused ConnectWise (SkyKick) vendor credentials to gain unauthorized
    access to Microsoft 365 tenants, primarily targeting organizations in the policy,
    national security, and trade sectors. Once authenticated, the actors escalated
    privileges by assigning directory roles to service principals and established
    persistence by adding new client secrets to legitimate security and management
    applications.
severity: critical
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


# ConnectWise M365 Application Abuse

This hunt reconstructs the multi-stage attack involving ConnectWise Cloud Management applications reported in October 2026. The adversary used valid vendor-held credentials to obtain Graph tokens from a datacenter IP address. Once inside, they self-assigned Global Administrator roles and modified trusted applications, such as the Huntress Security Platform and MSP management tools, to add long-lived client secrets. This hunt follows a phased flow: first scoping the estate for the affected applications, then triaging initial access signals from both the reported IP address and anomalous IP/User-Agent combinations for these apps, and finally hunting for the follow-on administrative changes and persistence triggers across the cloud control plane.

## scope-tenants
<!-- Scope tenants with ConnectWise apps -->
Identify which tenants have active ConnectWise applications to focus the search for initial access and persistence.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, connectwise_app_ids=connectwise_app_ids)
~~~yaml
expected: A list of tenant IDs and any associated hostnames. Silence means no recent
  sign-in activity was recorded for these applications.
reads:
- home_tenant_id
- app_id
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT DISTINCT home_tenant_id, device_hostname FROM hb_auth_signin WHERE instr(',' || '{{connectwise_app_ids}}' || ',', ',' || app_id || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## initial-access-parallel
<!-- Initial access parallel hunt -->
parallel:
- → password-spray-detection
- → app-auth-anomaly
join: → agent-triage-initial

## password-spray-detection
<!-- Password spray from actor IP -->
Identify password spraying attempts using the curl user agent from the reported actor IP, even if no hostnames are provided in scope.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, actor_ip=actor_ip, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Bursts of failed sign-ins from the actor IP against multiple accounts within
  a tenant. Silence means the IP was not used for spraying.
prevalence:
  by: home_tenant_id
  key:
  - actor_user_name
  rare_below: 2
reads:
- home_tenant_id
- actor_user_name
- src_endpoint_ip
- user_agent
- status_code
- device_hostname
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT home_tenant_id, actor_user_name, src_endpoint_ip, user_agent, status_code, COUNT(*) AS attempts, MIN(time) AS first_seen FROM hb_auth_signin WHERE src_endpoint_ip = '{{actor_ip}}' AND LOWER(user_agent) LIKE '%curl%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY home_tenant_id, actor_user_name, src_endpoint_ip, user_agent, status_code HAVING attempts > 3
```

## app-auth-anomaly
<!-- Anomalous ConnectWise app authentication -->
Detect successful authentication of ConnectWise apps from the known actor IP or from any IP/User-Agent combination that is rare or new for each tenant.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, connectwise_app_ids=connectwise_app_ids)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Successful sign-ins by the vendor apps from datacenter IPs or unusual user
  agents. Silence proves the apps behaved as expected for the lookback window.
prevalence:
  by: home_tenant_id
  key:
  - src_endpoint_ip
  - user_agent
  rare_below: 2
reads:
- home_tenant_id
- app_id
- src_endpoint_ip
- user_agent
- status_id
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT home_tenant_id, app_id, src_endpoint_ip, user_agent, status_id, COUNT(*) AS auth_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE instr(',' || '{{connectwise_app_ids}}' || ',', ',' || app_id || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY home_tenant_id, app_id, src_endpoint_ip, user_agent, status_id
```

## agent-triage-initial
<!-- Triage initial access signals -->
```agent target=hunter
cite: required
context:
- password-spray-detection
- app-auth-anomaly
max_iterations: 4
objective: Determine which tenants and service principals the adversary successfully
  compromised, citing sign-ins from the actor IP or rare/new infrastructure.
success_criteria: A list of compromised tenant IDs to focus the follow-on audit search.
tools:
- endpoint
- identity
```

## audit-log-follow-on
<!-- Follow-on role changes and persistence -->
The query identifies administrative changes the hijacked applications made, such as role self-assignments or credential additions.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, connectwise_app_ids=connectwise_app_ids)
~~~yaml
expected: The query returns rows where ConnectWise applications assign themselves
  the Global Administrator role or add client secrets to other applications like the
  Huntress Security Platform. Silence means the apps made no such changes in the audit
  window.
reads:
- cloud_account_uid
- actor_app_uid
- api_operation
- resource_name
- target_modified_property_names
- target_modified_property_new_values
- user_agent
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT cloud_account_uid, actor_app_uid, api_operation, resource_name, target_modified_property_names, target_modified_property_new_values, user_agent, time FROM hb_cloud_api_activity WHERE (instr(',' || '{{connectwise_app_ids}}' || ',', ',' || actor_app_uid || ',') > 0 OR LOWER(user_agent) LIKE '%python-urllib%') AND (api_operation IN ('Add member to role', 'Update application', 'Add service principal credential')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-complete
<!-- Triage complete attack chain -->
```agent target=hunter
cite: required
context:
- agent-triage-initial
- audit-log-follow-on
max_iterations: 6
objective: Confirm whether the compromised ConnectWise apps successfully escalated
  privileges or established persistence via other service principals, citing the full
  chain of events.
success_criteria: A verdict of malicious for any tenant where compromised access led
  to administrative modifications.
tools:
- endpoint
- identity
```

## decide-remediation
<!-- Decide on remediation path -->
if~: "the agent-triage-complete verdict is malicious for at least one tenant, specifically citing rogue credentials or role changes" (confidence: high, judge=hunter)
then: → contain-identity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-audit-logs)
else: → close-out

## contain-identity
<!-- Isolate identity and revoke credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke the client secrets added to secondary applications identified in the triage. Remove the ConnectWise service principals from the Global Administrator or Exchange Administrator directory roles. Revoke all active sessions for the affected service principals.
```
→ analyst-review

## analyst-review
<!-- Analyst manual impact review -->
```manual target=analyst
Review the full audit trail for the compromised apps to determine what directory or mailbox data the adversary may have accessed. Check for any 'Graph' token issuance events and verify if secondary apps performed any other actions after the rogue credential was added.
```
→ end

## close-out
<!-- Hunt close out -->
```manual target=analyst
Record that no unauthorized access or administrative changes were found. Recommend enabling 'App Instance Property Lock' in Entra ID for all high-privilege applications to prevent unauthorized credential additions in the future.
```
→ end
