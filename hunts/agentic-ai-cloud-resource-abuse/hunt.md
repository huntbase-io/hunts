---
analysis: 'A standard rule might fire on a single sign-in from a Tor IP, but this
  hunt uses a multi-stage behavioral pivot: correlating that sign-in with the unique
  pattern of automated API troubleshooting (rapid 400-to-200 transitions), which confirms
  the presence of an active AI agent.'
blind_spots:
- id: cloud-audit-latency
  question: whether an agent is operating in real-time
  requires: low-latency cloud control plane logs
  risk: Azure and Entra audit logs can have significant ingestion latency (15-60 minutes);
    an AI agent can exfiltrate data in under 5 minutes.
  stage: adaptive-api-probing
- id: vault-data-plane-visibility
  question: exactly which secret values were retrieved by the agent
  requires: Key Vault Data Plane logging
  risk: Without data plane logging, we see that the vault was accessed, but not which
    specific secrets were downloaded.
  stage: credential-and-data-exfiltration
coverage:
- stage: service-principal-compromise
  status: covered
  steps:
  - signins-from-malicious-ips
  - triage-initial-compromise
- stage: cloud-resource-discovery
  status: covered
  steps:
  - automated-discovery-patterns
- stage: adaptive-api-probing
  status: covered
  steps:
  - adaptive-api-troubleshooting
- stage: credential-and-data-exfiltration
  status: covered
  steps:
  - evaluate-agentic-lifecycle
  - secret-rotation-audit
- reason: Belongs to another part of the 'Threat actors use agentic AI tooling to
    find and abuse exposed secrets' series.
  stage: initial-secret-exposure
  status: out_of_scope
- reason: Belongs to another part of the 'Threat actors use agentic AI tooling to
    find and abuse exposed secrets' series.
  stage: web-vulnerability-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The rapid self-correction of agentic AI frameworks allows attackers
    to bypass errors and exfiltrate data in minutes. This hunt identifies the specific
    behavioral signature of AI agents, providing a negative result against automated
    intrusion frameworks.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using an agentic AI framework to automate cloud discovery
  and data exfiltration, identified by rapid, self-correcting API probing patterns
  and service principal abuse from campaign-associated infrastructure.
labels:
- hunt
- attack.t1078
- attack.t1071
- attack.t1041
- attack.t1090.003
- attack.t1110.003
- defense evasion
- discovery
- exfiltration
- initial access
name: Agentic AI Cloud Resource Abuse (ARTEX)
parameters:
  lookback_days:
    default: '14'
    description: Days of cloud and authentication history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of reporting hosts to narrow the initial sign-in scope.
    type: list[host]
  suspicious_ips:
    default:
    - 199.19.77.84
    - 199.19.77.18
    - 65.87.223.26
    - 157.22.126.128
    description: IP addresses associated with ARTEX activity and observed reconnaissance.
    from:
      kind: article
      observed: '2026-11-05'
      ref: ms-artex-2026
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on Entra ID (azure_ad) authentication and Azure Resource
  Manager (ARM) activity. Use the reporting hosts in the auth logs to narrow the blast
  radius.
references:
- name: "Microsoft \u2014 Threat actors use agentic AI tooling to find and abuse exposed\
    \ secrets"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
related:
- hunt: leaked-secret-scanning-github
  reason: That hunt focuses on the discovery of secrets in repositories; this hunt
    focuses on the abuse of those secrets in the cloud environment.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Secret Exposure in Public Repositories
    observables:
    - GitHub repositories containing OAuth client secrets
    - Azure API keys
    - AI inference-related API keys
    - ARTEX offensive framework scanning patterns
    slug: initial-secret-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Credential Abuse via Entra ID
    observables:
    - IP address 199.19.77.84
    - IP address 199.19.77.18
    - Service principal sign-ins for multitenant applications
    - Logins from Tor exit nodes
    slug: service-principal-compromise
    tactic: initial-access
    techniques:
    - T1078
  - name: Automated Cloud Reconnaissance
    observables:
    - Enumeration of Azure subscriptions
    - Enumeration of resource groups
    - Mapping of AI model deployments
    - Graph API search requests for sensitive content
    slug: cloud-resource-discovery
    tactic: discovery
    techniques:
    - T1071
  - name: Adaptive API Troubleshooting
    observables:
    - ARM requests returning HTTP 400 followed by HTTP 200 within 30-60 seconds
    - Rapid changes to api-version parameters (e.g., switching to 2023-07-01)
    - Switching between HTTP methods (GET/POST) after failure
    - Mixing Key Vault data-plane and control-plane API versions
    slug: adaptive-api-probing
    tactic: defense-evasion
    techniques:
    - T1071
  - name: Cloud Data Exfiltration
    observables:
    - Retrieval of Storage Account keys
    - Accessing Azure Key Vault secrets and metadata
    - SharePoint and OneDrive file downloads
    - Mailbox item access
    - Downloading App Service publishing credentials
    slug: credential-and-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Embedded Shell Command Injection
    observables:
    - IP address 65.87.223.26
    - Shell commands embedded in HTTP User-Agent headers
    - Attempts to obtain App Service authentication tokens
    slug: web-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
  summary: Threat actors use the ARTEX agentic AI framework to harvest exposed secrets
    from GitHub and automate the compromise of Entra ID service principals. Once authenticated,
    the AI agents perform cloud resource discovery and adaptive API troubleshooting
    to exfiltrate sensitive data from Azure Key Vault, Storage Accounts, and Microsoft
    365 environments.
series:
  index: 1
  slug: threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets
  title: Threat actors use agentic AI tooling to find and abuse exposed secrets
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


# Agentic AI Cloud Resource Abuse (ARTEX)

This phased hunt targets the automated behaviors of agentic AI frameworks like ARTEX. It begins by identifying service principal sign-ins originating from known campaign IPs or Tor exit nodes. It then pivots to find the behavioral hallmark of AI agents: adaptive API troubleshooting, where the agent identifies and corrects its own API version or method errors (400 to 200 transitions) within seconds. Finally, an agent weighs the full lifecycle from compromise to discovery to exfiltration.

## scope-reporting-devices
<!-- Scope active reporting devices -->
Identify the reporting devices recorded in the authentication logs to establish a hunt scope.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames that have reported Entra ID sign-in events. Silence
  suggests a gap in cloud-to-host log forwarding.
reads:
- device_hostname
- provider
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT DISTINCT device_hostname FROM hb_auth_signin WHERE provider = 'azure_ad' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Initial compromise and broad discovery -->
parallel:
- → signins-from-malicious-ips
- → automated-discovery-patterns
join: → triage-initial-compromise

## signins-from-malicious-ips
<!-- Sign-ins from campaign IPs and Tor -->
Correlate Entra ID authentication with the report's IP addresses and Tor exit nodes, filtered by the scoped devices.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, suspicious_ips=suspicious_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Service principal or user logons from 199.19.77.84 or Tor nodes. Silence
  indicates no direct hits on the reported IPs.
reads:
- time
- actor_user_name
- app_id
- src_endpoint_ip
- device_hostname
- status
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT time, actor_user_name, app_id, src_endpoint_ip, device_hostname, status FROM hb_auth_signin WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{suspicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## automated-discovery-patterns
<!-- Automated cloud discovery patterns -->
Identify identities performing high-frequency cloud resource enumeration.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Identities querying multiple subscriptions or resources in quick succession.
  Silence means no high-volume enumeration was captured.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 5
reads:
- actor_user_name
- api_operation
- api_service_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT actor_user_name, api_operation, api_service_name, src_endpoint_ip, COUNT(*) AS op_count, MIN(time) AS first_op FROM hb_cloud_api_activity WHERE (api_operation LIKE '%List%' OR api_operation LIKE '%Get%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation, api_service_name, src_endpoint_ip HAVING op_count > 10 ORDER BY op_count DESC
```

## triage-initial-compromise
<!-- Triage initial cloud compromise -->
```agent target=hunter
cite: required
context:
- scope-reporting-devices
- signins-from-malicious-ips
- automated-discovery-patterns
max_iterations: 3
objective: Identify service principals that have successfully authenticated from suspicious
  IPs and immediately transitioned to broad cloud discovery.
success_criteria: A per-identity verdict citing sign-in source and discovery volume.
tools:
- endpoint
- identity
```

## adaptive-api-troubleshooting
<!-- Adaptive API troubleshooting signature -->
Detect the core behavioral signature of an AI agent: immediate self-correction after API failures.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: An API request that fails (400) and is retried successfully (200) within
  65 seconds by the same actor. This is the hallmark of agentic automation.
reads:
- time
- actor_user_name
- api_operation
- status
- request_uri
- src_endpoint_ip
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT * FROM (SELECT time, actor_user_name, api_operation, status, request_uri, src_endpoint_ip, LAG(status) OVER (PARTITION BY actor_user_name, api_operation ORDER BY time) as prev_status, LAG(time) OVER (PARTITION BY actor_user_name, api_operation ORDER BY time) as prev_time FROM hb_cloud_api_activity WHERE time >= datetime('now', '-{{lookback_days}} days')) WHERE status = '200' AND prev_status = '400' AND (strftime('%s', time) - strftime('%s', prev_time)) <= 65
```

## evaluate-agentic-lifecycle
<!-- Evaluate full agentic lifecycle -->
```agent target=hunter
cite: required
context:
- triage-initial-compromise
- adaptive-api-troubleshooting
max_iterations: 5
objective: Determine if any service principals are being operated by an AI agent demonstrating
  adaptive troubleshooting and sensitive resource discovery.
success_criteria: A final verdict per identity citing the sequence of adaptive success
  after failure.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the evaluate-agentic-lifecycle verdict is malicious for at least one identity demonstrating adaptive troubleshooting" (confidence: high, judge=hunter)
then: → revoke-service-principal
indeterminate: → secret-rotation-audit
unavailable: → secret-rotation-audit (blind_spot: cloud-audit-latency)
else: → close-out

## revoke-service-principal
<!-- Revoke service principal -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the service principal and revoke all active OAuth refresh tokens for the compromised application.
```
→ secret-rotation-audit

## secret-rotation-audit
<!-- Secret rotation and impact audit -->
```manual target=analyst
Audit Key Vault and Storage Account logs for any 'Get' or 'List' operations performed by the compromised identity. Rotate every secret, key, or connection string in those containers.
```
→ close-out

## close-out
<!-- Hunt closure -->
```manual target=analyst
Finalize the investigation. If the adaptive troubleshooting pattern (400 -> 200) was verified as malicious, recommend it for promotion to a permanent detection rule.
```
→ end
