---
analysis: A standard detection rule alerts on the User Agent or sensitive paths. This
  hunt correlates those hits with wide scanning prevalence (targeting multiple hosts)
  and matches them against an organization's specific vulnerable asset inventory to
  reduce false positives and prioritize high-intent actors.
blind_spots:
- id: no-http-telemetry
  question: whether probes targeted unmanaged or shadow IT assets
  requires: hb_http_activity from all internet-facing servers
  risk: Probes against systems not reporting to central logging will be missed.
  stage: reconnaissance-application-probing
- id: encrypted-traffic
  question: the specific content of POST request payloads
  requires: TLS inspection or application-level logs
  risk: A successful probe (200 OK) might be an exploit attempt; without payload visibility,
    the hunt cannot confirm if code was actually executed.
  stage: reconnaissance-application-probing
coverage:
- stage: reconnaissance-application-probing
  status: covered
  steps:
  - http-probing-lead
  - ip-scanning-prevalence
  - vulnerable-asset-inventory
- reason: Belongs to a separate hunt focusing on GitHub audit logs and secret exposures.
  stage: initial-access-exposed-secret
  status: out_of_scope
- reason: Belongs to a separate hunt focusing on Azure Resource Manager enumeration
    via hb_cloud_api_activity.
  stage: reconnaissance-cloud-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Storm-3168: Agentic-driven cloud attacks
    using compromised service principals'' series.'
  stage: impact-resource-deletion
  status: out_of_scope
- reason: 'Belongs to another part of the ''Storm-3168: Agentic-driven cloud attacks
    using compromised service principals'' series.'
  stage: inhibit-recovery-lock-removal
  status: out_of_scope
- reason: 'Belongs to another part of the ''Storm-3168: Agentic-driven cloud attacks
    using compromised service principals'' series.'
  stage: credential-access-storage-keys
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Storm-3168 conducts extensive web reconnaissance before moving to
    destructive cloud operations; identifying these signals early allows for infrastructure
    blocking before initial access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is conducting automated web reconnaissance by probing for
  specific administrative and AI-related paths to identify vulnerable entry points
  for a subsequent cloud-focused intrusion.
labels:
- hunt
- attack.t1595.002
name: Storm-3168 Web Application Probing
parameters:
  langflow_path:
    default: /api/v1/validate/code
    description: The specific LangFlow code validation path.
    from:
      kind: article
      observed: '2026-09-25'
      ref: storm-3168-msrc
    type: path
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-25'
      ref: hunt-standard-lookback
    type: number
  probing_paths:
    default:
    - /wp-admin/
    - /wp-login.php
    - /php-cgi/
    description: Sensitive paths targeted by Storm-3168 probing.
    from:
      kind: article
      observed: '2026-09-25'
      ref: storm-3168-msrc
    type: list[path]
  storm_user_agent:
    default: python-requests/2.34.2
    description: The specific User Agent observed during Storm-3168 activity.
    from:
      kind: article
      observed: '2026-09-25'
      ref: storm-3168-msrc
    type: string
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing web servers, WAFs, and application gateways. Priority
  is given to hosts already identified in hb_exposed_assets as running WordPress or
  AI-related tooling.
references:
- name: "MSRC \u2014 Storm-3168: Agentic-driven cloud attacks using compromised service\
    \ principals"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
related:
- hunt: storm-3168-cloud-resource-destruction
  reason: Reconnaissance precedes the impact stage; that hunt monitors for resource
    deletion events.
  relation: follows
- hunt: storm-3168-azure-resource-destruction
  relation: follows
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Storm-3168 Web Application Probing

This hunt identifies reconnaissance activity linked to Storm-3168 (JADEPUFFER), an actor known for agentic ransomware operations. The actor uses automated scripts to identify web-based entry points by probing for WordPress administrative paths, PHP-CGI vulnerabilities, and LangFlow code validation endpoints. The hunt filters HTTP telemetry for specific user agents and URI paths, then cross-references findings with source IP scanning prevalence and exposed asset context to distinguish directed actor activity from general internet background noise.

## http-probing-lead
<!-- HTTP probing for sensitive paths -->
Identify HTTP requests matching known actor user agents or targeted vulnerability paths.

```sqlite target=web role=detection-candidate params=(probing_paths=probing_paths, langflow_path=langflow_path, storm_user_agent=storm_user_agent, lookback_days=lookback_days)
~~~yaml
expected: Requests matching the actor user agent or specific vulnerability paths.
  Hits on LangFlow or administrative paths with status 200 are high-interest.
reads:
- src_endpoint_ip
- url_hostname
- url_path
- user_agent
- status_code
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT src_endpoint_ip, url_hostname, url_path, user_agent, status_code, http_method, time FROM hb_http_activity WHERE (LOWER(url_path) = LOWER('{{langflow_path}}') OR instr(',' || '{{probing_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR user_agent = '{{storm_user_agent}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with prevalence and asset context -->
parallel:
- → ip-scanning-prevalence
- → vulnerable-asset-inventory
join: → agent-triage

## ip-scanning-prevalence
<!-- Source IP scanning prevalence -->
Stack-count source IPs to determine if they have targeted multiple distinct hostnames in the environment.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IPs targeting multiple hosts. Automated scanning is identified when host_targets
  exceeds normal per-IP limits.
prevalence:
  by: url_hostname
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- url_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT url_hostname) AS host_targets, COUNT(*) AS request_hits, MIN(time) AS first_seen FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING host_targets > 1 ORDER BY host_targets DESC
```

## vulnerable-asset-inventory
<!-- Vulnerable asset inventory -->
Identify hosts known to run WordPress, PHP, or LangFlow to confirm the relevance of the probes.

```sqlite target=endpoint role=enrichment
~~~yaml
expected: A list of hosts running products the actor is actively probing. Probes against
  these specific hosts indicate targeted intent.
reads:
- domain_or_ip
- product
- version
- port
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-26'
~~~
SELECT domain_or_ip, product, version, port FROM hb_exposed_assets WHERE product IS NOT NULL AND (LOWER(product) LIKE '%wordpress%' OR LOWER(product) LIKE '%php%' OR LOWER(product) LIKE '%langflow%')
```

## agent-triage
<!-- Evaluate probing activity -->
```agent target=hunter
cite: required
context:
- http-probing-lead
- ip-scanning-prevalence
- vulnerable-asset-inventory
max_iterations: 4
objective: Determine if source IPs are conducting targeted Storm-3168 application
  probing based on user agent, paths, status codes, scanning prevalence, and the presence
  of vulnerable software on the targets.
success_criteria: Verdicts for each suspect IP, identifying those that hit vulnerable
  assets with the Storm-3168 user agent or paths.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage verdict is malicious for at least one source IP conducting automated probes against WordPress or LangFlow assets" (confidence: high, judge=hunter)
then: → block-attacker-ip
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: no-http-telemetry)
else: → analyst-confirmation

## block-attacker-ip
<!-- Block attacker IP -->
```action target=network
~~~yaml
approval: required
~~~
Block the identified source IPs in the WAF, perimeter firewall, or application gateway to prevent further reconnaissance or exploitation.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Analyst confirmation -->
```manual target=analyst
Review the full HTTP request logs for the identified IPs. Check for subsequent POST requests to administrative or code-validation paths that might indicate successful exploitation. Validate the product version on the target hosts.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the identified IPs and the targeted paths. If successful probes were found against vulnerable versions of WordPress or LangFlow, ensure those systems are patched and credentials rotated.
```
→ end
