---
analysis: A simple rule for Telegram or S3 traffic creates too much noise. This hunt
  correlates the vulnerable state of a host with specific egress behaviors and rare
  identity patterns to find the malicious overlap that automated rules would miss.
blind_spots:
- id: no-network-visibility
  question: whether hosts in unmonitored segments are talking to Filebase
  requires: hb_network_connection or hb_dns_activity on all cloud VPCs
  risk: Exfiltration from unmonitored segments will not be detected.
  stage: exfiltration-to-filebase-s3
- id: unknown-auth-source
  question: whether a login attempt from a specific IP belongs to the attacker
  requires: hb_auth_signin with source IP attribution
  risk: Adversaries using residential proxies might blend in with legitimate user
    activity.
  stage: credential-abuse-saas-cloud
coverage:
- stage: c2-telegram-alerting
  status: covered
  steps:
  - network-egress-to-c2-and-exfil
- stage: exfiltration-to-filebase-s3
  status: covered
  steps:
  - network-egress-to-c2-and-exfil
- stage: credential-abuse-saas-cloud
  status: covered
  steps:
  - identity-access-anomalies
- reason: 'Belongs to another part of the ''Bissa Scanner Exposed: AI-Assisted Mass
    Exploitation and Credential Harvesting'' series.'
  stage: initial-access-mass-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Bissa Scanner Exposed: AI-Assisted Mass
    Exploitation and Credential Harvesting'' series.'
  stage: execution-credential-enumeration-payload
  status: out_of_scope
- reason: 'Belongs to another part of the ''Bissa Scanner Exposed: AI-Assisted Mass
    Exploitation and Credential Harvesting'' series.'
  stage: collection-data-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Bissa scanner converts internet-scale scanning into reliable,
    high-value compromises; a negative result over the exfiltration and credential-use
    surfaces confirms the organization has not been operationalized by the threat
    actor.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using Telegram for command-and-control alerts and Filebase
  S3 for data exfiltration after harvesting secrets from vulnerable application servers.
labels:
- hunt
- attack.t1102.002
- attack.t1071.001
- attack.t1567.002
- attack.t1078.004
- attack.t1528
name: Bissa Scanner C2 and S3 Exfiltration
parameters:
  c2_and_exfil_domains:
    default:
    - api.telegram.org
    - s3.filebase.com
    description: Domains used for Telegram alerting and S3 exfiltration.
    from:
      kind: article
      observed: '2026-04-22'
      ref: https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
    type: list[domain]
  cve_ids:
    default:
    - CVE-2025-55182
    - CVE-2025-9501
    description: CVEs used by Bissa scanner to gain initial access.
    from:
      kind: article
      observed: '2026-04-22'
      ref: https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  saas_providers:
    default:
    - aws
    - okta
    - github
    - azure
    - anthropic
    - openai
    - mistral
    - stripe
    - paypal
    - auth0
    description: SaaS and cloud providers targeted by the Bissa credential haul.
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the behavioral hunt to these hostnames; populate from the first
      step.
    type: list[host]
  scope_ips:
    default: []
    description: Source IPs of the vulnerable hosts to pivot on SaaS login activity.
    from:
      kind: article
      observed: '2026-04-22'
      ref: https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
    type: list[ip]
  scope_users:
    default: []
    description: User accounts seen on vulnerable hosts to pivot on SaaS login activity.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying hostnames vulnerable to CVE-2025-55182 or
  CVE-2025-9501 and joining them with the device inventory to ensure portability across
  telemetry surfaces. Pivot the identity search on any users or IPs associated with
  those vulnerable servers.
references:
- name: The DFIR Report - Bissa Scanner Exposed
  url: https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
related:
- hunt: bissa-scanner-initial-exploitation
  reason: Initial exploitation occurs prior to the alerting and exfiltration phases
    covered here.
  relation: follows
- hunt: bissa-scanner-exploitation-harvesting
  relation: follows
scenario:
  stages:
  - name: Mass Vulnerability Exploitation
    observables:
    - CVE-2025-55182
    - CVE-2025-9501
    - React Server Function endpoints
    - W3 Total Cache _parse_dynamic_mfunc payload
    - denemekulubum.com.tr/acquirer/
    - wiprz.com/acquirer/
    - cs2.ip.thc.org
    slug: initial-access-mass-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Local Credential and Metadata Enumeration
    observables:
    - .env file enumeration
    - Kubernetes service account context retrieval
    - Cloud metadata service (IMDS) access
    - Local database and Redis credential search
    - Cryptocurrency wallet search
    slug: execution-credential-enumeration-payload
    tactic: execution
    techniques:
    - T1059.004
    - T1083
  - name: Telegram Bot Command and Control
    observables:
    - api.telegram.org
    - '@bissapwned_bot'
    - '@bissa_scan_bot'
    - Bot ID 8798206332
    - Chat ID 1609309278
    slug: c2-telegram-alerting
    tactic: command-and-control
    techniques:
    - T1102.002
    - T1071.001
  - name: Archive Staging of Environment Files
    observables:
    - results/ directory monitoring
    - env-batch-*.zip
    - Batching of .env files into ZIP archives
    slug: collection-data-staging
    tactic: collection
    techniques:
    - T1560.001
  - name: Exfiltration to Filebase S3
    observables:
    - s3.filebase.com
    - 'bucket: bissapromax'
    - 'prefix: archives/'
    slug: exfiltration-to-filebase-s3
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Post-Compromise Credential Abuse
    observables:
    - Anthropic API keys
    - AWS access keys
    - Okta/Auth0 tokens
    - Stripe/PayPal tokens
    - GitHub personal access tokens
    - Slack integration tokens
    - Oracle Fusion REST export activity
    slug: credential-abuse-saas-cloud
    tactic: credential-access
    techniques:
    - T1078.004
    - T1528
  summary: The Bissa Scanner campaign involves large-scale, automated exploitation
    of React Server Components (CVE-2025-55182) and WordPress (CVE-2025-9501) to harvest
    secrets at scale. The operator, 'Dr. Tube', utilizes AI-assisted workflows via
    Claude Code and OpenClaw to triage stolen data and automate alerting through Telegram
    bots, eventually exfiltrating credentials to S3-compatible Filebase storage.
series:
  index: 2
  slug: bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting
  title: 'Bissa Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting'
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


# Bissa Scanner C2 and S3 Exfiltration

This hunt targets the post-compromise egress and exfiltration phase of the Bissa scanner operation. The operator uses Telegram bots for real-time alerting and S3-compatible Filebase buckets to archive stolen environment files. By scoping to hosts with known React or WordPress vulnerabilities and monitoring for specific network and identity anomalies, the hunt detects the transition from initial access to full-scale credential abuse in cloud and SaaS environments.

## identify-vulnerable-exposure
<!-- Identify vulnerable exposure -->
Find hostnames currently reporting the CVEs associated with the Bissa scanner to prioritize the network hunt.

```sqlite target=endpoint role=scoping params=(cve_ids=cve_ids)
~~~yaml
expected: A list of hostnames with vulnerable React or WordPress components. Silence
  means no known vulnerable surface in the current inventory.
reads:
- device_uid
- cve_uid
- affected_package_name
- affected_package_version
- severity
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT d.hostname AS device_hostname, v.cve_uid, v.affected_package_name, v.affected_package_version, v.severity FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE (instr(',' || '{{cve_ids}}' || ',', ',' || v.cve_uid || ',') > 0)
```

## check-for-egress-and-abuse
<!-- Check for egress and abuse -->
parallel:
- → network-egress-to-c2-and-exfil
- → identity-access-anomalies
join: → triage-operator-activity

## network-egress-to-c2-and-exfil
<!-- Network egress to C2 and exfil -->
Find DNS resolutions for Telegram and Filebase S3 from hosts in the vulnerable scope.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, c2_and_exfil_domains=c2_and_exfil_domains, scope_hosts=scope_hosts)
~~~yaml
expected: An application server or developer machine resolving Filebase S3 or Telegram
  API domains. Silence means no egress to the reported operator infrastructure was
  observed.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_lookup FROM hb_dns_activity WHERE (instr(',' || '{{c2_and_exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## identity-access-anomalies
<!-- Identity access anomalies -->
Identify rare authentication events for the SaaS providers targeted by Bissa, pivoting on identities found in the scoping step.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, saas_providers=saas_providers, scope_ips=scope_ips, scope_users=scope_users)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Low-frequency authentication events from unusual source IPs for sensitive
  providers. Silence means no suspicious login activity was captured for the prioritized
  identities.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  - provider
  rare_below: 3
reads:
- provider
- actor_user_name
- src_endpoint_ip
- activity_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT provider, actor_user_name, src_endpoint_ip, activity_name, COUNT(*) as event_count, MIN(time) as first_seen FROM hb_auth_signin WHERE (instr(',' || '{{saas_providers}}' || ',', ',' || LOWER(provider) || ',') > 0) AND (('{{scope_ips}}' = '' OR instr(',' || '{{scope_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) OR ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING event_count < 10
```

## triage-operator-activity
<!-- Triage operator activity -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-exposure
- network-egress-to-c2-and-exfil
- identity-access-anomalies
max_iterations: 5
objective: Confirm an active Bissa compromise and identify whether an attacker is
  using stolen credentials by analyzing vulnerable findings, DNS egress to command-and-control
  infrastructure, and anomalous logins to cloud or SaaS providers.
success_criteria: A verdict of malicious | suspicious | benign per host and user account,
  citing DNS rows and authentication logs.
tools:
- endpoint
- identity
```

## threat-response-decision
<!-- Threat response decision -->
if~: "The triage verdict is malicious for at least one host or SaaS account, indicating an attacker is using stolen credentials." (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → forensic-artifact-review
unavailable: → forensic-artifact-review (blind_spot: no-network-visibility)
else: → close-out-report

## contain-and-revoke
<!-- Contain and revoke -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host from the network. Invalidate and rotate all credentials associated with the compromised user or found in .env files, especially for AWS, Okta, and GitHub. Initiate a password reset for any identity suspected of being compromised.
```
→ forensic-artifact-review

## forensic-artifact-review
<!-- Forensic artifact review -->
```manual target=analyst
Examine the local results directory on the host. Look for ZIP files following the env-batch-*.zip pattern and runner scripts referencing the bissapromax bucket or Telegram bot user ID 8798206332.
```
→ close-out-report

## close-out-report
<!-- Close out report -->
```manual target=analyst
Document which data clusters were potentially accessed. Recommend moving secrets out of .env files and into a dedicated secret manager for all production services.
```
→ end
