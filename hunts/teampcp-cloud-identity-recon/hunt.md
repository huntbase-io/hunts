---
analysis: Detecting a single 'sts:GetCallerIdentity' or 'DescribeInstances' call is
  noisy. This hunt contextually links identity signals (source IP reputation, offensive
  User-Agent strings, and multi-service enumeration bursts) to build a high-confidence
  picture of automated credential abuse that a single rule cannot provide.
blind_spots:
- id: no-http-telemetry
  question: Were specific offensive User-Agents used for external API calls?
  requires: Outbound HTTP/HTTPS logging (Proxy or WAF)
  risk: Standard cloud logs show the action (sts:GetCallerIdentity) but not always
    the full User-Agent, which is often only captured by an inspection point like
    a proxy.
  stage: credential-validation-trufflehog
- id: no-cloud-audit-logs
  question: What specific resources (e.g., secret IDs) were retrieved?
  requires: AWS CloudTrail / Azure Activity logs
  risk: Access Advisor shows that a service was accessed, but it lacks the volume
    and resource-level granularity (GetSecretValue) needed to confirm exfiltration
    scope.
  stage: cloud-infrastructure-discovery
- id: workflow-log-deletion-visibility
  question: Were GitHub workflow logs deleted to hide malicious activity?
  requires: GitHub Enterprise Audit Logs
  risk: The available hb_auth_signin surface only captures authentication, not administrative
    actions like log deletion. This activity remains invisible without full GitHub
    audit logs.
  stage: malicious-workflow-execution
coverage:
- stage: credential-validation-trufflehog
  status: covered
  steps:
  - trufflehog-validation-attempts
  - logins-from-teampcp-infrastructure
- stage: cloud-infrastructure-discovery
  status: covered
  steps:
  - bursty-cloud-service-enumeration
- blind_spot: workflow-log-deletion-visibility
  reason: The available hb_auth_signin surface lacks administrative events like WorkflowLogDeleted
    and specific GitHub branch creation/deletion events.
  stage: malicious-workflow-execution
  status: not_visible
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: supply-chain-compromise-initial-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: interactive-container-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: mass-data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: TeamPCP's speed between theft and abuse is exceptionally high. A
    negative result across the identity and discovery surfaces ensures that recently
    stolen credentials are not already being used to map the environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are using stolen credentials from supply-chain victims to
  validate access via TruffleHog and perform broad cloud discovery from known VPN/VPS
  infrastructure.
labels:
- hunt
- attack.t1078
- attack.t1087.004
- attack.t1195
- attack.t1021.001
name: TeamPCP Cloud Identity Reconnaissance
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  offensive_ua_snippets:
    default:
    - trufflehog
    - kali-amd64
    - botocore/1.42.73
    description: Substrings found in User-Agents used by TeamPCP for validation and
      discovery.
    from:
      kind: article
      observed: '2024-03-27'
      ref: wiz-teampcp-2024
    type: list[string]
  teampcp_ips:
    default:
    - 105.245.181.120
    - 138.199.15.172
    - 154.47.29.12
    - 163.245.223.12
    - 170.62.100.245
    - 185.77.218.4
    - 193.32.126.157
    - 209.159.147.239
    - 23.234.107.104
    - 34.205.27.48
    - 103.75.11.59
    description: IP addresses associated with TeamPCP validation and reconnaissance
      infrastructure.
    from:
      kind: article
      observed: '2024-03-27'
      ref: wiz-teampcp-2024
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on users and principals associated with hosts running
  scanners (Trivy, KICS) or LLM libraries (LiteLLM) targeted by TeamPCP. This narrows
  the identity investigation to the most likely beachheads for credential theft.
references:
- name: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  url: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
related:
- hunt: teampcp-container-runtime-abuse
  reason: This hunt focuses on identity; the next in the series examines interactive
    access via ECS Exec and SSM.
  relation: follows
- hunt: teampcp-mass-data-exfil
  reason: Once recon is identified, the next phase is high-volume exfiltration from
    S3 and GitHub.
  relation: follows
scenario:
  stages:
  - name: Supply chain compromise of developer tools
    observables:
    - Trojanized Trivy binary
    - Malicious KICS GitHub Action
    - 'Malicious PyPI packages: LiteLLM, Telnyx'
    - 'Domain: kudelskisecurity.com'
    slug: supply-chain-compromise-initial-access
    tactic: initial-access
    techniques:
    - T1195
    - T1190
  - name: Credential validation with TruffleHog
    observables:
    - 'User-Agent: Trufflehog'
    - 'AWS API: sts:GetCallerIdentity'
    - 'IPs: 105.245.181.120, 185.77.218.4, 209.159.147.239, 23.234.107.104, 34.205.27.48'
    - Mullvad VPN exit nodes
    - Interserver VPS hosts
    slug: credential-validation-trufflehog
    tactic: credential-access
    techniques:
    - T1078
  - name: Cloud and identity discovery
    observables:
    - 'User-Agent: Boto3/1.42.73 (Kali Linux)'
    - 'AWS APIs: ListUsers, ListRoles, DescribeInstances, ListFunctions, DescribeDBInstances,
      ListBuckets, ListClusters, ListSecrets'
    - 'IPs: 138.199.15.172, 154.47.29.12, 170.62.100.245'
    slug: cloud-infrastructure-discovery
    tactic: discovery
    techniques:
    - T1078
  - name: GitHub workflow abuse and log evasion
    observables:
    - 'GitHub branch: dev_remote_ea5Eu/test/v1'
    - Nord Stream GitHub tool
    - Deletion of workflow logs
    - 'Resource name: pawn'
    - 'Resource name: massive-exfil'
    slug: malicious-workflow-execution
    tactic: execution
    techniques:
    - T1078
  - name: Interactive container exploration via ECS Exec
    observables:
    - 'AWS API: ExecuteCommand'
    - SSM Agent execution of Bash/Python
    - Anomalous processes on ECS containers
    slug: interactive-container-access
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1078
  - name: Mass repository and cloud data exfiltration
    observables:
    - 'GitHub API: git.clone'
    - 'User-Agent: git/2.43.0'
    - Massive AWS S3 GetObject events
    - Massive Secrets Manager GetSecretValue events
    - 'IPs: 138.199.15.172, 163.245.223.12, 193.32.126.157'
    slug: mass-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: TeamPCP utilizes stolen credentials from a series of supply chain attacks
    to rapidly validate access via TruffleHog and perform environment discovery across
    AWS and GitHub. They use stolen tokens to execute malicious GitHub workflows and
    leverage AWS ECS Exec for container exploration, culminating in mass exfiltration
    of source code and secrets via git-clone and cloud storage retrieval.
series:
  index: 1
  slug: tracking-teampcp-post-compromise-attacks-seen-in-the-wild
  title: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  total: 3
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  aws:
    category: siem
    huntbase:
      product: aws
    name: aws
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# TeamPCP Cloud Identity Reconnaissance

This hunt identifies at-risk hosts running software targeted by TeamPCP (Trivy, KICS, LiteLLM) and monitors for post-compromise reconnaissance. It specifically looks for automated credential validation using offensive User-Agents (TruffleHog), bursty enumeration of AWS services (IAM, ECS, RDS), and sign-ins originating from the group's known VPN and VPS exit nodes. The goal is to catch the transition from credential theft to environment mapping.

## at-risk-environments
<!-- Identify At-Risk Environments -->
Scope the hunt to hosts running the specific scanners and libraries targeted by TeamPCP's supply-chain operations.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of devices running the targeted packages. These hosts are the likely
  sources of stolen cloud/CI secrets.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%trivy%' OR LOWER(package_name) LIKE '%kics%' OR LOWER(package_name) LIKE '%litellm%' OR LOWER(package_name) LIKE '%telnyx%' OR LOWER(vendor_name) LIKE '%aquasec%' OR LOWER(vendor_name) LIKE '%checkmarx%'
```

## trufflehog-validation-attempts
<!-- Credential Validation via TruffleHog -->
Identify automated credential validation attempts using offensive User-Agents associated with TruffleHog or the adversary's specific Kali-Boto3 configuration.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to STS or identity provider endpoints using the specified
  User-Agents. Silence means no such agents were observed in the available web logs.
reads:
- src_endpoint_ip
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, url_hostname, url_path, user_agent, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE (LOWER(user_agent) LIKE '%trufflehog%' OR LOWER(user_agent) LIKE '%kali-amd64%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_hostname, url_path, user_agent
```

## corroborate-activity
<!-- Corroborate on Two Surfaces -->
parallel:
- → logins-from-teampcp-infrastructure
- → bursty-cloud-service-enumeration
join: → triage-recon

## logins-from-teampcp-infrastructure
<!-- Sign-ins from Malicious Infrastructure -->
Identify authenticated activity (AWS, GitHub, Azure) originating from the VPN/VPS IPs listed in the research.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, teampcp_ips=teampcp_ips)
~~~yaml
expected: Sign-in events from Mullvad or Interserver IPs. A hit here suggests direct
  abuse of stolen credentials.
reads:
- actor_user_name
- src_endpoint_ip
- provider
- activity_name
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, provider, activity_name, status, time FROM hb_auth_signin WHERE instr(',' || '{{teampcp_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## bursty-cloud-service-enumeration
<!-- Bursty AWS Service Enumeration -->
Identify IAM principals accessing an unusually high number of distinct AWS services, a key signal of TeamPCP's broad discovery phase.

```sqlite target=aws role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Principals accessing multiple services like ECS, Lambda, and SecretsManager
  in a short window. A principal with a high service count stands out from normal
  automation.
prevalence:
  by: service_name
  key:
  - principal_arn
  rare_below: 10
reads:
- principal_arn
- service_name
- last_authenticated
silence: not_evidence_of_absence
source: aws_iam_access_advisor
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT principal_arn, COUNT(DISTINCT service_name) AS service_count, GROUP_CONCAT(DISTINCT service_name) AS accessed_services, MAX(last_authenticated) AS last_seen FROM aws_iam_access_advisor WHERE last_authenticated >= datetime('now', '-{{lookback_days}} days') GROUP BY principal_arn HAVING service_count > 5 ORDER BY service_count DESC
```

## triage-recon
<!-- Triage Reconnaissance Activity -->
```agent target=hunter
cite: required
context:
- at-risk-environments
- trufflehog-validation-attempts
- logins-from-teampcp-infrastructure
- bursty-cloud-service-enumeration
max_iterations: 5
objective: Determine if any identities are being abused via offensive validation tools
  or broad cloud enumeration from VPN infrastructure.
success_criteria: A verdict of malicious | suspicious | benign per principal, citing
  specific IP origins and service access patterns.
tools:
- aws
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one IAM principal or user" (confidence: high, judge=hunter)
then: → revoke-credentials
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-audit-logs)
else: → close-out

## revoke-credentials
<!-- Revoke Compromised Credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Immediately revoke the IAM Access Keys and GitHub Personal Access Tokens (PATs) identified in the triage verdict. Notify the identity owners and trigger a password reset.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Pivot -->
```manual target=analyst
Review the services accessed by the compromised principals. If S3 or SecretsManager were accessed, pivot to the 'mass-data-exfiltration' hunt. Check for usage of ECS Exec in the AWS management console.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document that no post-compromise reconnaissance matching TeamPCP patterns was observed. Note any identified 'at-risk' hosts that were missing full management plane logging.
```
→ end
