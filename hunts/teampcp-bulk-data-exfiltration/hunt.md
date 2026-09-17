---
analysis: A simple rule might trigger on any 'git.clone' or AWS API call. This hunt
  uses stack-counting to identify 'massive' volume and correlates it with network-level
  byte counts and legacy client signatures to filter out legitimate engineering workflow
  noise.
blind_spots:
- id: limited-github-ip-logs
  owner: Version Control Systems Administrator
  question: Which IP address performed a specific git.clone operation?
  remediation: Enable GitHub Enterprise IP logging.
  requires: IP logging enabled in GitHub Audit Logs
  risk: Without IP logging, authentication events can only be tied to a token, not
    a location, making VPN/VPS identification impossible.
  stage: mass-data-exfiltration
- id: s3-access-logging-off
  owner: Cloud Infrastructure Team
  question: Which specific objects were exfiltrated from the bucket?
  remediation: Enable S3 bucket data event logging.
  requires: S3 Data Events logging (CloudTrail) or S3 Access Logs
  risk: If data event logging is disabled, we see the user logged in but not the specific
    files they stole.
  stage: mass-data-exfiltration
coverage:
- stage: mass-data-exfiltration
  status: covered
  steps:
  - auth-from-exfil-ips
  - detect-legacy-git-ua
  - massive-api-usage-by-ip
  - high-volume-outbound-flows
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: supply-chain-compromise-initial-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: credential-validation-trufflehog
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: cloud-infrastructure-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: malicious-workflow-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: interactive-container-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protecting core intellectual property (source code) and high-value
    cloud secrets is a critical obligation. Bulk exfiltration is the highest-impact
    stage of the TeamPCP campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised credentials to exfiltrate bulk source
  code and cloud secrets from known VPN and VPS exit nodes, identifiable by high-volume
  API activity and specific legacy User-Agent strings.
labels:
- hunt
- attack.t1041
- attack.t1078
- attack.t1195
name: TeamPCP Bulk Data Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  target_user_agent:
    default: git/2.43.0
    description: The specific legacy git user-agent seen in the campaign.
    type: string
  teampcp_exfil_ips:
    default:
    - 138.199.15.172
    - 163.245.223.12
    - 193.32.126.157
    description: IP addresses identified as exfiltration nodes for TeamPCP.
    from:
      kind: article
      observed: '2024-03-27'
      ref: wiz-teampcp-post-compromise
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
rationale: The hunt should prioritize users with access to critical S3 buckets (production
  databases, backups) and sensitive GitHub organizations (core infrastructure). Start
  with the 14-day window as the campaign is recent.
references:
- name: "Wiz \u2014 Tracking TeamPCP: investigating post-compromise attacks seen in\
    \ the wild"
  url: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
related:
- hunt: teampcp-credential-validation
  reason: This hunt focuses on the TruffleHog validation phase, which precedes exfiltration.
  relation: out-of-scope-alternative
- hunt: teampcp-cloud-discovery
  reason: Discovery/reconnaissance activity (ListUsers, DescribeInstances) is a separate
    phase from bulk data transfer.
  relation: out-of-scope-alternative
- hunt: interactive-container-exploitation-ecs-exec
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
  index: 3
  slug: tracking-teampcp-post-compromise-attacks-seen-in-the-wild
  title: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  total: 3
severity: critical
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# TeamPCP Bulk Data Exfiltration

This hunt focuses on the exfiltration stage of the TeamPCP campaign, where stolen Personal Access Tokens (PATs) and AWS keys are used to clone repositories and pull secrets at scale. We pivot on known malicious IPs associated with Mullvad VPN and Interserver VPS providers to identify 'massive' activity patterns. The hunt identifies the legacy 'git/2.43.0' user-agent and correlates auth-level API call frequency with network-level data volume to distinguish automated exfiltration from legitimate administrative tasks.

## auth-from-exfil-ips
<!-- Authentication events from known exfil IPs -->
Identify any sessions or API usage originating from the Mullvad or Interserver nodes used by TeamPCP.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, teampcp_exfil_ips=teampcp_exfil_ips)
~~~yaml
expected: A list of users and providers (github, aws) accessed from these IPs. Silence
  indicates no traffic from these specific indicators.
reads:
- activity_name
- actor_user_name
- dst_endpoint_name
- provider
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, activity_name, time FROM hb_auth_signin WHERE instr(',' || '{{teampcp_exfil_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## corroborate-exfil
<!-- Corroborate Exfiltration Indicators -->
parallel:
- → detect-legacy-git-ua
- → massive-api-usage-by-ip
- → high-volume-outbound-flows
join: → triage-exfiltration

## detect-legacy-git-ua
<!-- Legacy Git User-Agent Detection -->
Detect the specific 'git/2.43.0' user-agent which is characteristic of the TeamPCP GitHub exfiltration toolset.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, target_user_agent=target_user_agent)
~~~yaml
expected: Rows containing the target UA. This UA is older and stands out in environments
  with modern developer machines.
reads:
- src_endpoint_ip
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, user_agent, url_hostname, url_path, COUNT(*) as request_count FROM hb_http_activity WHERE user_agent = '{{target_user_agent}}' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, user_agent, url_hostname, url_path
```

## massive-api-usage-by-ip
<!-- Massive API activity (Git/S3/Secrets) -->
Stack-count specific sensitive API operations (cloning, secret retrieval) to find the 'massive' volume indicative of automated theft.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: An IP performing dozens or hundreds of secret retrievals or repository clones
  in a short window.
prevalence:
  by: src_endpoint_ip
  key:
  - url_hostname
  rare_below: 5
reads:
- src_endpoint_ip
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, url_hostname, COUNT(*) as call_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/git-upload-pack%' OR LOWER(url_path) LIKE '%getsecretvalue%' OR LOWER(url_hostname) LIKE '%.s3.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_hostname HAVING call_count > 50 ORDER BY call_count DESC
```

## high-volume-outbound-flows
<!-- High-volume outbound flows to malicious IPs -->
Examine network flow logs for cumulative byte counts to malicious IPs, corroborating actual exfiltration of data.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, teampcp_exfil_ips=teampcp_exfil_ips)
~~~yaml
expected: Outbound flows cumulatively exceeding 1MB to an IOC IP. Silence proves no
  high-volume traffic to these specific indicators.
reads:
- device_hostname
- dst_endpoint_ip
- src_endpoint_ip
- state_kind
- time
- traffic_bytes
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes, COUNT(*) as flow_count FROM hb_network_connection WHERE state_kind = 'log' AND instr(',' || '{{teampcp_exfil_ips}}' || ',', ',' || LOWER(dst_endpoint_ip) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip HAVING SUM(traffic_bytes) > 1048576 ORDER BY total_bytes DESC
```

## triage-exfiltration
<!-- Triage Mass Exfiltration Verdict -->
```agent target=hunter
cite: required
context:
- auth-from-exfil-ips
- detect-legacy-git-ua
- massive-api-usage-by-ip
- high-volume-outbound-flows
max_iterations: 4
objective: Determine if the activity is consistent with TeamPCP's mass exfiltration
  tactics (T1041).
success_criteria: Verdicts of malicious, suspicious, or benign per user account or
  IP.
tools:
- identity
- network
- web
```

## route-verdict
<!-- Route based on triage -->
if~: "The triage verdict is malicious for one or more users/IPs" (confidence: high, judge=hunter)
then: → remediate-compromise
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-github-ip-logs)
else: → close-out

## remediate-compromise
<!-- Remediate Compromised Credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the identified compromised GitHub PAT or AWS Access Key. Initiate a global secret rotation for any credentials that were accessed during the exfiltration window.
```
→ analyst-review

## analyst-review
<!-- Post-Exfiltration Impact Analysis -->
```manual target=analyst
Review the full history of the compromised credentials. Identify all S3 objects and GitHub repositories accessed. Notify relevant application owners of the potential exposure.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Document the absence of exfiltration activity from the known TeamPCP IPs and UA strings.
```
→ end
