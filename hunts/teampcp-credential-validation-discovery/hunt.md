---
analysis: A standard rule might detect a single malicious IP or user agent; this hunt
  correlates the host-side presence of specific packages with the cloud-side behavior
  of credential validation and broad discovery, which allows for a much more confident
  triage of valid-account abuse.
blind_spots:
- id: missing-aws-audit-visibility
  question: which specific secrets or objects were accessed in S3 and Secrets Manager
  requires: detailed CloudTrail and aws_iam_access_advisor
  risk: While Access Advisor shows that a service was accessed, it does not detail
    which specific high-value secrets were retrieved, masking the extent of data exfiltration.
  stage: cloud-infrastructure-discovery
- id: ip-rotation-mullvad
  question: whether the adversary has rotated to a new VPN node not in the known list
  requires: fresh IP intelligence for VPN exit nodes
  risk: The prevalence check helps find rare IPs, but a sophisticated attacker rotating
    IPs rapidly may evade detection if the baseline is not sufficiently narrow.
  stage: credential-validation-trufflehog
coverage:
- stage: credential-validation-trufflehog
  status: covered
  steps:
  - rare-auth-origins
  - offensive-tool-traffic
- stage: cloud-infrastructure-discovery
  status: covered
  steps:
  - iam-service-recon
- reason: This stage focuses on the initial injection into the target repositories,
    which is covered by vulnerability scanning and artifact integrity hunts.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: github-workflow-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: container-command-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: bulk-data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: TeamPCP uses supply chain compromises to harvest secrets that are
    then validated and abused within hours. Identifying this enumeration phase prevents
    massive exfiltration of repository contents and database information.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary validates stolen cloud credentials and enumerates cloud infrastructure
  using offensive tools like TruffleHog or specialized Boto3 scripts following a supply
  chain compromise.
labels:
- hunt
- attack.t1078
- attack.t1087
- attack.t1082
- attack.t1083
- attack.t1090.003
- attack.t1195
name: TeamPCP Credential Validation and Discovery
parameters:
  compromised_principals:
    default: []
    description: Identities discovered in the authentication step to narrow the service
      access search.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for post-compromise activity.
    type: number
  scope_hosts:
    default: []
    description: Hostnames discovered in the inventory step to narrow the HTTP signature
      search.
    type: list[host]
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
    description: Known TeamPCP IP addresses and VPN exit nodes.
    from:
      kind: article
      observed: '2024-03-27'
      ref: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
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
rationale: First identify build servers, CI/CD runners, and developer workstations
  where Trivy or KICS might be installed. These are the highest probability targets
  for initial secret harvesting.
references:
- name: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  url: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
related:
- hunt: github-supply-chain-workflow-abuse
  reason: Abuse of GitHub Actions and PATs for code execution and repository cloning
    belongs to a sibling hunt focusing on the VCS plane.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Supply chain compromise of developer tools
    observables:
    - Malicious versions of Trivy, KICS, LiteLLM, and Telnyx packages
    - Injected code in GitHub Actions and container images
    - 'Targeted projects: Aqua Security Trivy, Checkmarx KICS, LiteLLM PyPI'
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: Automated credential validation via TruffleHog
    observables:
    - sts:GetCallerIdentity API calls
    - 'User agent: Trufflehog'
    - 'Source IPs: 105.245.181.120, 185.77.218.4, 209.159.147.239, 23.234.107.104,
      34.205.27.48'
    - Mullvad VPN exit nodes
    - InterServer VPS hosts
    slug: credential-validation-trufflehog
    tactic: initial-access
    techniques:
    - T1078
  - name: Cloud and identity enumeration
    observables:
    - 'IAM: ListUsers, ListRoles, ListAttachedUserPolicies'
    - 'EC2: DescribeInstances'
    - 'S3: ListBuckets, GetBucketPublicAccessBlock'
    - 'Secrets Manager: ListSecrets'
    - 'ECS: ListClusters, ListTaskDefinitions'
    - 'User agent: Boto3/1.42.73 md/Botocore#1.42.73 ua/2.1 os/linux#6.17.10+kali-amd64'
    - 'Resource names: pawn, massive-exfil'
    slug: cloud-infrastructure-discovery
    tactic: discovery
    techniques:
    - T1087
    - T1082
    - T1083
  - name: Malicious GitHub workflow execution
    observables:
    - Creation of pull requests with malicious workflows
    - 'Tool: Nord Stream'
    - 'Branch name: dev_remote_ea5Eu/test/v1'
    - Deletion of workflow logs
    - 'Source IP: 138.199.15.172'
    - 'Source IP: 163.245.223.12'
    slug: github-workflow-abuse
    tactic: persistence
    techniques:
    - T1059.007
  - name: Interactive container access via ECS Exec
    observables:
    - ExecuteCommand calls on ECS tasks
    - Execution of Bash commands and Python scripts via SSM Agent
    - Execution from SSMSession context
    slug: container-command-execution
    tactic: execution
    techniques:
    - T1609
  - name: Mass exfiltration from repositories and cloud storage
    observables:
    - Mass git.clone operations
    - 'User agent: git/2.43.0'
    - Bulk GetSecretValue from Secrets Manager
    - Bulk GetObject from S3 buckets
    - 'Source IP: 193.32.126.157'
    slug: bulk-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1021.001
  summary: TeamPCP conducts supply chain attacks against developer tools and libraries
    (Trivy, KICS, LiteLLM) to harvest cloud credentials and CI/CD secrets. Following
    theft, the actor rapidly validates credentials using TruffleHog and explores victim
    AWS and GitHub environments to exfiltrate bulk data or execute commands via ECS
    Exec and malicious workflows.
series:
  index: 1
  slug: tracking-teampcp-post-compromise-attacks-seen-in-the-wild
  title: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  total: 2
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


# TeamPCP Credential Validation and Discovery

The adversary validates stolen cloud credentials and enumerates cloud infrastructure using offensive tools like TruffleHog or Boto3 scripts. This hunt targets the early post-compromise activity of TeamPCP by identifying hosts running compromised software, then looks for signs of credential validation and broad AWS infrastructure enumeration. By correlating the presence of the compromised software with anomalous cloud-side activity and known malicious IPs, the analyst identifies where secrets have been harvested and used.

## find-potential-beachheads
<!-- Affected supply chain package inventory -->
Identify hosts that have the packages targeted by TeamPCP installed, as these are the likely sources of stolen credentials.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running the vulnerable scanners or libraries. The analyst
  uses the resulting hostnames to populate the scope_hosts parameter in the offensive-tool-traffic
  query.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) IN ('trivy', 'kics', 'litellm', 'telnyx')
```

## parallel-leads
<!-- Fan-out to cloud and network evidence -->
parallel:
- → rare-auth-origins
- → offensive-tool-traffic
- → iam-service-recon
join: → investigation-agent

## rare-auth-origins
<!-- Rare and known-bad authentication origins -->
Find authentications originating from the reported TeamPCP IPs or other rare sources that only access a few accounts.

```sqlite target=identity role=baseline params=(teampcp_ips=teampcp_ips, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: 1d
expected: Authentication attempts from TeamPCP IPs or suspicious one-off IPs. The
  analyst uses these identities to populate the compromised_principals parameter for
  service reconnaissance.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, actor_user_name, COUNT(*) AS auth_events, MIN(time) AS first_auth FROM hb_auth_signin WHERE (instr(',' || '{{teampcp_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR time >= datetime('now', '-1 days')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name HAVING auth_events > 0 ORDER BY auth_events DESC
```

## offensive-tool-traffic
<!-- TruffleHog and Kali tool signatures -->
Identify network traffic containing signatures of offensive tools used for credential validation, scoped to the vulnerable scanner hosts.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Direct hits on TruffleHog or Kali-based Boto3 user agents originating from
  hosts in the environment or reaching out to cloud APIs.
reads:
- device_hostname
- user_agent
- url_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_agent, url_hostname, src_endpoint_ip, time FROM hb_http_activity WHERE (LOWER(user_agent) LIKE '%trufflehog%' OR LOWER(user_agent) LIKE '%kali%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## iam-service-recon
<!-- AWS IAM service enumeration -->
Find AWS principals that have recently authenticated to multiple discovery-related services, specifically filtering for principals involved in the suspicious authentication events.

```sqlite target=aws role=enrichment params=(lookback_days=lookback_days, compromised_principals=compromised_principals)
~~~yaml
expected: A principal that has recently accessed several discovery services in a short
  window. The agent will weigh if this principal is also linked to suspicious IPs
  or user agents.
reads:
- principal_arn
- service_name
- last_authenticated
silence: not_evidence_of_absence
source: aws_iam_access_advisor
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT principal_arn, service_name, last_authenticated FROM aws_iam_access_advisor WHERE ('{{compromised_principals}}' = '' OR instr(',' || '{{compromised_principals}}' || ',', ',' || principal_arn || ',') > 0) AND last_authenticated >= datetime('now', '-{{lookback_days}} days') AND LOWER(service_name) IN ('iam', 'ec2', 's3', 'ecs', 'secretsmanager', 'lambda', 'rds', 'route53')
```

## investigation-agent
<!-- Triage validation and discovery -->
```agent target=hunter
cite: required
context:
- find-potential-beachheads
- rare-auth-origins
- offensive-tool-traffic
- iam-service-recon
max_iterations: 6
objective: Determine if any identities or hosts show signs of TeamPCP post-compromise
  activity, specifically looking for broad discovery (IAM, S3, Secrets Manager) linked
  to validation signatures or known-bad IPs.
success_criteria: A verdict of malicious | suspicious | benign per host/principal,
  citing specific rows for service enumeration and IP/UA matches.
tools:
- aws
- endpoint
- identity
- web
```

## route-on-triage
<!-- Route based on investigation verdict -->
if~: "the agent verdict is malicious for at least one AWS principal or host" (confidence: high, judge=hunter)
then: → revoke-compromised-identities
indeterminate: → manual-forensic-review
unavailable: → manual-forensic-review (blind_spot: missing-aws-audit-visibility)
else: → close-out

## revoke-compromised-identities
<!-- Revoke compromised IAM identities -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke the IAM access keys or temporary credentials for the principals identified by the agent. Disable the user or role until a full forensic audit is complete.
```
→ manual-forensic-review

## manual-forensic-review
<!-- Forensic audit of AWS activity -->
```manual target=analyst
Examine AWS CloudTrail for the identified principals. Look for high-volume S3 GetObject, SecretsManager GetSecretValue, and RDS snapshot events. Search for IPs outside the parameter list that exhibit the same pattern.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no evidence of TeamPCP post-compromise validation or discovery was found. Schedule a re-run for next month.
```
→ end
