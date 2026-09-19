---
analysis: Correlates malicious IP activity with vulnerable tool inventory and stack-counts
  offensive user-agents, providing context a single rule cannot provide.
blind_spots:
- id: no-cloud-audit-logs
  question: whether the principal successfully accessed specific secret values
  requires: CloudTrail / Cloud audit logging
  risk: We see the discovery attempt but not the successful data theft.
  stage: cloud-discovery-enumeration
- id: endpoint-visibility
  question: whether TruffleHog was run from non-enrolled ephemeral runners
  requires: HTTP visibility on CI/CD runners
  risk: If runners are not enrolled, the process/HTTP evidence is lost.
  stage: credential-validation-trufflehog
coverage:
- stage: initial-access-supply-chain-injection
  status: covered
  steps:
  - vulnerable-software-inventory
- stage: credential-validation-trufflehog
  status: covered
  steps:
  - offensive-tool-user-agents
- stage: cloud-discovery-enumeration
  status: covered
  steps:
  - aws-enumeration-activity
- stage: lateral-movement-github-workflows
  status: covered
  steps:
  - offensive-tool-user-agents
- stage: exfiltration-mass-data-retrieval
  status: covered
  steps:
  - dns-exfiltration-corroboration
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: remote-execution-ecs-exec
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Valid credentials harvested via supply chain bypass perimeter controls;
    hunting for post-compromise validation and enumeration is required for early detection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging credentials stolen through DevOps supply-chain
  injections to perform rapid automated secret validation and cloud discovery from
  known VPN/VPS hosting nodes.
labels:
- hunt
- attack.t1195
- attack.t1078
- attack.t1526
- attack.t1087
- attack.t1041
name: Anomalous Cloud Identity and API Abuse (TeamPCP)
parameters:
  lookback_days:
    default: '14'
    description: Days of historical activity to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames found in the scoping step; leave empty for all
      estate.
    type: list[host]
  supply_chain_packages:
    default:
    - trivy
    - kics
    - litellm
    - telnyx
    description: Packages targeted for supply chain injection.
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
    description: IP addresses associated with TeamPCP validation and discovery nodes.
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
rationale: Start with developer workstations and CI/CD runners where Trivy, KICKS,
  or LiteLLM are deployed. Focus on the 14-day window following disclosures on March
  19.
references:
- name: "Wiz \u2014 Tracking TeamPCP: post-compromise attacks seen in the wild"
  url: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
related:
- hunt: teampcp-runtime-execution-ecs
  reason: This hunt focuses on API abuse; the sibling hunt covers ECS runtime execution.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Supply chain compromise
    observables:
    - Trivy binary
    - KICS GitHub Action
    - LiteLLM PyPI package
    - Telnyx Python package
    slug: initial-access-supply-chain-injection
    tactic: initial-access
    techniques:
    - T1195
  - name: Secret validation via TruffleHog
    observables:
    - 'User-Agent: Trufflehog'
    - 'API call: sts:GetCallerIdentity'
    - 'IP: 105.245.181.120'
    - 'IP: 185.77.218.4'
    - 'IP: 209.159.147.239'
    - 'IP: 23.234.107.104'
    - 'IP: 34.205.27.48'
    slug: credential-validation-trufflehog
    tactic: discovery
    techniques:
    - T1078
    - T1526
  - name: AWS environment enumeration
    observables:
    - 'IAM: ListUsers'
    - 'IAM: ListRoles'
    - 'EC2: DescribeInstances'
    - 'Lambda: ListFunctions'
    - 'S3: ListBuckets'
    - 'ECS: ListClusters'
    - 'User-Agent: Boto3/1.42.73 (Kali Linux)'
    - 'IP: 154.47.29.12'
    - 'IP: 170.62.100.245'
    slug: cloud-discovery-enumeration
    tactic: discovery
    techniques:
    - T1526
    - T1087
  - name: Abuse of GitHub Workflows
    observables:
    - 'Tool: Nord Stream'
    - 'Branch: dev_remote_ea5Eu/test/v1'
    - 'Action: Workflow log deletion'
    - 'IP: 138.199.15.172'
    - 'IP: 163.245.223.12'
    slug: lateral-movement-github-workflows
    tactic: lateral-movement
    techniques:
    - T1078
    - T1195
  - name: Interactive container access
    observables:
    - ECS Exec (SSM Agent)
    - Bash commands on containers
    - Python scripts on containers
    - SSMSession context tag
    slug: remote-execution-ecs-exec
    tactic: execution
    techniques:
    - T1610
    - T1059
  - name: Bulk data exfiltration
    observables:
    - git clone
    - 'User-Agent: git/2.43.0'
    - 'Domain: git.clone'
    - 'S3: GetObject'
    - 'SecretsManager: GetSecretValue'
    - 'IP: 193.32.126.157'
    slug: exfiltration-mass-data-retrieval
    tactic: exfiltration
    techniques:
    - T1041
    - T1567
  summary: The TeamPCP campaign involves supply chain attacks on open-source projects
    like Trivy and LiteLLM to harvest cloud and CI/CD credentials. Stolen secrets
    are validated with TruffleHog and used for extensive cloud discovery, lateral
    movement via GitHub workflows, and data exfiltration from S3 and private repositories.
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


# Anomalous Cloud Identity and API Abuse (TeamPCP)

Following the compromise of Trivy, KICKS, and LiteLLM, the TeamPCP group utilizes harvested secrets to validate access and enumerate cloud services. This hunt identifies hosts with targeted DevOps tools, identifies authentication from known adversary infrastructure (Mullvad, InterServer), and correlates this with the use of offensive tools like TruffleHog and Nord Stream across cloud and GitHub surfaces. It specifically pivots from identified suspicious software footprints to reduce noise from legitimate automation.

## vulnerable-software-inventory
<!-- Identify potentially compromised tools -->
Identify hosts where the targeted DevOps packages are installed to define the potential blast radius.

```sqlite target=endpoint role=scoping params=(supply_chain_packages=supply_chain_packages)
~~~yaml
expected: Hosts running Trivy, KICKS, or LiteLLM. This defines the initial scope.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (instr(',' || '{{supply_chain_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%trivy%' OR LOWER(package_name) LIKE '%litellm%')
```

## parallel-investigation
<!-- Parallel investigation -->
parallel:
- → auth-from-teampcp-nodes
- → offensive-tool-user-agents
- → aws-enumeration-activity
- → dns-exfiltration-corroboration
join: → triage-activity

## auth-from-teampcp-nodes
<!-- Auth from known adversary nodes -->
Detect sign-ins to cloud or GitHub services originating from the Mullvad or InterServer IPs listed in the research.

```sqlite target=identity role=detection-candidate params=(teampcp_ips=teampcp_ips, lookback_days=lookback_days)
~~~yaml
expected: Sign-ins from IPs used by TeamPCP. This is a high-confidence indicator of
  valid account abuse.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, time FROM hb_auth_signin WHERE instr(',' || '{{teampcp_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## offensive-tool-user-agents
<!-- TruffleHog and Nord Stream signatures -->
Locate automated validation tools and malicious GitHub management tools via HTTP user-agents, scoped to vulnerable hosts.

```sqlite target=web role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: HTTP activity matching offensive tool agents on scoped hosts.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 5
reads:
- device_hostname
- user_agent
- url_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_agent, url_hostname, MIN(time) as first_seen, COUNT(*) as count FROM hb_http_activity WHERE (LOWER(user_agent) LIKE '%trufflehog%' OR LOWER(user_agent) LIKE '%nord stream%' OR user_agent LIKE 'git/2.43.0%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_agent, url_hostname
```

## aws-enumeration-activity
<!-- AWS Internal discovery patterns -->
Identify IAM principals accessing multiple management services in a short window, indicative of TeamPCP's discovery phase.

```sqlite target=aws role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Principals accessing a wide range of sensitive AWS services (IAM, S3, SecretsManager)
  within the hunt window.
reads:
- principal_arn
- service_name
- last_authenticated
silence: not_evidence_of_absence
source: aws_iam_access_advisor
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT principal_arn, COUNT(DISTINCT service_name) as service_count, GROUP_CONCAT(DISTINCT service_name) as services, MAX(last_authenticated) as last_seen FROM aws_iam_access_advisor WHERE last_authenticated >= datetime('now', '-{{lookback_days}} days') AND service_name IN ('iam', 'secretsmanager', 's3', 'ecs', 'lambda', 'rds', 'route53') GROUP BY principal_arn HAVING service_count >= 3 ORDER BY service_count DESC
```

## dns-exfiltration-corroboration
<!-- DNS queries to exfiltration targets -->
Corroborate exfiltration activity by identifying queries to domains named in the research, scoped to vulnerable hosts.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Queries to 'git.clone' or researcher-identified domains from scoped hosts.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (LOWER(query_hostname) = 'git.clone' OR LOWER(query_hostname) = 'kudelskisecurity.com') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-activity
<!-- Synthesize post-compromise activity -->
```agent target=hunter
cite: required
context:
- vulnerable-software-inventory
- auth-from-teampcp-nodes
- offensive-tool-user-agents
- aws-enumeration-activity
- dns-exfiltration-corroboration
max_iterations: 6
objective: 'Identify principals or hosts that show a confluence of: 1) Presence of
  targeted software (Trivy/KICS), 2) Auth from TeamPCP IPs, and 3) AWS enumeration
  or offensive tool HTTP signatures.'
success_criteria: A verdict of 'malicious' for principals with direct IP/Tooling matches.
tools:
- aws
- endpoint
- identity
- web
```

## evaluate-verdict
<!-- Evaluate verdict -->
if~: "the triage verdict is malicious for at least one host or IAM principal" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-audit-logs)
else: → close-out

## isolate-and-revoke
<!-- Revoke keys and isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Revoke AWS Access Keys and GitHub PATs for the identified principal. Isolate the hosts identified in the scoping step.
```
→ analyst-review

## analyst-review
<!-- Review exfiltration extent -->
```manual target=analyst
Review GitHub Audit logs for 'git.clone' and CloudTrail for 'GetSecretValue' by the compromised principal.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record results and baseline normal user-agent activity.
```
→ end
