---
analysis: "A simple rule detects a password reset, but this hunt connects that reset\
  \ to automated Azure DevOps resource mapping and Kubernetes credential harvesting\u2014\
  a chain no single-surface rule can see."
blind_spots:
- id: mfa-registration-visibility
  question: what specific authentication method was registered by the actor
  requires: hb_account_change with mfa_method column
  risk: Legitimate SSPR followed by MFA registration may be indistinguishable from
    attacker takeover without method-level auditing.
  stage: identity-compromise-sspr
- id: git-content-visibility
  question: whether the files committed to the repository actually contained valid
    secrets
  requires: Git version history content auditing
  risk: Audit logs show the commit and filename but not the sensitive content, requiring
    manual review.
  stage: azure-devops-enumeration
coverage:
- stage: identity-compromise-sspr
  status: covered
  steps:
  - sspr-lead
  - analyze-sspr-lead
- stage: azure-devops-enumeration
  status: covered
  steps:
  - devops-enumeration-check
- stage: credential-harvesting-exfiltration
  status: covered
  steps:
  - kubeconfig-access-check
- reason: 'Belongs to another part of the ''\u200b\u200bBeyond source code: A path
    to the keys to the kingdom'' series.'
  stage: malicious-pipeline-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''\u200b\u200bBeyond source code: A path
    to the keys to the kingdom'' series.'
  stage: remote-access-tooling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Hijacked cloud identities provide a path to production environments
    that bypasses malware detection; monitoring SSPR and discovery activity is vital
    for supply chain protection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary hijacked a cloud identity using self-service password reset
  to perform automated discovery across Azure DevOps repositories and harvest Kubernetes
  configuration files.
labels:
- hunt
- attack.t1566
- attack.t1078
- attack.t1087
- attack.t1552.001
- command and control
- credential access
- discovery
- execution
- initial access
name: Cloud Identity Takeover and DevOps Enumeration
parameters:
  dev_tool_packages:
    default:
    - kubectl
    - azure-cli
    - docker
    - helm
    description: Package names indicating potential developer or cloud management
      infrastructure.
    type: list[string]
  kubeconfig_files:
    default:
    - kubeconfig
    - config
    - credentials
    description: Filenames associated with Kubernetes cluster configuration.
    from:
      kind: article
      observed: '2026-09-29'
      ref: msrc-beyond-source-code
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified as developer workstations or cloud management endpoints;
      paste results from the scoping query here.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt uses a software inventory query to focus file activity checks
  on hosts with developer tools, then uses SSPR activity as a cheap lead to justify
  deeper DevOps log analysis.
references:
- name: 'Beyond source code: A path to the keys to the kingdom'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
related:
- hunt: remote-access-tooling-in-dev-pipelines
  reason: The execution of Atera and Chisel within build agents is a separate stage
    of the campaign focusing on compute telemetry.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Identity Takeover via SSPR
    observables:
    - self-service password reset activity
    - registration of new authentication methods
    - MFA registration bypass
    slug: identity-compromise-sspr
    tactic: initial-access
    techniques:
    - T1566
    - T1078
  - name: Azure DevOps Environment Discovery
    observables:
    - enumeration of repositories, projects, pipelines, and deployment environments
    - automated scripts mapping cloud resources
    slug: azure-devops-enumeration
    tactic: discovery
    techniques:
    - T1087
    - T1018
  - name: Malicious Pipeline Deployment
    observables:
    - creation of malicious pipeline
    - deployment of kube agent
    - modification of pipeline scripts
    - execution of pipeline jobs to collect kubeconfig files
    slug: malicious-pipeline-execution
    tactic: execution
    techniques:
    - T1059
    - T1190
  - name: RMM and Tunneling Tooling
    observables:
    - Atera remote management agent installation
    - Chisel tunneling utility download
    - chisel commands establishing reverse tunnel to external IP
    slug: remote-access-tooling
    tactic: command-and-control
    techniques:
    - T1219
    - T1572
  - name: Kubernetes Credential Harvesting
    observables:
    - harvesting of kubeconfig files
    - addition of stolen kubeconfig files to a Git repository
    - Git version history modification
    slug: credential-harvesting-exfiltration
    tactic: credential-access
    techniques:
    - T1552.001
  summary: Storm-3068 compromised a user identity through a self-service password
    reset and registered their own MFA to gain persistent access. The actor pivoted
    to Azure DevOps to enumerate repositories and pipelines, then created a malicious
    pipeline to harvest Kubernetes credentials (kubeconfig) and establish remote access
    via Atera and Chisel protocol tunneling.
series:
  index: 1
  slug: beyond-source-code-a-path-to-the-keys-to-the-kingdom
  title: "\u200B\u200BBeyond source code: A path to the keys to the kingdom"
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


# Cloud Identity Takeover and DevOps Enumeration

Storm-3068 has been observed compromising accounts through self-service password reset (SSPR) to bypass traditional credentials. This hunt identifies the initial takeover in identity logs and then pivots into Azure DevOps audit logs to find high-volume enumeration of repositories and pipelines. Finally, it checks for the access of Kubernetes configuration files on developer workstations. The gated flow ensures that expensive cloud API and file-level queries only run when a suspicious account reset is detected, while the scoping step identifies critical developer infrastructure.

## scoping-dev-infrastructure
<!-- Scope developer infrastructure -->
Identify hosts that run cloud and Kubernetes management tools to focus endpoint file activity checks.

```sqlite target=endpoint role=scoping params=(dev_tool_packages=dev_tool_packages)
~~~yaml
expected: A list of hostnames belonging to developers or administrators. Silence means
  no relevant tools are installed.
reads:
- package_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE instr(',' || '{{dev_tool_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## sspr-lead
<!-- Identify suspicious password resets -->
Find accounts that performed a self-service password reset as a lead for identity takeover.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
expected: A list of accounts that reset their passwords. Silence proves no SSPR activity
  occurred in the window.
reads:
- user_name
- actor_user_name
- time
- activity_id
- provider
silence: evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT user_name, actor_user_name, time, activity_name FROM hb_account_change WHERE activity_id = 4 AND provider = 'm365' AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-sspr-lead
<!-- Analyze password reset patterns -->
```agent target=hunter
cite: required
context:
- sspr-lead
max_iterations: 3
objective: Determine if any account reset was performed by an unusual actor or exhibits
  patterns of identity hijacking.
success_criteria: A per-user verdict of suspicious for any identity with irregular
  reset patterns.
tools:
- endpoint
```

## gate-on-suspected-takeover
<!-- Gate on suspected identity takeover -->
if~: "the analyze-sspr-lead verdict is suspicious for at least one account" (confidence: high, judge=hunter)
then: → expensive-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: mfa-registration-visibility)
else: → close-out

## expensive-investigation
<!-- Parallel DevOps and credential check -->
parallel:
- → devops-enumeration-check
- → kubeconfig-access-check
join: → triage-intrusion-chain

## devops-enumeration-check
<!-- Azure DevOps resource enumeration -->
Identify accounts performing automated discovery across many repositories or pipelines.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An account mapping more than 5 DevOps objects in the window. Silence means
  no high-volume enumeration was detected.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 5
reads:
- actor_user_name
- api_operation
- resource_name
- time
- provider
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT actor_user_name, api_operation, COUNT(DISTINCT resource_name) AS res_count, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE provider = 'm365' AND (LOWER(api_operation) LIKE '%repository%' OR LOWER(api_operation) LIKE '%pipeline%' OR LOWER(api_operation) LIKE '%project%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation HAVING res_count > 5
```

## kubeconfig-access-check
<!-- Kubernetes credential harvesting -->
Find file activity involving Kubernetes configuration files on scoped developer hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, kubeconfig_files=kubeconfig_files)
~~~yaml
expected: Access events on kubeconfig files, particularly by the account identified
  in the lead. Silence means no such files were touched.
reads:
- device_hostname
- actor_user_name
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE instr(',' || '{{kubeconfig_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-intrusion-chain
<!-- Weigh the intrusion chain -->
```agent target=hunter
cite: required
context:
- analyze-sspr-lead
- devops-enumeration-check
- kubeconfig-access-check
max_iterations: 6
objective: Review the suspected identity reset and determine if it was followed by
  automated resource discovery and sensitive file harvesting.
success_criteria: A per-host and per-user verdict of malicious | suspicious | benign
  citing specific API operations and file paths.
tools:
- endpoint
```

## route-remediation
<!-- Route remediation -->
if~: "the triage-intrusion-chain verdict is malicious for at least one host and user" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: git-content-visibility)
else: → close-out

## isolate-identity
<!-- Isolate compromised identity -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the compromised user account in Entra ID, revoke all active Refresh Tokens, and reset the password.
```
→ secrets-rotation-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Manually review the cited rows and determine if the SSPR activity and subsequent DevOps calls constitute an intrusion. Rotate credentials for any confirmed account compromise.
```
→ secrets-rotation-review

## secrets-rotation-review
<!-- Secrets and Git history review -->
```manual target=analyst
Review the Git version history for the repositories identified in the DevOps enumeration. Specifically look for commits containing kubeconfig data and rotate all cluster credentials found within.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings, document the remediation steps taken, and update the detection tuning notes for SSPR activity.
```
→ end
