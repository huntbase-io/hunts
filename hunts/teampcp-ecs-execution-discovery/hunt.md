---
analysis: A simple detection rule flags the SSM Agent spawning bash; this hunt adds
  prevalence across the fleet and correlates with script content analysis to distinguish
  legitimate management from 'bold' manual adversary sessions.
blind_spots:
- id: linux-script-logging-missing
  question: What specifically ran inside the shell scripts?
  requires: hb_script_activity from Linux (Auditd/eBPF)
  risk: Without script content, we rely on command lines, which may be truncated or
    just show 'bash'.
  stage: remote-execution-ecs-exec
- id: ssm-identity-blind-spot
  question: Which AWS IAM identity commanded the container?
  requires: AWS CloudTrail (ExecuteCommand)
  risk: Endpoint logs show the agent's work, but not the identity of the person controlling
    it from outside.
  stage: remote-execution-ecs-exec
coverage:
- stage: remote-execution-ecs-exec
  status: covered
  steps:
  - ssm-child-processes
  - rare-ssm-commands
  - script-recon-patterns
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: initial-access-supply-chain-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: credential-validation-trufflehog
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: cloud-discovery-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: lateral-movement-github-workflows
  status: out_of_scope
- reason: 'Belongs to another part of the ''Tracking TeamPCP: post-compromise attacks
    seen in the wild'' series.'
  stage: exfiltration-mass-data-retrieval
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: TeamPCP uses ECS Exec to pivot from static credentials to runtime
    control. This hunt covers the last stage of the attack chain before exfiltration,
    providing a negative result for active interactive exploitation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging stolen cloud credentials to gain interactive
  container access via the AWS SSM Agent (ECS Exec) to perform discovery and exfiltrate
  secrets.
labels:
- hunt
- attack.t1610
- attack.t1059.004
- attack.t1059.006
- attack.t1078.004
name: 'TeamPCP: ECS Execution and Container Discovery'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-03-27'
      ref: Standard hunt window
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty for
      the full estate.
    type: list[host]
  ssm_agent_patterns:
    default:
    - amazon-ssm-agent
    - ssm-agent-worker
    description: Process names associated with the AWS SSM Agent used for ECS Exec.
    from:
      kind: article
      observed: '2024-03-27'
      ref: AWS SSM Agent Documentation
    type: list[string]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on AWS accounts with high-traffic ECS clusters or those where Trivy/KICS
  are integrated into CI/CD pipelines.
references:
- name: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
  url: https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild
related:
- hunt: teampcp-cloud-credential-recon
  reason: This hunt focuses on runtime/container execution; the sibling hunt targets
    the cloud-level API reconnaissance.
  relation: out-of-scope-alternative
- hunt: anomalous-cloud-identity-api-abuse-teampcp
  relation: follows
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
  index: 2
  slug: tracking-teampcp-post-compromise-attacks-seen-in-the-wild
  title: 'Tracking TeamPCP: post-compromise attacks seen in the wild'
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
tlp: clear
type: investigation
---


# TeamPCP: ECS Execution and Container Discovery

This hunt targets the runtime behavior of the TeamPCP threat actor within ECS container environments. After obtaining cloud credentials through supply chain compromises, the group utilizes the Amazon SSM Agent ('ECS Exec') to spawn shells directly on containers. This hunt identifies the SSM agent presence, detects unusual shell and Python processes spawned by the agent, and analyzes script execution patterns for characteristic reconnaissance commands and exfiltration scripts reported in recent attacks.

## identify-ssm-agent-inventory
<!-- Identify hosts with SSM Agent installed -->
Identify container hosts capable of supporting ECS Exec, providing a scope for the runtime hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where the SSM agent is present. This narrows the search
  to potential targets for TeamPCP's interactive container execution.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%ssm-agent%'
```

## ssm-child-processes
<!-- Interpreters spawned by the SSM Agent -->
Detect the core mechanism of ECS Exec: the agent spawning a shell or interpreter for an interactive session.

```sqlite target=endpoint role=detection-candidate params=(ssm_agent_patterns=ssm_agent_patterns, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Interactive shells or Python processes running under the SSM agent's context.
  This indicates an ECS Exec session is or was active.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE instr(',' || '{{ssm_agent_patterns}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND (LOWER(process_name) IN ('bash', 'sh', 'python', 'python3') OR LOWER(process_cmd_line) LIKE '%python%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Parallel Evidence Gathering -->
parallel:
- → rare-ssm-commands
- → script-recon-patterns
join: → triage-execution

## rare-ssm-commands
<!-- Rare command lines from SSM Agent -->
Highlight manual, one-off execution that deviates from standard automated management scripts.

```sqlite target=endpoint role=baseline params=(ssm_agent_patterns=ssm_agent_patterns, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One-off commands like 'pawn' or 'massive-exfil' as reported for TeamPCP,
  appearing on only a few hosts.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{ssm_agent_patterns}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING host_count <= 2 ORDER BY host_count ASC
```

## script-recon-patterns
<!-- Script content recon and exfiltration -->
Analyze the text of scripts running inside containers to confirm discovery and exfiltration tradecraft.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks performing cloud discovery. This confirms the 'why' behind
  the SSM session.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%get-caller-identity%' OR LOWER(script_content) LIKE '%list-secrets%' OR LOWER(script_content) LIKE '%boto3%' OR LOWER(script_content) LIKE '%describe-instances%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-execution
<!-- Triage Container Execution -->
```agent target=hunter
cite: required
context:
- ssm-child-processes
- rare-ssm-commands
- script-recon-patterns
max_iterations: 4
objective: Determine if the SSM activity on the identified hosts indicates an interactive
  session by TeamPCP. Look for AWS discovery commands, Python boto3 reconnaissance,
  and command lines that deviate from standard automated DevOps workflows.
success_criteria: A clear verdict of malicious, suspicious, or benign per host.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-container
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: linux-script-logging-missing)
else: → analyst-review

## isolate-container
<!-- Isolate Host/Container -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate any active SSM sessions and revoke the IAM credentials associated with the container's execution role.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited rows for the malicious verdict. Cross-reference with AWS CloudTrail to identify the authenticated identity that initiated the SSM session.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the affected containers and any discovered secrets. Update detection rules with any new unique command-line patterns found.
```
→ end
