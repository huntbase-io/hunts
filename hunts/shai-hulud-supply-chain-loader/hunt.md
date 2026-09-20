---
analysis: A single rule might catch the specific gh-token-monitor name, but this hunt
  pivots across hook configuration files, daemonization flags, and stack-counts rare
  process command lines to identify the framework as indicators rotate.
blind_spots:
- id: lead-data-not-available
  question: whether hook files were created on hosts not enrolled in the endpoint
    agent
  requires: hb_file_activity with full endpoint coverage
  risk: A host without file telemetry can silently host a poisoned repository that
    triggers the framework when accessed via an IDE.
  stage: initial-access-supply-chain-poisoning
- id: incomplete-telemetry
  question: whether the framework establishes persistence via a technique or name
    not listed in research
  requires: hb_scheduled_job and hb_process_activity
  risk: If the attacker rotates the persistence daemon name from gh-token-monitor,
    it may be missed unless the rare-processes query catches it.
  stage: persistence-daemon-and-deadman-monitor
coverage:
- stage: initial-access-supply-chain-poisoning
  status: covered
  steps:
  - shai-hulud-hook-leads
- stage: execution-loader-bootstrap
  status: covered
  steps:
  - rare-daemonized-processes
- stage: persistence-daemon-and-deadman-monitor
  status: covered
  steps:
  - token-monitor-persistence
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-memory-and-file-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: discovery-cloud-infrastructure-enumeration
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: c2-encrypted-communications
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: exfiltration-github-dead-drops
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: impact-destructive-wipe
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Shai-Hulud framework use of IDE and AI assistant hooks targets
    high-trust developer environments to harvest secrets with low visibility; a negative
    result over the developer estate is worth having.
  methodology: model-assisted
  trigger: intel-report
hypothesis: The adversary poisons a developer repository or AI coding assistant configuration
  to execute the Shai-Hulud loader and establish daemonized persistence.
labels:
- hunt
- attack.t1195
- attack.t1133
- attack.t1059.004
- attack.t1059.007
- attack.t1543.001
- attack.t1543.002
name: Shai-Hulud Framework Supply Chain Hook and Loader Bootstrap
parameters:
  loader_files:
    default:
    - setup.mjs
    - config.mjs
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - router_init.js
    - opensearch_init.js
    description: Stage-1 loader filenames identified in Shai-Hulud framework research.
    from:
      kind: article
      observed: '2026-05-12'
      ref: shai-hulud-framework-analysis
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the lead query to scope subsequent fanned-out
      queries.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope to developer workstations and CI/CD runner environments first. Use
  the hosts found in shai-hulud-hook-leads to populate the scope_hosts parameter for
  subsequent queries.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-credential-and-cloud-harvesting
  reason: This hunt focuses on the initial staging; the next hunt in the series addresses
    secret harvesting from memory and cloud infrastructure.
  relation: follows
scenario:
  stages:
  - name: Supply Chain Poisoning & Repository Hijacking
    observables:
    - hijacked Trivy and Checkmarx KICS tags
    - poisoned LiteLLM, TanStack, and UiPath npm/PyPI packages
    - '.vscode/tasks.json with runOn: folderOpen'
    - .claude/settings.json SessionStart hook
    - claude@users.noreply.github.com
    slug: initial-access-supply-chain-poisoning
    tactic: initial-access
    techniques:
    - T1195
    - T1133
  - name: Multi-language Loader Execution
    observables:
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - config.mjs
    - setup.mjs
    - router_init.js
    - opensearch_init.js
    - node .claude/setup.mjs
    - Bun runtime download
    slug: execution-loader-bootstrap
    tactic: execution
    techniques:
    - T1059.004
    - T1059.007
  - name: Daemonized Persistence & Token Monitoring
    observables:
    - /tmp/tmp.ts018051808.lock
    - ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
    - ~/.config/systemd/user/gh-token-monitor.service
    - loginctl enable-linger
    - __DAEMONIZED=1
    slug: persistence-daemon-and-deadman-monitor
    tactic: persistence
    techniques:
    - T1543.001
    - T1543.002
  - name: Memory Secret Extraction & Credential Harvesting
    observables:
    - Runner.Worker
    - /proc/*/mem scanning
    - gh auth token
    - ~/.aws/credentials
    - ~/.azure/accessTokens.json
    - ~/.config/gcloud/credentials.db
    - ~/.kube/config
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - .npmrc
    - .pypirc
    - .claude.json
    slug: credential-access-memory-and-file-harvesting
    tactic: credential-access
    techniques:
    - T1003.001
    - T1552.001
    - T1555
  - name: Cloud and K8s Secret Discovery
    observables:
    - AWS Secrets Manager enumeration
    - SSM Parameter Store enumeration
    - Kubernetes namespace listing
    - HashiCorp Vault KV mount enumeration
    slug: discovery-cloud-infrastructure-enumeration
    tactic: discovery
    techniques:
    - T1580
    - T1082
  - name: Encrypted Domain-based C2
    observables:
    - git-tanstack[.]com
    - thebeautifulmarchoftime GitHub commit search
    - RSA-4096-OAEP
    - AES-256-GCM
    slug: c2-encrypted-communications
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: GitHub Dead-drop Exfiltration
    observables:
    - 'Shai-Hulud: Here We Go Again repository description'
    - Dune-themed repo names (sardaukar, mentat, stillsuit)
    - results/ directory JSON commits
    - IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner
    slug: exfiltration-github-dead-drops
    tactic: exfiltration
    techniques:
    - T1567.001
  - name: Conditional Data Destruction
    observables:
    - rm -rf ~/
    - HTTP 40x response from https://api.github.com/user
    slug: impact-destructive-wipe
    tactic: impact
    techniques:
    - T1485
  summary: The Shai-Hulud framework by TeamPCP is a modular TypeScript toolkit that
    targets CI/CD pipelines and developer workstations through supply chain poisoning
    of npm/PyPI packages and IDE configurations. It extracts credentials from process
    memory, cloud environments, and local files before exfiltrating encrypted data
    to C2 domains or GitHub dead-drop repositories, featuring a 'deadman switch' that
    wipes the user directory if stolen tokens are revoked.
series:
  index: 1
  slug: shai-hulud-open-source-framework-static-analysis
  title: Shai-Hulud open source framework static analysis
  total: 3
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


# Shai-Hulud Framework Supply Chain Hook and Loader Bootstrap

The adversary poisons a developer repository or AI coding assistant configuration to execute the Shai-Hulud loader and establish daemonized persistence. This hunt identifies the entry points and local staging of a Shai-Hulud framework infection. It targets supply chain hooks in IDE and AI assistant configurations, specifically VSCode and Claude Code, which trigger the framework modular loaders. If the query finds leads, the hunt fans out to investigate daemonized process execution and the installation of GitHub token-monitoring persistence. The gated flow ensures that the analyst only queries expensive process and job telemetry for hosts showing early indicators of compromise.

## shai-hulud-hook-leads
<!-- Supply Chain Hook and Loader Leads -->
The query identifies creation of framework loaders or modifications to IDE/AI tool configuration hooks.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, loader_files=loader_files)
~~~yaml
expected: Any creation of loaders or modifications to VSCode/Claude settings in developer
  directories represents a lead. Silence suggests no active hook-based staging via
  these known paths.
reads:
- device_hostname
- file_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, activity_name, time FROM hb_file_activity WHERE (instr(',' || '{{loader_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR LOWER(file_path) LIKE '%/.vscode/tasks.json' OR LOWER(file_path) LIKE '%/.claude/settings.json') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Hook Leads -->
```agent target=hunter
cite: required
context:
- shai-hulud-hook-leads
max_iterations: 3
objective: Determine if file activity in shai-hulud-hook-leads represents the initial
  staging of the Shai-Hulud framework by matching paths and names to the article.
success_criteria: A verdict indicating if the leads are suspicious enough to open
  expensive queries.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Proceed to Full Investigation -->
if~: "the lead activity suggests the staging of a Shai-Hulud framework component" (confidence: high, judge=hunter)
then: → investigate-execution-and-persistence
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: lead-data-not-available)
else: → close-out

## investigate-execution-and-persistence
<!-- Investigate Execution and Persistence -->
parallel:
- → rare-daemonized-processes
- → token-monitor-persistence
join: → final-triage

## rare-daemonized-processes
<!-- Rare Daemonized Framework Execution -->
The query finds rare processes running with the framework daemonization flag or lock file references.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A command line seen on only one or two hosts containing the daemonization
  flag. Silence proving absence is only possible if all hosts report process telemetry.
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
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%__daemonized=1%' OR LOWER(process_cmd_line) LIKE '%tmp.ts018051808.lock%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count < 3
```

## token-monitor-persistence
<!-- GitHub Token Monitoring Persistence -->
The query searches for LaunchAgents, systemd services, or linger settings used for token-revocation monitoring.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Persistence entries matching the framework monitor daemon names. Silence
  means the specific persistence component may be rotated or missing.
reads:
- device_hostname
- job_name
- job_definition_path
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%gh-token-monitor%' OR LOWER(job_definition_path) LIKE '%gh-token-monitor%' OR LOWER(job_cmd_line) LIKE '%loginctl enable-linger%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final Triage of Framework Infection -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- rare-daemonized-processes
- token-monitor-persistence
max_iterations: 6
objective: Determine if a host is compromised by the Shai-Hulud framework by weighing
  the combined evidence from hooks, rare processes, and monitor daemons.
success_criteria: A final verdict of malicious | suspicious | benign per host with
  citations.
tools:
- endpoint
```

## route-verdict
<!-- Route Final Verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## contain-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do NOT revoke stolen GitHub tokens until the deadman monitor process is killed to prevent the handler from executing 'rm -rf'. Capture memory for secrets analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the identified hook files and the Rare Daemonized Processes query. Confirm if findings represent a variant of the Shai-Hulud framework and update tuning notes.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document the hosts examined. If no indicators were found, record evidence of absence for the known Shai-Hulud staging components.
```
→ end
