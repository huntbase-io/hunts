---
analysis: A simple detection rule on the npm package version is easily bypassed by
  the worm's propagation. This hunt pivots between software inventory, process runtime
  prevalence (Bun), and subsequent behavioral indicators like file harvest and proc-fs
  scraping to find the worm even after packages rotate.
blind_spots:
- id: limited-process-memory-visibility
  question: Whether the Runner.Worker memory was successfully read by a non-standard
    process.
  requires: EDR memory-access telemetry or Sysmon for Linux with Event ID 10
  risk: Without memory-access logs, we rely on the command-line presence of procfs
    strings, which the adversary could obfuscate or perform via a binary that does
    not use a shell helper.
  stage: ci-runner-memory-access
- id: short-lived-runners
  question: If the worm executed on a runner that was destroyed before logs were shipped.
  requires: Real-time process logs from ephemeral containers
  risk: Ephemeral CI runners may not persist logs to a central sink in time for the
    hunt to see the hook execution if the job finishes quickly.
  stage: npm-lifecycle-hook-execution
coverage:
- stage: npm-supply-chain-compromise
  status: covered
  steps:
  - affected-npm-packages
- stage: npm-lifecycle-hook-execution
  status: covered
  steps:
  - dropper-execution
- stage: portable-runtime-dropper
  status: covered
  steps:
  - bun-prevalence
- stage: credential-and-environment-sweep
  status: covered
  steps:
  - credential-sweep
- stage: ci-runner-memory-access
  status: covered
  steps:
  - memory-scraping
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: developer-tooling-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: blockchain-c2-routing
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: automated-package-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: ChainDrop is a high-velocity supply chain attack targeting the root
    of developer trust; identifying its presence on workstations and runners is essential
    to prevent large-scale credential theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has infected an npm package and triggered a preinstall hook
  that uses the Bun runtime to harvest credentials from the filesystem and CI runner
  process memory.
labels:
- hunt
- attack.t1195.002
- attack.t1059.003
- attack.t1105
- attack.t1552.001
- attack.t1555
- attack.t1003.001
name: 'ChainDrop: NPM Worm Endpoint and CI Runner Activity'
parameters:
  infected_packages:
    default:
    - keyv
    - cacheable-request
    description: NPM packages known to have been trojanized by ChainDrop.
    from:
      kind: article
      observed: '2026-08-06'
      ref: unit42-chaindrop
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on; leave empty for
      fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize development workstations and CI/CD runner environments where
  npm packages are frequently installed and updated.
references:
- name: 'ChainDrop: Inside a Self-Propagating npm Worm'
  url: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
related:
- hunt: chaindrop-persistence-and-propagation
  reason: This hunt identifies the initial execution and harvest; persistence in VS
    Code and Claude Code, and automated propagation, are handled in the follow-on
    hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Trojanized npm Package Installation
    observables:
    - registry.npmjs.org
    - keyv
    - cacheable-request
    slug: npm-supply-chain-compromise
    tactic: initial-access
    techniques:
    - T1195.002
  - name: NPM Preinstall Hook Execution
    observables:
    - preinstall
    - node setup.mjs
    slug: npm-lifecycle-hook-execution
    tactic: execution
    techniques:
    - T1059.003
  - name: Bun Runtime Dropper and Payload Execution
    observables:
    - setup.mjs
    - math_init.js
    - Bun 1.3.13
    - Oven GitHub repository
    - _NODE_RUNTIME_INIT=1
    slug: portable-runtime-dropper
    tactic: execution
    techniques:
    - T1105
  - name: Filesystem and Environment Credential Harvest
    observables:
    - .env
    - .git-credentials
    - .netrc
    - SSH keys
    - npm tokens
    - GitHub tokens
    - Kubernetes service-account tokens
    slug: credential-and-environment-sweep
    tactic: credential-access
    techniques:
    - T1552.001
    - T1555
  - name: CI Runner Process Memory Scraping
    observables:
    - Runner.Worker
    - /proc/pid/maps
    - /proc/pid/mem
    - OIDC tokens
    slug: ci-runner-memory-access
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Persistence via VS Code and Claude Code Hooks
    observables:
    - .vscode/tasks.json
    - .claude/settings.json
    - Environment Setup
    - SessionStart
    - .claude/math_init.js
    - com.user.gh-token-monitor
    - gh-token-monitor.service
    slug: developer-tooling-persistence
    tactic: persistence
    techniques:
    - T1546
  - name: Ethereum Smart Contract C2 Resolution
    observables:
    - Ethereum transaction
    - blockchain-based C2 resolution
    slug: blockchain-c2-routing
    tactic: command-and-control
    techniques:
    - T1102
  - name: Worm Propagation via Package Republishing
    observables:
    - 'Shai-Hulud: Here We Go Again'
    - .github/workflows/codeql_analysis.yml
    - npm:registry.npmjs.org
    - release-drafter.yml
    - /opensearch-js
    slug: automated-package-propagation
    tactic: lateral-movement
    techniques:
    - T1534
    - T1574.006
  summary: ChainDrop is a self-propagating npm worm that infects developer environments
    via trojanized package lifecycle hooks to harvest cloud credentials, SSH keys,
    and CI runner secrets. It persists through cross-linked VS Code and AI tool configurations
    and uses Ethereum smart contracts for C2 routing to spread by republishing infected
    versions of legitimate packages.
series:
  index: 1
  slug: chaindrop-inside-a-self-propagating-npm-worm
  title: 'ChainDrop: Inside a Self-Propagating npm Worm'
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


# ChainDrop: NPM Worm Endpoint and CI Runner Activity

ChainDrop is a self-propagating worm that spreads by trojanizing npm packages and hijacking the preinstall lifecycle hook. It uses a legitimate portable runtime, Bun, as an execution vehicle to evade standard Node.js instrumentation. Once running, the worm sweeps the filesystem for developer credentials and scrapes GitHub Actions runner memory for OIDC tokens and runner secrets. This hunt focuses on the initial execution of the worm on developer endpoints and CI runners. It identifies affected hosts via software inventory, detects the presence of the Bun-based dropper, and corroborates the activity by looking for unauthorized access to sensitive credential files and Linux process memory associated with CI agents.

## affected-npm-packages
<!-- Affected npm packages in inventory -->
Identify hosts that have the trojanized npm packages installed in their development environments.

```sqlite target=endpoint role=scoping params=(infected_packages=infected_packages)
~~~yaml
expected: A list of hostnames and paths where the vulnerable packages are installed.
  Silence indicates the packages are not present in the reported inventory.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE package_type = 'npm' AND instr(',' || '{{infected_packages}}' || ',', ',' || package_name || ',') > 0
```

## early-parallel
<!-- Early execution and runtime check -->
parallel:
- → dropper-execution
- → bun-prevalence
join: → triage-initial

## dropper-execution
<!-- Dropper and lifecycle hook execution -->
Detect the execution of setup.mjs or the specific environment variable used by the worm to prevent recursion.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process command lines referencing the dropper file or the worm's internal
  state variable. This confirms the malicious hook fired.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%setup.mjs%' OR LOWER(process_cmd_line) LIKE '%math_init.js%' OR LOWER(process_cmd_line) LIKE '%_node_runtime_init%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## bun-prevalence
<!-- Rare Bun runtime execution -->
Identify hosts running the Bun runtime, which the worm uses as a portable dropper to evade standard Node instrumentation.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous execution of the Bun binary. Since it is less common than Node.js
  in many environments, stack-counting helps find the beachhead.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%bun%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3
```

## triage-initial
<!-- Evaluate initial execution -->
```agent target=hunter
cite: required
context:
- affected-npm-packages
- dropper-execution
- bun-prevalence
max_iterations: 3
objective: Determine if the setup.mjs dropper or Bun runtime was triggered on hosts
  that also contain the trojanized npm packages.
success_criteria: A list of hosts with confirmed execution, citing command lines and
  package inventory.
tools:
- endpoint
```

## impact-parallel
<!-- Follow-on impact triage -->
parallel:
- → credential-sweep
- → memory-scraping
join: → final-assessment

## credential-sweep
<!-- Credential file harvest -->
Identify instances where Node or Bun processes access sensitive files like .env, .npmrc, or SSH keys.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File activity showing the worm's runtime accessing credential stores. Silence
  suggests no broad sweep occurred or was captured.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%.env%' OR LOWER(file_path) LIKE '%.npmrc%' OR LOWER(file_path) LIKE '%.git-credentials%' OR LOWER(file_path) LIKE '%/.ssh/%') AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## memory-scraping
<!-- CI Runner process memory scraping -->
Detect the worm accessing the memory of the GitHub Actions Runner worker to steal OIDC tokens.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines showing Python or Shell helpers reading the Linux proc filesystem
  for the GitHub runner process. This is a high-confidence indicator of ChainDrop
  impact on CI infrastructure.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%runner.worker%' AND (LOWER(process_cmd_line) LIKE '%/proc/%/maps%' OR LOWER(process_cmd_line) LIKE '%/proc/%/mem%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-assessment
<!-- Confirm credential theft and impact -->
```agent target=hunter
cite: required
context:
- triage-initial
- credential-sweep
- memory-scraping
max_iterations: 5
objective: Analyze the file access and memory scraping activity in the context of
  the initial dropper execution to verify if ChainDrop successfully harvested credentials.
success_criteria: A per-host verdict of malicious if the chain from infected package
  to file or memory harvest is complete.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-process-memory-visibility)
else: → close-out

## isolate-and-remediate
<!-- Isolate and remediate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint, terminate the Bun and Node processes identified by the agent, and delete the malicious files: .claude/math_init.js, .claude/settings.json, .claude/setup.mjs, .vscode/setup.mjs, and .vscode/tasks.json.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited evidence. Confirm if Bun was used to touch .env or SSH files. Inspect CI runner logs for matching setup.mjs activity. Rotate all developer tokens, npm credentials, and SSH keys discovered in the sweep.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the absence of ChainDrop activity in the current window and record any tuning notes for the Bun prevalence query.
```
→ end
