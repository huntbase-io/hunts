---
analysis: A simple rule might flag the command line, but a hunt correlates the dropper
  execution with the subsequent rare file access and persistence creation across three
  telemetry surfaces (process, software inventory, and file activity) within a tight
  time window.
blind_spots:
- id: no-process-telemetry
  question: whether the specific dropper script was executed
  requires: hb_process_activity with command line capture
  risk: Without command line telemetry, script names like setup.mjs cannot be seen,
    as the process name is usually 'node' or 'bun'.
  stage: dropper-execution-and-evasion
- id: procfs-filtering
  question: whether the worm scraped CI runner memory
  requires: hb_file_activity capturing /proc access
  risk: Many EDRs filter /proc noise; if filtered, OIDC token theft remains invisible.
  stage: ci-memory-scraping
coverage:
- stage: npm-hook-infection
  status: covered
  steps:
  - detect-worm-execution
- stage: dropper-execution-and-evasion
  status: covered
  steps:
  - detect-worm-execution
- stage: ci-memory-scraping
  status: covered
  steps:
  - ci-memory-scraping
- stage: developer-credential-harvesting
  status: covered
  steps:
  - rare-credential-access
- stage: ai-tool-persistence
  status: covered
  steps:
  - persistence-file-creation
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: blockchain-c2-routing
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: supply-chain-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ChainDrop specifically targets developer workstation and CI infrastructure
    to propagate silently and steal secrets. Negative results on this hunt provide
    confidence that our internal software supply chain and CI secrets remain uncompromised.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trojanized npm packages to execute a background
  worm that harvests developer credentials and establishes cross-linked persistence
  via VS Code and AI-assisted coding tools.
labels:
- hunt
- attack.t1195.002
- attack.t1059.003
- attack.t1552.001
- attack.t1552.004
- attack.t1003.001
- attack.t1546
- attack.t1547
name: ChainDrop Endpoint Infection and Secret Theft
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  persistence_files:
    default:
    - .vscode/tasks.json
    - .claude/settings.json
    - .claude/setup.mjs
    - com.user.gh-token-monitor.plist
    - gh-token-monitor.service
    description: Configuration files modified for cross-linked persistence.
    from:
      kind: article
      observed: '2026-08-06'
      ref: unit42-chaindrop
    type: list[path]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search (e.g., CI runners
      or dev workstations) obtained from the scoping step.
    type: list[host]
  sensitive_paths:
    default:
    - .ssh/id_rsa
    - .ssh/id_ed25519
    - kubeconfig
    - .env
    - .netrc
    - .docker/config.json
    - .npmrc
    - .vault-token
    description: Sensitive developer files targeted for exfiltration.
    from:
      kind: article
      observed: '2026-08-06'
      ref: unit42-chaindrop
    type: list[path]
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt is programmatically restricted to hosts identified as running
  Node.js, npm, or Bun via the first scoping step. Analysts should run 'scope-npm-environments',
  copy the hostnames, and paste them into the 'scope_hosts' parameter before running
  the behavior queries.
references:
- name: "Unit 42 \u2014 ChainDrop: Inside a Self-Propagating npm Worm"
  url: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
related:
- hunt: chaindrop-network-and-supply-chain
  reason: This hunt focuses on endpoint infection; the follow-on hunt examines blockchain-based
    C2 resolution and npm-based propagation.
  relation: follows
scenario:
  stages:
  - name: Trojanised npm Package Hook
    observables:
    - 'package.json containing preinstall: node setup.mjs'
    - setup.mjs
    - math_init.js
    slug: npm-hook-infection
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Dropper Execution and Locale Evasion
    observables:
    - Downloading Bun 1.3.13 from GitHub
    - Check for Russian language locale
    - Exiting as russian language detected!
    - Environment variable _NODE_RUNTIME_INIT=1
    - Detached background process spawning
    slug: dropper-execution-and-evasion
    tactic: execution
    techniques:
    - T1059.003
    - T1105
    - T1614.001
    - T1027
  - name: GitHub Actions Memory Scraping
    observables:
    - Runner.Worker process target
    - Opening /proc/<pid>/maps
    - Opening /proc/<pid>/mem
    - Scraping for OIDC tokens and runner secrets
    slug: ci-memory-scraping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Developer Tooling Credential Harvesting
    observables:
    - Accessing .ssh/id_rsa
    - Reading kubeconfig and service-account tokens
    - Harvesting .env and .netrc files
    - Collecting Docker, Helm, Poetry, and PyPI credentials
    - Accessing Jenkins encrypted credentials
    slug: developer-credential-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
    - T1552.004
  - name: Cross-linked AI and Dev Tool Persistence
    observables:
    - .vscode/tasks.json with task Environment Setup
    - .claude/settings.json with SessionStart command hook
    - node .claude/setup.mjs
    - node .vscode/setup.mjs
    - com.user.gh-token-monitor LaunchAgent
    - gh-token-monitor.service systemd unit
    slug: ai-tool-persistence
    tactic: persistence
    techniques:
    - T1546
    - T1547
  - name: Blockchain C2 Infrastructure
    observables:
    - Ethereum transaction-based C2 reconfiguration
    - Network traffic to Ethereum blockchain nodes
    slug: blockchain-c2-routing
    tactic: command-and-control
    techniques:
    - T1102.001
  - name: Supply Chain Worm Propagation
    observables:
    - Republishing packages to registry.npmjs.org
    - 'GitHub repository description Shai-Hulud: Here We Go Again'
    - .github/workflows/codeql_analysis.yml serializing secrets
    - OIDC token exchange with npm:registry.npmjs.org
    slug: supply-chain-propagation
    tactic: impact
    techniques:
    - T1571
    - T1195
  summary: ChainDrop is a self-propagating npm worm that infects packages via malicious
    preinstall hooks to steal developer credentials, including GitHub Actions runner
    secrets extracted via memory scraping. It uses Ethereum transactions for command-and-control
    routing and persists by embedding itself in VS Code and AI tool configurations
    before republishing itself to further npm packages.
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
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# ChainDrop Endpoint Infection and Secret Theft

ChainDrop is a self-propagating npm worm that infects legitimate packages by adding a preinstall hook. Once executed, it downloads a portable runtime (Bun), detaches a background process, and sweeps the host for cloud credentials, SSH keys, and CI secrets. It specifically targets GitHub Actions runner memory to steal OIDC tokens and secrets that are designed to exist only during job execution. This hunt identifies the infection by looking for the specific dropper scripts, rare access to sensitive developer configuration files by script interpreters, and the creation of persistence artifacts in IDE and AI tool directories. The triage agent correlates these behaviors to distinguish legitimate developer activity from the worm's automated collection and propagation routine, prioritizing the temporal link between dropper execution and credential theft.

## scope-npm-environments
<!-- Scope to npm-enabled hosts -->
Identify hosts with npm or Bun installed, which are the primary targets for this supply chain worm.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running Node.js or Bun environments. Silence means no such
  software was inventoried.
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
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (LOWER(package_name) IN ('npm', 'node', 'bun')) AND asset_scope = 'endpoint'
```

## detect-worm-execution
<!-- ChainDrop execution via JS Dropper -->
Identify process execution of the specific worm scripts or environment variables named in the research within the scoped estate.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes running setup.mjs or math_init.js, often spawned by node or bun
  interpreters. Silence indicates these specific command-line indicators are not present.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (process_cmd_line LIKE '%setup.mjs%' OR process_cmd_line LIKE '%math_init.js%' OR process_cmd_line LIKE '%_NODE_RUNTIME_INIT=1%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate behavior and persistence -->
parallel:
- → rare-credential-access
- → persistence-file-creation
- → ci-memory-scraping
join: → triage-infection

## rare-credential-access
<!-- Rare harvesting of developer credentials -->
Identify rare file access to sensitive developer configurations by script interpreters, standing out from normal tool usage.

```sqlite target=endpoint role=baseline params=(sensitive_paths=sensitive_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Access to SSH keys or .env files by node/bun processes that is limited to
  a few hosts. Silence means no suspicious interpreter access to these files.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 5
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT file_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_file_activity WHERE (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%' OR LOWER(process_name) LIKE '%python%') AND (instr(',' || '{{sensitive_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR file_path LIKE '%/.ssh/%' OR file_path LIKE '%/kubeconfig%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path HAVING hosts < 5
```

## persistence-file-creation
<!-- AI and IDE tool persistence creation -->
Detect the creation or update of VS Code and Claude Code configuration files used for cross-linked persistence.

```sqlite target=endpoint role=enrichment params=(persistence_files=persistence_files, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of IDE task files or AI settings files that link to external scripts.
  Normal developer usage might write these, so prevalence counts are important.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (instr(',' || '{{persistence_files}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR file_path LIKE '%/.vscode/tasks.json' OR file_path LIKE '%/.claude/settings.json') AND activity_name IN ('Create', 'Update') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ci-memory-scraping
<!-- CI environment memory scraping -->
Detect script interpreters accessing process memory maps, a behavior used to steal OIDC tokens from CI runners.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A script interpreter reading memory or maps of another process. Extremely
  rare and highly characteristic of the ChainDrop worm's CI logic.
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE (file_path LIKE '/proc/%/mem' OR file_path LIKE '/proc/%/maps') AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%python%' OR LOWER(process_name) LIKE '%bun%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infection
<!-- Triage ChainDrop infection -->
```agent target=hunter
cite: required
context:
- detect-worm-execution
- rare-credential-access
- persistence-file-creation
- ci-memory-scraping
max_iterations: 6
objective: Determine if any host shows the pattern of ChainDrop infection. Prioritize
  the temporal correlation between the execution of the dropper (setup.mjs/math_init.js)
  and the specific behavior of scraping /proc/ memory or harvesting sensitive files
  (SSH keys, .env). Check if these occur within a short window on the same device.
success_criteria: A verdict of malicious | suspicious | benign citing specific process
  paths and file access events.
tools:
- endpoint
```

## respond-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host, specifically noting correlation between dropper execution and sensitive file access." (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-telemetry)
else: → analyst-review

## isolate-infected-host
<!-- Isolate host and revoke tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke and rotate all SSH keys, npm tokens, GitHub personal access tokens, and cloud credentials (AWS/Azure/GCP) associated with the compromised user or CI environment. Collect the math_init.js payload if present.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Verify the cited files and processes. Review the exfiltration repositories under the victim's GitHub account if applicable. Confirm if 'com.user.gh-token-monitor' or 'gh-token-monitor.service' were established.
```
→ end
