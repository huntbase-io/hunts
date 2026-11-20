---
analysis: This hunt pivots from IDE configuration files to blockchain-based network
  activity and then to GitHub package audit logs. A single detection rule cannot link
  these across multiple surfaces to confirm a self-propagating infection.
blind_spots:
- id: no-endpoint-telemetry
  question: whether the hook files exist on hosts not reporting file activity
  requires: hb_file_activity coverage on all developer workstations
  risk: An infected workstation with no telemetry can re-infect the repository indefinitely.
  stage: developer-tooling-persistence
- id: ephemeral-runners
  question: whether the C2 resolution happened within a short-lived GitHub Actions
    job
  requires: Real-time DNS logging for ephemeral CI runners
  risk: The DNS lookup may vanish before it is collected if the runner environment
    is destroyed immediately after the job.
  stage: blockchain-c2-routing
coverage:
- stage: developer-tooling-persistence
  status: covered
  steps:
  - detect-worm-hooks
  - check-latent-persistence
- stage: blockchain-c2-routing
  status: covered
  steps:
  - check-blockchain-c2
- stage: automated-package-propagation
  status: covered
  steps:
  - check-npm-propagation
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: npm-supply-chain-compromise
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: npm-lifecycle-hook-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: portable-runtime-dropper
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: credential-and-environment-sweep
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: ci-runner-memory-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The ChainDrop worm compromises the software supply chain by weaponizing
    developer tools; this hunt validates that no automated persistence or propagation
    is active on our contributors' machines.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised developer environments by injecting malicious
  hooks into IDE configuration files, using automated GitHub workflows to propagate
  an npm worm and resolve C2 via Ethereum smart contracts.
labels:
- hunt
- attack.t1546
- attack.t1102
- attack.t1534
- attack.t1574.006
name: 'ChainDrop Worm: Developer Tooling Persistence and Supply Chain Propagation'
parameters:
  eth_gateways:
    default:
    - mainnet.infura.io
    - api.etherscan.io
    - cloudflare-eth.com
    - eth-mainnet.g.alchemy.com
    description: Ethereum API and gateway domains used for blockchain-based C2 resolution.
    from:
      kind: article
      observed: '2026-08-06'
      ref: chaindrop-analysis
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: default-retention
    type: number
  scope_github_users:
    default: []
    description: GitHub identities (organizations or logins) associated with infected
      workstations.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: scoping-result
    type: list[string]
  scope_hosts:
    default: []
    description: Limit analysis to specific hosts found in the initial scoping step.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: scoping-result
    type: list[host]
  worm_artifacts:
    default:
    - math_init.js
    - setup.mjs
    description: Unique filenames associated with the worm's hooks and droppers.
    from:
      kind: article
      observed: '2026-08-06'
      ref: chaindrop-analysis
    type: list[string]
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
rationale: Focus on developer endpoints and CI/CD environments. Prioritize users with
  'maintainer' or 'owner' roles in GitHub and npm repositories.
references:
- name: 'ChainDrop: Inside a Self-Propagating npm Worm'
  url: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
related:
- hunt: npm-supply-chain-compromise
  reason: Initial infection via typosquatted packages is covered by the primary supply
    chain hunt; this hunt focuses on the worm's lifecycle.
  relation: out-of-scope-alternative
- hunt: chaindrop-npm-worm-activity
  relation: follows
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
  index: 2
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
  github:
    category: siem
    huntbase:
      product: github
    name: github
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# ChainDrop Worm: Developer Tooling Persistence and Supply Chain Propagation

ChainDrop is a self-propagating npm worm targeting workstations and CI/CD runners. This hunt focuses on identifying persistence within VS Code and Claude Code configurations, detecting latent system services, and uncovering blockchain-based C2 routing. It concludes by verifying whether the infected account has propagated the worm by republishing malicious npm packages. The workflow uses file telemetry to find hooks, DNS activity to find Ethereum resolution, and GitHub audit logs to confirm supply chain impact.

## detect-worm-hooks
<!-- Detect IDE and Workflow Hooks -->
Identify the creation of unique malicious hooks in VS Code and Claude Code directories that trigger the worm's dropper.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, worm_artifacts=worm_artifacts)
~~~yaml
expected: Rows indicating the creation of unique dropper or payload files in hidden
  developer directories like .vscode or .claude.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE instr(',' || '{{worm_artifacts}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND (LOWER(file_path) LIKE '%\.vscode\%' OR LOWER(file_path) LIKE '%\.claude\%') AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-infection
<!-- Corroborate Persistence and Propagation -->
parallel:
- → check-latent-persistence
- → check-blockchain-c2
- → check-npm-propagation
join: → triage-findings

## check-latent-persistence
<!-- Check for Latent OS Services -->
Search for the installation of the macOS LaunchAgent or Linux systemd service described in the latent capability of the worm.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A LaunchAgent or systemd unit named gh-token-monitor; silence indicates
  the latent capability was not activated on the identified hosts.
reads:
- device_hostname
- job_name
- job_definition_path
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_definition_path, time FROM hb_scheduled_job WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(job_name) LIKE '%gh-token-monitor%' OR LOWER(job_definition_path) LIKE '%gh-token-monitor%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## check-blockchain-c2
<!-- Blockchain Gateway Resolution -->
Identify anomalous DNS requests to Ethereum gateways used by the worm to resolve its dynamic C2 infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, eth_gateways=eth_gateways, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare resolution of Ethereum gateways from identified suspect hosts. Correlation
  with the worm's lead files increases confidence.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{eth_gateways}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## check-npm-propagation
<!-- Suspect npm Package Updates -->
Query GitHub package logs to find npm packages updated during the infection window for specific identities.

```sqlite target=github role=triage params=(lookback_days=lookback_days, scope_github_users=scope_github_users)
~~~yaml
expected: A list of recently published packages for manual correlation with infected
  workstations and identities.
reads:
- name
- organization
- updated_at
silence: not_evidence_of_absence
source: github_package
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT name, organization, updated_at FROM github_package WHERE package_type = 'npm' AND ('{{scope_github_users}}' = '' OR instr(',' || '{{scope_github_users}}' || ',', ',' || organization || ',') > 0) AND updated_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-findings
<!-- Weigh Evidence per Host -->
```agent target=hunter
cite: required
context:
- detect-worm-hooks
- check-latent-persistence
- check-blockchain-c2
- check-npm-propagation
max_iterations: 4
objective: Determine if the observed IDE hooks and network resolution patterns indicate
  an active ChainDrop infection and if propagation has occurred.
success_criteria: A verdict of malicious for hosts exhibiting both hook files and
  blockchain activity, or suspicious for those with hook files only.
tools:
- endpoint
- github
```

## route-on-verdict
<!-- Route on Infection Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-endpoint-telemetry)
else: → manual-review

## contain-and-revoke
<!-- Contain and Revoke Secrets -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all GitHub and npm tokens associated with the identity found on the workstation. Delete the .vscode and .claude directories containing the hooks.
```
→ manual-review

## manual-review
<!-- Analyst Review of Propagation -->
```manual target=analyst
Review the packages listed in the propagation step. Cross-reference their update time with the workstation infection window. Audit the package contents for the setup.mjs and preinstall hooks.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the impact on the software supply chain. Notify downstream consumers if infected packages were confirmed. Recommend standing detection for unique malicious filenames in IDE configuration paths.
```
→ end
