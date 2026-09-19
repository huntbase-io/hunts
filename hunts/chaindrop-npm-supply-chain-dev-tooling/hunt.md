---
analysis: A standard detection rule might fire on 'node setup.mjs'. This hunt pivots
  to identify the *origin* (the package inventory) and the *impact* (credential harvesting
  and IDE persistence) to give a complete picture of the compromise on a developer
  machine that a single process-based alert misses.
blind_spots:
- id: endpoint-visibility-gap
  question: Was the bun binary deleted immediately after execution?
  requires: EDR with process integrity monitoring
  risk: The hunt relies on seeing the process execution; if the binary is deleted
    before EDR captures the hash or path correctly, the execution evidence may be
    ephemeral.
  stage: execution-bun-dropper
- id: file-content-inspection
  question: What specifically was added to the settings.json or tasks.json?
  requires: hb_script_activity or custom file integrity rules
  risk: hb_file_activity only shows that the file was written to. We cannot confirm
    the presence of 'SessionStart' or 'folderOpen' hooks without reading the file
    content.
  stage: persistence-dev-tooling-hooks
coverage:
- stage: initial-access-supply-chain-npm
  status: covered
  steps:
  - identify-exposed-hosts
- stage: execution-bun-dropper
  status: covered
  steps:
  - execution-patterns
- stage: persistence-dev-tooling-hooks
  status: covered
  steps:
  - ide-hook-persistence
- stage: credential-access-developer-stores
  status: covered
  steps:
  - credential-store-access
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: discovery-c2-smart-contract
  status: out_of_scope
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: exfiltration-and-worm-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: npm supply chain attacks targeting high-volume packages have massive
    blast radii. A negative result on confirmed compromised packages across the engineering
    fleet provides critical assurance that the current campaign has not established
    a beachhead.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised local developer environments by installing
  trojanized npm packages that establish persistence in IDE configurations and harvest
  credentials using a bundled JS runtime.
labels:
- hunt
- attack.t1195.002
- attack.t1059.001
- attack.t1554
- attack.t1555
name: 'CHAINDROP: npm Supply Chain and Dev-Tooling Backdoors'
parameters:
  compromised_packages:
    default:
    - keyv
    - flat-cache
    - cacheable-request
    - cacheable
    - cache-manager
    description: High-download npm packages known to be compromised in this campaign.
    from:
      kind: article
      observed: '2026-08-06'
      ref: elastic-labs-chaindrop
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_hashes:
    default:
    - 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
    - fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb
    - 54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668
    description: SHA256 hashes for Math_Symbol.js and setup.mjs.
    from:
      kind: article
      observed: '2026-08-06'
      ref: elastic-labs-chaindrop
    type: list[hash]
  scope_hosts:
    default: []
    description: Hosts to narrow the search to (e.g., from a software inventory match).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations assigned to software engineering or DevOps teams.
  Start with hosts where 'keyv' or 'flat-cache' are detected in the software inventory.
references:
- name: "Elastic Security Labs \u2014 Shai-Hulud strikes again: CHAINDROP worm hits\
    \ 400+ npm packages"
  url: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
related:
- hunt: chaindrop-worm-propagation
  reason: This hunt focuses on the endpoint infection and local developer environment;
    propagation via smart-contract discovery and repository backdooring is handled
    in the second hunt of the series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Trojanized npm Package Installation
    observables:
    - keyv
    - flat-cache
    - cacheable-request
    - preinstall hook in package.json
    - setup.mjs
    slug: initial-access-supply-chain-npm
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Bun Runtime Execution and Payload Delivery
    observables:
    - node setup.mjs
    - bun v1.3.13
    - Math_Symbol.js
    - math_init.js
    - 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
    slug: execution-bun-dropper
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via Developer Tooling Hooks
    observables:
    - .claude/settings.json
    - .vscode/tasks.json
    - SessionStart hook
    - folderOpen task
    slug: persistence-dev-tooling-hooks
    tactic: persistence
    techniques:
    - T1554
  - name: Multi-Provider Credential Harvesting
    observables:
    - Anthropic
    - Claude
    - OpenAI
    - AWS
    - GCP
    - GitHub PATs
    - npm tokens
    slug: credential-access-developer-stores
    tactic: credential-access
    techniques:
    - T1555
  - name: C2 Resolution via Ethereum Smart Contract
    observables:
    - '0xE1f2395ee43e45A1556EC6438a88c31B83493103'
    - go.getblock.io
    - eth.llamarpc.com
    - eth-mainnet.nodereal.io
    - thebeautifulmarchoftime
    slug: discovery-c2-smart-contract
    tactic: discovery
    techniques:
    - T1584.005
  - name: Exfiltration and Supply Chain Worm Propagation
    observables:
    - awqhnjewqjkl.icu
    - npm-cache.com
    - 'Shai-Hulud: Here We Go Again'
    - claude@users.noreply.github.com
    - 'chore: update config'
    - IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients
    slug: exfiltration-and-worm-propagation
    tactic: lateral-movement
    techniques:
    - T1041
    - T1195.002
  summary: The CHAINDROP worm campaign, attributed to Shai-Hulud, compromises npm
    packages through trojanized monorepos and self-propagating scripts that steal
    a wide array of developer and cloud credentials. The worm uses Ethereum smart
    contracts for C2 resolution and automatically backdoors co-owned packages to expand
    its reach across the supply chain.
series:
  index: 1
  slug: shai-hulud-strikes-again-chaindrop-worm-hits-400-npm-packages
  title: 'Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages'
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


# CHAINDROP: npm Supply Chain and Dev-Tooling Backdoors

This hunt targets the endpoint-resident phase of the Shai-Hulud (CHAINDROP) worm. It focuses on the installation of compromised npm packages like 'keyv', the execution of the 'setup.mjs' dropper via node/bun, and the subsequent injection of persistence hooks into VS Code and Claude Code configurations. Finally, it looks for the characteristic credential harvesting behavior directed at AI tools and cloud providers by the malware's collector component.

## identify-exposed-hosts
<!-- Identify hosts with compromised npm packages -->
Locate machines where the primary trojanized packages are installed to prioritize investigation.

```sqlite target=endpoint role=scoping params=(compromised_packages=compromised_packages)
~~~yaml
expected: A list of hostnames running high-risk packages. Silence suggests no direct
  installation of these specific entry-point packages.
reads:
- device_hostname
- install_path
- package_name
- package_type
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE package_type = 'npm' AND instr(',' || '{{compromised_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## branch-evidence-collection
<!-- Collect Execution and Persistence Evidence -->
parallel:
- → execution-patterns
- → ide-hook-persistence
- → credential-store-access
join: → triage-malware-behavior

## execution-patterns
<!-- Detection of Dropper and Bun Runtime Execution -->
Identify the execution of 'setup.mjs' and the subsequently downloaded 'bun' runtime running the payload.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, malicious_hashes=malicious_hashes)
~~~yaml
expected: Process events showing node or bun executing the specific JS filenames mentioned
  in the report. Silence means no recorded execution matching these command lines.
reads:
- device_hostname
- process_cmd_line
- process_hash_sha256
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_hash_sha256, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_cmd_line) LIKE '%setup.mjs%' OR LOWER(process_cmd_line) LIKE '%math_symbol.js%' OR LOWER(process_cmd_line) LIKE '%math_init.js%' OR instr(',' || '{{malicious_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ide-hook-persistence
<!-- IDE Configuration Modifications -->
Search for file modifications to IDE settings that include the malicious hooks.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Modification events where a node/bun process (likely from the npm preinstall)
  writes to IDE config files. Silence means no such process-file pairs were logged.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(file_path) LIKE '%/.vscode/tasks.json' OR LOWER(file_path) LIKE '%/.claude/settings.json') AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## credential-store-access
<!-- Suspicious Access to Credential Stores -->
Monitor for node or bun processes accessing sensitive configuration and credential files.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: Aggregated access counts per host and process. Frequent or unusual access
  to these paths by a runtime launched via npm is highly suspicious.
prevalence:
  by: device_hostname
  key:
  - file_path
  - process_name
  rare_below: 5
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, COUNT(*) as access_count FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%') AND (LOWER(file_path) LIKE '%/.aws/credentials' OR LOWER(file_path) LIKE '%/.npmrc' OR LOWER(file_path) LIKE '%/.ssh/id_%' OR LOWER(file_path) LIKE '%/.config/gcloud/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path
```

## triage-malware-behavior
<!-- Triage CHAINDROP Behavior -->
```agent target=hunter
cite: required
context:
- identify-exposed-hosts
- execution-patterns
- ide-hook-persistence
- credential-store-access
max_iterations: 4
objective: 'Determine if any host shows the complete chain of CHAINDROP activity:
  initial access via package, execution via bun/node, and follow-on credential access
  or IDE persistence.'
success_criteria: A final list of infected hosts with cited rows from process and
  file surfaces.
tools:
- endpoint
```

## malicious-verdict-decision
<!-- Act on Verdict -->
if~: "The triage verdict is malicious or suspicious for any host, citing both execution and follow-on credential/persistence activity." (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: endpoint-visibility-gap)
else: → close-hunt

## contain-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke all npm and GitHub tokens, and initiate a full credential rotation for cloud and AI services.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Review of Developer Activity -->
```manual target=analyst
Inspect the file paths accessed by node/bun. Cross-reference with the organization's use of 'keyv' or related packages. Check GitHub repositories for unauthorized 'chore: update config' commits.
```
→ end

## close-hunt
<!-- Close and Document -->
```manual target=analyst
Document the absence of CHAINDROP on scoped hosts and note the versions of npm/node in use for risk assessment.
```
→ end
