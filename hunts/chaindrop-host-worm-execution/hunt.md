---
analysis: 'A simple detection rule might flag the preinstall hook, but this hunt provides
  the context an analyst needs: it correlates the software inventory with the prevalence
  of the Bun runtime and the modification of IDE configuration files. The gated flow
  ensures that expensive behavioral analysis is only conducted when a viable lead
  is identified.'
blind_spots:
- id: transient-package-install
  question: whether a compromised package was installed and then removed within the
    inventory snapshot interval
  requires: continuous package manager logging
  risk: hb_software_inventory is a point-in-time snapshot and will miss packages that
    were present only long enough for the preinstall hook to execute.
  stage: initial-access-npm-package
- id: short-retention-windows
  question: whether the dropper executed before the lookback window
  requires: extended endpoint event retention
  risk: If the infection occurred weeks ago, the process activity logs may have rolled
    over, leaving only the persistent software inventory as evidence.
  stage: execution-via-dropper
coverage:
- stage: initial-access-npm-package
  status: covered
  steps:
  - npm-inventory-lead
- stage: execution-via-dropper
  status: covered
  steps:
  - dropper-execution-check
  - rare-bun-execution
- stage: credential-harvesting
  status: covered
  steps:
  - analyst-review
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: c2-discovery-and-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: worm-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: 'The CHAINDROP worm targets the core assets of a modern engineering
    team: source code and cloud credentials. A negative result confirms that these
    high-value identities remain uncompromised by this specific campaign.'
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has gained initial access through a backdoored npm package
  preinstall hook, which executes a dropper to install a rogue Bun runtime and harvest
  developer credentials from local IDE configurations.
labels:
- hunt
- attack.t1195.002
- attack.t1059.001
- attack.t1555
name: 'CHAINDROP: Host-Based Node.js Worm Execution and Harvesting'
parameters:
  compromised_packages:
    default:
    - keyv
    - flat-cache
    - cacheable-request
    - cacheable
    - cache-manager
    description: Core npm packages identified as compromised in the CHAINDROP campaign.
    from:
      kind: article
      observed: '2026-08-04'
      ref: Elastic Security Labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for process activity.
    type: number
  scope_hosts:
    default: []
    description: Host list returned from the scoping step to narrow behavior queries.
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on developer endpoints and build servers where npm installs
  are frequent. The agent in 'evaluate-inventory' provides a list of hosts with confirmed
  software hits. The analyst must paste these hostnames into the 'scope_hosts' parameter
  for the subsequent process behavioral queries.
references:
- name: "Elastic Security Labs \u2014 Shai-Hulud strikes again: CHAINDROP worm hits\
    \ 400+ npm packages"
  url: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
related:
- hunt: chaindrop-network-propagation
  reason: This hunt covers the local host artifacts; a subsequent hunt covers the
    network-based C2 resolution and exfiltration.
  relation: follows
scenario:
  stages:
  - name: Trojanized npm Package Installation
    observables:
    - keyv
    - flat-cache
    - cacheable-request
    - cacheable
    - cache-manager
    - preinstall hook in package.json
    - setup.mjs
    slug: initial-access-npm-package
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Multi-Path Dropper Execution
    observables:
    - node setup.mjs
    - bun v1.3.13
    - Math_Symbol.js
    - math_init.js
    - .claude/settings.json SessionStart hook
    - .vscode/tasks.json folderOpen task
    - 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
    - fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb
    - 54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668
    slug: execution-via-dropper
    tactic: execution
    techniques:
    - T1059.001
  - name: Developer and AI Credential Harvesting
    observables:
    - Anthropic
    - Claude
    - Codex
    - Cursor
    - OpenAI
    - Gemini
    - npm tokens
    - GitHub PATs
    - Kubernetes service account tokens
    - HashiCorp Vault tokens
    slug: credential-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Dynamic C2 Discovery and Data Exfiltration
    observables:
    - '0xE1f2395ee43e45A1556EC6438a88c31B83493103'
    - go.getblock.io
    - eth.llamarpc.com
    - awqhnjewqjkl.icu
    - npm-cache.com
    - thebeautifulmarchoftime
    - 'Shai-Hulud: Here We Go Again'
    slug: c2-discovery-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1041
  - name: Self-Propagating Supply Chain Infection
    observables:
    - claude@users.noreply.github.com
    - 'chore: update config'
    - IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients
    - bypass_2fa
    slug: worm-propagation
    tactic: persistence
    techniques:
    - T1195
  summary: The Shai-Hulud campaign, also known as CHAINDROP, targets JavaScript developers
    via compromised npm maintainer accounts to deploy a self-propagating worm. The
    malware executes via npm hooks to steal cloud, AI, and developer credentials,
    then uses stolen npm tokens to automatically backdoor and republish all packages
    owned by the victim.
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# CHAINDROP: Host-Based Node.js Worm Execution and Harvesting

The CHAINDROP worm uses the npm supply chain by trojanizing popular packages with preinstall hooks. This hunt focuses on the endpoint footprint of the compromise: the presence of known-malicious npm packages, the execution of Node.js-based droppers, and the deployment of a rogue Bun runtime for credential harvesting. It employs a gated flow to first scope the environment for affected packages before fanning out into expensive behavioral analysis of process activity and prevalence-based detection of the Bun runtime.

## npm-inventory-lead
<!-- Find compromised npm packages in inventory -->
Identify hosts that have installed the primary compromised packages named in the research to narrow the scope.

```sqlite target=endpoint role=scoping params=(compromised_packages=compromised_packages)
~~~yaml
expected: Hosts with known-compromised npm packages installed. Silence indicates these
  specific packages are not in the current inventory snapshot.
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
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE package_type = 'npm' AND instr(',' || '{{compromised_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## evaluate-inventory
<!-- Evaluate software inventory lead -->
```agent target=hunter
cite: required
context:
- npm-inventory-lead
max_iterations: 3
objective: Determine if the identified npm packages on any host match the threat profile
  described in the research and warrant a full behavioral investigation.
success_criteria: A verdict for each host naming the compromised package and recommending
  next steps.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on inventory lead -->
if~: "the evaluate-inventory verdict identifies at least one host with a compromised npm package" (confidence: high, judge=hunter)
then: → behavioral-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: transient-package-install)
else: → close-out

## behavioral-fan-out
<!-- Corroborate behavioral evidence -->
parallel:
- → dropper-execution-check
- → rare-bun-execution
join: → final-triage

## dropper-execution-check
<!-- Detect dropper and payload execution -->
Find the specific process execution strings associated with the CHAINDROP dropper and its obfuscated payload.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process events showing node.exe or node executing the dropper files. Silence
  suggests the execution phase did not occur in the window.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%setup.mjs%' OR LOWER(process_cmd_line) LIKE '%math_symbol.js%' OR LOWER(process_cmd_line) LIKE '%math_init.js%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-bun-execution
<!-- Stack-count rare Bun runtime usage -->
Identify hosts where the Bun runtime is executing from unusual or temporary paths, which is characteristic of this worm.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts where Bun has run recently from a path seen on 5 or fewer
  hosts. Silence means Bun usage is either absent or fleet-wide.
prevalence:
  by: device_hostname
  key:
  - path
  - process_cmd_line
  - user_name
  rare_below: 5
reads:
- process_path
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, process_cmd_line, user_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) IN ('bun', 'bun.exe') OR LOWER(process_path) LIKE '%/bun%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING hosts <= 5 ORDER BY hosts ASC
```

## final-triage
<!-- Final triage of CHAINDROP activity -->
```agent target=hunter
cite: required
context:
- evaluate-inventory
- dropper-execution-check
- rare-bun-execution
max_iterations: 6
objective: Determine if the combined signals confirm a successful supply-chain infection
  and subsequent malicious execution on any host.
success_criteria: A verdict of infected | suspicious | benign for each host, citing
  the package, the dropper process, and the Bun execution path.
tools:
- endpoint
```

## route-infection
<!-- Route on infection verdict -->
if~: "the final-triage verdict is infected for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: short-retention-windows)
else: → analyst-review

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Notify the identity team to revoke all npm and GitHub tokens associated with the user on this machine.
```
→ analyst-review

## analyst-review
<!-- Review behavioral activity -->
```manual target=analyst
Review hb_file_activity for modifications to .vscode/tasks.json or .claude/settings.json. Examine hb_script_activity for the full text of the obfuscated payload execution blocks.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
The hunt found no primary compromised packages or dropper execution paths during the lookback period.
```
→ end
