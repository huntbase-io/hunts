---
analysis: A static rule can catch known C2 domains, but this hunt pivots between suspicious
  software inventory, rare blockchain-related DNS queries, and unauthorized source
  control activity from new contributors. It identifies dynamic C2 domains resolved
  via smart contracts which a single rule cannot anticipate.
blind_spots:
- id: rpc-visibility-gap
  owner: Infrastructure Team
  question: whether a host is querying Ethereum nodes to resolve C2 infrastructure
  remediation: Enable DNS logging on endpoint agents and forward resolver logs to
    the central surface.
  requires: Endpoint DNS monitoring or network-level DNS logging (hb_dns_activity)
  risk: Without visibility into DNS queries for RPC providers, the primary C2 discovery
    mechanism remains invisible.
  stage: c2-discovery-and-exfiltration
- id: github-token-audit-delay
  owner: AppSec Team
  question: how quickly a malicious package update is detected after publication
  remediation: Configure GitHub Webhooks to alert on package publication events.
  requires: Real-time GitHub package audit events (github_package_version)
  risk: Delays in GitHub API ingestion mean the worm could propagate before the hunt
    identifies the commit.
  stage: worm-propagation
coverage:
- stage: c2-discovery-and-exfiltration
  status: covered
  steps:
  - rpc-discovery-baseline
  - c2-exfiltration-leads
- stage: worm-propagation
  status: covered
  steps:
  - github-worm-commits
- reason: Handled by the first hunt in this series focusing on the initial install
    hook.
  stage: initial-access-npm-package
  status: out_of_scope
- reason: Handled by the first hunt in this series focusing on the dropper and bun
    execution.
  stage: execution-via-dropper
  status: out_of_scope
- reason: Handled by the first hunt in this series focusing on the collector component.
  stage: credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The CHAINDROP worm automates the compromise of secondary npm packages
    using stolen credentials; early detection of C2 discovery prevents exfiltration
    of sensitive secrets and stops the spread of supply-chain infections.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has infected local development environments via trojanized
  npm packages and is using Ethereum smart contracts to discover C2 infrastructure
  before propagating the worm using stolen GitHub credentials.
labels:
- hunt
- attack.t1041
- attack.t1195.002
- attack.t1555
name: 'CHAINDROP: C2 Discovery and Worm Propagation'
parameters:
  c2_domains:
    default:
    - awqhnjewqjkl.icu
    - npm-cache.com
    description: Known exfiltration and C2 domains.
    from:
      kind: article
      observed: '2026-08-06'
      ref: elastic-security-labs
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: hunt-config
    type: number
  npm_packages:
    default:
    - keyv
    - flat-cache
    - cacheable-request
    - cacheable
    - cache-manager
    description: NPM packages known to be initially compromised.
    from:
      kind: article
      observed: '2026-08-06'
      ref: elastic-security-labs
    type: list[string]
  rpc_domains:
    default:
    - go.getblock.io
    - eth.llamarpc.com
    - eth-mainnet.nodereal.io
    - mainnet.infura.io
    - eth-mainnet.g.alchemy.com
    - rpc.ankr.com
    - nodes.lala.xyz
    - cloudflare-eth.com
    description: Ethereum RPC providers used by the worm for C2 discovery.
    from:
      kind: article
      observed: '2026-08-06'
      ref: elastic-security-labs
    type: list[domain]
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty to hunt across the
      whole estate.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: analyst-scoping
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
rationale: Focus on developer workstations and build servers that have npm installed.
  Use the software inventory to prioritize hosts with the known-affected dependencies.
references:
- name: "Elastic Security Labs \u2014 Shai-Hulud strikes again: CHAINDROP worm hits\
    \ 400+ npm packages"
  url: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
related:
- hunt: chaindrop-dropper-execution-and-harvesting
  reason: The initial dropper execution and credential harvesting happen before C2
    discovery and propagation.
  relation: precedes
- hunt: chaindrop-host-worm-execution
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
  index: 2
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
  github:
    category: siem
    huntbase:
      product: github
    name: github
  hunter:
    agent: true
    name: Hunt agent
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# CHAINDROP: C2 Discovery and Worm Propagation

This hunt targets the post-exploitation phase of the CHAINDROP worm. It focuses on identifying hosts that perform dynamic C2 discovery by querying Ethereum RPC nodes and detecting unauthorized GitHub package updates from accounts with no prior history for those packages. By correlating host-level network behavior with identity-level source control activity, we identify compromised developer workstations and secondary supply-chain infection attempts.

## affected-npm-inventory
<!-- Inventory of affected npm packages -->
Identify hosts that have the compromised versions of key packages installed to narrow the scope of network monitoring.

```sqlite target=endpoint role=scoping params=(npm_packages=npm_packages)
~~~yaml
expected: A list of hosts running the targeted packages. Silence suggests no direct
  use of the known-compromised libraries.
reads:
- device_hostname
- package_name
- package_version
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE package_type = 'npm' AND (instr(',' || '{{npm_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0)
```

## discovery-signals
<!-- Gather network discovery and supply chain propagation signals -->
parallel:
- → rpc-discovery-baseline
- → c2-exfiltration-leads
- → github-worm-commits
join: → triage-signals

## rpc-discovery-baseline
<!-- Baseline Ethereum RPC DNS lookups -->
Find hosts querying blockchain RPC providers to resolve C2 domains from the Ethereum smart contract.

```sqlite target=endpoint role=baseline params=(rpc_domains=rpc_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare connections to blockchain RPC nodes from developer machines indicate
  discovery phase. High counts on many hosts may signify legitimate development.
prevalence:
  by: device_hostname
  key:
  - rpc_domain
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(query_hostname) AS rpc_domain, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY rpc_domain HAVING hosts <= 5
```

## c2-exfiltration-leads
<!-- Direct network connections to rare C2 domains -->
Identify active exfiltration by monitoring for rare connections to known C2 and dead-drop domains unique to scoped hosts.

```sqlite target=network role=detection-candidate params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Direct hits to rare infrastructure confirming successful discovery and exfiltration.
  Higher host counts indicate unrelated noise.
prevalence:
  by: device_hostname
  key:
  - c2_domain
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(dst_endpoint_hostname) AS c2_domain, COUNT(DISTINCT device_hostname) AS hosts, GROUP_CONCAT(DISTINCT device_hostname) AS device_list FROM hb_network_connection WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY c2_domain HAVING hosts <= 3
```

## github-worm-commits
<!-- New GitHub package contributor activity -->
Detect worm propagation by identifying package versions published by accounts with no historical presence for that specific package.

```sqlite target=github role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Package versions published by first-time authors for that repository indicate
  potential account takeover or automated worm propagation.
reads:
- author
- package_name
- created_at
- html_url
silence: not_evidence_of_absence
source: github_package_version
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT package_name, author, MIN(created_at) AS first_published_at, html_url FROM github_package_version GROUP BY package_name, author HAVING first_published_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-signals
<!-- Triage discovery and propagation -->
```agent target=hunter
cite: required
context:
- affected-npm-inventory
- rpc-discovery-baseline
- c2-exfiltration-leads
- github-worm-commits
max_iterations: 4
objective: Determine if any host with the affected npm packages is engaging in Ethereum-based
  C2 discovery or if GitHub accounts associated with the organization are publishing
  malicious package versions via new contributor accounts.
success_criteria: A detailed verdict citing host-to-RPC connections or unauthorized
  GitHub commits.
tools:
- endpoint
- github
- network
```

## route-on-verdict
<!-- Route based on infection evidence -->
if~: "the agent finds evidence of rare C2 discovery (RPC DNS) or GitHub propagation (new contributor package versions) for any host or account" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → manual-audit
unavailable: → manual-audit (blind_spot: rpc-visibility-gap)
else: → close-out

## contain-and-revoke
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host from the network and revoke all GitHub and npm tokens associated with the user. Check the GitHub repository for unauthorized commits.
```
→ manual-audit

## manual-audit
<!-- Manual remediation and audit -->
```manual target=analyst
Audit GitHub package logs for versions published by identified accounts. Verify if other internal developer accounts were used to propagate the worm. Review metadata of suspicious versions for the intimidation string.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document findings, update list of malicious C2 domains if new ones were resolved, and verify all affected hosts have been cleaned.
```
→ end
