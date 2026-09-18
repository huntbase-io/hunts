---
analysis: A standard detection rule on the C2 domains will fail as soon as the attacker
  updates the Ethereum smart contract. This hunt instead targets the immutable 'discovery'
  behavior (querying blockchain RPCs from Node.js) and the 'propagation' behavior
  (auditing SaaS package authorship) which the attacker cannot rotate without rewriting
  the worm.
blind_spots:
- id: limited-github-visibility
  question: whether we can see the 'intimidation string' in the commit body vs just
    the author name
  requires: github_package_version with full commit messages
  risk: An attacker could change the author identity, leaving us only with DNS/Network
    signals which are more likely to rotate.
  stage: exfiltration-and-worm-propagation
- id: eth-smart-contract-opacity
  question: what C2 domain was returned by the Ethereum smart contract
  requires: application-layer network inspection of JSON-RPC
  risk: We see the host 'talking' to the RPC provider, but we don't know the new C2
    domain it received, making our network query reactive rather than proactive.
  stage: discovery-c2-smart-contract
coverage:
- stage: discovery-c2-smart-contract
  status: covered
  steps:
  - rpc-dns-resolution
- stage: exfiltration-and-worm-propagation
  status: covered
  steps:
  - c2-network-traffic
  - github-propagation-audit
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: initial-access-supply-chain-npm
  status: out_of_scope
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: execution-bun-dropper
  status: out_of_scope
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: persistence-dev-tooling-hooks
  status: out_of_scope
- reason: 'Belongs to another part of the ''Shai-Hulud strikes again: CHAINDROP worm
    hits 400+ npm packages'' series.'
  stage: credential-access-developer-stores
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: "The CHAINDROP worm targets the core trust mechanism of development\u2014\
    package managers\u2014and spreads automatically using stolen credentials. Validating\
    \ that developer hosts are not resolving C2 via blockchain is the only way to\
    \ catch the worm before it compromises internal proprietary code or exfiltrates\
    \ cloud secrets."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised local developer tools or npm packages to
  resolve C2 endpoints via Ethereum RPC providers and is now using stolen credentials
  to propagate a worm to co-owned packages.
labels:
- hunt
- attack.t1584.005
- attack.t1041
- attack.t1195.002
- attack.t1555
name: 'CHAINDROP Worm: C2 Discovery and Propagation'
parameters:
  c2_domains:
    default:
    - npm-cache.com
    - awqhnjewqjkl.icu
    description: Known C2 domains observed in the campaign.
    from:
      kind: article
      observed: '2026-08-06'
      ref: Shai-Hulud strikes again
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  rpc_providers:
    default:
    - go.getblock.io
    - eth.llamarpc.com
    - eth-mainnet.nodereal.io
    description: Ethereum RPC providers used by the worm for C2 resolution.
    from:
      kind: article
      observed: '2026-08-06'
      ref: Shai-Hulud strikes again
    type: list[domain]
  scope_hosts:
    default: []
    description: Comma-separated hostnames to focus the hunt; leave empty for the
      entire estate.
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
rationale: The hunt should start by targeting the entire development fleet (hosts
  with npm/node) as supply chain compromises often bypass standard 'high-value' server
  scoping. Use the lookback to catch the early discovery phase before the smart contract
  rotates the C2.
references:
- name: 'Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages'
  url: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
related:
- hunt: chaindrop-endpoint-execution-hooks
  reason: This hunt focuses on infrastructure and propagation; endpoint execution
    (Bun dropper, preinstall hooks) is covered in its own sibling hunt.
  relation: out-of-scope-alternative
- hunt: chaindrop-npm-supply-chain-dev-tooling
  relation: follows
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
    huntbase:
      product: hb-endpoint-control
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


# CHAINDROP Worm: C2 Discovery and Propagation

This hunt focuses on the 'Shai-Hulud' CHAINDROP worm's infrastructure-agnostic discovery phase and its lateral propagation. It identifies hosts using Node.js or Bun that resolve blockchain RPC endpoints—a technique used by the worm to find its current C2 domain via an Ethereum smart contract. It then corroborates this with direct exfiltration traffic and SaaS-side auditing of GitHub package versions for suspicious author metadata associated with the worm's self-publishing logic.

## scope-developer-hosts
<!-- Scope developer environments -->
Identify hosts that have npm or Node.js installed, as these are the primary targets for the CHAINDROP supply chain worm.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or build servers. Silence suggests
  the inventory surface is not populating or npm is not managed via standard packages.
reads:
- device_hostname
- package_name
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) = 'npm' OR LOWER(package_name) = 'node' OR LOWER(package_type) = 'npm')
```

## corroborate-worm-activity
<!-- Corroborate worm activity across surfaces -->
parallel:
- → rpc-dns-resolution
- → c2-network-traffic
- → github-propagation-audit
join: → triage-agent

## rpc-dns-resolution
<!-- DNS lookups to Ethereum RPC providers -->
Find Node.js or Bun processes querying blockchain RPC nodes to resolve the C2 smart contract.

```sqlite target=endpoint role=baseline params=(rpc_providers=rpc_providers, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A developer host querying RPC providers via a script interpreter. Frequent
  queries to different providers may indicate the 'fallback' logic described in the
  article.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%') AND instr(',' || '{{rpc_providers}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## c2-network-traffic
<!-- Network exfiltration to C2 domains -->
Identify established network connections from development tools to the known exfiltration domains.

```sqlite target=network role=triage params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct outbound connections to known C2 domains. Silence is not definitive
  as the attacker rotates these domains via the smart contract.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%bun%') AND (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## github-propagation-audit
<!-- SaaS audit for worm-generated versions -->
Detect evidence of the worm's propagation phase by identifying package versions authored by 'claude' or containing the intimidation string.

```sqlite target=github role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: New package versions in internal GitHub organizations authored by the 'claude'
  identity, which the worm uses during automated commits.
reads:
- author
- package_name
- created_at
- html_url
silence: not_evidence_of_absence
source: github_package_version
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT author, package_name, created_at, html_url FROM github_package_version WHERE (LOWER(author) LIKE '%claude%' OR LOWER(author) LIKE '%thebeautifulmarchoftime%') AND created_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage worm signals -->
```agent target=hunter
cite: required
context:
- rpc-dns-resolution
- c2-network-traffic
- github-propagation-audit
max_iterations: 4
objective: Determine if any host is infected by CHAINDROP by matching blockchain RPC
  DNS queries with exfiltration traffic or suspicious GitHub package updates.
success_criteria: A verdict of 'malicious' for hosts showing two or more of the signals,
  or 'suspicious' for single outliers.
tools:
- endpoint
- github
- network
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict identifies at least one host as malicious due to coincident RPC discovery and C2 traffic" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-github-visibility)
else: → analyst-review

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all GitHub PATs, npm tokens, and cloud credentials associated with the user of this host.
```
→ analyst-review

## analyst-review
<!-- Analyst detailed review -->
```manual target=analyst
Review the RPC DNS lookups and exfiltration traffic. Check the GitHub package versions for the 'claude' author identity. If malicious, ensure all credentials listed in the report (GitHub, npm, cloud) are rotated.
```
→ cleanup-closeout

## cleanup-closeout
<!-- Cleanup and closeout -->
```manual target=analyst
Record which RPC providers were hit. If exfiltration domains were seen that were NOT in the parameter list, add them for next time. Close the hunt.
```
→ end
