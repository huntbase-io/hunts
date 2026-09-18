---
analysis: A simple detection rule might alert on a single connection to an Ethereum
  node; this hunt correlates that network signal with the specific npm OIDC exchange
  pattern and recent package activity, providing the context required for a high-confidence
  supply chain compromise verdict.
blind_spots:
- id: limited-github-audit
  owner: DevOps Team
  question: Which specific OIDC tokens were issued and for which repositories?
  remediation: Enable GitHub Enterprise audit log streaming to the central SIEM.
  requires: GitHub Enterprise Audit Log
  risk: Without the full audit log, we may see the package update but not the specific
    runner identity that performed the exchange.
  stage: supply-chain-propagation
- id: encrypted-rpc-traffic
  owner: Network Engineering
  question: Was the content of the RPC call related to a specific C2 transaction?
  remediation: Implement TLS inspection for CI/CD egress traffic.
  requires: Deep Packet Inspection (DPI) on port 443
  risk: We can see the DNS resolution and connection to a node, but the specific C2
    commands are encrypted within HTTPS/RPC.
  stage: blockchain-c2-routing
coverage:
- stage: blockchain-c2-routing
  status: covered
  steps:
  - blockchain-c2-dns
- stage: supply-chain-propagation
  status: covered
  steps:
  - npm-oidc-exchange
  - github-package-updates
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: npm-hook-infection
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: dropper-execution-and-evasion
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: ci-memory-scraping
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: developer-credential-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''ChainDrop: Inside a Self-Propagating npm
    Worm'' series.'
  stage: ai-tool-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The ChainDrop worm compromises the integrity of the software supply
    chain by weaponizing legitimate CI/CD runners. A negative result confirms that
    your organization's release identities haven't been hijacked to spread malware
    to downstream customers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using blockchain nodes for C2 resolution and leveraging
  OIDC-based trusted publishing to propagate malicious npm packages through CI/CD
  runners.
labels:
- hunt
- attack.t1102.001
- attack.t1571
- attack.t1195
name: ChainDrop C2 and npm Propagation
parameters:
  blockchain_rpc_domains:
    default:
    - mainnet.infura.io
    - eth-mainnet.g.alchemy.com
    - cloudflare-eth.com
    - api.etherscan.io
    - eth.llamarpc.com
    description: Common Ethereum RPC provider endpoints used for blockchain-based
      C2 resolution.
    from:
      kind: manual
      observed: '2026-08-06'
      ref: ChainDrop Analysis
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt (e.g., CI runners).
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
rationale: Focus on servers and workstations where 'npm' or 'bun' are present in the
  software inventory. These environments are at the highest risk for the propagation
  phase of ChainDrop.
references:
- name: 'ChainDrop: Inside a Self-Propagating npm Worm'
  url: https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/
related:
- hunt: npm-hook-infection
  reason: This hunt focuses on network C2 and propagation; the actual code injection
    into package.json belongs to a static file analysis hunt.
  relation: out-of-scope-alternative
- hunt: chaindrop-endpoint-infection-secret-theft
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# ChainDrop C2 and npm Propagation

ChainDrop is a self-propagating worm that specifically targets development environments. This hunt examines the 'network orchestration' and 'propagation' phases of the attack. It searches for indicators of blockchain-based C2 resolution—used by the worm to dynamically reconfigure its infrastructure—and detects the specific OIDC token exchange pattern used to hijack npm publishing identities. By correlating these network signals with recent GitHub package activity, the hunt identifies compromised accounts and runners used to spread the worm.

## scope-npm-environments
<!-- Identify npm and Bun environments -->
Identify hosts with package managers installed that are the primary targets of the ChainDrop worm.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of developer workstations and CI runners. Silence means these tools
  are not tracked in inventory, not that they are absent.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'npm' OR LOWER(package_name) = 'bun') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## propagation-behavior-parallel
<!-- Analyze network and propagation activity -->
parallel:
- → blockchain-c2-dns
- → npm-oidc-exchange
- → github-package-updates
join: → triage-signals

## blockchain-c2-dns
<!-- Blockchain C2 resolution -->
Detect resolution of Ethereum RPC nodes used to reconfigure C2 infrastructure via smart contract transactions.

```sqlite target=endpoint role=baseline params=(blockchain_rpc_domains=blockchain_rpc_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host talking to a blockchain node. In a corporate environment, this is
  rare for standard CI/CD runners and indicates potential C2 resolution.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as resolution_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{blockchain_rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## npm-oidc-exchange
<!-- npm Trusted Publishing OIDC exchange -->
Identify automated token exchange requests to the npm registry, which ChainDrop uses to republish malicious packages using the runner's identity.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A POST request to the OIDC exchange endpoint. While legitimate for 'trusted
  publishing' workflows, its presence on a host that also shows C2 DNS is highly suspicious.
reads:
- device_hostname
- url_full
- http_method
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_full, http_method, user_agent, time FROM hb_http_activity WHERE url_hostname = 'registry.npmjs.org' AND url_path LIKE '%/exchange/oidc%' AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## github-package-updates
<!-- Recent npm package publications -->
Audit recent npm package updates in GitHub to find potentially republished malicious packages.

```sqlite target=github role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Recent npm package updates. The analyst should correlate these with the
  hosts identified in the previous steps.
reads:
- organization
- name
- repository_full_name
- updated_at
silence: not_evidence_of_absence
source: github_package
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT organization, name, repository_full_name, updated_at FROM github_package WHERE package_type = 'npm' AND updated_at >= datetime('now', '-{{lookback_days}} days') ORDER BY updated_at DESC
```

## triage-signals
<!-- Triage ChainDrop signals -->
```agent target=hunter
cite: required
context:
- blockchain-c2-dns
- npm-oidc-exchange
- github-package-updates
max_iterations: 4
objective: Determine if the network traffic to blockchain nodes and npm registry activity
  on specific hosts correlates with recent package updates, indicating a self-propagating
  worm compromise.
success_criteria: A verdict of 'malicious' if a host shows both blockchain DNS and
  npm OIDC exchanges, citing specific timestamps.
tools:
- endpoint
- github
- web
```

## decide-verdict
<!-- Route based on compromise -->
if~: "the triage verdict is malicious for at least one host or repository" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: limited-github-audit)
else: → close-out

## isolate-and-revoke
<!-- Isolate host and revoke tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and immediately revoke all GitHub and npm publishing tokens associated with the accounts identified in the triage step.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Audit recent npm package releases for the 'preinstall' lifecycle hook and verify if they were published by unauthorized runners.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hunt results. If no activity was found, verify that the DNS lookback period was sufficient for the reconfiguration event of Aug 4.
```
→ end
