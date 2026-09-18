---
analysis: A standard detection rule might flag a single suspicious connection to a
  blockchain node. This hunt correlates that connection with rare modifications to
  IDE config files and anomalous authentication volume to registries, providing the
  necessary context to confirm a supply chain worm.
blind_spots:
- id: limited-endpoint-telemetry
  owner: Endpoint Security Team
  question: What specifically was added to the tasks.json file?
  remediation: Enable file content auditing or shadow-copy snapshots for configuration
    directories.
  requires: EDR visibility into file content changes (diffs)
  risk: We can see the file was touched, but without the content change, we cannot
    distinguish a legitimate config update from a malicious persistence hook.
  stage: ide-tool-config-persistence
- id: ephemeral-runner-visibility
  owner: DevOps Team
  question: Were any repositories modified by the stolen tokens from these runners?
  remediation: Ingest GitHub and npm audit logs into the SIEM.
  requires: SaaS audit logs for GitHub and npm
  risk: If the runner is ephemeral and destroyed, and we lack SaaS audit logs, the
    propagation goes completely unseen until a downstream victim is hit.
  stage: automated-propagation-and-c2
coverage:
- stage: ide-tool-config-persistence
  status: covered
  steps:
  - ide-config-persistence
- stage: automated-propagation-and-c2
  status: covered
  steps:
  - blockchain-c2-dns
  - automated-auth-propagation
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: vulnerable-upstream-contribution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: malicious-package-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: runner-memory-credential-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Developer environments and CI/CD pipelines are high-value targets
    with extensive access. Persistence here survives application code changes and
    provides a launchpad for broader supply chain contamination.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised a developer environment and established persistence
  by modifying IDE configurations, while using blockchain infrastructure for command-and-control
  and stolen tokens for automated propagation.
labels:
- hunt
- attack.t1543
- attack.t1505
- attack.t1102
- attack.t1078
name: SDLC Persistence and Automated C2 Propagation
parameters:
  blockchain_domains:
    default:
    - cloudflare-eth.com
    - mainnet.infura.io
    - api.etherscan.io
    - eth-mainnet.g.alchemy.com
    - eth.llamarpc.com
    description: Common Ethereum JSON-RPC and explorer domains used for blockchain-based
      C2.
    from:
      kind: article
      observed: '2026-08-21'
      ref: unit42-sdlc-supply-chain
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the investigation.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/sdlc-supply-chain/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target developer workstations and CI/CD runners first. Use the package
  inventory to find systems with IDEs or the Bun runtime installed.
references:
- name: "Unit 42 \u2014 Connecting the Dots: Securing the Overlooked Corners of the\
    \ SDLC Supply Chain"
  url: https://unit42.paloaltonetworks.com/sdlc-supply-chain/
related:
- hunt: sdlc-initial-compromise-and-harvesting
  reason: Initial execution of malicious packages and credential harvesting occurs
    before persistence is established.
  relation: precedes
- hunt: sdlc-supply-chain-build-run-compromise
  relation: follows
scenario:
  stages:
  - name: Malicious Upstream Contribution
    observables:
    - liblzma version 5.6.0
    - liblzma version 5.6.1
    - CVE-2024-3094
    - malicious tarballs
    - OpenSSL zero-day
    slug: vulnerable-upstream-contribution
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Malicious Package Hook Execution
    observables:
    - npm install
    - package.json preinstall script
    - Bun runtime download
    - 727 KB obfuscated payload
    slug: malicious-package-execution
    tactic: execution
    techniques:
    - T1584.005
    - T1059.007
    - T1204.002
    - T1105
  - name: CI/CD Runner Memory Scraping
    observables:
    - Python script reading process memory
    - GitHub Actions runners
    - OpenID Connect (OIDC) tokens
    - .git-credentials
    slug: runner-memory-credential-theft
    tactic: credential-access
    techniques:
    - T1003
    - T1552
  - name: Developer Tool Persistence
    observables:
    - .vscode/tasks.json
    - Claude Code configuration
    - VS Code extensions
    slug: ide-tool-config-persistence
    tactic: persistence
    techniques:
    - T1543
    - T1505
  - name: Automated Propagation and C2
    observables:
    - Ethereum blockchain transactions
    - GitHub API calls
    - npm token usage
    - rogue code repositories
    slug: automated-propagation-and-c2
    tactic: c2
    techniques:
    - T1102
    - T1078
  summary: Attackers are targeting the software supply chain by embedding backdoors
    in foundational libraries and deploying autonomous worms like ChainDrop that hijack
    npm preinstall hooks. These attacks exploit the high privileges of developer tools
    to steal OIDC tokens from CI/CD runner memory, establish persistent backdoors
    in IDE configurations, and propagate via stolen credentials using blockchain-based
    command and control.
series:
  index: 2
  slug: connecting-the-dots-securing-the-overlooked-corners-of-the-software-development-lifecycle-sdlc-s
  title: 'Connecting the Dots: Securing the Overlooked Corners of the Software Development
    Lifecycle (SDLC) Supply Chain'
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# SDLC Persistence and Automated C2 Propagation

This hunt targets the 'ChainDrop' and 'Shai-Hulud' style of supply chain attacks. It specifically looks for unauthorized modifications to developer tool configurations (like VS Code tasks) which provide a persistent execution hook, and correlates this with anomalous network activity to blockchain nodes and high-frequency authentication to code registries which may indicate automated token-driven propagation across the software development lifecycle.

## scope-dev-environments
<!-- Scope to Developer Environments -->
Identify hosts with developer tools or runtimes (VS Code, Bun, Claude Code) installed that are susceptible to supply chain worms.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames where development activity is likely occurring. Silence
  means no such software was found in the inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%visual studio code%' OR LOWER(package_name) LIKE '%bun%' OR LOWER(package_name) LIKE '%claude%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## persistence-and-c2-detection
<!-- Correlate Persistence and C2 Signals -->
parallel:
- → ide-config-persistence
- → blockchain-c2-dns
- → automated-auth-propagation
join: → triage-sdlc-threat

## ide-config-persistence
<!-- IDE Tool Configuration Persistence -->
Detect modifications to VS Code or Claude Code configuration files by processes other than the IDE itself.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Anomalous processes (e.g., node, bun, python) modifying critical IDE task
  files. Success implies a persistence mechanism was likely installed.
reads:
- device_hostname
- file_path
- process_name
- process_cmd_line
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, process_cmd_line, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.vscode/tasks.json' OR LOWER(file_path) LIKE '%claude%config%') AND activity_id IN (1, 3, 5) AND LOWER(process_name) NOT LIKE '%code%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## blockchain-c2-dns
<!-- Blockchain Infrastructure C2 -->
Identify DNS lookups to Ethereum blockchain nodes, which is the observed C2 mechanism for the ChainDrop worm.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, blockchain_domains=blockchain_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unexpected DNS lookups to blockchain nodes from developer endpoints. Rare
  counts across the fleet increase suspicion.
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
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookups, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{blockchain_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## automated-auth-propagation
<!-- Automated Auth Propagation -->
Find high-frequency or anomalous authentication to code registries (GitHub/npm) which may indicate token-based worm propagation.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A spike in successful authentications to registries for a specific user,
  potentially indicating an automated script using stolen tokens.
reads:
- actor_user_name
- provider
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, provider, dst_endpoint_name, COUNT(*) as signins, MIN(time) as first_seen FROM hb_auth_signin WHERE provider IN ('github', 'npm') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, provider, dst_endpoint_name HAVING signins > 20
```

## triage-sdlc-threat
<!-- Triage SDLC Threat Signals -->
```agent target=hunter
cite: required
context:
- ide-config-persistence
- blockchain-c2-dns
- automated-auth-propagation
max_iterations: 5
objective: Determine if the correlated signals (unauthorized IDE config modification,
  blockchain C2 traffic, and registry authentication spikes) indicate a supply chain
  worm like ChainDrop.
success_criteria: A per-host verdict of malicious, suspicious, or benign with reasoning
  based on the combination of persistence and propagation evidence.
tools:
- endpoint
- identity
```

## evaluate-triage
<!-- Evaluate Triage Verdict -->
if~: "the triage verdict is malicious for a developer host with confirmed file modifications and C2 traffic" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review-sdlc
unavailable: → analyst-review-sdlc (blind_spot: limited-endpoint-telemetry)
else: → analyst-review-sdlc

## isolate-compromised-host
<!-- Isolate Host and Revoke Tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and rotate the affected user's GitHub and npm tokens immediately.
```
→ analyst-review-sdlc

## analyst-review-sdlc
<!-- Review SDLC Supply Chain Findings -->
```manual target=analyst
Verify the task modifications in VS Code, check repository logs for rogue commits, and investigate the Python/Bun payloads if recovered.
```
→ end
