---
analysis: A simple detection rule might catch the git-tanstack.com domain, but this
  hunt pivots between development tool inventory, secret store network metadata, and
  rare process/domain pairing to find the framework even when the primary C2 has rotated.
blind_spots:
- id: encryption-metadata-only
  question: What specifically was exfiltrated within the encrypted envelopes?
  requires: TLS decryption or endpoint content inspection
  risk: We see the exfiltration attempt and channel but cannot confirm the sensitivity
    of the stolen secrets without forensic analysis of the host.
  stage: c2-and-exfiltration
- id: vault-custom-ports
  question: Is the attacker enumerating a Vault instance running on a non-standard
    port?
  requires: full network visibility across all ports
  risk: The current network query focuses on default ports (8200, 6443); a custom
    configuration could allow enumeration to go unnoticed.
  stage: cloud-infrastructure-discovery
coverage:
- stage: cloud-infrastructure-discovery
  status: covered
  steps:
  - secret-store-access
- stage: c2-and-exfiltration
  status: covered
  steps:
  - dns-c2-lead
  - github-search-api
  - rare-external-conns
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: ide-and-assistant-poisoning
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: loader-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: endpoint-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-and-memory-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Cloud secret exposure (AWS/Vault) represents a critical risk to organizational
    infrastructure; a negative result over CI/CD pipelines and developer workstations
    is high-value for ensuring no automated secret drainage is occurring.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a compromised development environment to enumerate
  cloud and vault secrets, followed by exfiltration via a mimicry domain or GitHub
  dead-drop fallback.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1133
- attack.t1195
name: 'Shai-Hulud: Cloud Discovery and Encrypted Exfiltration'
parameters:
  k8s_port:
    default: '6443'
    description: Default port for Kubernetes API server.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  primary_c2:
    default: git-tanstack.com
    description: Primary exfiltration domain identified in the framework.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud analysis
    type: domain
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on (e.g., CI runners or dev machines).
    type: list[host]
  search_string:
    default: thebeautifulmarchoftime
    description: The fallback search string used in GitHub commit searches.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud analysis
    type: string
  vault_port:
    default: '8200'
    description: Default port for HashiCorp Vault.
    type: number
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
rationale: Start by identifying hosts with development tools installed. The framework
  specifically targets environments where AWS/K8s/Vault credentials might reside.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-persistence-and-harvesting
  reason: The previous hunt in this series covers the initial loader execution, memory
    harvesting, and deadman-switch persistence.
  relation: precedes
- hunt: shai-hulud-dev-hook-poisoning
  relation: follows
scenario:
  stages:
  - name: IDE and AI Assistant Hook Poisoning
    observables:
    - '.vscode/tasks.json with runOn: folderOpen'
    - .claude/settings.json with SessionStart hook
    - .claude/setup.mjs
    - .vscode/setup.mjs
    - claude@users.noreply.github.com
    slug: ide-and-assistant-poisoning
    tactic: initial-access
    techniques:
    - T1195
  - name: Bun Runtime Loader Execution
    observables:
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - config.mjs
    - router_init.js
    - opensearch_init.js
    slug: loader-execution
    tactic: execution
    techniques:
    - T1059
  - name: Daemonization and Token Monitoring
    observables:
    - ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
    - ~/.config/systemd/user/gh-token-monitor.service
    - /tmp/tmp.ts018051808.lock
    - __DAEMONIZED=1 environment variable
    slug: endpoint-persistence
    tactic: persistence
    techniques:
    - T1543.001
    - T1543.002
  - name: Secret Harvesting and Memory Extraction
    observables:
    - ~/.aws/credentials
    - ~/.azure/accessTokens.json
    - ~/.config/gcloud/credentials.db
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - Runner.Worker process memory access via /proc/*/mem
    - gh auth token command execution
    slug: credential-and-memory-harvesting
    tactic: credential-access
    techniques:
    - T1552
    - T1003
  - name: Cloud and Vault Secret Enumeration
    observables:
    - AWS Secrets Manager enumeration
    - Kubernetes namespace and secret listing
    - HashiCorp Vault KV mount enumeration
    - Stripe keys and database connection string regex patterns
    slug: cloud-infrastructure-discovery
    tactic: discovery
    techniques:
    - T1528
  - name: Encrypted C2 and GitHub Dead-drops
    observables:
    - git-tanstack[.]com
    - GitHub search for thebeautifulmarchoftime
    - 'GitHub repo description Shai-Hulud: Here We Go Again'
    - Dune-themed repository names (e.g., sardaukar, mentat, stillsuit)
    - RSA-4096-OAEP encrypted payloads
    slug: c2-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1090.003
  summary: Shai-Hulud is a modular offensive framework used by TeamPCP to target developers
    and CI/CD pipelines via supply chain poisoning and malicious IDE hooks. It automates
    extensive credential harvesting from filesystems and process memory, enumerates
    cloud secrets in AWS and Kubernetes, and exfiltrates encrypted data through C2
    domains or GitHub dead-drop repositories.
series:
  index: 2
  slug: shai-hulud-open-source-framework-static-analysis
  title: Shai-Hulud open source framework static analysis
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Shai-Hulud: Cloud Discovery and Encrypted Exfiltration

This hunt focuses on the 'Shai-Hulud' framework's post-harvesting stages. Specifically, we look for high-volume network interactions with secret storage services (AWS Secrets Manager, Kubernetes API, HashiCorp Vault) and exfiltration patterns to known C2 infrastructure or the framework's fallback mechanism involving GitHub commit searches and Dune-themed dead-drop repositories.

## scoping-dev-environments
<!-- Scope to development and CI environments -->
Identify hosts running tools targeted by Shai-Hulud (Bun, NPM, AWS CLI, Kubectl).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or CI/CD pipelines.
reads:
- device_hostname
- package_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE package_name IN ('bun', 'npm', 'aws-cli', 'kubectl', 'vault') AND asset_scope = 'endpoint'
```

## dns-c2-lead
<!-- DNS lookups to mimicry C2 domain -->
Find hosts resolving the primary exfiltration domain git-tanstack.com.

```sqlite target=endpoint role=detection-candidate params=(primary_c2=primary_c2, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hostnames resolving domains that mimic legitimate open-source projects like
  TanStack.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (LOWER(query_hostname) = LOWER('{{primary_c2}}') OR instr(LOWER(query_hostname), 'tanstack') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-parallel
<!-- Corroborate exfiltration and discovery -->
parallel:
- → github-search-api
- → secret-store-access
- → rare-external-conns
join: → triage-agent

## github-search-api
<!-- GitHub API interaction with fallback string -->
Identify HTTP requests to GitHub's search API using the framework's fallback query.

```sqlite target=web role=enrichment params=(search_string=search_string, lookback_days=lookback_days)
~~~yaml
expected: Requests to GitHub for the specific fallback string 'thebeautifulmarchoftime'.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- url_full
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, time FROM hb_http_activity WHERE url_hostname = 'api.github.com' AND (instr(LOWER(url_query), LOWER('{{search_string}}')) > 0 OR instr(LOWER(url_full), LOWER('{{search_string}}')) > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## secret-store-access
<!-- Anomalous secret store interaction -->
Find network connections to Vault, K8s, or AWS secret endpoints from development workstations.

```sqlite target=network role=triage params=(vault_port=vault_port, k8s_port=k8s_port, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: High-frequency or novel connections to infrastructure secret stores.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (dst_endpoint_port IN ({{vault_port}}, {{k8s_port}}) OR instr(LOWER(dst_endpoint_hostname), 'secretsmanager') > 0 OR instr(LOWER(dst_endpoint_hostname), 'ssm.') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-external-conns
<!-- Rare process-domain network pairs -->
Stack-count process and external hostname pairs to find one-off exfiltration channels.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An unusual process (like Bun or a temporary script) talking to a rare external
  hostname.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_hostname
  rare_below: 3
reads:
- process_name
- dst_endpoint_hostname
- device_hostname
- time
- direction
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, dst_endpoint_hostname, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-agent
<!-- Weigh exfiltration and discovery evidence -->
```agent target=hunter
cite: required
context:
- dns-c2-lead
- github-search-api
- secret-store-access
- rare-external-conns
max_iterations: 3
objective: Determine if any host shows evidence of cloud secret enumeration followed
  by exfiltration via the git-tanstack.com domain or the GitHub fallback search mechanism.
success_criteria: A per-host verdict citing specific DNS, HTTP, or Network rows.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route based on triage -->
if~: "The triage verdict is malicious for at least one host involving TanStack C2 or GitHub fallback activity." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encryption-metadata-only)
else: → analyst-review

## isolate-host
<!-- Isolate compromised workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any cloud credentials used by that host, and perform memory forensics to identify the framework payload.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the processes flagged by the 'rare-external-conns' step. Check for OIDC token abuse in CI environments and rotate any secrets identified in the 'secret-store-access' step.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record all identified C2 domains and search strings. If the 'dns-c2-lead' query provided high-fidelity results, promote it to a standing detection rule.
```
→ end
