---
analysis: A single detection rule for the C2 domain fails if infrastructure rotates;
  this hunt correlates the network signal with the prevalence of API polling and the
  behavioural footprint of the persistence daemon and its destructive payload, providing
  context an analyst must weigh before acting.
blind_spots:
- id: no-process-visibility
  question: whether the deadman switch is currently monitoring a token
  requires: hb_process_activity with command-line arguments
  risk: A host without process logging could have its token revoked by an administrator,
    triggering the destruction before the hunt identifies the threat.
  stage: impact-destructive-wipe
- id: github-search-visibility
  question: if the host searched GitHub for a rotated C2 domain
  requires: hb_http_activity with full URL query parameters
  risk: If the primary C2 domain is blocked, the attacker can rotate infrastructure
    via signed commits; without visibility into the GitHub search query, we cannot
    see the transition.
  stage: c2-encrypted-communications
coverage:
- stage: c2-encrypted-communications
  status: covered
  steps:
  - lead-dns-c2
  - http-github-activity
- stage: exfiltration-github-dead-drops
  status: covered
  steps:
  - http-github-activity
- stage: impact-destructive-wipe
  status: covered
  steps:
  - process-monitor-and-wipe
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: initial-access-supply-chain-poisoning
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: execution-loader-bootstrap
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: persistence-daemon-and-deadman-monitor
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-memory-and-file-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: discovery-cloud-infrastructure-enumeration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Shai-Hulud framework contains a credible threat of data destruction
    during incident response; detecting the deadman switch is required to prevent
    large-scale data loss when credentials are rotated.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using the Shai-Hulud framework to exfiltrate stolen credentials
  through GitHub dead-drops and has installed a destructive deadman switch that triggers
  a home-directory wipe if tokens are revoked.
labels:
- hunt
- attack.t1071.001
- attack.t1090.003
- attack.t1567.001
- attack.t1485
name: 'Shai-Hulud: Exfiltration and Deadman Switch'
parameters:
  c2_domains:
    default:
    - git-tanstack.com
    description: Primary C2 domains identified in the Shai-Hulud framework.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud static analysis
    type: list[domain]
  fallback_search_string:
    default: thebeautifulmarchoftime
    description: The signed string used to locate rotated C2 domains on GitHub.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud static analysis
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: retention-policy
    type: number
  scope_hosts:
    default: []
    description: A list of hostnames to narrow the search; leave empty to hunt across
      the entire estate.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: analyst-entry
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with developer workstations and CI/CD runners where GitHub and cloud
  credentials are most prevalent. Focus on hosts with Linux or macOS profiles.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-persistence-and-harvesting
  reason: Initial access through supply chain poisoning and local credential harvesting
    are handled in separate hunts.
  relation: out-of-scope-alternative
- hunt: shai-hulud-secret-harvesting-discovery
  relation: follows
scenario:
  stages:
  - name: Supply Chain Poisoning & Repository Hijacking
    observables:
    - hijacked Trivy and Checkmarx KICS tags
    - poisoned LiteLLM, TanStack, and UiPath npm/PyPI packages
    - '.vscode/tasks.json with runOn: folderOpen'
    - .claude/settings.json SessionStart hook
    - claude@users.noreply.github.com
    slug: initial-access-supply-chain-poisoning
    tactic: initial-access
    techniques:
    - T1195
    - T1133
  - name: Multi-language Loader Execution
    observables:
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - config.mjs
    - setup.mjs
    - router_init.js
    - opensearch_init.js
    - node .claude/setup.mjs
    - Bun runtime download
    slug: execution-loader-bootstrap
    tactic: execution
    techniques:
    - T1059.004
    - T1059.007
  - name: Daemonized Persistence & Token Monitoring
    observables:
    - /tmp/tmp.ts018051808.lock
    - ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
    - ~/.config/systemd/user/gh-token-monitor.service
    - loginctl enable-linger
    - __DAEMONIZED=1
    slug: persistence-daemon-and-deadman-monitor
    tactic: persistence
    techniques:
    - T1543.001
    - T1543.002
  - name: Memory Secret Extraction & Credential Harvesting
    observables:
    - Runner.Worker
    - /proc/*/mem scanning
    - gh auth token
    - ~/.aws/credentials
    - ~/.azure/accessTokens.json
    - ~/.config/gcloud/credentials.db
    - ~/.kube/config
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - .npmrc
    - .pypirc
    - .claude.json
    slug: credential-access-memory-and-file-harvesting
    tactic: credential-access
    techniques:
    - T1003.001
    - T1552.001
    - T1555
  - name: Cloud and K8s Secret Discovery
    observables:
    - AWS Secrets Manager enumeration
    - SSM Parameter Store enumeration
    - Kubernetes namespace listing
    - HashiCorp Vault KV mount enumeration
    slug: discovery-cloud-infrastructure-enumeration
    tactic: discovery
    techniques:
    - T1580
    - T1082
  - name: Encrypted Domain-based C2
    observables:
    - git-tanstack[.]com
    - thebeautifulmarchoftime GitHub commit search
    - RSA-4096-OAEP
    - AES-256-GCM
    slug: c2-encrypted-communications
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: GitHub Dead-drop Exfiltration
    observables:
    - 'Shai-Hulud: Here We Go Again repository description'
    - Dune-themed repo names (sardaukar, mentat, stillsuit)
    - results/ directory JSON commits
    - IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner
    slug: exfiltration-github-dead-drops
    tactic: exfiltration
    techniques:
    - T1567.001
  - name: Conditional Data Destruction
    observables:
    - rm -rf ~/
    - HTTP 40x response from https://api.github.com/user
    slug: impact-destructive-wipe
    tactic: impact
    techniques:
    - T1485
  summary: The Shai-Hulud framework by TeamPCP is a modular TypeScript toolkit that
    targets CI/CD pipelines and developer workstations through supply chain poisoning
    of npm/PyPI packages and IDE configurations. It extracts credentials from process
    memory, cloud environments, and local files before exfiltrating encrypted data
    to C2 domains or GitHub dead-drop repositories, featuring a 'deadman switch' that
    wipes the user directory if stolen tokens are revoked.
series:
  index: 3
  slug: shai-hulud-open-source-framework-static-analysis
  title: Shai-Hulud open source framework static analysis
  total: 3
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Shai-Hulud: Exfiltration and Deadman Switch

The Shai-Hulud framework employs a sophisticated exfiltration pipeline that prioritizes domain-based C2 before falling back to GitHub repository dead-drops. Crucially, the framework installs a monitoring daemon that polls the GitHub API to detect token revocation. If the token is invalidated by the defender, the daemon executes a destructive command to wipe the user's home directory. This hunt identifies the network-facing exfiltration activity and the behavioural footprint of the deadman switch to ensure safe remediation.

## lead-dns-c2
<!-- Primary C2 domain lookups -->
Identify hosts resolving the framework's primary C2 domain to scope the investigation.

```sqlite target=endpoint role=scoping params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts that contacted the default framework infrastructure. Silence
  proves only that the default domain was not used.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with impact and activity -->
parallel:
- → process-monitor-and-wipe
- → http-github-activity
join: → triage-agent

## process-monitor-and-wipe
<!-- Monitor daemon and destructive activity -->
Detect the execution of the Shai-Hulud monitoring daemon or the destructive wipe command itself.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The presence of the gh-token-monitor process or a broad directory deletion
  command. This is the definitive indicator of a framework infection.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%gh-token-monitor%' OR LOWER(process_cmd_line) LIKE '%rm -rf%' OR LOWER(process_cmd_line) LIKE '%tmp.ts018051808.lock%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## http-github-activity
<!-- GitHub API activity and rotation -->
Identify high-frequency GitHub API polling or searches for rotated C2 infrastructure.

```sqlite target=web role=baseline params=(fallback_search_string=fallback_search_string, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A high count of requests to the GitHub user endpoint per host, indicating
  the deadman switch is polling for revocation. Silence on the rotation string is
  expected unless infrastructure has rotated.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 3
reads:
- device_hostname
- url_hostname
- url_path
- url_full
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ( (LOWER(url_hostname) = 'api.github.com' AND LOWER(url_path) = '/user') OR url_full LIKE '%' || '{{fallback_search_string}}' || '%' ) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path
```

## triage-agent
<!-- Triage exfiltration and deadman switch -->
```agent target=hunter
cite: required
context:
- lead-dns-c2
- process-monitor-and-wipe
- http-github-activity
max_iterations: 5
objective: Determine if the evidence indicates a Shai-Hulud framework infection and
  evaluate whether a destructive deadman switch is active on any host.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows from the process and HTTP surfaces.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-agent verdict is malicious for at least one host and identifies the token-monitoring daemon or destructive file deletion commands" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → token-investigation
unavailable: → token-investigation (blind_spot: no-process-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate the gh-token-monitor process and any instances of Bun or Node running malicious scripts before revoking any identified GitHub tokens.
```
→ token-investigation

## token-investigation
<!-- Review leaked tokens -->
```manual target=analyst
Audit GitHub, AWS, and Kubernetes secrets for any tokens originating from the identified hosts. Check user shell histories and configuration files for exposed material.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Summarize the findings. If the gh-token-monitor or the git-tanstack.com domain were confirmed, recommend promoting the associated queries to standing detection rules.
```
→ end
