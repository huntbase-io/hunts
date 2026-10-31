---
analysis: A standard rule might detect an individual file read; this hunt correlates
  secret harvesting from memory with a surge in discovery traffic across multiple
  surfaces, identifying a coordinated campaign rather than a lone anomalous event.
blind_spots:
- id: no-endpoint-visibility
  question: Whether secret files were accessed on unmanaged workstations or BYOD devices.
  requires: hb_file_activity with endpoint agent coverage
  risk: An intruder can harvest secrets from an unmanaged machine and use them to
    pivot into the cloud environment invisibly to this hunt.
  stage: credential-access-memory-and-file-harvesting
- id: encrypted-discovery-traffic
  question: Whether specific Secrets Manager or SSM Parameter Store API calls were
    made.
  requires: hb_http_activity with TLS inspection for AWS API endpoints
  risk: Without TLS inspection, discovery activity appears as generic HTTPS traffic
    to AWS, masking the volume and nature of the enumeration.
  stage: discovery-cloud-infrastructure-enumeration
coverage:
- stage: credential-access-memory-and-file-harvesting
  status: covered
  steps:
  - lead-sensitive-file-access
  - baseline-memory-access
- stage: discovery-cloud-infrastructure-enumeration
  status: covered
  steps:
  - cloud-discovery-traffic
- reason: Covered in the supply chain poisoning hunt of this series.
  stage: initial-access-supply-chain-poisoning
  status: out_of_scope
- reason: Covered in the execution hunt of this series.
  stage: execution-loader-bootstrap
  status: out_of_scope
- reason: Covered in the persistence hunt of this series.
  stage: persistence-daemon-and-deadman-monitor
  status: out_of_scope
- reason: Covered in the exfiltration hunt of this series.
  stage: c2-encrypted-communications
  status: out_of_scope
- reason: Covered in the exfiltration hunt of this series.
  stage: exfiltration-github-dead-drops
  status: out_of_scope
- reason: Covered in the exfiltration hunt of this series.
  stage: impact-destructive-wipe
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The Shai-Hulud frameworks ability to extract secrets from process
    memory bypasses standard masking; a negative result over the fleet provides assurance
    that this pervasive supply chain threat has not established a beachhead.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed the Shai-Hulud framework to extract credentials
  from filesystem paths and process memory, subsequently using them to automate the
  discovery of cloud and Kubernetes infrastructure secrets.
labels:
- hunt
- attack.t1003.001
- attack.t1082
- attack.t1552.001
- attack.t1555
- attack.t1580
name: Shai-Hulud Secret Harvesting and Discovery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to focus investigation; if empty, the entire
      fleet is queried.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: analyst-scoping
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
rationale: Prioritize GitHub Actions runners (self-hosted and managed) and developer
  workstations. Focus on hosts running Linux or macOS where /proc or configuration
  directories are accessible.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-loader-execution
  reason: The loader must execute first to bootstrap the environment that performs
    the harvesting.
  relation: precedes
- hunt: shai-hulud-exfiltration-c2
  reason: Harvested and discovered secrets are later exfiltrated via encrypted channels.
  relation: follows
- hunt: shai-hulud-supply-chain-loader
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
  index: 2
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


# Shai-Hulud Secret Harvesting and Discovery

This hunt targets the internal logic of the Shai-Hulud framework as it traverses the filesystem and memory to aggregate credentials. Shai-Hulud specifically targets AWS, Azure, and Kubernetes configuration files, and it attempts to dump the memory of the GitHub Runner.Worker process to bypass secret masking. The hunt identifies these harvesting patterns and correlates them with subsequent automated enumeration of cloud secret stores like AWS Secrets Manager or the Kubernetes API. We start by scoping for sensitive file access, then fan out to baseline memory reads and cloud discovery traffic.

## lead-sensitive-file-access
<!-- Lead: Sensitive file access -->
Identify hosts where processes are reading sensitive cloud or developer credentials using a high-performance filter for known target filenames.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts and processes accessing high-value credential files. Silence means
  no such files were touched by monitored processes.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, process_name, time FROM hb_file_activity WHERE activity_id = 2 AND LOWER(file_name) IN ('credentials', 'accesstokens.json', 'credentials.db', 'config', '.npmrc', '.pypirc', '.env') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Parallel investigation -->
parallel:
- → baseline-memory-access
- → cloud-discovery-traffic
join: → triage-agent

## baseline-memory-access
<!-- Baseline: Rare /proc/mem reads -->
Find rare instances of processes reading their own or other processes memory, specifically targeting runner.worker as identified in framework static analysis.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of processes performing rare memory reads across the fleet. Silence
  suggests no such scraping occurred on scoped hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- file_path
- time
- activity_id
- process_cmd_line
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 2 AND LOWER(file_path) LIKE '/proc/%/mem' AND (LOWER(process_name) LIKE '%runner.worker%' OR LOWER(process_cmd_line) LIKE '%runner.worker%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## cloud-discovery-traffic
<!-- Cloud and K8s discovery traffic -->
Detect high-volume or rare enumeration of cloud secrets or Kubernetes namespaces to distinguish standard developer activity from anomalous discovery.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A surge in API requests or rare API paths used for secret storage services.
  Silence means no such enumeration was visible.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT url_path, url_hostname, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS req_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_hostname) LIKE '%secretsmanager%' OR LOWER(url_hostname) LIKE '%ssm%' OR LOWER(url_path) LIKE '%/api/v1/namespaces%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_path, url_hostname HAVING host_count <= 3 ORDER BY req_count DESC
```

## triage-agent
<!-- Triage harvesting and discovery -->
```agent target=hunter
cite: required
context:
- lead-sensitive-file-access
- baseline-memory-access
- cloud-discovery-traffic
max_iterations: 6
objective: Determine if a host has been used to harvest credentials from files or
  memory, and if those credentials were used to enumerate cloud secrets.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  process names and discovery URLs.
tools:
- endpoint
- web
```

## verdict-decision
<!-- Decision: Route on verdict -->
if~: "the triage verdict is malicious for at least one host indicating confirmed harvesting followed by enumeration" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: no-endpoint-visibility)
else: → analyst-validation

## contain-host
<!-- Isolate beachhead host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Notify the cloud security team to rotate any IAM credentials or K8s tokens that were present on the host.
```
→ analyst-validation

## analyst-validation
<!-- Analyst: Validate harvesting scope -->
```manual target=analyst
Review the process lineage for the memory reads. Cross-reference the HTTP discovery traffic with CloudTrail logs to confirm which specific Secrets Manager paths were accessed.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the malicious process names and paths. If the behavior was confirmed, promote the memory access logic to a permanent detection rule for Linux and macOS environments.
```
→ end
