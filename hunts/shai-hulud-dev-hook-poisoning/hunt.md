---
analysis: A simple detection rule for the 'gh-token-monitor' string can be bypassed
  by renaming the service; this hunt instead pivots between hook poisoning, rare Bun-based
  execution, and the functional outcome of secret harvesting, requiring an agent to
  weigh the intersection of multiple weak signals.
blind_spots:
- id: missing-file-telemetry
  question: Were hook files modified in excluded or unindexed developer project folders?
  requires: hb_file_activity for hidden directories
  risk: A poisoned repo cloned into a directory excluded from EDR monitoring would
    be invisible during the poisoning stage.
  stage: ide-and-assistant-poisoning
- id: transient-persistence
  question: Was the token-monitor daemon deleted before the hunt ran?
  requires: hb_scheduled_job with high frequency collection
  risk: The framework's deadman switch monitors self-terminate after 24 hours, making
    point-in-time snapshots potentially miss the indicator.
  stage: endpoint-persistence
coverage:
- stage: ide-and-assistant-poisoning
  status: covered
  steps:
  - detect-hook-poisoning
- stage: loader-execution
  status: covered
  steps:
  - suspicious-memory-scraping
  - credential-harvesting-reads
- stage: endpoint-persistence
  status: covered
  steps:
  - rare-persistence-monitors
- stage: credential-and-memory-harvesting
  status: covered
  steps:
  - suspicious-memory-scraping
  - credential-harvesting-reads
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: cloud-infrastructure-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: c2-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Shai-Hulud's targeting of IDE hooks and AI assistant configurations
    bypasses traditional 'identity' perimeters by weaponizing the developer's local
    environment; a negative result over the developer estate is critical for supply
    chain integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using poisoned IDE hooks (VSCode/Claude Code) to execute
  a modular Bun-based framework that establishes deadman-switch persistence and extracts
  secrets from GitHub runner memory.
labels:
- hunt
- attack.t1195
- attack.t1059
- attack.t1543.001
- attack.t1543.002
- attack.t1552
- attack.t1003
name: 'Shai-Hulud: Developer Hook Poisoning and Memory Harvesting'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  poisoned_hook_paths:
    default:
    - .vscode/tasks.json
    - .claude/settings.json
    - .claude/setup.mjs
    - .vscode/setup.mjs
    description: IDE and AI assistant hook paths targeted for poisoning.
    from:
      kind: article
      observed: '2026-05-12'
      ref: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
    type: list[path]
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to hunt across
      the entire estate.
    type: list[host]
  sensitive_files:
    default:
    - .aws/credentials
    - .azure/accessTokens.json
    - .config/gcloud/credentials.db
    - .ssh/id_rsa
    - .kube/config
    description: Target paths for the FileSystemService collector.
    from:
      kind: article
      observed: '2026-05-12'
      ref: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
    type: list[path]
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
rationale: Start with developer workstations and CI/CD runner hosts. If no software
  inventory is available, hunt across all macOS and Linux assets using the behavioral
  queries directly.
references:
- name: Security Labs - Shai-Hulud Framework Static Analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-cloud-infrastructure-discovery
  reason: This hunt focuses on the developer workstation and initial harvesting; cloud-side
    enumeration (SSM, Secrets Manager) is a follow-on stage.
  relation: out-of-scope-alternative
- hunt: shai-hulud-c2-and-exfiltration
  reason: Encrypted exfiltration to mimics and GitHub repositories involves network/SaaS
    telemetry handled in a sibling hunt.
  relation: out-of-scope-alternative
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
  index: 1
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
tlp: clear
type: investigation
---


# Shai-Hulud: Developer Hook Poisoning and Memory Harvesting

This hunt targets the local lifecycle of the Shai-Hulud framework. It identifies the initial poisoning of developer configuration files (hooks), the execution of modular loaders that bootstrap the Bun runtime, and the establishment of rare persistence monitors. It specifically looks for the 'self-propagating' loop where harvested credentials are used to push backdoored tasks back into repositories, and corroborates this with high-signal evidence of /proc/mem extraction on GitHub runners.

## scope-dev-environment
<!-- Identify Developer and Runner Assets -->
Scope the hunt to hosts running developer tools or identified as runners to focus on high-risk surfaces.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to developers or build servers. Silence means
  no such software is present.
reads:
- collected_at
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%vscode%' OR LOWER(package_name) LIKE '%bun%' OR LOWER(package_name) LIKE '%claude%' OR LOWER(package_name) LIKE '%cursor%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## detect-hook-poisoning
<!-- Poisoned IDE Hook Activity -->
Find modifications to IDE task and assistant settings that trigger payload execution on folder open.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, poisoned_hook_paths=poisoned_hook_paths)
~~~yaml
expected: File writes to sensitive IDE hooks. Silence here does not mean the framework
  is absent, as a poisoned repo could have been cloned with the hooks already in place.
reads:
- activity_id
- actor_user_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE (instr(',' || '{{poisoned_hook_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR LOWER(file_path) LIKE '%/.vscode/tasks.json' OR LOWER(file_path) LIKE '%/.claude/settings.json') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-deep-hunt
<!-- Parallel Evidence Gathering -->
parallel:
- → rare-persistence-monitors
- → suspicious-memory-scraping
- → credential-harvesting-reads
join: → triage-shai-hulud

## rare-persistence-monitors
<!-- Rare Token Monitoring Services -->
Stack-count the persistent monitors installed by the deadman switch to find one-off instances.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A LaunchAgent or systemd service seen on only a few hosts. Silence suggests
  no active deadman switch persistence.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_definition_path
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_cmd_line
- job_definition_path
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT job_name, job_definition_path, job_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%monitor%' OR LOWER(job_definition_path) LIKE '%gh-token-monitor%' OR LOWER(job_cmd_line) LIKE '%api.github.com/user%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name, job_definition_path, job_cmd_line HAVING host_count <= 3
```

## suspicious-memory-scraping
<!-- Runner Memory Extraction via Proc -->
Detect the extraction of Runner.Worker secrets via process memory reading.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Python or Bun processes reading from /proc/pid/mem of a GitHub Runner. Silence
  means this specific technique was not observed.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/proc/%/mem%' AND LOWER(process_cmd_line) LIKE '%runner.worker%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## credential-harvesting-reads
<!-- Sensitive File Harvesting Pattern -->
Check for mass reading of cloud and identity secrets by unusual processes.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_files=sensitive_files)
~~~yaml
expected: A single process (Bun, Python, or shell) reading multiple distinct credential
  files in a short window.
reads:
- activity_id
- actor_user_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, COUNT(*) AS file_count FROM hb_file_activity WHERE instr(',' || '{{sensitive_files}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND activity_id = 2 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, actor_user_name HAVING file_count >= 2
```

## triage-shai-hulud
<!-- Triage Developer Compromise -->
```agent target=hunter
cite: required
context:
- detect-hook-poisoning
- rare-persistence-monitors
- suspicious-memory-scraping
- credential-harvesting-reads
max_iterations: 4
objective: Identify hosts where IDE hook modifications occurred followed by suspicious
  memory access or mass secret harvesting. Distinguish legitimate developer tool activity
  from the Bun-based framework behavior.
success_criteria: A verdict of malicious | suspicious | benign per host citing the
  intersection of hook poisoning and harvesting activity.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke all GitHub tokens and rotate cloud credentials (AWS/Azure/GCP) associated with the compromised user account immediately.
```
→ analyst-review

## analyst-review
<!-- Manual Review and Tuning -->
```manual target=analyst
Examine the processes that read from /proc/mem and the context of any IDE hook modifications. Confirm whether the activity matches known TeamPCP tradecraft (e.g., using Bun or custom Python runners).
```
→ end

## close-out
<!-- Close and Record -->
```manual target=analyst
Record the window of time and the hosts that provided telemetry. No findings in this window suggests no active Shai-Hulud infection of developer tools.
```
→ end
