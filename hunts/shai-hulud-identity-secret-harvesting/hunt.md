---
analysis: 'A standard rule alerts on a single sensitive file read. This hunt uses
  multi-surface pivots to find the behavioral signature: one process reading multiple
  multi-cloud secrets while simultaneously attempting memory-scraping of runner processes,
  specifically when that process is fileless (on_disk=0).'
blind_spots:
- id: telemetry-gap-ci
  owner: DevOps Engineering
  question: Did harvesting occur on an ephemeral runner that has already terminated?
  remediation: Enable real-time telemetry streaming to a central SIEM for all CI/CD
    environments.
  requires: Persistent logging for ephemeral CI runners
  risk: Memory scraping indicators are lost if runner telemetry is not streamed and
    retained off-host.
  stage: credential-access-memory-scraping
- id: script-telemetry-limited
  owner: Security Engineering
  question: Is script block logging enabled for non-PowerShell interpreters?
  remediation: Implement system-wide script block auditing for all shell and language
    interpreters.
  requires: hb_script_activity for Python/Bun
  risk: If Python or Bun script execution is not captured, the high-fidelity 'isSecret'
    pattern match cannot be verified.
  stage: credential-access-memory-scraping
coverage:
- stage: credential-access-secrets-harvesting
  status: covered
  steps:
  - credential-file-access
- stage: credential-access-memory-scraping
  status: covered
  steps:
  - proc-memory-access
  - script-scraping-logic
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: execution-bootstrap-loaders
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: persistence-deadman-switch
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: c2-exfiltration-hybrid-channels
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: lateral-movement-repo-poisoning
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Shai-Hulud's power comes from its automated weaponization loop; identifying
    the credential harvest before it is used to poison repositories is the only way
    to stop the supply chain propagation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is programmatically harvesting cloud credentials and CI secrets
  by reading configuration files and scraping process memory from developer workstations
  and CI runners.
labels:
- hunt
- attack.t1555
- attack.t1003.007
- attack.t1552.001
- attack.t1041
- attack.t1195
name: 'Shai-Hulud: Identity and Secret Harvesting'
parameters:
  developer_tools:
    default:
    - bun
    - git
    - docker
    - aws-cli
    - kubectl
    - vscode
    - claude
    description: Software packages indicating a developer workstation or CI environment.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: common engineering toolsets
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations and CI runners with the Bun runtime or common developer
  CLI tools installed. Use hb_software_inventory as the primary scoping surface.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-exfiltration-channels
  reason: Exfiltration of the harvested data happens immediately after collection
    via hybrid channels.
  relation: follows
- hunt: shai-hulud-bootstrap-loaders
  reason: The framework loaders must execute successfully to initialize the harvesting
    providers.
  relation: precedes
scenario:
  stages:
  - name: Supply chain poisoning and tag hijacking
    observables:
    - Hijacked Trivy and Checkmarx KICS tags
    - Poisoned LiteLLM PyPI package
    - Poisoned TanStack and UiPath npm packages
    - Spoofed commit dates 2099-01-01
    - Author TeamPCP_OSS <TeamPCP>
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: Staged loader execution
    observables:
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - config.mjs
    - router_init.js
    - setup.mjs
    - opensearch_init.js
    - Download of Bun runtime
    - __DAEMONIZED=1 environment variable
    slug: execution-bootstrap-loaders
    tactic: execution
  - name: Local and cloud secrets harvesting
    observables:
    - Reading ~/.aws/credentials
    - Reading ~/.azure/accessTokens.json
    - Reading ~/.config/gcloud/credentials.db
    - Reading ~/.ssh/id_*
    - Reading ~/.kube/config
    - Reading /var/run/secrets/kubernetes.io/serviceaccount/token
    - Execution of 'gh auth token'
    - Capturing process.env
    - Regex matching for ghp_, gho_, npm_, ghs_
    slug: credential-access-secrets-harvesting
    tactic: credential-access
  - name: CI/CD runner memory extraction
    observables:
    - Searching for Runner.Worker PID via /proc/*/cmdline
    - Reading /proc/[pid]/maps and /proc/[pid]/mem
    - Python stdin execution with sudo
    - Extraction of JSON structures with 'isSecret':true
    slug: credential-access-memory-scraping
    tactic: credential-access
  - name: Persistence and deadman switch installation
    observables:
    - ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
    - ~/.config/systemd/user/gh-token-monitor.service
    - loginctl enable-linger
    - /tmp/tmp.ts018051808.lock
    - Polling https://api.github.com/user every 60 seconds
    - Execution of 'rm -rf ~/' upon token revocation
    slug: persistence-deadman-switch
    tactic: persistence
    techniques:
    - T1133
  - name: Encrypted exfiltration and C2
    observables:
    - HTTPS POST to git-tanstack[.]com
    - GitHub commit search for 'thebeautifulmarchoftime'
    - Dune-themed GitHub repository creation (e.g., sardaukar-mentat-01)
    - 'GitHub repo description ''Shai-Hulud: Here We Go Again'''
    - Committing encrypted JSON to results/ directory
    - Double-base64-encoded tokens in commit messages
    slug: c2-exfiltration-hybrid-channels
    tactic: exfiltration
    techniques:
    - T1041
    - T1090.003
  - name: Developer tool hook poisoning
    observables:
    - 'Creation of .vscode/tasks.json with runOn: folderOpen'
    - Creation of .claude/settings.json with SessionStart hook
    - Commits attributed to claude@users.noreply.github.com
    - 'Commit message ''chore: update dependencies'''
    slug: lateral-movement-repo-poisoning
    tactic: lateral-movement
    techniques:
    - T1195
  summary: TeamPCP utilizes the Shai-Hulud framework to conduct supply chain attacks
    against developers and CI/CD pipelines, poisoning npm/PyPI packages and GitHub
    repositories with malicious hooks. The framework harvests extensive credentials
    from files, environment variables, and process memory before exfiltrating data
    via encrypted HTTPS channels or GitHub dead-drop repositories.
series:
  index: 1
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


# Shai-Hulud: Identity and Secret Harvesting

This hunt identifies the early-stage data collection phase of the Shai-Hulud framework. It targets the specialized FileSystemService and GitHubRunner providers, which automate the theft of AWS, GCP, Azure, Kubernetes, and SSH secrets. The hunt specifically monitors for processes reading multiple high-value configuration files and uses script telemetry to identify the unique memory-scraping logic used to bypass CI/CD secret masking on GitHub Actions runners, prioritizing processes that exhibit fileless behavior.

## scope-to-exposed-environments
<!-- Identify exposed dev and CI environments -->
Focus the hunt on hosts with software components known to be targeted by the Shai-Hulud framework.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, developer_tools=developer_tools)
~~~yaml
expected: A list of hosts containing developer tools or the Bun runtime. Absence of
  results suggests the framework hasn't targeted the expected software profile.
reads:
- device_hostname
- package_name
- package_version
- install_path
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (instr(',' || '{{developer_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) = 'bun') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## gather-harvesting-evidence
<!-- Parallel harvesting analysis -->
parallel:
- → credential-file-access
- → proc-memory-access
- → script-scraping-logic
join: → triage-identity-harvesting

## credential-file-access
<!-- Automated access to multi-cloud secrets -->
Detect a single process reading multiple different cloud and SSH credential files within scoped environments.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, developer_tools=developer_tools)
~~~yaml
expected: A single process reading multiple distinct secret paths. This identifies
  the 'FileSystemService' provider.
reads:
- device_hostname
- process_name
- process_cmd_line
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, COUNT(DISTINCT file_path) as unique_secrets_read, GROUP_CONCAT(file_path) as path_list FROM hb_file_activity WHERE activity_id = 2 AND (LOWER(file_path) LIKE '%/.aws/credentials' OR LOWER(file_path) LIKE '%/.ssh/id_%' OR LOWER(file_path) LIKE '%/.kube/config' OR LOWER(file_path) LIKE '%/.azure/accessTokens.json' OR LOWER(file_path) LIKE '%/.config/gcloud/credentials.db' OR LOWER(file_path) LIKE '%/.env') AND device_hostname IN (SELECT device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{developer_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) = 'bun')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line HAVING unique_secrets_read >= 2
```

## proc-memory-access
<!-- Unusual memory access from fileless processes -->
Identify processes (especially those not on disk) reading the memory of other processes to steal secrets from runners.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, developer_tools=developer_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A fileless process reading /proc/pid/mem on a dev host or CI runner. This
  targets the 'GitHubRunner' provider.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- on_disk
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/proc/%/mem%' OR LOWER(process_cmd_line) LIKE '%/proc/%/maps%') AND on_disk = 0 AND device_hostname IN (SELECT device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{developer_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) = 'bun')) AND LOWER(process_name) NOT IN ('gdb', 'strace', 'lsof') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line, user_name
```

## script-scraping-logic
<!-- Python memory scraping script analysis -->
Corroborate memory access with the specific regex and scraping logic found in the framework code.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, developer_tools=developer_tools)
~~~yaml
expected: Script content exhibiting the exact environment extraction patterns mentioned
  in the dossier.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%re.match%' OR LOWER(script_content) LIKE '%m.group%' OR LOWER(script_content) LIKE '%sys.stdout.buffer.write%' OR LOWER(script_content) LIKE '%runner.worker%') AND LOWER(script_content) LIKE '%issecret%' AND device_hostname IN (SELECT device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{developer_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) = 'bun')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-identity-harvesting
<!-- Triage identity harvesting evidence -->
```agent target=hunter
cite: required
context:
- credential-file-access
- proc-memory-access
- script-scraping-logic
max_iterations: 3
objective: Determine if the observed behavior represents the Shai-Hulud framework's
  harvesting stage. Prioritize hosts where a single process matches both secret file
  reads and memory scraping behavior.
success_criteria: A malicious | suspicious | benign verdict for each host, citing
  specific evidence.
tools:
- endpoint
```

## route-harvesting-verdict
<!-- Route on harvesting verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: telemetry-gap-ci)
else: → analyst-final-review

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to prevent exfiltration of harvested credentials.
```
→ rotate-harvested-credentials

## rotate-harvested-credentials
<!-- Rotate harvested credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Immediately revoke and rotate all secrets found in the file paths cited by the agent (AWS, GitHub tokens, SSH keys, etc.).
```
→ analyst-final-review

## analyst-final-review
<!-- Analyst final review -->
```manual target=analyst
Review the cited evidence. Confirm that all CI/CD runners affected have been decommissioned and that harvested tokens have been rotated globally.
```
→ end
