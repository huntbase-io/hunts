---
analysis: A single detection rule would likely false positive on legitimate developer
  setup scripts. This hunt uses prevalence stacking (rare loaders), scoping (dev workstations),
  and multi-surface corroboration (file write to hooks followed by runtime execution)
  to build a high-confidence case for an analyst to review.
blind_spots:
- id: limited-endpoint-telemetry
  owner: endpoint-security-team
  question: whether the 'setup.mjs' file content actually contains the loader logic
  remediation: Deploy Sysmon or a similar agent to capture process command lines and
    script block contents.
  requires: EDR with process command line and file integrity monitoring
  risk: An analyst might misidentify a legitimate build script as a loader if only
    filenames are available; conversely, an attacker could rename the loader to a
    common utility name.
  stage: execution-bootstrap-loaders
- id: github-connector-coverage
  owner: devsecops-team
  question: whether the malicious commits were pushed to repositories not covered
    by current logging
  remediation: Ensure all organizational GitHub repositories are onboarded to the
    central logging platform.
  requires: GitHub Enterprise audit log connector (hb_file_activity via github provider)
  risk: Lateral movement via repo poisoning on personal or shadow-IT repositories
    will be invisible to this hunt.
  stage: lateral-movement-repo-poisoning
coverage:
- stage: execution-bootstrap-loaders
  status: covered
  steps:
  - behavior-loader-process
  - prevalence-rare-loaders
- stage: lateral-movement-repo-poisoning
  status: covered
  steps:
  - detect-poisoned-hooks
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-secrets-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-memory-scraping
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: persistence-deadman-switch
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: c2-exfiltration-hybrid-channels
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: "The 'Shai-Hulud' framework's ability to poison developer tools creates\
    \ a self-propagating loop within the engineering environment. Standard endpoint\
    \ detections often miss these IDE hooks, and the impact\u2014loss of CI/CD secrets\
    \ and cloud credentials\u2014is critical to business operations."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using poisoned repository hooks in VS Code or Claude Code
  to execute malicious loaders on developer workstations following a supply chain
  compromise.
labels:
- hunt
- attack.t1195
- attack.t1059
- attack.t1547
name: Developer Environment Poisoning
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: standard-lookback
    type: number
  shai_hulud_loaders:
    default:
    - setup.mjs
    - config.mjs
    - router_init.js
    - opensearch_init.js
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    description: Loader filenames identified in the Shai-Hulud framework source.
    from:
      kind: article
      observed: '2026-05-12'
      ref: datadog-shai-hulud
    type: list[string]
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
rationale: The hunt should be scoped to all systems with developer tools (Git, VS
  Code, Node.js) and CI/CD runner environments. Focus on hosts with recent Git activity
  or new npm/pypi package installations.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-exfiltration-channels
  reason: This hunt focuses on workstation poisoning; exfiltration of harvested data
    via hybrid RSA/AES channels is a separate stage.
  relation: out-of-scope-alternative
- hunt: shai-hulud-c2-deadman-persistence
  relation: follows
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
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Developer Environment Poisoning

This hunt focuses on the 'Shai-Hulud' framework's mechanism for persisting and spreading within developer environments. It targets the creation of malicious IDE tasks (tasks.json) and AI agent hooks (settings.json) that trigger automated execution when a repository is opened. It further corroborates this by looking for the framework's characteristic loaders—such as setup.mjs and config.mjs—being executed by Node or Bun runtimes, and stacks these behaviors to identify rare, targeted infections across the engineering fleet.

## scoping-dev-tools
<!-- Identify developer workstations -->
Identify hosts that have VS Code, Bun, or Git installed to narrow the search for repository poisoning.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or CI systems. Silence indicates
  no covered dev tools are inventoried.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%vscode%' OR LOWER(package_name) LIKE '%code%' OR LOWER(package_name) LIKE '%git%' OR LOWER(package_name) LIKE '%bun%') AND asset_scope = 'endpoint'
```

## corroborate-poisoning
<!-- Corroborate hooks and execution -->
parallel:
- → detect-poisoned-hooks
- → behavior-loader-process
- → prevalence-rare-loaders
join: → triage-poisoning

## detect-poisoned-hooks
<!-- Detection of poisoned IDE/Agent hooks -->
Find file writes to .vscode/tasks.json or .claude/settings.json, especially those originating from GitHub providers or associated with the reported commit author.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: File write events to configuration files that trigger code execution. Hits
  on the GitHub provider with the specific actor email are high-confidence indicators
  of the lateral movement stage.
reads:
- device_hostname
- file_path
- actor_user_name
- process_cmd_line
- provider
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, actor_user_name, process_cmd_line, provider, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.vscode/tasks.json' OR LOWER(file_path) LIKE '%/.claude/settings.json') AND (LOWER(actor_user_name) LIKE '%claude%' OR LOWER(process_cmd_line) LIKE '%git%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## behavior-loader-process
<!-- Execution of Shai-Hulud loaders -->
Identify process execution of Bun or Node runtimes that reference the known loader filenames.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, shai_hulud_loaders=shai_hulud_loaders)
~~~yaml
expected: Execution of small JS/TS scripts by the Bun runtime, particularly those
  named setup.mjs or config.mjs.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) IN ('node', 'bun', 'sh', 'bash', 'python') OR LOWER(process_path) LIKE '%/bun%') AND (instr(',' || '{{shai_hulud_loaders}}' || ',', ',' || LOWER(SUBSTR(process_cmd_line, INSTR(process_cmd_line, ' ') + 1)) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%setup.mjs%' OR LOWER(process_cmd_line) LIKE '%config.mjs%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## prevalence-rare-loaders
<!-- Prevalence of loader execution -->
Stack count the execution of loaders to find rare, targeted infections that stand out from legitimate CI/CD noise.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique or rare instances of setup script execution. A legitimate build system
  might show hundreds of hosts; the framework's malicious loader will likely be localized.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%setup.mjs%' OR LOWER(process_cmd_line) LIKE '%config.mjs%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## triage-poisoning
<!-- Triage poisoning indicators -->
```agent target=hunter
cite: required
context:
- scoping-dev-tools
- detect-poisoned-hooks
- behavior-loader-process
- prevalence-rare-loaders
max_iterations: 4
objective: Determine if the combination of .vscode/tasks.json or .claude/settings.json
  writes followed by the execution of loaders (setup.mjs, config.mjs) indicates an
  active Shai-Hulud infection.
success_criteria: A per-host verdict of Malicious | Suspicious | Benign with citations
  of the hook-write and the execution event.
tools:
- endpoint
```

## decision-route
<!-- Route on triage -->
if~: "the triage verdict is malicious for at least one host based on correlated file and process activity" (confidence: high, judge=hunter)
then: → action-isolate-host
indeterminate: → task-analyst-review
unavailable: → task-analyst-review (blind_spot: limited-endpoint-telemetry)
else: → task-close-out

## action-isolate-host
<!-- Isolate affected workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke any local SSH keys, cloud credentials, or GitHub tokens found on the device. Audit recently pushed commits to internal repositories from this user.
```
→ task-analyst-review

## task-analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited hook files and loader processes. Inspect .vscode/tasks.json for 'runOn: folderOpen' and .claude/settings.json for 'SessionStart' hooks. Recover the 'setup.mjs' or 'config.mjs' binaries if possible for further analysis.
```
→ end

## task-close-out
<!-- Close out hunt -->
```manual target=analyst
If no malicious activity was found, record the negative result. If suspicious activity was found but overturned, update tuning for Node/Bun build script baselines.
```
→ end
