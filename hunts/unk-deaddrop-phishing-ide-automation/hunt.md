---
analysis: "Detecting a 'git clone' is too noisy for developer workstations. This hunt\
  \ pivots between the repository creation, the rare parent-child process relationship\
  \ of an IDE launching a shell script from a vendor path, and the installation of\
  \ persistent VSIX artifacts\u2014a correlation a single rule cannot perform without\
  \ high false positives."
blind_spots:
- id: no-file-directory-telemetry
  owner: security-engineering
  question: if the malicious repo directory was created via git clone
  remediation: Enable full file auditing for user home directories.
  requires: EDR directory creation auditing
  risk: If hb_file_activity does not capture directory creation (activity_id 1), we
    rely solely on process execution which might be missed if the user does not open
    the IDE.
  stage: initial-access-phishing-github
- id: script-logic-visibility
  owner: security-engineering
  question: the exact behavior of the decoded shell payloads
  remediation: Deploy script-block logging for bash and powershell.
  requires: hb_script_activity content capture
  risk: The launcher scripts are platform-specific loaders; without script block logging,
    the hunter cannot see the final Go binary download URL or the C2 server without
    sandbox analysis.
  stage: execution-ide-task-automation
coverage:
- stage: initial-access-phishing-github
  status: covered
  steps:
  - suspicious-repo-clones
- stage: execution-ide-task-automation
  status: covered
  steps:
  - ide-automated-task-execution
- stage: persistence-malicious-vsix
  status: covered
  steps:
  - malicious-vsix-extension
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: c2-overlord-rat-connectivity
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: credential-access-wallet-theft
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: exfiltration-over-c2
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: defense-evasion-cleanup
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: North Korean threat actors are specifically targeting developers
    with sophisticated IDE-based lures that bypass traditional email filters. This
    hunt provides an essential negative result over the developer estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has lured a developer to clone a malicious GitHub repository,
  triggering automated IDE task execution and a persistent VSIX extension installation.
labels:
- hunt
- attack.t1566
- attack.t1195.002
- attack.t1204.002
- attack.t1059.003
- attack.t1059.004
- attack.t1546
name: UNK_DeadDrop IDE Phishing and Task Automation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_repos:
    default:
    - pulsynk
    - trixauvex
    - rekt-db
    - forge-4626-invariants
    - x402-kit
    description: Lure repository names identified in the UNK_DeadDrop campaign.
    from:
      kind: article
      observed: '2026-05-27'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on (e.g., from the scoping
      step).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations and servers with VS Code or Cursor. The
  campaign primarily targets macOS and Linux for persistence, while Windows is used
  for one-time stealer execution.
references:
- name: "Proofpoint: Don\u2019t Fear the Repo: UNK_DeadDrop Phishing Campaign Targets\
    \ Developers"
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: c2-overlord-rat-connectivity
  reason: This hunt covers delivery and execution; a follow-on hunt is required for
    the Overlord framework's WebSocket C2 traffic.
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Malicious GitHub Repos
    observables:
    - https://github.com/Pulsynk/pulsynk
    - https://github.com/Trixauvex-org/trixauvex
    - https://github.com/PedrinPY/rekt-db
    - https://github.com/sr-werney/forge-4626-invariants
    - https://github.com/skyjum/x402-kit
    - git clone
    slug: initial-access-phishing-github
    tactic: initial-access
    techniques:
    - T1566
    - T1195.002
  - name: IDE Workspace Task Execution
    observables:
    - .vscode/tasks.json
    - 'runOptions.runOn: folderOpen'
    - /bin/bash vendor/run-update.sh
    - wscript.exe //B //Nologo vendor/run-update-hidden-launch.vbs
    slug: execution-ide-task-automation
    tactic: execution
    techniques:
    - T1204.002
    - T1059.003
    - T1059.004
  - name: Persistence via Malicious VSIX Extension
    observables:
    - Malicious .vsix extension masquerading as Google service
    - Extension activation on IDE start (macOS/Linux)
    slug: persistence-malicious-vsix
    tactic: persistence
    techniques:
    - T1546
  - name: Overlord RAT Command and Control
    observables:
    - google-update-support-linux-amd64
    - google-update-support-darwin-amd64
    - google-update-support-darwin-arm64
    - WebSocket connectivity to hardcoded C&C
    slug: c2-overlord-rat-connectivity
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: Credential and Wallet Discovery
    observables:
    - browserlogin module accessing Chrome/Firefox credentials
    - companywallet module targeting desktop crypto wallets
    - Targeting browser wallet extensions
    slug: credential-access-wallet-theft
    tactic: credential-access
    techniques:
    - T1555
  - name: Stolen Asset Exfiltration
    observables:
    - 2-phase ZIP and upload of wallet data to C&C
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  - name: Anti-Forensic Workspace Cleanup
    observables:
    - cleanup module
    - Deletion of cloned repository payloads and directories
    slug: defense-evasion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: UNK_DeadDrop is a DPRK-aligned campaign targeting developers with fake
    recruitment and code review lures leading to malicious GitHub repositories. The
    attack exploits IDE task automation in VS Code and Cursor to execute platform-specific
    loaders, install persistent malicious VSIX extensions, and deploy the Overlord
    RAT to exfiltrate credentials and cryptocurrency wallets.
series:
  index: 1
  slug: unk-deaddrop-phishing-campaign-targets-developers
  title: UNK_DeadDrop phishing campaign targets developers
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


# UNK_DeadDrop IDE Phishing and Task Automation

This hunt targets the UNK_DeadDrop campaign where North Korean-aligned actors use fake recruitment lures to deliver malicious code via IDE automation. The hunt identifies the characteristic transition from repository cloning to automated script execution within developer environments (VS Code and Cursor). It specifically seeks out platform-specific launcher scripts and the installation of persistent, masquerading VSIX extensions on macOS and Linux, as well as the execution of suspicious Node.js pipelines on Windows.

## find-developer-ides
<!-- Identify developer hosts with IDEs -->
Scope the hunt to hosts where Visual Studio Code or Cursor are installed, as these are the primary targets of the campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers. Silence means no hosts in the
  estate have these IDEs installed via tracked packages.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%visual studio code%' OR LOWER(package_name) LIKE '%cursor%')
```

## parallel-evidence-collection
<!-- Parallel investigation of IDE artifacts -->
parallel:
- → suspicious-repo-clones
- → ide-automated-task-execution
- → malicious-vsix-extension
join: → triage-infection-chain

## suspicious-repo-clones
<!-- Creation of malicious repository directories -->
Find evidence of a user cloning or creating directories matching the campaign lures.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, malicious_repos=malicious_repos)
~~~yaml
expected: File activity rows showing the creation of known malicious repository names.
  Silence means no such directories were created.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE activity_id = 1 AND (file_type = 'directory' OR file_type = 'file') AND (instr(',' || '{{malicious_repos}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ide-automated-task-execution
<!-- Automated IDE shell task execution -->
Detect IDEs (VS Code, Cursor) launching shell scripts from suspicious subdirectories like 'vendor/' as defined in tasks.json.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A parent IDE process spawning a shell or script engine with a command line
  pointing to a repo-local update script.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%code%' OR LOWER(parent_process_name) LIKE '%cursor%' OR LOWER(parent_process_name) LIKE '%electron%') AND (LOWER(process_cmd_line) LIKE '%vendor/%' OR LOWER(process_cmd_line) LIKE '%run-update%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## malicious-vsix-extension
<!-- Installation of persistent VSIX extensions -->
Identify rare VSIX extension installations masquerading as Google services in the editor's extension folder.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Stack-counted file creation events showing rare Google-themed VSIX extensions
  within IDE extension paths.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, COUNT(*) as installs, MIN(time) as first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%extensions/google%' OR LOWER(file_name) LIKE '%google%vsix%') AND (LOWER(file_path) LIKE '%.vscode%' OR LOWER(file_path) LIKE '%.cursor%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, file_path, file_name HAVING installs <= 3
```

## triage-infection-chain
<!-- Triage the UNK_DeadDrop infection chain -->
```agent target=hunter
cite: required
context:
- suspicious-repo-clones
- ide-automated-task-execution
- malicious-vsix-extension
max_iterations: 4
objective: Determine if any host has successfully cloned a campaign repository and
  proceeded to execute automated IDE tasks or install the persistent VSIX extension.
success_criteria: A per-host verdict of malicious, suspicious, or benign, specifically
  citing the intersection of repo names and shell commands.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-affected-host
indeterminate: → analyst-remediation-task
unavailable: → analyst-remediation-task (blind_spot: no-file-directory-telemetry)
else: → close-out

## isolate-affected-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not terminate the IDE process until memory has been captured, as payloads may reside in the Electron process.
```
→ analyst-remediation-task

## analyst-remediation-task
<!-- Analyst review and credential cleanup -->
```manual target=analyst
Review the cited rows. If confirmed, identify any GitHub tokens, SSH keys, or cloud credentials stored on the host and initiate revocation. Inspect the .vscode/tasks.json file in the identified workspace to confirm the execution logic.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the hosts affected and any new lures found. Update the malicious_repos parameter if new repository names were identified during the hunt.
```
→ end
