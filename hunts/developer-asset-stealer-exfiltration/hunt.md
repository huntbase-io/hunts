---
analysis: A single detection rule might alert on a binary name, but this hunt pivots
  between the IDE's child processes, file access to sensitive stores (bypassing specific
  name reliance), and bulk file deletion patterns to identify the full lifecycle of
  the UNK_DeadDrop RAT.
blind_spots:
- id: no-file-read-telemetry
  question: Was the sensitive file actually read or just touched/opened?
  requires: hb_file_activity with activity_id = 2 (Read)
  risk: Without specific 'read' telemetry, we rely on 'open' or 'update' events which
    may be nosier or missing.
  stage: credential-access-wallet-theft
- id: ephemeral-processes
  question: Did the RAT binary run and exit before the snapshot?
  requires: hb_process_activity with high-frequency logging
  risk: The 'cleanup' module deletes the binary, meaning short-lived execution might
    only be visible in historical process logs, not snapshots.
  stage: c2-overlord-rat-connectivity
coverage:
- stage: c2-overlord-rat-connectivity
  status: covered
  steps:
  - lead-overlord-rat-processes
  - rat-network-connectivity
- stage: credential-access-wallet-theft
  status: covered
  steps:
  - credential-wallet-access
- stage: exfiltration-over-c2
  status: covered
  steps:
  - rat-network-connectivity
- stage: defense-evasion-cleanup
  status: covered
  steps:
  - anti-forensic-cleanup
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: initial-access-phishing-github
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: execution-ide-task-automation
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: persistence-malicious-vsix
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: DPRK-aligned groups are heavily targeting developers to steal intellectual
    property and financial assets. This hunt ensures that post-exploitation activity,
    specifically asset theft and anti-forensic cleanup, is detected even if the initial
    phishing stage was missed.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed a cross-platform RAT within developer workspaces,
  disguised as a Google update service, which is now exfiltrating credentials and
  wallets while performing anti-forensic cleanup.
labels:
- hunt
- attack.t1041
- attack.t1071.001
- attack.t1090.003
- attack.t1555
- attack.t1070.004
name: Developer Asset Stealer and Exfiltration
parameters:
  browser_processes:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    - google chrome
    - microsoft edge
    - firefox
    description: Legitimate browser process names to exclude from credential access
      checks.
    type: list[string]
  c2_domains:
    default:
    - runoptions.runon
    description: C2 domains associated with the Overlord RAT.
    from:
      kind: article
      observed: '2026-05-30'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rat_binary_names:
    default:
    - google-update-support-linux-amd64
    - google-update-support-darwin-amd64
    - google-update-support-darwin-arm64
    description: Observed binary names for the Overlord RAT.
    from:
      kind: article
      observed: '2026-05-30'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    type: list[string]
  scope_hosts:
    default: []
    description: Target specific hosts from the scoping step; leave empty for whole
      estate.
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
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize hosts with VS Code or Cursor; these are the primary vector.
  Use the software inventory to generate the initial host list.
references:
- name: "Proofpoint \u2014 Don\u2019t Fear the Repo: UNK_DeadDrop Phishing Campaign\
    \ Targets Developers to Steal"
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: malicious-vsix-persistence
  reason: Persistence via malicious VS Code extensions requires telemetry from the
    extension directory and editor logs, handled in a separate hunt.
  relation: out-of-scope-alternative
- hunt: unk-deaddrop-phishing-ide-automation
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
  index: 2
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


# Developer Asset Stealer and Exfiltration

This hunt focuses on the post-exploitation behaviors of the UNK_DeadDrop cluster and its Overlord RAT. It identifies developer-centric hosts, then looks for suspicious Go-based binaries or IDE-spawned processes running from user-writable directories (.vscode, node_modules) that exhibit unauthorized access to browser 'Login Data' or crypto wallets. It further corroborates this with outbound network connections from IDE child processes targeting known C2 indicators and bulk deletions of source files (.go, .js, .py, .env) by non-git processes, which matches the RAT's documented anti-forensic 'cleanup' module.

## scoping-developer-workstations
<!-- Identify developer workstations -->
Identify hosts running developer-specific tools (VS Code, Cursor) that are the primary targets for this campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts used by developers. This provides the primary scope for
  subsequent behavioral steps.
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

## lead-overlord-rat-processes
<!-- Unusual binaries in developer directories -->
Detect the Overlord RAT by looking for suspicious binaries or Go-based processes running from within .vscode or node_modules folders.

```sqlite target=endpoint role=detection-candidate params=(rat_binary_names=rat_binary_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Any process with a 'Google update' description or specific name running
  from a user-writable dev directory is highly anomalous.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_file_description
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_file_description, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\.vscode\\%' OR LOWER(process_path) LIKE '%/.vscode/%' OR LOWER(process_path) LIKE '%\\node_modules\\%' OR LOWER(process_path) LIKE '%/node_modules/%') AND (instr(',' || '{{rat_binary_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_file_description) LIKE '%google update%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## post-exploitation-parallel
<!-- Corroborate post-exploitation behaviors -->
parallel:
- → rat-network-connectivity
- → credential-wallet-access
- → anti-forensic-cleanup
join: → triage-agent

## rat-network-connectivity
<!-- Outbound connections to C2 domains -->
Identify outbound DNS queries initiated by child processes of IDEs targeting known C2 indicators.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions of the campaign's C2 domains originating from IDE-related
  interpreters or processes.
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
SELECT device_hostname, process_name, query_hostname, COUNT(*) as connection_count FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## credential-wallet-access
<!-- Non-browser access to credential stores -->
Detect access to browser 'Login Data' or wallet extension folders by processes that are not legitimate browsers.

```sqlite target=endpoint role=triage params=(browser_processes=browser_processes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes like 'bash', 'node', or custom Go binaries reading Chrome/Edge
  credential files or wallet folders. This is a primary indicator of asset theft.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%login data%' OR LOWER(file_path) LIKE '%wallet%' OR LOWER(file_path) LIKE '%extension%') AND activity_id IN (2, 3) AND NOT (instr(',' || '{{browser_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## anti-forensic-cleanup
<!-- Bulk deletions of source and env files -->
Detect the Overlord 'cleanup' module performing bulk deletions of source code files or .env files in the workspace using non-git processes.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A high volume of deletions of sensitive source or environment files within
  a short window by an unusual process.
reads:
- device_hostname
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, COUNT(*) as deletions, MIN(time) as start_time, MAX(time) as end_time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.go' OR LOWER(file_path) LIKE '%.js' OR LOWER(file_path) LIKE '%.py' OR LOWER(file_path) LIKE '%.env' OR LOWER(file_path) LIKE '%.vbs') AND activity_id = 4 AND LOWER(process_name) NOT LIKE '%git%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING deletions > 5
```

## triage-agent
<!-- Triage Developer Asset Theft -->
```agent target=hunter
cite: required
context:
- lead-overlord-rat-processes
- rat-network-connectivity
- credential-wallet-access
- anti-forensic-cleanup
max_iterations: 6
objective: Identify hosts where a process from a dev directory (like .vscode) performed
  credential access followed by bulk deletions of workspace files, and optionally
  connected to known C2 domains.
success_criteria: A malicious verdict citing specific file paths and the process responsible.
tools:
- endpoint
```

## decision-route
<!-- Route on Triage -->
if~: "the triage verdict is 'malicious' for at least one host, indicating asset theft or RAT persistence" (confidence: high, judge=hunter)
then: → action-isolate
indeterminate: → task-review
unavailable: → task-review (blind_spot: no-file-read-telemetry)
else: → task-close

## action-isolate
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the .vscode folder contents and any suspicious binaries found in user-writable paths for forensics before imaging.
```
→ task-review

## task-review
<!-- Manual Remediation & Forensics -->
```manual target=analyst
1. Search for malicious VSIX extensions in the VS Code/Cursor extensions directory. 2. Verify if 'Login Data' or crypto wallet files were exfiltrated by checking network logs against the timeframe of file access. 3. Rotate all credentials stored in browsers for the affected user. 4. Identify the source GitHub repository clone that initiated the infection.
```
→ end

## task-close
<!-- Close Hunt -->
```manual target=analyst
Record the scoped hosts and the negative findings. Monitor for recurring activity from similar GitHub/GitLab repository patterns.
```
→ end
