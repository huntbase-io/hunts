---
analysis: 'A simple detection rule might alert on ''run-update.sh'', but this hunt
  combines three surfaces: identifying the target population (IDEs), checking for
  rare script execution, and correlating it with specific external repository lures.
  This reduces false positives from legitimate build scripts while catching renamed
  loaders.'
blind_spots:
- id: no-process-visibility
  question: whether the interpreter was definitely spawned by the IDE's automation
    engine
  requires: hb_process_activity with parent command line
  risk: We might miss execution if the user runs the script manually from the terminal
    inside the IDE, though this would still show as a process hit but with a different
    parent context.
  stage: execution-ide-task-automation
- id: http-proxy-logs
  question: which specific repository was cloned
  requires: hb_http_activity with full url_path
  risk: If the organization uses a proxy that strips URL paths for privacy, we will
    see traffic to 'github.com' but not the specific repo names.
  stage: initial-access-spearphishing
coverage:
- stage: initial-access-spearphishing
  status: covered
  steps:
  - http-to-malicious-repos
- stage: execution-ide-task-automation
  status: covered
  steps:
  - ide-launcher-scripts
  - rare-user-path-scripts
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: persistence-malicious-vsix
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: command-and-control-overlord-rat
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: credential-theft-and-collection
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
  justification: DPRK-aligned groups like UNK_DeadDrop specifically target high-value
    assets (API keys, wallets) belonging to developers. A negative result confirms
    that the fleet's developers haven't been successfully phished into running malicious
    automation payloads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: 'An adversary is abusing the ''runOn: folderOpen'' feature in VS Code
  and Cursor to execute malicious shell or VBS scripts automatically when a developer
  opens a cloned, untrusted GitHub repository.'
labels:
- hunt
- attack.t1566
- attack.t1195.002
- attack.t1204.002
- attack.t1190
name: Developer IDE Automation Abuse
parameters:
  launcher_scripts:
    default:
    - run-update.sh
    - run-update-hidden-launch.vbs
    description: Specific launcher scripts observed in the infection chain.
    from:
      kind: article
      observed: '2026-05-27'
      ref: Proofpoint UNK_DeadDrop
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_repo_names:
    default:
    - pulsynk
    - trixauvex
    - rekt-db
    - forge-4626-invariants
    - x402-kit
    description: Keywords from malicious GitHub repository names or accounts.
    from:
      kind: article
      observed: '2026-05-27'
      ref: Proofpoint UNK_DeadDrop
    type: list[string]
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
rationale: The hunt should start with hosts identified as 'Developer' machines or
  those with high-end IDEs like Cursor and Visual Studio Code installed. Focus on
  the last 14 days of activity as this represents a fresh wave.
references:
- name: "Proofpoint \u2014 UNK_DeadDrop Phishing Campaign Targets Developers"
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: persistence-malicious-vsix
  reason: This hunt finds the initial launcher; the next hunt focuses on the persistent
    VSIX extension it installs.
  relation: follows
- hunt: overlord-rat-c2
  reason: The launcher scripts deploy a Go-based RAT; that hunt covers the subsequent
    C2 behavior.
  relation: follows
scenario:
  stages:
  - name: Spearphishing via Fake Developer Lures
    observables:
    - Attacker-controlled sender domains
    - 'URLs to GitHub repositories: pulsynk/pulsynk, Trixauvex-org/trixauvex, PedrinPY/rekt-db,
      wayout4u/rekt-db, Stomp47/rekt-db, sr-werney/forge-4626-invariants, ziobiri/forge-4626-invariants,
      mireles343/forge-4626-invariants, skyjum/x402-kit, rkama411/x402-kit'
    - 'Job titles: Full-Stack Engineer, Agent Lead Developer'
    slug: initial-access-spearphishing
    tactic: initial-access
    techniques:
    - T1566
    - T1195.002
  - name: Execution via IDE Task Automation
    observables:
    - 'File: .vscode/tasks.json'
    - 'Command: runOptions.runOn: folderOpen'
    - 'Process: /bin/bash vendor/run-update.sh'
    - 'Process: wscript.exe //B //Nologo vendor/run-update-hidden-launch.vbs'
    slug: execution-ide-task-automation
    tactic: execution
    techniques:
    - T1204.002
  - name: Persistence via Malicious VSIX Extension
    observables:
    - Malicious VS Code extension (VSIX) masquerading as a Google service
    - Automated activation on editor startup (macOS/Linux)
    slug: persistence-malicious-vsix
    tactic: persistence
    techniques:
    - T1546
  - name: C2 via Overlord RAT
    observables:
    - Go-based Overlord RAT binaries
    - 'File: google-update-support-linux-amd64'
    - 'File: google-update-support-darwin-amd64'
    - 'File: google-update-support-darwin-arm64'
    - WebSocket persistent connectivity to hardcoded C2
    - Multi-hop proxy infrastructure
    slug: command-and-control-overlord-rat
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: Credential Theft and Collection
    observables:
    - 'Overlord module: browserlogin (theft of Chrome and Firefox credentials)'
    - 'Overlord module: companywallet (crypto wallet stealer)'
    - Creation of temporary ZIP files for exfiltration
    slug: credential-theft-and-collection
    tactic: credential-access
    techniques:
    - T1555
  - name: Exfiltration of Wallets and Credentials
    observables:
    - Upload of ZIP files containing decrypted credentials and desktop wallets to
      C2
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  - name: Indicator Removal via Cleanup Module
    observables:
    - 'Overlord module: cleanup'
    - Deletion of workspace artifacts and malicious payloads from cloned repositories
    slug: defense-evasion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: UNK_DeadDrop is a North Korean-aligned phishing campaign targeting developers
    across finance, tech, and crypto sectors via fake recruitment lures and code review
    requests. The campaign employs malicious GitHub repositories that abuse VS Code
    and Cursor IDE task automation to execute platform-specific Go-based loaders (Overlord
    RAT) or Node.js pipelines, resulting in the theft of browser credentials and cryptocurrency
    wallets.
series:
  index: 1
  slug: unk-deaddrop-phishing-campaign-targets-developers
  title: UNK_DeadDrop phishing campaign targets developers
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Developer IDE Automation Abuse

This hunt targets the initial access and execution phase of the UNK_DeadDrop campaign. It focuses on the abuse of IDE task automation where hidden '.vscode/tasks.json' files trigger platform-specific loaders (run-update.sh or run-update-hidden-launch.vbs) located in the repository's vendor/ or src/ directories. We first identify hosts with relevant developer tools, then look for the execution of these specific launcher scripts spawned by IDE processes or interpreters. Finally, we correlate this with web traffic to the malicious GitHub repositories used in the campaign to confirm the lure source.

## scope-developer-hosts
<!-- Scope hosts with VS Code or Cursor -->
Identify hosts that have Visual Studio Code or Cursor installed, as they are the primary targets for this automation abuse.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with developer IDEs installed. This narrows the hunt
  to developers who might clone the malicious repos.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%visual studio code%' OR LOWER(package_name) LIKE '%cursor%'
```

## corroborate-activity
<!-- Search for behavior and lures simultaneously -->
parallel:
- → ide-launcher-scripts
- → rare-user-path-scripts
- → http-to-malicious-repos
join: → triage-ide-abuse

## ide-launcher-scripts
<!-- IDE-spawned launcher scripts -->
Find the execution of the campaign-specific loaders (run-update.sh, run-update-hidden-launch.vbs) regardless of their path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Direct evidence of the loaders running. Spawning from bash, wscript, or
  code/cursor processes is high-confidence signal.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%run-update.sh%' OR LOWER(process_cmd_line) LIKE '%run-update-hidden-launch.vbs%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-user-path-scripts
<!-- Rare script execution from user directories -->
Stack-count interpreter execution from user-writable paths to find anomalous scripts that may not match the known naming convention.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A baseline of script activity. A script seen on only one or two developer
  machines running from a home directory is suspicious.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%/home/%' OR LOWER(process_path) LIKE '%/users/%' OR LOWER(process_path) LIKE '%\users\%') AND (LOWER(process_name) LIKE '%bash%' OR LOWER(process_name) LIKE '%wscript%' OR LOWER(process_name) LIKE '%sh%' OR LOWER(process_name) LIKE '%cmd.exe%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3 ORDER BY hosts ASC
```

## http-to-malicious-repos
<!-- HTTP traffic to campaign repositories -->
Match HTTP activity to the specific GitHub repository keywords named in the UNK_DeadDrop report.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A hit indicates a developer has interacted with or cloned a repository from
  the campaign. Combined with script execution, this confirms a compromise.
reads:
- device_hostname
- url_hostname
- url_path
- actor_user_name
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, actor_user_name, user_agent, time FROM hb_http_activity WHERE LOWER(url_hostname) LIKE '%github.com%' AND (LOWER(url_path) LIKE '%pulsynk%' OR LOWER(url_path) LIKE '%trixauvex%' OR LOWER(url_path) LIKE '%rekt-db%' OR LOWER(url_path) LIKE '%forge-4626%' OR LOWER(url_path) LIKE '%x402-kit%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-ide-abuse
<!-- Weigh IDE automation evidence -->
```agent target=hunter
cite: required
context:
- scope-developer-hosts
- ide-launcher-scripts
- rare-user-path-scripts
- http-to-malicious-repos
max_iterations: 4
objective: Determine if any host has executed malicious automation scripts after cloning
  a repo from the campaign.
success_criteria: A verdict citing specific process lines and matching GitHub repo
  paths.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is 'malicious' or 'suspicious' for any host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## isolate-host
<!-- Isolate host and collect forensics -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Collect the contents of the .vscode/tasks.json and the script path cited in the triage.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage evidence. If confirmed, initiate the follow-up hunts for VSIX persistence and Overlord RAT activity.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. No evidence of UNK_DeadDrop IDE automation abuse was found in the lookback window.
```
→ end
