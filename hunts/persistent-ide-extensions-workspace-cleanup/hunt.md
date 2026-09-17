---
analysis: A single detection rule would likely cause excessive false positives on
  legitimate Google extensions or file deletions. This hunt uses prevalence (stack-counting)
  to find rare extensions and corroborates them with specific cleanup behavior (deleting
  infection scripts) across two different IDE ecosystems, requiring an analyst or
  agent to weigh the combined evidence.
blind_spots:
- id: limited-file-telemetry
  question: Can we see files being created in the IDE extension directories?
  requires: EDR configuration to monitor hidden folders (.vscode, .cursor) in user
    home directories.
  risk: If the EDR only monitors system paths or common Program Files, extension-based
    persistence will remain invisible.
  stage: persistence-malicious-vsix
- id: cursor-visibility
  question: Are we missing hosts using Cursor vs. VS Code?
  requires: Software inventory detection for Cursor IDE.
  risk: Cursor is less common than VS Code; if inventory tools do not track it, we
    miss the zero-interaction execution path.
  stage: persistence-malicious-vsix
coverage:
- stage: persistence-malicious-vsix
  status: covered
  steps:
  - new-google-extensions
  - rare-extension-baseline
- stage: defense-evasion-cleanup
  status: covered
  steps:
  - cleanup-activity
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: initial-access-spearphishing
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: execution-ide-task-automation
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
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The abuse of IDE extensions for persistence is a highly effective,
    stealthy technique that targets high-value developer assets and bypasses standard
    OS persistence checks. Identifying these masqueraded extensions is critical for
    protecting intellectual property and cryptocurrency assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has achieved persistence by installing a malicious IDE extension
  masquerading as a Google service and is deleting workspace scripts to evade detection.
labels:
- hunt
- attack.t1546
- attack.t1070.004
name: Persistent IDE Extensions and Workspace Cleanup
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_filenames:
    default:
    - run-update.sh
    - run-update-hidden-launch.vbs
    - tasks.json
    - google-update-support-linux-amd64
    - google-update-support-darwin-amd64
    - google-update-support-darwin-arm64
    description: Filenames associated with the UNK_DeadDrop infection and cleanup
      modules.
    from:
      kind: article
      observed: '2026-05-30'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
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
rationale: Target all developer workstations and any servers with IDE software installed.
  Use the lookback period to cover the window of the UNK_DeadDrop campaign (April-May
  2026).
references:
- name: UNK_DeadDrop phishing campaign targets developers
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: execution-ide-task-automation
  reason: Initial execution via tasks.json is a separate behavior focused on the 'folderOpen'
    trigger.
  relation: out-of-scope-alternative
- hunt: command-and-control-overlord-rat
  reason: The network behavior of the Go-based Overlord RAT is handled in a dedicated
    network hunt.
  relation: out-of-scope-alternative
- hunt: developer-ide-automation-abuse
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
  index: 2
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
tlp: clear
type: investigation
---


# Persistent IDE Extensions and Workspace Cleanup

This hunt targets the persistence and defense evasion phases of the UNK_DeadDrop campaign. It specifically looks for the installation of Visual Studio Code or Cursor extensions that mimic legitimate Google services, which the threat actor uses to maintain access on macOS and Linux. Additionally, it identifies the 'cleanup' behavior where the malware removes its own infection scripts (run-update.sh/vbs) and the .vscode/tasks.json configuration to minimize forensic footprints.

## scope-ide-hosts
<!-- Find hosts with developer IDEs -->
Identify hosts running Visual Studio Code or Cursor, the primary targets for malicious extension persistence.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames where targeted IDEs are installed. Silence means no
  targeted IDEs were found in inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%visual studio code%' OR LOWER(package_name) LIKE '%cursor%'
```

## parallel-correlate
<!-- Parallel correlation of extensions and cleanup -->
parallel:
- → new-google-extensions
- → rare-extension-baseline
- → cleanup-activity
join: → triage-agent

## new-google-extensions
<!-- Google-masquerading IDE extensions -->
Detect new file creations in IDE extension directories that use 'google' in the path or filename.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: File creation events for extensions mimicking Google services. Legitimate
  Google extensions (like Go or Cloud Code) may appear and must be filtered by the
  agent.
reads:
- device_hostname
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.vscode/extensions/google%' OR LOWER(file_path) LIKE '%/.cursor/extensions/google%' OR LOWER(file_path) LIKE '%\\.vscode\\extensions\\google%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-extension-baseline
<!-- Prevalence of IDE extension paths -->
Baseline extension installation paths to identify those unique to a small number of hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of extension paths seen on 3 or fewer hosts. High host counts indicate
  common tools.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(file_path) as extension_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/extensions/%' OR LOWER(file_path) LIKE '%\\extensions\\%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## cleanup-activity
<!-- Deletion of workspace artifacts -->
Corroborate extension activity with the deletion of specific infection scripts and IDE configurations.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, malicious_filenames=malicious_filenames)
~~~yaml
expected: File deletion events targeting the specified filenames. Silence means no
  such files were deleted, but they may still exist.
reads:
- device_hostname
- file_name
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE activity_id = 4 AND (instr(',' || '{{malicious_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Evaluate persistence and cleanup evidence -->
```agent target=hunter
cite: required
context:
- scope-ide-hosts
- new-google-extensions
- rare-extension-baseline
- cleanup-activity
max_iterations: 4
objective: Determine if any host has a rare VS Code/Cursor extension with a suspicious
  name (e.g. masquerading as Google) and has recently seen deletions of the scripts
  named in the research.
success_criteria: A per-host verdict of malicious, suspicious, or benign with citations
  of extension paths and deleted files.
tools:
- endpoint
```

## route-verdict
<!-- Route based on agent verdict -->
if~: "The triage verdict is malicious for at least one host due to the presence of a rare extension and script deletions." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: limited-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, preserve the extension folder for analysis, and collect the user's IDE history.
```
→ analyst-triage

## analyst-triage
<!-- Manual analyst triage -->
```manual target=analyst
Review the file activity and extension metadata. Confirm if the extension is a known legitimate Google extension or a malicious masquerade. Check for any subsequent network activity to the Overlord C2.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
If no malicious activity was found, document the scope of hosts examined and the status of IDE extensions across the fleet.
```
→ end
