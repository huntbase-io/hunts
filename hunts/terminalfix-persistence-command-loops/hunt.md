---
analysis: While static rules exist for Run keys, this hunt identifies the behavioral
  correlation between redundant persistence methods and a specific automated script
  loop. It uses prevalence baselines to distinguish TerminalFix persistence from standard
  updater tasks in ProgramData, a context a single rule cannot easily evaluate.
blind_spots:
- id: no-script-logging
  owner: Endpoint Engineering
  question: What specific commands were executed within the asynchronous loop?
  remediation: Enable Group Policy for PowerShell Script Block Logging and Module
    Logging.
  requires: hb_script_activity with full block logging (PowerShell v5+)
  risk: Without script block logging, we see the persistence and the presence of the
    loop, but not the contents of the commands being executed via Invoke-Expression.
  stage: asynchronous-command-loop
- id: registry-snapshot-only
  owner: SOC Platform
  question: When was the persistence established and what was the parent process?
  remediation: Deploy Sysmon registry monitoring for Run keys in both HKCU and HKLM
    hives.
  requires: hb_registry_activity in log mode (Sysmon Event ID 12/13/14)
  risk: Snapshots show existing keys but not the timeframe of creation, making it
    difficult to correlate persistence setup with the initial sideloading event.
  stage: persistence-establishment
coverage:
- stage: persistence-establishment
  status: covered
  steps:
  - registry-persistence-check
  - scheduled-task-baseline
- stage: asynchronous-command-loop
  status: covered
  steps:
  - powershell-loop-check
- reason: Covered in the initial access hunt of this series.
  stage: initial-access-clipboard-captcha
  status: out_of_scope
- reason: Covered in the delivery/sideloading hunt of this series.
  stage: payload-delivery-sideloading
  status: out_of_scope
- reason: Covered in the delivery/sideloading hunt of this series.
  stage: steganographic-extraction
  status: out_of_scope
- reason: Covered in the reconnaissance/tunnel hunt of this series.
  stage: internal-reconnaissance
  status: out_of_scope
- reason: Covered in the reconnaissance/tunnel hunt of this series.
  stage: reverse-tunnel-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The TerminalFix campaign relies on redundant persistence to maintain
    its command execution loop. Identifying these mechanisms provides a high-confidence
    way to detect a host that has reached the long-term beachhead stage of the intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are maintaining access via redundant persistence in ProgramData
  subdirectories and using a PowerShell-based file-watch loop for asynchronous command
  execution.
labels:
- hunt
- attack.t1547.001
- attack.t1053.005
- attack.t1059.001
name: 'TerminalFix: Persistent Command Loops'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-29'
      ref: hunt-standard
    type: number
  payload_path_pattern:
    default: C:\\ProgramData\\%\\%
    description: The directory pattern targeting subdirectories of ProgramData used
      for staging.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: string
  persistence_id:
    default: LockScreenContentServer_MuODG5yBM
    description: The specific masquerading identifier used for tasks and run keys.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
    gates:
    - design-checks
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scoping focuses on Windows endpoints specifically executing binaries from
  deep ProgramData paths, as this is the standard staging location for TerminalFix
  implants. Widen the search if the campaign is observed using other user-writable
  paths like AppData.
references:
- name: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-initial-access-sideloading
  reason: Initial DLL sideloading occurs before persistence and the command loop are
    established.
  relation: precedes
- hunt: terminalfix-reverse-tunnel-recon
  reason: The command loop facilitates the subsequent reconnaissance and reverse tunnel
    deployment.
  relation: follows
scenario:
  stages:
  - name: Socially engineered clipboard execution
    observables:
    - Fake Cloudflare Turnstile CAPTCHA overlay
    - PowerShell command copied to clipboard and pasted by user
    - 'Terminal output: Starting Cloudflare verification...'
    - 'Terminal output: I am not a robot - Cloudflare ID: f47f2a8c21c9df4e'
    slug: initial-access-clipboard-captcha
    tactic: initial-access
    techniques:
    - T1059.001
    - T1115
  - name: DLL sideloading via LockScreenContentServer
    observables:
    - C:\ProgramData\f47f2a8c21c9df4e
    - 1.bat
    - LockScreenContentServer.exe
    - dui70.dll (unsigned, forged timestamp 2104)
    - 'SHA-256: 18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f'
    slug: payload-delivery-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
    - T1574.002
  - name: Steganographic payload retrieval
    observables:
    - POST requests to attacker domains for PNG files
    - 'PowerShell function: Extract-RawFileFromImage'
    - Decoding RGBA pixel data to reconstruct executables and DLLs
    slug: steganographic-extraction
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Redundant persistence configuration
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM
    - 'Scheduled task: LockScreenContentServer_MuODG5yBM'
    - 'Task frequency: every 60 minutes'
    - 'Hidden folder attributes: attrib +s +h'
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Active Directory and infrastructure discovery
    observables:
    - nltest /domain_trust
    - net group "domain admins" /domain
    - Get-ADUser
    - Get-ADComputer
    - Ping sweeps of dc, sql, db, backup, gateway, and mail servers
    slug: internal-reconnaissance
    tactic: discovery
    techniques:
    - T1059.001
  - name: File-based C2 command loop
    observables:
    - PowerShell file-watch loop on local text file
    - Invoke-Expression (IEX) execution of file contents
    - Command results written to output text file
    slug: asynchronous-command-loop
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Reverse WebSocket SOCKS tunnel
    observables:
    - pythonw.exe
    - client.py
    - gitnow.dev:443
    - Encrypted WebSocket channel for TCP proxy access
    slug: reverse-tunnel-deployment
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
    - T1041
  summary: The TerminalFix campaign utilizes fake Cloudflare CAPTCHA prompts to trick
    users into executing PowerShell scripts that download and sideload a malicious
    DLL. The intrusion leverages steganography within PNG files to deliver a second-stage
    payload, establishes persistent network access via Registry Run keys and scheduled
    tasks, and deploys a Python-based reverse tunnel for internal network proxying
    and reconnaissance.
series:
  index: 2
  slug: terminalfix-campaign-deploys-a-reverse-tunnel-through-multistage-intrusion
  title: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
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


# TerminalFix: Persistent Command Loops

This hunt targets the persistence and command-and-control stages of the TerminalFix campaign. It investigates the specific redundant persistence markers (Registry Run keys and Scheduled Tasks) used to maintain the LockScreenContentServer implant, specifically looking for execution from non-standard subdirectories within ProgramData. Additionally, it examines PowerShell script activity for patterns matching an asynchronous file-watch command loop, which allows attackers to execute arbitrary code by simply writing to a local text file. Correlation between these persistence mechanisms and automated script behavior identifies hosts functioning as durable network beachheads.

## scoping-programdata-execution
<!-- Execution from suspicious ProgramData subfolders -->
Identify hosts running any binary from ProgramData subdirectories, which serves as the primary staging area for TerminalFix components.

```sqlite target=endpoint role=scoping params=(payload_path_pattern=payload_path_pattern, lookback_days=lookback_days)
~~~yaml
expected: Processes executing from subdirectories of ProgramData. Silence is evidence
  of absence for standard campaign staging on the examined estate.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, user_name, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_path) LIKE '{{payload_path_pattern}}' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → registry-persistence-check
- → scheduled-task-baseline
- → powershell-loop-check
join: → triage-agent

## registry-persistence-check
<!-- Registry Run key persistence check -->
Identify the creation of the masqueraded Registry Run key used by TerminalFix to survive reboots.

```sqlite target=endpoint role=detection-candidate params=(persistence_id=persistence_id, lookback_days=lookback_days)
~~~yaml
expected: Registry writes or existing Run values containing the campaign's persistence
  identifier and pointing to the ProgramData path.
reads:
- device_hostname
- process_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, reg_target, reg_value_data, process_name, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' AND (LOWER(reg_target) LIKE '%' || LOWER('{{persistence_id}}') || '%' OR LOWER(reg_value_data) LIKE '%' || LOWER('{{persistence_id}}') || '%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## scheduled-task-baseline
<!-- Rare scheduled tasks in ProgramData -->
Perform a prevalence analysis on scheduled tasks that execute commands from ProgramData subdirectories.

```sqlite target=endpoint role=baseline params=(payload_path_pattern=payload_path_pattern)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rarely seen scheduled tasks pointing to ProgramData; the TerminalFix task
  is expected to appear with a low host count.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_cmd_line
- job_name
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT job_name, job_cmd_line, COUNT(DISTINCT device_hostname) as host_count FROM hb_scheduled_job WHERE LOWER(job_cmd_line) LIKE '{{payload_path_pattern}}' GROUP BY job_name, job_cmd_line HAVING host_count <= 3
```

## powershell-loop-check
<!-- PowerShell File-Watch and IEX loop -->
Locate PowerShell scripts implementing a file-watcher or polling loop used to asynchronously execute attacker-controlled files.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing code designed to monitor the filesystem for new
  input and execute it immediately.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE ((LOWER(script_content) LIKE '%filesystemwatcher%' AND LOWER(script_content) LIKE '%invoke-expression%') OR (LOWER(script_content) LIKE '%while($true)%' AND LOWER(script_content) LIKE '%get-content%' AND LOWER(script_content) LIKE '%iex%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Evaluate persistence and command loop -->
```agent target=hunter
cite: required
context:
- scoping-programdata-execution
- registry-persistence-check
- scheduled-task-baseline
- powershell-loop-check
max_iterations: 4
objective: Determine if any host shows evidence of redundant persistence (Run key
  + Task) coupled with an automated script command loop. Verify if these components
  are executing from the targeted ProgramData subfolders.
success_criteria: A structured verdict per host (Malicious, Suspicious, Benign) with
  citations to specific rows.
tools:
- endpoint
```

## verdict-decision
<!-- Route based on verdict -->
if~: "the triage-agent identifies at least one host with both persistence and command-loop activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-logging)
else: → close-out

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect all files from the ProgramData subfolders identified in the triage, specifically targeting the text file used by the PowerShell loop. Prepare for full incident response.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the script content for the watch-loop and identify the file being watched. Check for other processes launched by the sideloading host. Cross-reference with the 'Reverse Tunnel' and 'Internal Reconnaissance' hunts in this series.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
If no malicious activity was found, document the hosts scanned and the prevalence baselines established. Close the hunt.
```
→ end
