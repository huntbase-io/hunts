---
analysis: Standard rules on encoded PowerShell often create alert fatigue from admin
  tools. This hunt specifically gates on the social-engineering context (explorer.exe
  as parent) and correlates it with fleet-wide rare persistence to confirm a breach.
  It instructs the agent to verify the sub-minute temporal link between the lure execution
  and persistence establishment.
blind_spots:
- id: no-process-telemetry
  question: whether explorer.exe was the parent of the shell
  requires: hb_process_activity with parent process tracking
  risk: If the parent process record is missing or the EDR does not capture the shell's
    parent consistently, the ClickFix paste indicator is invisible.
  stage: initial-execution-run-box-paste
- id: no-script-logging
  question: the true content of an encoded or obfuscated command
  requires: hb_script_activity (PowerShell Script Block Logging)
  risk: If script block logging is disabled, the deobfuscated payload is invisible,
    and the hunt must rely on subsequent process and file activity.
  stage: obfuscated-script-execution
coverage:
- stage: initial-execution-run-box-paste
  status: covered
  steps:
  - explorer-spawns-shell
- stage: obfuscated-script-execution
  status: covered
  steps:
  - deobfuscated-script-blocks
- stage: persistence-mechanism-establishment
  status: covered
  steps:
  - rare-persistence-tasks
  - rare-run-keys
- reason: 'Belongs to another part of the ''A Buffet of ClickFix: Lures, Infrastructure
    & Payloads'' series.'
  stage: living-off-the-land-network-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''A Buffet of ClickFix: Lures, Infrastructure
    & Payloads'' series.'
  stage: defense-evasion-dll-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''A Buffet of ClickFix: Lures, Infrastructure
    & Payloads'' series.'
  stage: impact-malware-payloads
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: ClickFix lures bypass traditional perimeter controls by exploiting
    user trust to execute code within an active, authorized session. A negative result
    over the estate confirms that social engineering campaigns are not establishing
    persistent beachheads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has tricked a user into pasting a malicious command into the
  Windows Run box, causing explorer.exe to spawn an obfuscated shell that establishes
  persistence via scheduled tasks or Run keys.
labels:
- hunt
- attack.t1059.001
- attack.t1053.005
- attack.t1547.001
- attack.t1115
- command and control
- defense evasion
- execution
- impact
- persistence
name: ClickFix Paste-and-Run Execution and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-23'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead query to be examined in depth; leave
      empty to check all hosts.
    from:
      kind: manual
      observed: '2024-11-23'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/tradecraft-tuesday-clickfix-lures-and-infrastructure
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on general user workstations first; servers with high automation
  activity should be reviewed separately to avoid shell launch noise. Paste the hostname
  list from the lead query into the scope_hosts parameter for the follow-on investigation.
references:
- name: "Huntress \u2014 A Buffet of ClickFix: Lures, Infrastructure & Payloads"
  url: https://www.huntress.com/blog/tradecraft-tuesday-clickfix-lures-and-infrastructure
related:
- hunt: living-off-the-land-network-abuse
  reason: This hunt focuses on the social engineering paste and persistence, not the
    subsequent network usage of utilities like finger.exe.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Run box command execution
    observables:
    - explorer.exe spawning powershell.exe
    - explorer.exe spawning cmd.exe
    - process_cmd_line containing Net.WebClient
    - process_cmd_line containing Invoke-WebRequest
    - process_cmd_line containing iwr
    slug: initial-execution-run-box-paste
    tactic: execution
    techniques:
    - T1059.001
  - name: Encoded and obfuscated script blocks
    observables:
    - encoded powershell blocks
    - ExecutionPolicy Bypass
    - scripts retrieved from browser cache
    - malicious javascript disguised as legitimate tags
    slug: obfuscated-script-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Establishment of persistence
    observables:
    - new registry keys in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - new registry keys in HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    - schtasks.exe creating new tasks
    - tasks referencing binaries in AppData
    slug: persistence-mechanism-establishment
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: C2 via finger utility
    observables:
    - finger.exe making outbound network connections
    - finger.exe connecting to BBQ-themed domains
    - finger.exe used for data exfiltration or payload retrieval
    - outbound traffic on port 79
    slug: living-off-the-land-network-abuse
    tactic: command-and-control
    techniques:
    - T1218
  - name: DLL Sideloading
    observables:
    - unsigned DLLs loaded by trusted system binaries
    - DLLs created in user-writable locations (AppData, Downloads)
    - suspicious module loads into node.exe
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Deployment of infostealers and ransomware
    observables:
    - node.js RAT installation
    - RMM tool deployment
    - infostealers accessing browser credential stores
    - ransomware encryption activity
    slug: impact-malware-payloads
    tactic: impact
    techniques:
    - T1555
    - T1486
  summary: Attackers use 'ClickFix' lures to trick users into pasting malicious commands
    into the Windows Run box or terminal, often disguised as CAPTCHA verification
    steps. These commands initiate a multi-stage attack chain involving Living-off-the-Land
    binaries like finger.exe for C2, persistence via scheduled tasks and registry
    keys, and final payloads including infostealers, RATs, and ransomware.
series:
  index: 1
  slug: a-buffet-of-clickfix-lures-infrastructure-payloads
  title: 'A Buffet of ClickFix: Lures, Infrastructure & Payloads'
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


# ClickFix Paste-and-Run Execution and Persistence

This hunt identifies ClickFix tradecraft, where social engineering lures trick users into executing code directly from the explorer.exe process (the Run box). It starts with a lead query searching for shell interpreters launched by explorer.exe with suspicious arguments. If confirmed, the hunt opens expensive queries to recover deobfuscated script block content and identifies rare persistence artifacts referencing user-writable paths like AppData. An agent then correlates the interactive paste event with subsequent persistence, specifically looking for sub-minute temporal links between execution and persistence, to reach a verdict.

## explorer-spawns-shell
<!-- Shell interpreters spawned by explorer.exe -->
Find potential ClickFix pastes by identifying shell interpreters launched directly from the user desktop process with suspicious arguments.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows naming a host where explorer.exe launched a shell with download or
  obfuscation flags. Normal administrative shell launches directly from explorer are
  rare.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\\explorer.exe' AND (LOWER(process_name) LIKE '%\\powershell.exe' OR LOWER(process_name) LIKE '%\\cmd.exe' OR LOWER(process_name) LIKE '%\\pwsh.exe' OR LOWER(process_name) LIKE '%\\wscript.exe') AND (LOWER(process_cmd_line) LIKE '%-enc%' OR LOWER(process_cmd_line) LIKE '%iex%' OR LOWER(process_cmd_line) LIKE '%iwr%' OR LOWER(process_cmd_line) LIKE '%net.webclient%' OR LOWER(process_cmd_line) LIKE '%invoke-webrequest%' OR LOWER(process_cmd_line) LIKE '%bypass%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess lead suspicion -->
```agent target=hunter
cite: required
context:
- explorer-spawns-shell
max_iterations: 3
objective: Determine if any of the shell launches from explorer.exe are suspicious
  enough to warrant a full persistence and script block investigation.
success_criteria: A verdict of suspicious or benign per host, citing suspicious command
  line patterns.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on lead suspicion -->
if~: "the assess-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → fan-out-investigation
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-process-telemetry)
else: → close-out

## fan-out-investigation
<!-- Investigate script and persistence artifacts -->
parallel:
- → deobfuscated-script-blocks
- → rare-persistence-tasks
- → rare-run-keys
join: → final-triage

## deobfuscated-script-blocks
<!-- Deobfuscated script block content -->
Recover the actual commands executed by the suspicious shells to confirm malicious intent and payload delivery.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script block rows showing second-stage download or persistence logic. Silence
  here may indicate the malicious script was not logged.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(script_content) LIKE '%net.webclient%' OR LOWER(script_content) LIKE '%invoke-webrequest%' OR LOWER(script_content) LIKE '%start-process%' OR LOWER(script_content) LIKE '%iwr %') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-persistence-tasks
<!-- Rare scheduled tasks in user paths -->
Identify scheduled tasks that are unique across the fleet and point to suspicious user-writable paths or PowerShell commands.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Tasks seen on very few hosts referencing AppData. A task created shortly
  after an explorer shell launch is high-fidelity evidence.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT LOWER(job_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(job_cmd_line) LIKE '%\\appdata\\%' OR LOWER(job_cmd_line) LIKE '%\\users\\public\\%' OR LOWER(job_cmd_line) LIKE '%powershell%' OR LOWER(job_cmd_line) LIKE '%-enc%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(job_cmd_line) HAVING hosts <= 3 ORDER BY hosts
```

## rare-run-keys
<!-- Rare Run key persistence in user paths -->
Find registry Run keys established in user-writable directories that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare registry values pointing to profile-resident binaries.
prevalence:
  by: device_hostname
  key:
  - reg_value_data
  rare_below: 3
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT LOWER(reg_value_data) AS data, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_registry_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(reg_target) LIKE '%\\currentversion\\run%' OR LOWER(reg_target) LIKE '%\\currentversion\\runonce%') AND (LOWER(reg_value_data) LIKE '%\\appdata\\%' OR LOWER(reg_value_data) LIKE '%\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(reg_value_data) HAVING hosts <= 3 ORDER BY hosts
```

## final-triage
<!-- Correlate paste and persistence -->
```agent target=hunter
cite: required
context:
- assess-lead
- deobfuscated-script-blocks
- rare-persistence-tasks
- rare-run-keys
max_iterations: 6
objective: Determine if the explorer shell spawn matches the ClickFix attack chain.
  Look specifically for a sub-minute temporal link between the explorer shell launch
  and the creation of any persistence artifacts (tasks or Run keys).
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows across the context and the sub-minute temporal correlation.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-script-logging)
else: → manual-review

## isolate-host
<!-- Isolate host and remediate persistence -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Remove the identified scheduled tasks and associated binaries found in AppData. Scan the user profile for unauthorized Run keys and browser cache injections.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Review the correlated evidence. If isolated, confirm that the malicious tasks and run keys are gone. If suspicious but not malicious, look for legitimate admin tools launched via explorer that might need exclusion.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record what was examined and what was not visible. No suspicious explorer shell spawns were identified in this window.
```
→ end
