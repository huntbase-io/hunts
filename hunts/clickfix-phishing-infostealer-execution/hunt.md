---
analysis: A static detection rule for browser-spawned shells creates high noise from
  legitimate browser-update tasks; this hunt uses an agent to evaluate command suspicion
  and fleet prevalence to distinguish true threats from background noise.
blind_spots:
- id: missing-process-telemetry
  question: whether the shell was launched by a browser or a legitimate user-driven
    task
  requires: Reliable parent process reporting for all terminal shells
  risk: If an adversary uses a method that breaks the parent-child relationship, the
    lead query will not see the execution.
  stage: execution-clickfix-powershell
- id: no-file-access-telemetry
  question: whether an infostealer successfully read the browser's Login Data file
  requires: hb_file_activity with activity_id 14 (Open)
  risk: If the EDR only logs file writes or deletes, the stealthy read operations
    of an infostealer will be invisible.
  stage: credential-access-infostealer
coverage:
- stage: initial-access-clickfix-landing
  status: covered
  steps:
  - browser-spawned-shells-lead
- stage: execution-clickfix-powershell
  status: covered
  steps:
  - browser-spawned-shells-lead
  - rare-browser-shell-commands
- stage: credential-access-infostealer
  status: covered
  steps:
  - unauthorized-credential-store-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ClickFix was responsible for over 50 percent of malware loader activity
    in 2025; ensuring these social engineering attempts are caught and addressed with
    training is critical for lowering organizational risk.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has tricked a user into manually executing an encoded command
  from a ClickFix landing page, which then deploys an infostealer to harvest browser
  credentials.
labels:
- hunt
- attack.t1566.002
- attack.t1059.001
- attack.t1555.003
- credential access
- execution
- initial access
name: ClickFix Phishing and Infostealer Execution
parameters:
  browser_binaries:
    default:
    - chrome.exe
    - msedge.exe
    - brave.exe
    - firefox.exe
    - opera.exe
    description: Common browser process names observed as parents in ClickFix attacks.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  shell_binaries:
    default:
    - powershell.exe
    - cmd.exe
    - pwsh.exe
    description: Shell binaries typically used in manual paste instructions.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/defense-drill-interventions
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on standard user endpoints where browsers are the primary tool. Domain
  controllers and dedicated servers are less likely to be initial ClickFix targets
  but should be monitored for secondary credential usage.
references:
- name: "Huntress \u2014 Defense Drill Interventions"
  url: https://www.huntress.com/blog/defense-drill-interventions
related:
- hunt: malicious-browser-extension-credential-theft
  reason: This hunt focuses on manual command pasting; credential theft via malicious
    browser extensions uses different telemetry surfaces.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ClickFix Social Engineering
    observables:
    - ClickFix landing pages
    - Fake 'Fix' buttons
    - Network connections to ClickFix domains
    - ChatGPT-themed phishing sites
    slug: initial-access-clickfix-landing
    tactic: initial-access
    techniques:
    - T1566
  - name: Malicious Command Execution
    observables:
    - powershell.exe -enc
    - cmd.exe /c
    - Encoded PowerShell script blocks
    - User-initiated command execution from browser
    slug: execution-clickfix-powershell
    tactic: execution
    techniques:
    - T1566
  - name: Infostealer Credential Theft
    observables:
    - Infostealer malware execution
    - Access to browser Login Data files
    - Access to Local State files in AppData\Local\Google\Chrome\User Data
    - Credential harvesting from password stores
    slug: credential-access-infostealer
    tactic: credential-access
    techniques:
    - T1555
  summary: Attackers utilize ClickFix social engineering to trick users into executing
    malicious commands under the guise of fixing browser or document errors. This
    technique typically serves as a delivery mechanism for information stealers that
    target credentials stored within web browsers.
severity: medium
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


# ClickFix Phishing and Infostealer Execution

ClickFix is a prominent social engineering technique where users are persuaded to manually execute malicious commands to fix a supposed browser or document error. This hunt finds shell executions originating from web browsers, uses an agent to evaluate the command for signs of obfuscation or infostealer loaders, and opens a fan-out investigation for suspicious leads. The hunt measures command rarity across the fleet while simultaneously monitoring for unauthorized access to browser credential stores. Finally, an analyst confirms the infection and assigns a Defense Drill to address the underlying human risk.

## browser-spawned-shells-lead
<!-- Shell processes spawned by web browsers -->
Identify potential ClickFix command execution by finding terminal shells launched directly from a web browser process.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, shell_binaries=shell_binaries, browser_binaries=browser_binaries)
~~~yaml
expected: A shell command originating from a browser. This typically occurs when a
  user follows instructions to open a terminal and paste a command from a malicious
  landing page.
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
verified_at: '2026-11-06'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE activity_id = 1 AND (instr(',' || '{{shell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (instr(',' || '{{browser_binaries}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%-enc%' OR LOWER(process_cmd_line) LIKE '%/c %' OR LOWER(process_cmd_line) LIKE '%-command%' OR LOWER(process_cmd_line) LIKE '%iex%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead-suspicion
<!-- Evaluate lead suspicion -->
```agent target=hunter
cite: required
context:
- browser-spawned-shells-lead
max_iterations: 3
objective: Examine the process_cmd_line values from browser-spawned-shells-lead. Identify
  Base64 encoded blobs, Invoke-WebRequest or IEX patterns, and manual paste indicators
  that suggest an infostealer loader.
success_criteria: A per-host verdict of suspicious | benign for the detected browser-shell
  pairs.
tools:
- endpoint
```

## gate-on-suspicion
<!-- Gate: Proceed to fan-out? -->
if~: "the evaluate-lead-suspicion verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → corroboration-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-telemetry)
else: → close-out

## corroboration-fan-out
<!-- Corroboration Fan-out -->
parallel:
- → rare-browser-shell-commands
- → unauthorized-credential-store-access
join: → triage-infection

## rare-browser-shell-commands
<!-- Rare browser-spawned shell commands -->
Stack-count the shell commands spawned by browsers to isolate unique manual pastes from fleet-wide software tasks.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, browser_binaries=browser_binaries, shell_binaries=shell_binaries)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Malicious commands are typically unique to one victim or a small cluster,
  whereas legitimate updaters appear across many hosts.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE activity_id = 1 AND (instr(',' || '{{browser_binaries}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (instr(',' || '{{shell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_cmd_line) HAVING host_count <= 2 ORDER BY host_count ASC
```

## unauthorized-credential-store-access
<!-- Unauthorized access to browser credential stores -->
Find non-browser processes accessing sensitive browser data files, which confirms infostealer behavior.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, browser_binaries=browser_binaries)
~~~yaml
expected: Processes that are not legitimate browsers reading credential databases
  are a high-fidelity indicator of a successful infostealer infection.
reads:
- device_hostname
- process_name
- file_path
- actor_user_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, process_name, file_path, actor_user_name, time FROM hb_file_activity WHERE activity_id IN (1, 2, 14) AND (LOWER(file_path) LIKE '%\\google\\chrome\\user data\\%\\login data' OR LOWER(file_path) LIKE '%\\microsoft\\edge\\user data\\%\\login data' OR LOWER(file_path) LIKE '%\\local state') AND NOT (instr(',' || '{{browser_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infection
<!-- Synthesize infection evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead-suspicion
- rare-browser-shell-commands
- unauthorized-credential-store-access
max_iterations: 5
objective: Determine if the host has been compromised by a ClickFix attack. A malicious
  verdict requires seeing a suspicious shell command that is both rare across the
  fleet and correlated with non-browser access to browser profile data.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  evidence rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on infection -->
if~: "the triage-infection verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-access-telemetry)
else: → close-out

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke all active cloud sessions for the affected user. Reset passwords for all accounts stored in the browser profile.
```
→ analyst-review

## analyst-review
<!-- Analyst review and training -->
```manual target=analyst
Confirm the malicious command used. Assign a 'ClickFix Defense Drill' to the user to reduce future human risk. Document the specific infostealer variant if identified.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the number of suspicious browser shell spawns examined. Update browser parameter lists if new platforms are used by users.
```
→ end
