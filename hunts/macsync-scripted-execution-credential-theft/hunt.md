---
analysis: "A static detection rule for 'curl piped to shell' creates excessive noise\
  \ in developer environments. This hunt uses a gated flow to first isolate suspicious\
  \ one-liners and then corroborate them with rare in-memory script logic and exfiltration\
  \ staging files\u2014a multi-surface pivot that a single process rule cannot perform."
blind_spots:
- id: process-history-retention
  owner: SOC Infrastructure
  question: Whether the initial curl pipe command was executed outside the telemetry
    retention window.
  remediation: Increase retention for hb_process_activity on macOS endpoints to 30
    days.
  requires: hb_process_activity with at least 30 days of command-line history
  risk: If the malvertising event happened more than 14 days ago, the primary lead
    query will return zero results despite an active infection.
  stage: initial-access-clickfix-lure
- id: script-logging-disabled
  owner: Mac Platform Team
  question: Whether the in-memory daemon_function and osascript logic can be observed.
  remediation: Deploy MDM profiles to enable comprehensive shell and script block
    logging.
  requires: hb_script_activity with full AppleScript and Shell block logging enabled
  risk: By default, many macOS systems do not log script block content. Without this,
    the background logic of the stealer is invisible.
  stage: background-zsh-loader
coverage:
- stage: initial-access-clickfix-lure
  status: covered
  steps:
  - curl-to-shell-lead
- stage: background-zsh-loader
  status: covered
  steps:
  - macsync-script-logic
- stage: dynamic-applescript-theft
  status: covered
  steps:
  - macsync-script-logic
  - staging-file-activity
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: persistent-macho-rat
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: screen-capture-helper
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: wallet-app-trojanization
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: MacSync Stealer targets highly valuable developer credentials and
    crypto assets via legitimate AI domains; identifying the initial scripted execution
    is the only way to stop the theft before session cookies are exfiltrated.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has deployed MacSync Stealer on a macOS host by tricking a
  user into executing a curl-to-zsh one-liner, which then runs in-memory scripts to
  harvest credentials and keychains.
labels:
- hunt
- attack.t1566.002
- attack.t1204.002
- attack.t1059.004
- attack.t1027
- attack.t1140
- attack.t1059.002
- attack.t1555.001
- attack.t1548.004
name: MacSync Scripted Execution and Credential Theft
parameters:
  ai_keywords:
    default:
    - claude
    - anthropic
    - chatgpt
    - claude code
    description: Keywords to identify potential target hosts running AI software.
    from:
      kind: article
      observed: '2026-08-17'
      ref: huntress-macsync
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt based on the scoping step.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-claude-macsync
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on macOS workstations used by developers or researchers who are likely
  to experiment with AI tools. Use the software inventory to identify targets that
  have recently installed or searched for AI assistance tools.
references:
- name: 'Huntress - MacSync Stealer: How a Google Search for Claude Led to a macOS
    Infostealer'
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macsync-persistence-macho-rat
  reason: This hunt focuses on the initial delivery and in-memory theft; long-term
    persistence via Mach-O RATs and LaunchAgents is a separate stage of the kill chain.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ClickFix Malvertising Lure
    observables:
    - curl -sL [URL] | zsh
    - claude.ai/share/
    - Google Ads sponsored search for 'Claude Code'
    - Display name 'Apple Support'
    slug: initial-access-clickfix-lure
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.002
    - T1059.004
  - name: Background ZSH Loader
    observables:
    - daemon_function
    - Base64 encoded gzip heredoc
    - /tmp/osalogging.zip
    slug: background-zsh-loader
    tactic: execution
    techniques:
    - T1027
    - T1140
    - T1059.004
  - name: Dynamic AppleScript Stealer
    observables:
    - osascript in-memory execution
    - Chromium Safe Storage AES key extraction
    - TCC prompt for Full Disk Access
    - User password phishing prompt
    - Extraction of login keychain secrets
    slug: dynamic-applescript-theft
    tactic: credential-access
    techniques:
    - T1059.002
    - T1555.001
    - T1548.004
  - name: Mach-O RAT and Persistence
    observables:
    - 85.206.161.241:8443
    - WebSocket over TLS
    - LaunchAgent plist creation in Home folder
    - .mpwd credential file
    - .zshrc modification
    slug: persistent-macho-rat
    tactic: persistence
    techniques:
    - T1543.001
    - T1071.001
    - T1573.002
  - name: Screen Recording Permission Capture
    observables:
    - Capture agent binary with blank icon
    - --tcc-only command line flag
    - -o [path] screenshot output
    - TCC Screen Recording prompt
    slug: screen-capture-helper
    tactic: collection
    techniques:
    - T1113
    - T1548.004
  - name: Crypto Wallet Trojanization
    observables:
    - Modification of 60+ wallet extensions
    - Trojanized Ledger Wallet app
    - Fake recovery phrase phishing HTML
    - Targeting of 21 desktop wallet apps
    slug: wallet-app-trojanization
    tactic: impact
    techniques:
    - T1539
    - T1552
    - T1491
  summary: A malvertising campaign for 'Claude Code' lures users to a legitimate shared
    conversation on claude.ai that instructs them to run a curl one-liner. This executes
    a multi-stage infection chain involving a background zsh loader, a dynamic AppleScript
    stealer that harvests credentials and keychain data, and a persistent Mach-O RAT.
    The attack concludes by gaining screen recording permissions and trojanizing crypto
    wallet applications to phish for recovery phrases.
series:
  index: 1
  slug: macsync-stealer-how-a-google-search-for-claude-led-to-a-macos-infostealer
  title: 'MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer'
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


# MacSync Scripted Execution and Credential Theft

This hunt identifies the early stages of a MacSync Stealer infection by looking for the initial scripted delivery and the subsequent in-memory AppleScript execution used for credential theft. It uses a gated approach, first identifying suspicious curl-to-shell patterns before performing a fan-out investigation for in-memory script logic and exfiltration staging files. The hunt focuses on developer environments where AI tools like Claude are common lures.

## scoping-ai-software
<!-- Identify hosts with AI software -->
Find macOS hosts running AI-related tools that match the malvertising campaign lures.

```sqlite target=endpoint role=scoping params=(ai_keywords=ai_keywords)
~~~yaml
expected: A list of hostnames to focus the hunt on. Silence means no known AI software
  matches were found.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{ai_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{ai_keywords}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## curl-to-shell-lead
<!-- Suspicious curl-to-shell lead -->
Identify the primary ClickFix delivery mechanism where curl pipes content directly to a shell interpreter.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process events showing one-liner scripted execution. Silence proof that
  no such command ran within the retention window.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl %' AND (LOWER(process_cmd_line) LIKE '%|%zsh%' OR LOWER(process_cmd_line) LIKE '%|%sh%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-curl-lead
<!-- Assess lead suspicion -->
```agent target=hunter
cite: required
context:
- curl-to-shell-lead
max_iterations: 3
objective: Judge whether the curl-to-shell commands are consistent with malvertising
  ClickFix lures, noting any suspicious parent processes or arguments.
success_criteria: A verdict of malicious | suspicious | benign citing specific process
  command lines.
tools:
- endpoint
```

## gate-on-curl
<!-- Gate on suspicious execution -->
if~: "the assess-curl-lead verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: process-history-retention)
else: → close-out-benign

## parallel-investigation
<!-- Parallel evidence gathering -->
parallel:
- → macsync-script-logic
- → staging-file-activity
join: → triage-macsync

## macsync-script-logic
<!-- MacSync in-memory script logic -->
Identify the rare background daemon functions and AppleScript keychain theft logic.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare scripts containing MacSync core logic. Silence suggests no scripted
  theft was captured.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 3
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%daemon_function%' OR LOWER(script_content) LIKE '%osascript%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING COUNT(DISTINCT device_hostname) <= 3
```

## staging-file-activity
<!-- Exfiltration staging file -->
Find the creation of the specific /tmp/osalogging.zip archive used to stage stolen loot.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Records of the staging zip file being created or modified. Silence means
  the file was not created or has already been removed.
reads:
- device_hostname
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_path) = '/tmp/osalogging.zip' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-macsync
<!-- Triage infection evidence -->
```agent target=hunter
cite: required
context:
- assess-curl-lead
- macsync-script-logic
- staging-file-activity
max_iterations: 6
objective: Analyze the combined results of the curl lead, the rare daemon script logic,
  and the staging file creation to confirm a successful MacSync infection.
success_criteria: A verdict of malicious | suspicious | benign citing relevant telemetry
  across all steps.
tools:
- endpoint
```

## route-infection
<!-- Route based on infection status -->
if~: "the triage-macsync verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: script-logging-disabled)
else: → close-out-benign

## isolate-and-remediate
<!-- Isolate and remediate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint from the network. Kill any active zsh processes with daemon_function logic. Remove the staging file at /tmp/osalogging.zip. Prompt the user for an immediate password reset and session revocation.
```
→ analyst-final-review

## analyst-final-review
<!-- Analyst final review -->
```manual target=analyst
Review the telemetry for the affected hosts. Confirm if the user actually clicked 'Allow' on the TCC prompts mentioned in the report. Check for any follow-on RAT persistence that may have survived the cleanup.
```
→ close-out-benign

## close-out-benign
<!-- Close out hunt -->
```manual target=analyst
Log the examined hosts and the time window. Note any visibility gaps in script or process logging for future remediation.
```
→ end
