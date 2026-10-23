---
analysis: This is a hunt because a single rule for curl execution is too noisy for
  many environments; this playbook adds value by correlating execution rarity with
  specific unauthorized file access on macOS, requiring an analyst to weigh the temporal
  context.
blind_spots:
- id: missing-process-telemetry
  question: whether the curl command contained the base64 string
  requires: hb_process_activity with full process_cmd_line
  risk: Without full command-line arguments, the specific ClickFix pattern cannot
    be distinguished from normal shell usage.
  stage: click-fix-terminal-execution
- id: ephemeral-file-access
  question: whether the shell process successfully read the cookie file
  requires: hb_file_activity with high-frequency capture
  risk: If the attacker uses a method that is not captured as a standard file read
    event (e.g., specific memory mapping techniques), the exfiltration may be missed.
  stage: browser-session-cookie-theft
coverage:
- stage: click-fix-terminal-execution
  status: covered
  steps:
  - shell-curl-patterns
  - rare-shell-commands
- stage: browser-session-cookie-theft
  status: covered
  steps:
  - cookie-file-access
- reason: 'Belongs to another part of the ''ClickFix to BEC in 24 Hours: Tragic Quadrant
    | Huntress'' series.'
  stage: session-hijack-mfa-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''ClickFix to BEC in 24 Hours: Tragic Quadrant
    | Huntress'' series.'
  stage: hidden-inbox-rule-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''ClickFix to BEC in 24 Hours: Tragic Quadrant
    | Huntress'' series.'
  stage: bec-invoice-manipulation-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: ClickFix lures are highly effective at bypassing MFA by stealing
    established browser sessions. Detecting the initial terminal execution and the
    resulting cookie file access is essential to stop the attack before it escalates
    to full BEC.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a social engineering lure to trick a macOS user into
  executing a malicious shell command in Terminal that steals browser session cookies
  for account takeover.
labels:
- hunt
- attack.t1204.002
- attack.t1059.004
- attack.t1539
- credential access
- execution
- impact
- initial access
- persistence
name: ClickFix Shell Execution and Cookie Theft
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-24'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: The list of hostnames identified in the lead query; if left empty,
      the hunt runs across the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets macOS hosts. It begins with a lead query identifying suspicious
  shell execution; the results of this first step should be used to populate the scope_hosts
  parameter for the subsequent parallel queries to reduce noise and resource consumption.
references:
- name: "Huntress \u2014 ClickFix to BEC in 24 Hours: Tragic Quadrant"
  url: https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris
related:
- hunt: session-hijack-mfa-bypass
  reason: This hunt detects the initial theft; session-hijack monitors for the subsequent
    misuse of those cookies.
  relation: follows
scenario:
  stages:
  - name: ClickFix Social Engineering Execution
    observables:
    - Terminal.app
    - Command+Space
    - curl
    - Base64-encoded IP address in shell command
    slug: click-fix-terminal-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1059.004
  - name: Browser Session Cookie Theft
    observables:
    - Microsoft 365 session cookie
    - Access to browser cookie storage files
    slug: browser-session-cookie-theft
    tactic: credential-access
    techniques:
    - T1539
  - name: Session Hijacking and MFA Bypass
    observables:
    - Two browsers active in one session
    - Two different operating systems for the same login
    - Traffic routed through a VPN
    - Sign-in without password or MFA prompt
    slug: session-hijack-mfa-bypass
    tactic: initial-access
    techniques:
    - T1133
    - T1550.004
  - name: Persistence via Hidden Inbox Rule
    observables:
    - Inbox rule named '..'
    - Rule set to archive messages containing invoice numbers
    slug: hidden-inbox-rule-persistence
    tactic: persistence
    techniques:
    - T1137.005
  - name: Business Email Compromise Impact
    observables:
    - Replies to Treasury emails
    - Modified routing numbers for payments
    - Deletion of sent messages
    - Emptying of trash/deleted items folder
    slug: bec-invoice-manipulation-impact
    tactic: impact
    techniques:
    - T1565.002
  summary: A user seeking AI assistance was targeted by a ClickFix social engineering
    attack that induced them to execute a malicious shell command via Terminal. This
    command stole a Microsoft 365 session cookie, enabling the attacker to bypass
    MFA, gain unauthorized inbox access, and perform mailbox manipulation to redirect
    invoice payments in a Business Email Compromise (BEC) scenario.
series:
  index: 1
  slug: clickfix-to-bec-in-24-hours-tragic-quadrant-huntress
  title: 'ClickFix to BEC in 24 Hours: Tragic Quadrant | Huntress'
  total: 2
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


# ClickFix Shell Execution and Cookie Theft

This hunt targets the initial endpoint stages of a ClickFix-style attack on macOS. It lead with a scoping query to identify hosts running shell interpreters with curl and base64 encoding. It then corroborates these leads by identifying rare command strings and unauthorized access to browser cookie databases, including Safari and Chromium-based paths, specifically on the suspect hosts. An agent weighs the combined evidence to identify successful session theft, ensuring that the file exfiltration occurred after the suspicious command execution.

## shell-curl-patterns
<!-- Shell interpreters running curl and base64 -->
Identify hosts running the specific ClickFix pattern of shell interpreters executing curl with base64 payloads to serve as the suspect list for the hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts running encoded curl commands in Terminal. If zero rows are returned,
  no hosts are currently suspected of this ClickFix variant.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/zsh') AND LOWER(process_cmd_line) LIKE '%curl%' AND LOWER(process_cmd_line) LIKE '%base64%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate execution and impact -->
parallel:
- → rare-shell-commands
- → cookie-file-access
join: → triage-endpoint-activity

## rare-shell-commands
<!-- Rare shell commands with encoding -->
Identify unique shell payloads across suspect hosts to separate targeted ClickFix attacks from standard administrative activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific payload strings seen only on one or two suspected hosts.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/zsh') AND LOWER(process_cmd_line) LIKE '%base64%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY LOWER(process_cmd_line) HAVING host_count <= 3 ORDER BY host_count ASC
```

## cookie-file-access
<!-- Non-browser access to cookie files -->
Identify when shell interpreters or curl access browser cookie storage files on suspect hosts, indicating successful theft.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A shell or curl process reading a cookie database for Chrome, Edge, or Safari.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (instr(LOWER(file_path), 'library/application support/google/chrome/') > 0 OR instr(LOWER(file_path), 'library/application support/microsoft edge/') > 0 OR instr(LOWER(file_path), 'library/cookies/') > 0 OR LOWER(file_path) LIKE '%cookies.binarycookies%') AND (LOWER(file_path) LIKE '%cookies%' OR LOWER(file_path) LIKE '%login data%' OR LOWER(file_path) LIKE '%cookies.binarycookies%') AND (LOWER(process_name) LIKE '%sh' OR LOWER(process_name) LIKE '%bash' OR LOWER(process_name) LIKE '%zsh' OR LOWER(process_name) LIKE '%curl') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-endpoint-activity
<!-- Triage endpoint activity -->
```agent target=hunter
cite: required
context:
- shell-curl-patterns
- rare-shell-commands
- cookie-file-access
max_iterations: 4
objective: Determine if the shell execution (shell-curl-patterns) and the cookie database
  access (cookie-file-access) indicate a successful ClickFix session theft on any
  host, prioritizing rare commands and requiring that the file access occurred after
  the shell command ran.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  command lines and temporal correlation with file paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-process-telemetry)
else: → close-out-hunt

## contain-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR. Revoke all active Microsoft 365 sessions for the affected user to invalidate any stolen session cookies.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the host browser history to find the AI platform or GPT link that delivered the lure. Document any discovered C2 IPs from the shell command analysis.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record confirmed hostnames and user accounts. Submit discovered indicators for internal blocklisting.
```
→ end
