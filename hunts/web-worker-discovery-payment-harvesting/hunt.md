---
analysis: A single detection rule on 'w3wp spawning cmd' often generates too much
  noise from legitimate maintenance. This hunt distinguishes threat from noise by
  using a gated flow, stack-counting commands for rarity, and corroborating with file
  access to sensitive configuration and payment files.
blind_spots:
- id: missing-process-telemetry
  question: whether w3wp.exe spawned any child processes on non-enrolled hosts
  requires: Endpoint agent coverage on every web server
  risk: A compromised server without process telemetry could execute shells and harvest
    data invisibly.
  stage: web-worker-shell-execution
- id: obfuscated-script-content
  question: what code was executed within encoded PowerShell blocks
  requires: hb_script_activity for deep script inspection
  risk: Attackers using -enc will hide their discovery intent from process command-line
    monitoring.
  stage: web-worker-shell-execution
coverage:
- stage: web-worker-shell-execution
  status: covered
  steps:
  - iis-worker-shell-execution-lead
  - evaluate-lead-agent
- stage: iis-and-web-environment-discovery
  status: covered
  steps:
  - rare-w3wp-child-commands
- stage: payment-data-harvesting
  status: covered
  steps:
  - rare-w3wp-child-commands
  - sensitive-file-access-triage
- reason: Belongs to another part of the 'Determined Attacker Uploads Malicious Webshells
    to Parks and Rec Management Platform Servers' series.
  stage: web-application-probing-and-brute-force
  status: out_of_scope
- reason: Belongs to another part of the 'Determined Attacker Uploads Malicious Webshells
    to Parks and Rec Management Platform Servers' series.
  stage: webshell-ingress-via-member-upload
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Web servers hosting payment data are high-value targets. This hunt
    ensures that post-compromise activity, such as credential harvesting and card
    data searches, is detected even if the initial exploit is missed.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using a compromised IIS web worker to execute discovery
  tools and search for payment card data or database credentials.
labels:
- hunt
- attack.t1505.003
- attack.t1059.001
- attack.t1047
- attack.t1083
- collection
- discovery
- execution
- initial access
name: Web Worker Discovery and Payment Data Harvesting
parameters:
  discovery_tools:
    default:
    - appcmd.exe
    - whoami.exe
    - hostname.exe
    - systeminfo.exe
    - net.exe
    - netstat.exe
    - tasklist.exe
    - ipconfig.exe
    description: Administrative tools often used via a web shell.
    from:
      kind: article
      observed: '2026-09-30'
      ref: huntress-parks-and-rec
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  payment_endpoint_paths:
    default:
    - _fortis\webhooks
    - webhooks
    - payment
    description: Substrings of paths associated with payment transaction logs.
    from:
      kind: article
      observed: '2026-09-30'
      ref: huntress-parks-and-rec
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the detailed investigation.
    type: list[host]
  sensitive_filenames:
    default:
    - web.config
    - applicationhost.config
    - connectionstrings.config
    description: Configuration files that store credentials or secrets.
    from:
      kind: article
      observed: '2026-09-30'
      ref: huntress-parks-and-rec
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/parks-recreation-platform-webshell-attack
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing IIS servers, specifically those with multi-tenant
  directory structures on secondary drives (D:, E:).
references:
- name: "Huntress \u2014 Determined Attacker Uploads Malicious Webshells to Parks\
    \ and Rec Management Platform Servers"
  url: https://www.huntress.com/blog/parks-recreation-platform-webshell-attack
related:
- hunt: web-application-probing-and-brute-force
  reason: Initial access attempts via brute force and tilde enumeration are handled
    by a separate hunt focused on web logs.
  relation: out-of-scope-alternative
- hunt: web-shell-ingress-platform-probing
  relation: follows
scenario:
  stages:
  - name: Web Application Probing and Brute Force
    observables:
    - POST /management/login.aspx
    - POST /info/household/login.aspx
    - GET /a*~1* (IIS 8.3 tilde enumeration)
    - WebDAV OPTIONS method
    - Upload.ashx::$DATA
    - FileUpload.ashx::$DATA
    slug: web-application-probing-and-brute-force
    tactic: initial-access
    techniques:
    - T1110
    - T1190
  - name: Webshell Ingress via Member Upload
    observables:
    - 'Path: /documents/MemberFiles/'
    - aa7d-4056-8061-8f32887196b9.aspx
    - 5893-4e83-a45c-188a5e4686fd.aspx
    - 2ae9-4d05-ae6d-ad10ccf25ed9.aspx
    - ed12-4938-9661-f4034526d911.aspx
    - 8362-42b6-8906-4a33eaaa4bb0.aspx
    - 5ef0-4da3-b162-01844bf0109e.aspx
    - 791a-4e96-a5ea-e5c7cfd35fd2.jpg
    slug: webshell-ingress-via-member-upload
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
  - name: Web-Worker Shell Execution
    observables:
    - Parent process w3wp.exe spawning cmd.exe
    - Parent process w3wp.exe spawning powershell.exe
    - cmd.exe /c whoami
    - cmd.exe /c net user
    - cmd.exe /c wmic process where "name='w3wp.exe'" get ProcessId,CommandLine
    - Import-Module WebAdministration; Get-Website
    slug: web-worker-shell-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: IIS and Web Environment Discovery
    observables:
    - appcmd.exe list sites
    - appcmd.exe list vdirs
    - appcmd.exe list app
    - dir /b E:\Content\info\App_Code\*DB*
    - dir /b E:\Content\info\App_Code\*Sql*
    - C:\inetpub\temp\appPools
    - C:\Windows\System32\drivers\etc\hosts
    slug: iis-and-web-environment-discovery
    tactic: discovery
    techniques:
    - T1083
  - name: Payment Data Harvesting
    observables:
    - findstr /i /c:"connectionString" /c:"password" /c:"Data Source" E:\Content\info\web.config
    - findstr /s /i /m /c:"CVV" /c:"CardNumber" /c:"CreditCard" E:\Content\info\*.aspx
    - findstr /s /i /m "AuthorizeNet Fortis CardConnect BluePay PayPal Braintree Stripe"
    - type E:\Content\info\_fortis\Webhooks\*.txt
    - findstr /i "exp_date exp_month exp_year expiration cvv first_six last_four card_number"
    slug: payment-data-harvesting
    tactic: collection
    techniques:
    - T1505.003
  summary: A threat actor, likely based in China, compromised multiple instances of
    a parks and recreation management platform by abusing a legitimate member registration
    and file upload feature to plant ASPX webshells. Once established, the attacker
    performed extensive reconnaissance of the IIS environment and local file system,
    specifically targeting configuration files and Fortis webhook logs to steal payment
    card data and credentials.
series:
  index: 2
  slug: determined-attacker-uploads-malicious-webshells-to-parks-and-rec-management-platform-servers
  title: Determined Attacker Uploads Malicious Webshells to Parks and Rec Management
    Platform Servers
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


# Web Worker Discovery and Payment Data Harvesting

This hunt targets the post-exploitation phase following a web shell upload to an IIS server. It starts with a cheap lead query to identify interactive command shells spawned by the IIS web worker. If shell activity is confirmed, the hunt fans out to identify rare administrative commands and targeted file access to sensitive configuration files or payment integration logs. This allows an analyst to distinguish between routine application maintenance and an active intruder harvesting credentials and credit card information.

## iis-worker-shell-execution-lead
<!-- IIS worker spawning command shells -->
Identify any instance where the IIS web worker process (w3wp.exe) spawns a command shell or administrative tool to detect active web shells.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows showing w3wp.exe spawning shell interpreters. Silence suggests no common
  shell-based webshell activity occurred on these hosts during the window.
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
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\\w3wp.exe' AND (LOWER(process_name) LIKE '%\\cmd.exe' OR LOWER(process_name) LIKE '%\\powershell.exe' OR LOWER(process_name) LIKE '%\\wmic.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead-agent
<!-- Evaluate shell execution lead -->
```agent target=hunter
cite: required
context:
- iis-worker-shell-execution-lead
max_iterations: 3
objective: 'Review the shell commands spawned by w3wp.exe. Look for reconnaissance
  like whoami, hostname, or directory listings (dir /b) on non-standard drives like
  D: or E:. Determine if these commands suggest a human operator.'
success_criteria: A clear per-host assessment of suspicious activity.
tools:
- endpoint
```

## gate-on-lead-decision
<!-- Gate on shell lead -->
if~: "the evaluation identifies at least one host with suspicious w3wp.exe child processes" (confidence: high, judge=hunter)
then: → discovery-and-harvesting-fan-out
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: missing-process-telemetry)
else: → close-out-summary

## discovery-and-harvesting-fan-out
<!-- Discovery and harvesting fan-out -->
parallel:
- → rare-w3wp-child-commands
- → sensitive-file-access-triage
join: → triage-breach-agent

## rare-w3wp-child-commands
<!-- Rare w3wp.exe child commands -->
Identify rare administrative or search commands spawned by the web worker that deviate from baseline behavior.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, discovery_tools=discovery_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific search commands or tools like appcmd.exe appearing on a small number
  of web servers. High-count commands are likely legitimate application updates.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(parent_process_name) LIKE '%\\w3wp.exe' AND (LOWER(process_name) LIKE '%\\appcmd.exe' OR LOWER(process_name) LIKE '%\\whoami.exe' OR LOWER(process_name) LIKE '%\\hostname.exe' OR LOWER(process_name) LIKE '%\\systeminfo.exe' OR LOWER(process_name) LIKE '%\\net.exe' OR LOWER(process_name) LIKE '%\\netstat.exe' OR LOWER(process_name) LIKE '%\\tasklist.exe' OR LOWER(process_name) LIKE '%\\ipconfig.exe' OR LOWER(process_cmd_line) LIKE '%findstr%') AND ('{{discovery_tools}}' != '') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## sensitive-file-access-triage
<!-- Sensitive file access by shell processes -->
Identify instances where shells or administrative children of w3wp.exe access sensitive configuration or payment log files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, sensitive_filenames=sensitive_filenames, payment_endpoint_paths=payment_endpoint_paths, scope_hosts=scope_hosts)
~~~yaml
expected: Command processes reading configuration files or payment logs. This is highly
  suspicious as applications should read these directly without spawning a shell.
reads:
- activity_name
- device_hostname
- file_name
- file_path
- parent_process_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(parent_process_name) LIKE '%\\w3wp.exe' OR LOWER(process_name) LIKE '%\\cmd.exe' OR LOWER(process_name) LIKE '%\\powershell.exe') AND (instr(',' || '{{sensitive_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR LOWER(file_path) LIKE '%\\_fortis\\webhooks\\%' OR LOWER(file_path) LIKE '%\\webhooks\\%') AND ('{{payment_endpoint_paths}}' != '') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-breach-agent
<!-- Triage breach evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead-agent
- rare-w3wp-child-commands
- sensitive-file-access-triage
max_iterations: 6
objective: 'Determine if any host shows signs of a human intruder. Look for the chain:
  shell launch -> environment discovery (appcmd, drive enumeration) -> data harvesting
  (findstr for card data, reading web.config or payment logs). Citing specific command
  lines and file paths is required.'
success_criteria: A final malicious | suspicious | benign verdict per host.
tools:
- endpoint
```

## route-on-triage-decision
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on shell execution and harvesting activity" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: missing-process-telemetry)
else: → close-out-summary

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised web server immediately. Collect memory samples and preserve application directories for forensic investigation.
```
→ analyst-final-review

## analyst-final-review
<!-- Analyst final review -->
```manual target=analyst
Review cited rows; confirm if findstr keywords match patterns observed in the report (CVV, CardNumber). Rotate any credentials found in configuration files.
```
→ end

## close-out-summary
<!-- Hunt close out -->
```manual target=analyst
Record that no suspicious w3wp.exe shell activity was found. Document any benign application child processes for future tuning.
```
→ end
