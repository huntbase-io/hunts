---
analysis: A simple detection rule targeting the listed IPs will fail within days.
  This hunt uses a behavioral pivot by searching for the specific sequence of exfiltration
  stages in HTTP requests and stack-counting those patterns to identify rare, malicious
  traffic across the fleet.
blind_spots:
- id: limited-http-visibility
  question: whether exfiltration is occurring over encrypted channels that hide URL
    parameters
  requires: TLS inspection or endpoint-based HTTP logging
  risk: Malware using HTTPS may hide the stage query parameters from network-level
    sensors, leaving only IP/DNS metadata for analysis.
  stage: c2-exfiltration-over-http
- id: ephemeral-infrastructure
  question: whether the infection is communicating with new, undocumented C2 IPs
  requires: frequent indicator updates
  risk: AMOS infrastructure rotates daily; a negative result on specific IPs does
    not guarantee a host is clean if the behavioral exfiltration pattern is also missed.
  stage: c2-exfiltration-over-http
coverage:
- stage: c2-exfiltration-over-http
  status: covered
  steps:
  - c2-ip-connections
  - http-stage-patterns
  - dns-malicious-lookups
- reason: Covered by the initial access hunt in this series.
  stage: initial-access-copy-paste-terminal
  status: out_of_scope
- reason: Covered by the persistence hunt in this series.
  stage: persistence-via-hidden-application-support
  status: out_of_scope
- reason: Belongs to another part of the 'Atomic macOS (AMOS) Stealer Activity' series.
  stage: script-execution-and-payload-retrieval
  status: out_of_scope
- reason: Belongs to another part of the 'Atomic macOS (AMOS) Stealer Activity' series.
  stage: credential-and-wallet-collection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AMOS stealer exfiltrates high-value assets including AWS credentials,
    cryptocurrency wallets, and browser-stored passwords. Detecting the network exfiltration
    sequence is a critical final opportunity to limit the impact of an intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary exfiltrates keychain, browser, and wallet data from macOS
  hosts by sending a sequence of HTTP POST requests containing specific stage parameters
  to malicious infrastructure.
labels:
- hunt
- attack.t1071.001
- attack.t1041
- attack.t1090.003
name: AMOS Stealer C2 and Exfiltration Patterns
parameters:
  c2_domains:
    default:
    - getmacouscloud.com
    - ferncore13.com
    - grove-89.com
    description: Domains used by AMOS for delivery and C2.
    from:
      kind: article
      observed: '2026-08-05'
      ref: unit42-amos-2026
    type: list[domain]
  c2_ips:
    default:
    - 161.35.146.120
    - 188.166.78.138
    description: Known AMOS command and control IP addresses.
    from:
      kind: article
      observed: '2026-08-05'
      ref: unit42-amos-2026
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-16'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the behavioral search.
    from:
      kind: manual
      observed: '2026-09-16'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the search on macOS endpoints. While the C2 IPs are specific to early
  August 2026, the HTTP POST stage parameters are a durable indicator of the malware's
  exfiltration logic.
references:
- name: "Unit 42 \u2014 Atomic macOS (AMOS) Stealer Activity"
  url: https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/
related:
- hunt: amos-stealer-persistence-and-collection
  reason: This hunt focuses on network behavior; local file persistence and collection
    artifacts belong to a separate investigation surface.
  relation: out-of-scope-alternative
- hunt: amos-stealer-macos-phased
  relation: follows
scenario:
  stages:
  - name: Deceptive Terminal Command Execution
    observables:
    - getmacouscloud.com
    - curl -s hxxps://ferncore13.com/curl/...
    - zsh -c "$(curl ...)"
    slug: initial-access-copy-paste-terminal
    tactic: initial-access
    techniques:
    - T1204.001
    - T1059.004
  - name: Scripted Payload Retrieval
    observables:
    - ferncore13.com
    - grove-89.com
    - /tmp/helper
    - 71781ad8adefb499aee9bcbe1a166e69ccc37a47066682f617d65c76d8cde88c
    - 7ea6ff8b12c59aaae1ab6f4f5a57045dad5a8127954f3ffd3d1c154d40d7ca3a
    slug: script-execution-and-payload-retrieval
    tactic: execution
    techniques:
    - T1105
    - T1059.004
  - name: Hidden Application Support Persistence
    observables:
    - /tmp/starter
    - ~/Library/Application Support/.com.apple.accountsd/
    - ~/Library/Application Support/.com.apple.metadata.mds/
    - .service
    - .mdworker
    - AccountsHelper
    - mdworker_shared
    slug: persistence-via-hidden-application-support
    tactic: persistence
    techniques:
    - T1543.001
    - T1564.001
  - name: Credential and Wallet Harvesting
    observables:
    - /tmp/out.zip
    - zsh_history
    - deskwallets/Binance/
    - FileGrabber/aws/
    - FileGrabber/docker/
    - Telegram Data/
    slug: credential-and-wallet-collection
    tactic: collection
    techniques:
    - T1555
    - T1115
    - T1560.001
  - name: Command and Control Exfiltration
    observables:
    - 161.35.146.120
    - 188.166.78.138
    - stage=boot
    - stage=credentials
    - stage=wallets
    - stage=browsers
    slug: c2-exfiltration-over-http
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1041
  summary: Atomic macOS (AMOS) stealer infects users via deceptive toolkit setup pages
    that trick them into running Zsh scripts in Terminal. The malware establishes
    persistence through hidden directories and scripts in Application Support, harvests
    credentials and cryptocurrency wallets, and exfiltrates the staged data to C2
    servers over HTTP.
series:
  index: 2
  slug: atomic-macos-amos-stealer-activity
  title: Atomic macOS (AMOS) Stealer Activity
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


# AMOS Stealer C2 and Exfiltration Patterns

The adversary transmits stolen browser data, credentials, and cryptocurrency wallets via HTTP POST requests after collecting them on the host. These requests include a stage parameter identifying the type of data being sent, such as boot, credentials, or wallets. This hunt identifies behavioral network patterns by searching for these parameters and correlating them with known malicious infrastructure. An agent weighs the network evidence to confirm an active AMOS infection and routes the host for isolation if exfiltration is detected.

## c2-ip-connections
<!-- Direct connections to known C2 infrastructure -->
Identify hosts establishing direct network connections to the IP addresses reported in AMOS campaigns.

```sqlite target=network role=scoping params=(c2_ips=c2_ips, lookback_days=lookback_days)
~~~yaml
expected: A hit shows a host communicating with a known malicious IP. Silence suggests
  no direct connection occurred to these specific nodes within the window.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-exfiltration
<!-- Corroborate behavioral exfiltration -->
parallel:
- → http-stage-patterns
- → dns-malicious-lookups
join: → triage-amos-activity

## http-stage-patterns
<!-- Exfiltration stage patterns in HTTP POST requests -->
Detect the characteristic stage parameters used by AMOS during exfiltration across the fleet or scoped hosts.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Multiple POST requests with different stage values from a single host indicate
  active data exfiltration. Silence provides evidence of absence if proxy or endpoint
  coverage is complete.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_query
  rare_below: 3
reads:
- device_hostname
- url_hostname
- url_query
- http_method
- user_agent
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_query, http_method, user_agent, COUNT(*) as req_count, MIN(time) as first_seen FROM hb_http_activity WHERE http_method = 'POST' AND (LOWER(url_query) LIKE '%stage=boot%' OR LOWER(url_query) LIKE '%stage=init_session%' OR LOWER(url_query) LIKE '%stage=credentials%' OR LOWER(url_query) LIKE '%stage=wallets%' OR LOWER(url_query) LIKE '%stage=browsers%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_query, http_method, user_agent
```

## dns-malicious-lookups
<!-- DNS lookups for delivery and C2 domains -->
Identify hosts attempting to resolve domains associated with the AMOS infection chain.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Lookups to ferncore13.com or getmacouscloud.com from user processes confirm
  the host interacted with malicious infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## triage-amos-activity
<!-- Triage exfiltration evidence -->
```agent target=hunter
cite: required
context:
- c2-ip-connections
- http-stage-patterns
- dns-malicious-lookups
max_iterations: 6
objective: Determine if any macOS hosts are infected with AMOS stealer by weighing
  direct C2 connections, exfiltration stage patterns, and malicious DNS lookups.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  rows for the exfiltration stages.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on triage results -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-http-visibility)
else: → close-out

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate credential revocation for all users associated with the device.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual forensic review -->
```manual target=analyst
Review the triage evidence and check for the presence of hidden directories in Application Support such as .com.apple.accountsd or .com.apple.metadata.mds.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the hunt results and note if any hosts in scope lacked endpoint telemetry.
```
→ end
