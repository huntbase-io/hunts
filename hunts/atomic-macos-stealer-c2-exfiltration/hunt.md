---
analysis: A single rule on static IPs fails as AMOS infrastructure rotates. This hunt
  correlates the behavioral 'join' of a staging file (out.zip) with rare outbound
  traffic from system-masquerading processes (like accountsd) and specific HTTP exfiltration
  stages, providing context an analyst can use to confirm a breach.
blind_spots:
- id: https-visibility-gap
  question: What are the URL parameters (stage=boot) for encrypted HTTPS traffic?
  requires: Endpoint-based HTTP dissection or SSL decryption proxy.
  risk: If AMOS uses HTTPS without decryption, query parameters like stage=wallets
    will not be visible in hb_http_activity.
  stage: c2-exfiltration
- id: ephemeral-staging
  question: Is the out.zip file deleted before the EDR or osquery can snapshot it?
  requires: hb_file_activity with close-to-realtime collection.
  risk: If the malware stages and exfiltrates data very rapidly, the 'out.zip' file
    may be deleted before detection steps run.
  stage: collection-and-staging
coverage:
- stage: c2-exfiltration
  status: covered
  steps:
  - amos-http-exfiltration
  - rare-outbound-baseline
  - amos-dns-indicators
- stage: collection-and-staging
  status: covered
  steps:
  - amos-staging-file
- reason: Handled by the Initial Access hunt in this series.
  stage: initial-access-terminal-execution
  status: out_of_scope
- reason: Handled by the Persistence hunt in this series.
  stage: persistence-and-masquerading
  status: out_of_scope
- reason: Belongs to another part of the 'Atomic macOS (AMOS) Stealer Activity' series.
  stage: credential-and-permission-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AMOS is a fast-evolving threat to macOS credentials. Because its
    network signatures (staged POST requests) are more stable than its file hashes,
    a cross-surface behavioral hunt provides the most durable coverage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is exfiltrating sensitive macOS data, including keychain items
  and browser cookies, via distinctive HTTP POST requests with 'stage=' parameters
  to rare or known-malicious IP infrastructure.
labels:
- hunt
- attack.t1071.001
- attack.t1041
- attack.t1090.003
- attack.t1555
name: Atomic macOS Stealer C2 and Data Exfiltration
parameters:
  c2_domains:
    default:
    - getmacouscloud.com
    - ferncore13.com
    - grove-89.com
    - malware-traffic-analysis.net
    description: Known AMOS infrastructure domains.
    from:
      kind: article
      observed: '2026-08-05'
      ref: unit42-amos-2026
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; provided by the scoping
      step.
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with all macOS (darwin) hosts. Focus on systems where administrative
  passwords might be entered into terminal prompts.
references:
- name: "Unit 42 \u2014 Atomic macOS (AMOS) Stealer Activity"
  url: https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/
related:
- hunt: amos-persistence-masquerading
  reason: This hunt focuses on the network aftermath; the persistence mechanisms (launchd
    plists) are a sibling behavioral signal.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Deceptive Terminal Command Execution
    observables:
    - getmacouscloud.com
    - ferncore13.com
    - curl -L
    - zsh script execution via Terminal
    - 608e70d1338612686917ee5cd300ff7ed8e318dfd787a50257f92142e99bd688
    slug: initial-access-terminal-execution
    tactic: initial-access
    techniques:
    - T1204.002
    - T1059.004
  - name: Persistence via Masqueraded Binaries
    observables:
    - /tmp/helper
    - /tmp/starter
    - .com.apple.accountsd/AccountsHelper
    - .com.apple.metadata.mds/mdworker_shared
    - ~/Library/Application Support/.com.apple.accountsd/
    - ~/Library/Application Support/.com.apple.metadata.mds/
    slug: persistence-and-masquerading
    tactic: persistence
    techniques:
    - T1543.001
    - T1036
  - name: Password Prompt and Permission Requests
    observables:
    - OS password prompt for administrative access
    - TCC permissions requests for Finder, Desktop, Documents, and Notes
    slug: credential-and-permission-access
    tactic: credential-access
    techniques:
    - T1555
  - name: Local Data Collection and Staging
    observables:
    - /tmp/out.zip
    - zsh_history
    - deskwallets/Binance
    - FileGrabber/aws
    - FileGrabber/docker
    slug: collection-and-staging
    tactic: collection
    techniques:
    - T1005
    - T1115
  - name: Exfiltration over HTTP POST
    observables:
    - 161.35.146.120
    - 188.166.78.138
    - grove-89.com
    - HTTP POST with stage=boot
    - HTTP POST with stage=credentials
    - HTTP POST with stage=wallets
    - HTTP POST with stage=browsers
    slug: c2-exfiltration
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1041
  summary: Users are lured to fake setup pages where they are instructed to paste
    a malicious command into the macOS Terminal. This command downloads Zsh scripts
    and Mach-O binaries that establish persistence by masquerading as Apple services,
    prompt for administrative credentials, and exfiltrate browser and crypto wallet
    data to a C2 server via HTTP POST.
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


# Atomic macOS Stealer C2 and Data Exfiltration

This hunt targets the network infrastructure and exfiltration behavior of Atomic macOS (AMOS) stealer. While the malware's delivery mechanisms and file paths rotate, its reliance on a staged exfiltration process—captured as sequential HTTP POST requests with specific stage parameters (e.g., stage=boot, stage=wallets)—remains a durable behavioral signal. We identify these parameters in HTTP traffic, corroborate them with local collection artifacts like 'out.zip', and match network activity against masqueraded system processes and known C2 domains.

## scoping-macos
<!-- Identify macOS fleet -->
Narrow the estate to macOS devices, as AMOS is platform-specific, and produce a list for subsequent filtering.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of macOS hostnames to be used in the scope_hosts parameter. Zero
  rows means no macOS devices were recently seen.
reads:
- hostname
- os_version
- device_uid
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, os_version, device_uid FROM hb_devices WHERE platform = 'darwin' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Correlate HTTP, Network, Staging, and DNS Indicators -->
parallel:
- → amos-http-exfiltration
- → rare-outbound-baseline
- → amos-dns-indicators
- → amos-staging-file
join: → triage-amos-activity

## amos-http-exfiltration
<!-- AMOS Staged HTTP Exfiltration -->
Detect the specific 'stage=' URL parameters used by AMOS for exfiltrating data.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP POST requests containing AMOS-specific stage parameters. Multiple stages
  from one host indicate high-confidence exfiltration.
reads:
- device_hostname
- url_full
- http_method
- dst_endpoint_ip
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_full, http_method, dst_endpoint_ip, user_agent, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(http_method) = 'post' AND (instr(LOWER(url_full), 'stage=boot') > 0 OR instr(LOWER(url_full), 'stage=credentials') > 0 OR instr(LOWER(url_full), 'stage=wallets') > 0 OR instr(LOWER(url_full), 'stage=browsers') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-baseline
<!-- Rare Outbound Connections from Masqueraded Processes -->
Find outbound network activity from processes that exclude known browsers and focus on AMOS masquerade targets like accountsd or mdworker.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process-IP pair involving a system-sounding process exfiltrating
  data. AMOS binaries often masquerade as .com.apple.accountsd.
prevalence:
  by: device_hostname
  key:
  - user_name
  - process_path
  - dst_endpoint_ip
  rare_below: 3
reads:
- user_name
- process_path
- dst_endpoint_ip
- device_hostname
- direction
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_name, process_path, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND dst_endpoint_port IN (80, 443) AND (LOWER(process_path) NOT LIKE '%safari%' AND LOWER(process_path) NOT LIKE '%chrome%' AND LOWER(process_path) NOT LIKE '%firefox%') AND (LOWER(process_path) LIKE '%.apple.%' OR LOWER(process_path) LIKE '%mdworker%' OR LOWER(process_path) LIKE '%helper%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_name, process_path, dst_endpoint_ip HAVING hosts <= 3 ORDER BY hosts ASC
```

## amos-dns-indicators
<!-- DNS Filtering for AMOS Infrastructure -->
Filter for DNS resolutions of known AMOS-associated domains to pipe into triage.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Resolutions for known malicious domains. Silence means indicators have likely
  rotated, requiring reliance on behavioral signals.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## amos-staging-file
<!-- Detection of out.zip Staging -->
Corroborate exfiltration with the presence of the 'out.zip' staging file in temporary directories.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation or modification of 'out.zip' in /tmp. This confirms the collection
  stage of the AMOS lifecycle.
reads:
- device_hostname
- file_path
- file_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_name) = 'out.zip' OR LOWER(file_path) LIKE '%/tmp/out.zip%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-amos-activity
<!-- Weigh Exfiltration Evidence -->
```agent target=hunter
cite: required
context:
- amos-http-exfiltration
- rare-outbound-baseline
- amos-dns-indicators
- amos-staging-file
max_iterations: 4
objective: Determine if any host is exfiltrating data via AMOS patterns. A host showing
  matches in more than one signal (e.g., DNS hit + Rare IP hit, or HTTP stage + out.zip
  file touch) must be prioritized.
success_criteria: A verdict of malicious | suspicious | benign per host citing specific
  rows from at least two surfaces.
tools:
- endpoint
- network
- web
```

## decision-amos-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host based on the correlation of staged HTTP exfiltration and anomalous non-browser processes" (confidence: high, judge=hunter)
then: → action-isolate-host
indeterminate: → task-analyst-review
unavailable: → task-analyst-review (blind_spot: https-visibility-gap)
else: → task-close-out

## action-isolate-host
<!-- Isolate macOS Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the file from /tmp/out.zip before any system cleanup.
```
→ task-analyst-review

## task-analyst-review
<!-- Analyst Post-Mortem -->
```manual target=analyst
Review the cited rows. Confirm whether the identified process (e.g., AccountsHelper) was masquerading as a system process and if the out.zip file was present.
```
→ end

## task-close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record that no multi-surface AMOS exfiltration patterns were observed.
```
→ end
