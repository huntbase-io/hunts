---
analysis: A simple rule for 'WinDirStat' is too noisy. This hunt correlates software
  inventory (scoping), process behavior (temp binary execution), and network prevalence
  (rare rotational TLDs) into a single triage decision that a standalone rule cannot
  make without high false positives.
blind_spots:
- id: limited-http-visibility
  owner: Network Engineering
  question: whether the traffic originated from a YouTube link or a Blogspot redirect
  remediation: Enable TLS decryption and log referrers on edge proxies.
  requires: hb_http_activity with full URI/referrer visibility
  risk: Without referrer data, we cannot distinguish between accidental lure clicks
    and intentional searches, leading to lower confidence in initial access attribution.
  stage: initial-access-seo-youtube
- id: ephemeral-tmp-files
  owner: Endpoint Security
  question: the hash of the .tmp file before it is deleted by the installer
  remediation: Ensure EDR is configured to capture file hashes for all temporary directory
    activity.
  requires: hb_file_activity with hash capture
  risk: OfferLoader often deletes its intermediate files immediately after dropping
    the next stage; if real-time process/file events are missed, the primary artifact
    is gone.
  stage: execution-trojanized-installer
coverage:
- stage: initial-access-seo-youtube
  status: covered
  steps:
  - scope-suspicious-inventory
  - http-fingerprint-gating
- stage: execution-trojanized-installer
  status: covered
  steps:
  - detect-inno-setup-temp-execution
- stage: loader-gating-c2
  status: covered
  steps:
  - rare-rotational-dns
  - http-fingerprint-gating
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: payload-execution-insomnia
  status: out_of_scope
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: tunneling-steganography-arktunnel
  status: out_of_scope
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: browser-hijacking-docro
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The CL-CRI-1171 campaign has operated for over two years, infecting
    over 10,000 systems. Because it uses generic 'OfferLoader' infrastructure to deliver
    multiple distinct RATs, identifying the gating logic is the most reliable way
    to catch the infection early.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is delivering malware via trojanized Inno Setup installers,
  identified by temporary binary execution and beaconing to rotational compound-word
  domains.
labels:
- hunt
- attack.t1195.002
- attack.t1190
- attack.t1566.002
- attack.t1071.001
- attack.t1090.003
name: OfferLoader Trojanized Installer and PPI Gating
parameters:
  installer_keywords:
    default:
    - windirstat.exe
    - bluetooth driver for windows 10.exe
    - windirstat
    - setup.exe
    - installer.exe
    description: Filenames or package names of software often trojanized in this campaign.
    from:
      kind: article
      observed: '2026-09-09'
      ref: unit42-cl-cri-1171
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of telemetry to examine.
    from:
      kind: manual
      observed: '2026-09-09'
      ref: default
    type: number
  lure_domains:
    default:
    - atthelake.info
    - noiseship.cfd
    - voyagemist.space
    description: Known lure and gating domains from the report.
    from:
      kind: article
      observed: '2026-09-09'
      ref: unit42-cl-cri-1171
    type: list[domain]
  scope_hosts:
    default: []
    description: 'Optional: limit the hunt to these hostnames.'
    from:
      kind: manual
      observed: '2026-09-09'
      ref: default
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts where users might download third-party software or game optimizations.
  If 'windirstat' or 'bluetooth' drivers are not part of the standard image, start
  with those hosts. Widen to the whole fleet if rotational DNS activity is detected.
references:
- name: "Unit 42 \u2014 Untracked Nightmares: The Threats Hiding Behind Commodity\
    \ Infrastructure"
  url: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
related:
- hunt: payload-execution-insomnia
  reason: This hunt finds the loader; a follow-up is required for the Insomnia RAT
    payload.
  relation: follows
- hunt: tunneling-steganography-arktunnel
  reason: ARKTunnel is a common secondary payload delivered by this gating infrastructure.
  relation: follows
scenario:
  stages:
  - name: SEO Poisoning and YouTube Gaming Lures
    observables:
    - atthelake.info
    - noiseship.cfd
    - YouTube video titles like 'CS2 Potato Graphics Settings'
    - Referrer domains like Blogspot
    - Base64 click_id fingerprints in URLs
    slug: initial-access-seo-youtube
    tactic: initial-access
    techniques:
    - T1190
    - T1566.002
  - name: Trojanised Installer Execution
    observables:
    - windirstat.exe
    - Bluetooth Driver for Windows 10.exe
    - Inno Setup installation wizard
    - Pascal [Code] section execution
    slug: execution-trojanized-installer
    tactic: execution
    techniques:
    - T1195.002
    - T1204.002
  - name: OfferLoader PPI Gating
    observables:
    - voyagemist.space
    - windirstat.tmp
    - Rotational domains following two-word compound patterns (bubbleslip, churchpail)
    - Beacon returning 'ok' or 'no' string
    slug: loader-gating-c2
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: Insomnia RAT Deployment
    observables:
    - Node.js environment
    - Python agents
    - Cross-platform execution on Windows and macOS
    slug: payload-execution-insomnia
    tactic: execution
    techniques:
    - T1059.006
    - T1059.007
  - name: ARKTunnel Steganography and Tunneling
    observables:
    - WebSocket tunneling
    - Bitmap image files (.bmp) for payload unpacking
    - Fictitious corporate identity rotations
    slug: tunneling-steganography-arktunnel
    tactic: command-and-control
    techniques:
    - T1572
    - T1027.003
  - name: Docro Chrome Backdoor
    observables:
    - Chrome browser extension components
    - Revived 2015 browser hijacking techniques
    slug: browser-hijacking-docro
    tactic: evasion
    techniques:
    - T1185
  summary: The CL-CRI-1171 campaign uses YouTube gaming lures and SEO poisoning to
    distribute a versatile PPI loader named OfferLoader. The loader fingerprint victims
    via a Base64 encoded 'click_id' before deploying a rotating suite of payloads
    including Insomnia RAT, ARKTunnel, and Docro Hijacker onto enterprise endpoints.
series:
  index: 1
  slug: untracked-nightmares-the-threats-hiding-behind-commodity-infrastructure
  title: 'Untracked Nightmares: The Threats Hiding Behind Commodity Infrastructure'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# OfferLoader Trojanized Installer and PPI Gating

This hunt targets the delivery and gating phase of the CL-CRI-1171 campaign. It identifies the execution of trojanized installers (like WinDirStat or Bluetooth Drivers) that use Inno Setup to drop and run temporary (.tmp) payloads. It further corroborates this by looking for the distinctive rotational C2 domains and the presence of Base64 fingerprints (click_id) in HTTP traffic, which are characteristic of the Pay-Per-Install (PPI) gating mechanism.

## scope-suspicious-inventory
<!-- Scope by Suspicious Software Inventory -->
Identify hosts where trojanized software has been installed based on package name.

```sqlite target=endpoint role=scoping params=(installer_keywords=installer_keywords)
~~~yaml
expected: A list of hosts containing software names matching the campaign lures. Silence
  is not evidence of absence as many installers are run as standalone executables
  without registration.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE instr(',' || '{{installer_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## detect-inno-setup-temp-execution
<!-- Inno Setup Executing Temporary Payloads -->
Identify the core behavior of OfferLoader: an installer launching a .tmp binary from a user-writable path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, installer_keywords=installer_keywords)
~~~yaml
expected: An installer process spawning a temporary file from AppData\Temp. This is
  the primary behavioral marker of the OfferLoader Pascal script execution.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%.tmp' OR LOWER(process_cmd_line) LIKE '%.tmp%') AND (LOWER(process_path) LIKE '%\\appdata\\local\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND (instr(',' || '{{installer_keywords}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE '%setup%' OR LOWER(parent_process_name) LIKE '%install%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-network
<!-- Corroborate Network Activity -->
parallel:
- → rare-rotational-dns
- → http-fingerprint-gating
join: → triage-offerloader

## rare-rotational-dns
<!-- Rare Rotational C2 DNS Resolutions -->
Find low-prevalence DNS lookups to the campaign's preferred TLDs (.cfd, .space, .info).

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Domains like 'bubbleslip.cfd' appearing on very few hosts. This highlights
  the rotational 'compound word' domain pattern.
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
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (query_hostname LIKE '%.cfd' OR query_hostname LIKE '%.space' OR query_hostname LIKE '%.info' OR query_hostname LIKE '%.xyz') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## http-fingerprint-gating
<!-- HTTP Fingerprint Gating (click_id) -->
Search for the 'click_id' parameter in HTTP requests, confirming the PPI gating mechanism.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, lure_domains=lure_domains, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests featuring the click_id parameter to rotational or lure domains.
  This is evidence of the environment fingerprinting described in the research.
reads:
- device_hostname
- url_hostname
- url_query
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_query, user_agent, time FROM hb_http_activity WHERE (url_query LIKE '%click_id=%' OR url_path LIKE '%click_id=%') AND (instr(',' || '{{lure_domains}}' || ',', ',' || url_hostname || ',') > 0 OR url_hostname LIKE '%.cfd' OR url_hostname LIKE '%.space') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-offerloader
<!-- Triage OfferLoader Infection Chain -->
```agent target=hunter
cite: required
context:
- detect-inno-setup-temp-execution
- rare-rotational-dns
- http-fingerprint-gating
max_iterations: 4
objective: Identify hosts where a suspicious installer (e.g. WinDirStat) executed
  a .tmp binary and subsequently communicated with the PPI gating infrastructure (click_id
  or rotational domains).
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  process and network rows.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host and links process execution to network gating" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review-results
unavailable: → analyst-review-results (blind_spot: limited-http-visibility)
else: → analyst-review-results

## isolate-infected-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR. Collect any .tmp binaries from the user's Local AppData Temp directory and the parent installer executable for forensic analysis.
```
→ analyst-review-results

## analyst-review-results
<!-- Analyst Review of Findings -->
```manual target=analyst
Review the agent's findings. Confirm if the .tmp execution matches OfferLoader patterns. If confirmed, initiate follow-up hunts for Insomnia RAT, ARKTunnel, or Docro Hijacker.
```
→ end
