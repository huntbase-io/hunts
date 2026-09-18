---
analysis: This hunt pivots from a generic loader to the specific behaviors of three
  unrelated malware families (Node.js/Python RATs, BMP steganography, and Chrome extension
  hijacking). A single rule would struggle to correlate these disparate activities
  into a single high-confidence alert.
blind_spots:
- id: incomplete-edr-coverage
  question: Are there unmanaged endpoints running the PPI loader that we cannot see?
  requires: Endpoint agent on all managed and unmanaged assets.
  risk: Infections on unmanaged devices contribute to persistent network access without
    behavioral visibility.
- id: steganography-payload-blindness
  question: Is the BMP file actually being used for payload extraction?
  requires: Process memory inspection or deep file inspection (DLP).
  risk: A simple file read event for a .bmp is low fidelity; without seeing the extraction
    routine, we rely on process-tree context.
  stage: tunneling-steganography-arktunnel
- id: macos-script-visibility
  question: Can we see the content of the scripts executed by Node/Python on macOS?
  requires: hb_script_activity for macOS interpreter engines.
  risk: Insomnia RAT uses a cross-platform Python agent; without script content, it
    is hard to distinguish malicious activity from legitimate local automation.
  stage: payload-execution-insomnia
coverage:
- stage: payload-execution-insomnia
  status: covered
  steps:
  - insomnia-behavior
- stage: tunneling-steganography-arktunnel
  status: covered
  steps:
  - arktunnel-behavior
  - c2-network-activity
- stage: browser-hijacking-docro
  status: covered
  steps:
  - docro-behavior
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: initial-access-seo-youtube
  status: out_of_scope
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: execution-trojanized-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''Untracked Nightmares: The Threats Hiding
    Behind Commodity Infrastructure'' series.'
  stage: loader-gating-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The CL-CRI-1171 cluster demonstrates how commodity loaders mask high-priority
    RATs (Insomnia, ARKTunnel) that typically go untracked. A negative result confirms
    that the fleet is free from these cross-platform persistence and hijacking threats.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using commodity pay-per-install (PPI) infrastructure to
  deploy cross-platform Node.js/Python RATs (Insomnia), steganography-based tunnelers
  (ARKTunnel), and browser hijackers (Docro) to enterprise endpoints.
labels:
- hunt
- attack.t1059.006
- attack.t1059.007
- attack.t1572
- attack.t1027.003
- attack.t1185
- attack.t1090.003
name: Cross-Platform RAT and Browser Hijacking (PPI Payloads)
parameters:
  c2_domains:
    default:
    - atthelake.info
    - noiseship.cfd
    - voyagemist.space
    description: Known C2 domains associated with the PPI infrastructure.
    from:
      kind: article
      observed: '2026-09-09'
      ref: unit42-ppi-campaign
    type: list[domain]
  chrome_safe_processes:
    default:
    - chrome.exe
    - setup.exe
    - googleupdate.exe
    - google_updater.exe
    description: Legitimate processes allowed to modify Chrome extension files.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: baseline-chrome-behavior
    type: list[string]
  loader_filenames:
    default:
    - windirstat.exe
    - windirstat.tmp
    - bluetooth driver for windows 10.exe
    description: Filenames of the initial trojanized installers.
    from:
      kind: article
      observed: '2026-09-09'
      ref: unit42-ppi-campaign
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Target hosts for the hunt; populated by the scoping step's findings.
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
    model: hb_google/gemini-3-flash-preview
rationale: Begin by scanning for the reported 'windirstat' and 'bluetooth driver'
  filenames. The behavioral steps use forward-slash path normalization to ensure visibility
  across Windows and macOS for cross-platform RATs.
references:
- name: "Unit 42 \u2014 Untracked Nightmares: The Threats Hiding Behind Commodity\
    \ Infrastructure"
  url: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
related:
- hunt: ppi-loader-initial-access-funnels
  reason: Initial access via SEO poisoning and YouTube gaming lures is covered by
    a sibling hunt focusing on web telemetry.
  relation: out-of-scope-alternative
- hunt: offerloader-trojanized-installer-gating
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Cross-Platform RAT and Browser Hijacking (PPI Payloads)

This hunt targets the second-stage payloads delivered by the CL-CRI-1171 campaign (OfferLoader). It specifically investigates the behavior of the Insomnia RAT (cross-platform Node.js and Python agents), ARKTunnel (which uses bitmap steganography for payload unpacking), and Docro (a Chrome backdoor). The hunt pivots from initial loader indicators to behavioral anomalies like interpreters running from user-writable paths, rare bitmap file access in temporary directories, and unauthorized modifications to browser extension stores. By correlating the loader's execution with these subsequent behaviors, we distinguish targeted RAT activity from generic commodity infections.

## loader-execution-scoping
<!-- Initial Loader Execution Scoping -->
Identify hosts that executed the initial trojanized installer to prioritize them in the behavioral analysis.

```sqlite target=endpoint role=scoping params=(loader_filenames=loader_filenames, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames that executed the PPI loader. Silence indicates the
  loader may be using different filenames than reported.
reads:
- device_hostname
- process_name
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (instr(',' || '{{loader_filenames}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{loader_filenames}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## concurrent-behavior-check
<!-- Concurrent Payload Behavior Check -->
parallel:
- → insomnia-behavior
- → arktunnel-behavior
- → docro-behavior
- → c2-network-activity
join: → triage-agent

## insomnia-behavior
<!-- Insomnia RAT: Interpreters in user-writable paths -->
Detect the Insomnia RAT's cross-platform agents (Node.js/Python) running from user-specific or temporary directories.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A Node.js or Python interpreter running from a user's directory. Benign
  signal includes legitimate local development or locally-installed apps.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_path, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) IN ('node.exe', 'node', 'python.exe', 'python', 'python3')) AND (LOWER(process_path) LIKE '%/appdata/%' OR LOWER(process_path) LIKE '%/users/%' OR LOWER(process_path) LIKE '%/tmp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## arktunnel-behavior
<!-- ARKTunnel: Rare BMP access in temporary paths -->
Find rare bitmap file activity that may indicate ARKTunnel unpacking its payload using steganography.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A process reading a .bmp file in a temporary path. Rare counts are highly
  suspicious for steganography extraction.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, COUNT(*) AS access_count, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_path) LIKE '%.bmp' AND (LOWER(file_path) LIKE '%/temp/%' OR LOWER(file_path) LIKE '%/appdata/%' OR LOWER(file_path) LIKE '%/tmp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path HAVING access_count < 5
```

## docro-behavior
<!-- Docro: Browser Extension Store Modification -->
Detect modifications to Chrome extension paths by processes other than the browser itself.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, chrome_safe_processes=chrome_safe_processes)
~~~yaml
expected: A non-browser process writing to the extension directory. Silence suggests
  the hijacker may be using a different persistence mechanism.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/google/chrome/%/extensions/%' OR LOWER(file_path) LIKE '%/application support/google/chrome/%/extensions/%') AND NOT (instr(',' || '{{chrome_safe_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-activity
<!-- PPI Cluster C2 and Redirector Activity -->
Match host network traffic against the reported rotational C2 domains.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Direct connection to a domain listed in the PPI cluster research.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, time FROM hb_network_connection WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage PPI Payload Evidence -->
```agent target=hunter
cite: required
context:
- loader-execution-scoping
- insomnia-behavior
- arktunnel-behavior
- docro-behavior
- c2-network-activity
max_iterations: 5
objective: Determine if the host is compromised by the CL-CRI-1171 campaign based
  on overlapping indicators from the scoping and behavioral steps.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  relevant rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-edr-coverage)
else: → close-out

## isolate-host
<!-- Isolate Host and Collect Artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect any .bmp files found in the identified temporary directories and export the identified Chrome extension manifest for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Final Analyst Review -->
```manual target=analyst
Review the relationship between the loader's execution and the subsequent RAT behavior. Confirm whether the Node.js/Python activity was triggered by the windirstat process.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
No malicious PPI payloads were confirmed. Log the results and close the hunt.
```
→ end
