---
analysis: 'A standard detection rule might flag the /tmp/osalogging.zip IOC, but this
  hunt provides the broader context: it correlates the rare archive with specific
  wallet path tampering and network exfil. By combining three surfaces (file, network,
  device inventory) and using prevalence to find variations, we confirm impact rather
  than just alerting on a static string.'
blind_spots:
- id: no-macos-file-visibility
  owner: security_operations
  question: whether wallet application binaries were modified or replaced on disk
  remediation: Enable and verify osquery file_events or similar ESF-compatible logging
    on the macOS fleet.
  requires: Endpoint Security Framework (ESF) file logging
  risk: Without ESF-based file activity, we cannot see the stealthy replacement of
    app bundle files, only secondary signals like exfiltration traffic.
  stage: impact-wallet-trojanization
- id: randomized-staging-paths
  owner: detection_engineering
  question: whether the attacker used a randomized path instead of /tmp/osalogging.zip
  remediation: Implement a standing rule for any new ZIP or TAR archives created in
    /tmp by shell or AppleScript interpreters.
  requires: prevalence-based file baseline
  risk: If the filename is host-specific, the lead detection query will miss it, placing
    total reliance on the prevalence-based query.
  stage: impact-wallet-trojanization
coverage:
- stage: impact-wallet-trojanization
  status: covered
  steps:
  - detect-staging-archive
  - rare-tmp-archives
  - wallet-app-modifications
  - c2-network-activity
- reason: Handled in a prior hunt focusing on malvertising and initial browser redirects.
  stage: initial-access-clickfix-lure
  status: out_of_scope
- reason: Handled in a prior hunt focusing on LaunchAgent and plist creation.
  stage: persistence-macho-rat
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: execution-zsh-in-memory
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: credential-access-applescript-stealer
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: collection-screen-recording-helper
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Cryptocurrency theft via trojanized applications is permanent and
    has severe financial impact. Detecting the staging of stolen data and the tampering
    of trusted wallet applications is a critical control for protecting organizational
    and personal assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has trojanized local cryptocurrency wallet applications on
  macOS hosts to phish for recovery phrases and is staging stolen data in an archive
  at /tmp/osalogging.zip.
labels:
- hunt
- attack.t1560.001
- attack.t1491
- attack.t1041
name: MacSync Wallet Trojanization and Exfiltration
parameters:
  c2_ips:
    default:
    - 85.206.161.241
    description: Known C2 IPs for MacSync exfiltration.
    from:
      kind: article
      observed: '2026-08-17'
      ref: huntress-macsync
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-01'
      ref: retention-standard
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-claude-macsync
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on macOS workstations, particularly those assigned to users in engineering,
  finance, or executive roles likely to manage digital assets or use advanced developer
  tools like Claude Code.
references:
- name: 'MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer'
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macos-tcc-permission-abuse
  reason: The abuse of TCC permissions for screen recording is a distinct behavior
    handled in a sibling hunt focusing on the RAT's capabilities.
  relation: out-of-scope-alternative
- hunt: macsync-rat-persistence-tcc-helper
  relation: follows
scenario:
  stages:
  - name: ClickFix Malvertising Lure
    observables:
    - claude.ai
    - sponsored Google Search results
    - curl one-liner command in Terminal
    slug: initial-access-clickfix-lure
    tactic: initial-access
    techniques:
    - T1583.008
    - T1204.002
  - name: Polymorphic ZSH Loader
    observables:
    - zsh daemon_function
    - gzip-compressed base64-encoded heredoc
    - zsh loader wrapper
    slug: execution-zsh-in-memory
    tactic: execution
    techniques:
    - T1059.004
  - name: In-Memory AppleScript Stealer
    observables:
    - osascript in system memory
    - TCC Full Disk Access permission prompt
    - Chromium Safe Storage AES key extraction
    - login.keychain access
    slug: credential-access-applescript-stealer
    tactic: credential-access
    techniques:
    - T1059.002
    - T1555.003
    - T1056.003
  - name: Mach-O RAT Persistence
    observables:
    - 85.206.161.241:8443
    - ~/Library/LaunchAgents plist creation
    - .mpwd file in user home directory
    - WebSocket over TLS traffic
    slug: persistence-macho-rat
    tactic: persistence
    techniques:
    - T1543.001
    - T1071.001
  - name: TCC Screen Capture Agent
    observables:
    - separate signed helper binary
    - --tcc-only command flag
    - -o screenshot path flag
    - screen recording TCC prompt
    slug: collection-screen-recording-helper
    tactic: collection
    techniques:
    - T1113
  - name: Crypto Wallet Phishing and Exfiltration
    observables:
    - /tmp/osalogging.zip
    - modified Ledger Wallet application
    - spoofed recovery phrase phishing pages
    - 60 targeted wallet browser extensions
    slug: impact-wallet-trojanization
    tactic: impact
    techniques:
    - T1560.001
    - T1491
  summary: MacSync is a macOS infostealer distributed via 'ClickFix' malvertising
    where users are tricked into executing a curl command on a fake Claude AI support
    page. The intrusion utilizes a multi-stage kill chain involving polymorphic ZSH
    loaders and in-memory AppleScript to steal credentials, browser data, and crypto
    wallet recovery phrases while maintaining persistence through a Mach-O RAT.
series:
  index: 3
  slug: macsync-stealer-how-a-google-search-for-claude-led-to-a-macos-infostealer
  title: 'MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer'
  total: 3
severity: critical
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


# MacSync Wallet Trojanization and Exfiltration

This hunt focuses on the final impact stage of the MacSync Stealer kill chain: the modification of legitimate cryptocurrency wallet applications and the staging of stolen data for exfiltration. Adversaries replace application files with malicious equivalents that present fake recovery-phrase entry forms, a high-impact action as recovery phrases cannot be revoked or rotated like passwords. We look for the hardcoded staging path /tmp/osalogging.zip, use prevalence to find other rare archives in /tmp, and identify anomalous file writes to crypto wallet application paths and connections to known exfiltration infrastructure.

## scope-macos-endpoints
<!-- Identify macOS Endpoints -->
Narrows the hunt to the macOS fleet where MacSync is designed to execute.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of macOS hosts currently enrolled. Zero results mean no macOS devices
  are being monitored.
reads:
- hostname
- os_version
- last_seen
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT hostname, os_version, last_seen FROM hb_devices WHERE platform = 'darwin' AND activity_id = 2
```

## detect-staging-archive
<!-- Detect Hardcoded Staging Archive -->
Finds the specific file path used by MacSync to stage stolen data for exfiltration.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Any creation or modification of /tmp/osalogging.zip is highly suspicious.
  Silence proves this specific IOC name was not used.
reads:
- device_hostname
- file_path
- process_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) = '/tmp/osalogging.zip' AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-theft
<!-- Corroborate Theft and Exfiltration -->
parallel:
- → rare-tmp-archives
- → wallet-app-modifications
- → c2-network-activity
join: → triage-impact

## rare-tmp-archives
<!-- Rare Zip Archives in /tmp -->
Identifies non-standard exfiltration staging if the attacker randomized the zip file name.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Archives appearing on only one or two hosts in the /tmp directory; excludes
  fleet-wide standard temporary files.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 2
reads:
- file_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT file_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE file_path LIKE '/tmp/%.zip' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name HAVING host_count <= 2
```

## wallet-app-modifications
<!-- Wallet Application Modifications -->
Detects the trojanization phase where legitimate wallet app bundle files are modified or replaced.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: File writes or modifications to directories associated with hardware or
  software crypto wallets.
reads:
- device_hostname
- file_path
- process_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/ledger%' OR LOWER(file_path) LIKE '%/exodus%' OR LOWER(file_path) LIKE '%/phantom%' OR LOWER(file_path) LIKE '%/metamask%' OR LOWER(file_path) LIKE '%/electrum%') AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-activity
<!-- Exfiltration Network Connections -->
Confirms if hosts with suspicious file activity are also communicating with the known exfiltration infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Network activity to the report's C2 IP. Absence does not prove zero risk
  if the IP has rotated.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-impact
<!-- Triage Theft and Exfiltration -->
```agent target=hunter
cite: required
context:
- detect-staging-archive
- rare-tmp-archives
- wallet-app-modifications
- c2-network-activity
max_iterations: 4
objective: Identify hosts with confirmed wallet tampering and evidence of data staging
  for exfiltration.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  zip path and the wallet application involved.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-macos-file-visibility)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Advise the user to move all funds from any local crypto wallets or browser extensions to new addresses generated on a clean device.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Examine the /tmp/ folder and the application bundles of the affected wallets. Collect any modified binaries for reverse engineering to identify exfiltration endpoints or unique victim tokens.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the hunt results. If false positives were found (e.g., legitimate wallet software updates), record the signing certificates or process paths for tuning.
```
→ end
