---
analysis: 'A simple detection rule for the initial curl command is easily bypassed
  by rotating domains. This hunt looks for the durable outcomes: the Mach-O RAT in
  the home directory, the LaunchAgent naming convention, and the behavioral indicators
  of screen capture tools.'
blind_spots:
- id: limited-macos-file-visibility
  question: Can we see modifications to files inside protected application bundles
    or system folders?
  requires: Endpoint agent with full disk access (FDA)
  risk: If the EDR agent lacks FDA, it may not report modifications to the internal
    files of trojanized wallet apps.
  stage: crypto-wallet-trojanization
- id: tls-obfuscation-blindspot
  question: Are we able to see the content of the WebSocket connection to the C2?
  requires: Network traffic decryption / WebSocket inspection
  risk: The RAT uses an embedded OpenSSL stack to bypass system trust, making its
    C2 traffic opaque to simple packet filters.
  stage: persistence-macho-rat
coverage:
- stage: persistence-macho-rat
  status: covered
  steps:
  - persistence-indicators
  - rare-launchagents
  - rat-c2-connections
- stage: screen-capture-helper
  status: covered
  steps:
  - screen-capture-helper
- stage: crypto-wallet-trojanization
  status: covered
  steps:
  - wallet-app-tampering
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: initial-access-execution-curl
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: background-loader-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: credential-theft-applescript
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Infostealers like MacSync target highly sensitive credentials and
    crypto keys that can lead to immediate financial loss. Finding the persistent
    RAT and the specialized capture helpers is critical to ensuring the threat is
    fully removed.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term persistence on a macOS host using
  a Mach-O RAT and LaunchAgents, potentially while tampering with cryptocurrency wallet
  applications or using signed capture helpers.
labels:
- hunt
- attack.t1543.001
- attack.t1546.004
- attack.t1071.001
- attack.t1113
- attack.t1548
- attack.t1554
name: MacSync RAT Persistence and Wallet Tampering
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rat_c2_ips:
    default:
    - 85.206.161.241
    description: Known C2 IP addresses for the MacSync RAT.
    from:
      kind: article
      observed: '2026-08-17'
      ref: huntress-macsync-blog
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt.
    type: list[host]
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
rationale: Focus on developer machines and personal workstations where users are likely
  to install AI development tools like Claude Code.
references:
- name: "Huntress \u2014 MacSync Stealer: How a Google Search for Claude Led to a\
    \ macOS Infostealer"
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macos-tcc-bypass-indicators
  reason: General hunt for TCC bypass attempts using osascript or signed binaries.
  relation: sibling
- hunt: macsync-stealer-in-memory-lure
  relation: follows
scenario:
  stages:
  - name: Malvertising and User Execution
    observables:
    - Google Ads sponsored search results
    - claude.ai shared conversation
    - curl one-liner in Terminal
    - zsh loader wrapper
    slug: initial-access-execution-curl
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.001
  - name: In-Memory Background Loader
    observables:
    - daemon_function script content
    - gzip compressed Base64 heredoc
    - Creation of /tmp/osalogging.zip
    - Cleanup of staging files
    slug: background-loader-exfiltration
    tactic: execution
    techniques:
    - T1059.004
    - T1027
  - name: AppleScript Credential Theft
    observables:
    - osascript execution from memory
    - TCC prompt for Full Disk Access
    - Extraction of Chromium Safe Storage keys
    - Login keychain password phishing
    - Writing credentials to .mpwd
    slug: credential-theft-applescript
    tactic: credential-access
    techniques:
    - T1555.001
    - T1555.003
    - T1548.003
  - name: RAT Installation and Persistence
    observables:
    - Mach-O binary in User Home folder
    - LaunchAgent plist creation in ~/Library/LaunchAgents/
    - Modification of .zshrc
    - WebSocket TLS connection to 85.206.161.241:8443
    - Single-byte XOR 0xAA obfuscated fallback domain
    slug: persistence-macho-rat
    tactic: persistence
    techniques:
    - T1543.001
    - T1546.004
    - T1071.001
  - name: Screen Recording Permission Acquisition
    observables:
    - Signed capture agent helper
    - TCC prompt for Screen Recording
    - Helper running with --tcc-only or -o flags
    - Screenshot images saved to disk for RAT upload
    slug: screen-capture-helper
    tactic: collection
    techniques:
    - T1113
    - T1548
  - name: Application Trojanization
    observables:
    - Rewriting/replacing files in wallet browser extensions
    - Tampering with Ledger Wallet companion apps
    - Tampering with desktop wallet apps
    - Fake recovery phrase phishing screens
    slug: crypto-wallet-trojanization
    tactic: impact
    techniques:
    - T1554
  summary: Users are directed via Google malvertising to a legitimate-appearing Claude
    AI conversation that tricks them into running a malicious curl command. This initiates
    a multi-stage macOS infection that uses memory-resident AppleScript to steal keychain
    and browser credentials, establishes persistence via LaunchAgents, and installs
    a Mach-O RAT capable of screen capture and trojanizing cryptocurrency wallet applications.
series:
  index: 2
  slug: macsync-stealer-how-a-google-search-for-claude-led-to-a-macos-infostealer
  title: 'MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer'
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


# MacSync RAT Persistence and Wallet Tampering

This hunt focuses on the post-infection stages of the MacSync Stealer (also known as ClickFix) campaign. We look for the installation of the Mach-O RAT into the user's home folder, the creation of LaunchAgents, modifications to shell configuration files, and the presence of screen-capture agents using specialized flags like --tcc-only. Additionally, we examine file activity within common cryptocurrency wallet paths to detect unauthorized rewriting or trojanization of sensitive applications.

## macos-host-scoping
<!-- Scope macOS Assets -->
Identify active macOS devices in the estate that could be targeted by this specific infostealer.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of macOS hostnames. Silence means no macOS devices were recently
  active.
reads:
- hostname
- device_uid
- os_version
- time
- platform
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT hostname AS device_hostname, device_uid, os_version FROM hb_devices WHERE platform = 'darwin' AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-indicators
<!-- Modifications to Shell Config and Credential Files -->
Find early indicators of RAT installation, such as .zshrc persistence or the local credential store .mpwd used by MacSync.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File writes to .zshrc or the appearance of .mpwd / osalogging.zip. These
  are highly suspicious on developer or end-user macOS machines.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%/.zshrc' OR LOWER(file_path) LIKE '%/.mpwd' OR LOWER(file_path) LIKE '%/osalogging.zip') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate RAT Activity -->
parallel:
- → rare-launchagents
- → screen-capture-helper
- → rat-c2-connections
- → wallet-app-tampering
join: → triage-agent

## rare-launchagents
<!-- Rare LaunchAgent Persistence -->
Identify suspicious persistence via LaunchAgents in user directories, stack-counting to find rare entries.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare LaunchAgent plists. Adversaries often mimic updater names, so unique
  or rare cmd_lines are the pivot.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_cmd_line
  rare_below: 3
reads:
- job_name
- job_definition_path
- job_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT job_name, job_definition_path, job_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_scheduled_job WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(job_definition_path) LIKE '%/library/launchagents/%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name, job_definition_path, job_cmd_line HAVING host_count <= 3
```

## screen-capture-helper
<!-- Detection of Screen Capture Helper Flags -->
Find processes using the specific TCC-bypass flags (--tcc-only, -o) identified in the MacSync capture agent.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Unusual binaries executing with --tcc-only. This is a highly specific indicator
  for this malware family.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (process_cmd_line LIKE '%--tcc-only%' OR (process_cmd_line LIKE '% -o %' AND LOWER(process_name) NOT LIKE '%compiler%' AND LOWER(process_name) NOT LIKE '%git%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rat-c2-connections
<!-- C2 WebSocket Traffic -->
Correlate host activity with known MacSync C2 infrastructure.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, rat_c2_ips=rat_c2_ips, lookback_days=lookback_days)
~~~yaml
expected: A connection to 85.206.161.241, especially on port 8443. This confirms active
  command and control.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{rat_c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 8443) AND time >= datetime('now', '-{{lookback_days}} days')
```

## wallet-app-tampering
<!-- Tampering with Crypto Wallet Applications -->
Detect the final stage where the malware rewrites browser extensions or hardware wallet companion apps.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File modifications to crypto wallet paths, especially if initiated by a
  rare process.
reads:
- device_hostname
- file_path
- activity_name
- process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, file_path, activity_name, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%ledger%' OR LOWER(file_path) LIKE '%phantom%' OR LOWER(file_path) LIKE '%metamask%' OR LOWER(file_path) LIKE '%ethereum%') AND (activity_id IN (1, 3, 5)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze Infostealer Killchain -->
```agent target=hunter
cite: required
context:
- persistence-indicators
- rare-launchagents
- screen-capture-helper
- rat-c2-connections
- wallet-app-tampering
max_iterations: 6
objective: Review the file activity (especially .mpwd and .zshrc), the rare LaunchAgents,
  the screen capture flags, and the C2 connection to confirm a MacSync Stealer infection.
success_criteria: A verdict of malicious | suspicious | benign per host with citations.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route Based on Triage -->
if~: "the triage verdict is malicious for at least one host, indicating a persistent RAT or wallet tampering." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-macos-file-visibility)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any active browser sessions, and reset all stored passwords. Advise the user to move crypto assets if their wallet app was tampered with.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Artifact Recovery -->
```manual target=analyst
Review the triage agent results. Manually verify the presence of the Mach-O binary in the user home folder. Document the specific wallet apps targeted.
```
→ end

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Summarize the hosts scanned. If no indicators of persistence were found, record this as evidence of absence for the MacSync RAT.
```
→ end
