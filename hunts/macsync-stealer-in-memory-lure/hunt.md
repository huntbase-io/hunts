---
analysis: A standard detection rule might alert on 'curl | sh', but this hunt uses
  behavioral baselining for AppleScript UI patterns and corroborates against multiple
  surfaces to identify the polymorphic 'background loader' phase which is designed
  to remain silent.
blind_spots:
- id: macos-process-telemetry-gap
  owner: Endpoint Security Team
  question: Was the curl command executed directly from a terminal or through a subshell
    of a browser process?
  remediation: Enable high-verbosity process auditing for macOS via the Endpoint Security
    Framework.
  requires: hb_process_activity with high fidelity macOS audit logs
  risk: If process auditing is not capturing the full command line of ephemeral shell
    sub-processes, the polymorphic loader may be missed.
  stage: initial-access-execution-curl
- id: memory-only-osascript-capture
  owner: Detection Engineering
  question: What were the specific AppleScript commands executed in memory?
  remediation: Deploy endpoint monitoring that supports osascript script block extraction.
  requires: hb_script_activity for osascript
  risk: Without script block logging for osascript, we depend on command-line patterns
    which can be truncated or obfuscated.
  stage: credential-theft-applescript
coverage:
- stage: initial-access-execution-curl
  status: covered
  steps:
  - curl-to-shell-loader
- stage: background-loader-exfiltration
  status: covered
  steps:
  - suspicious-exfil-files
  - c2-network-connections
- stage: credential-theft-applescript
  status: covered
  steps:
  - rare-osascript-dialogs
  - osascript-tcc-patterns
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: persistence-macho-rat
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: screen-capture-helper
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: crypto-wallet-trojanization
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MacSync Stealer utilizes highly effective malvertising lures and
    in-memory execution to steal session cookies and keychain data. A negative result
    confirms the effectiveness of current endpoint controls on macOS.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using malvertising lures directing users to a legitimate
  AI domain to execute a polymorphic zsh loader that delivers an in-memory AppleScript
  for credential theft.
labels:
- hunt
- attack.t1566.002
- attack.t1204.001
- attack.t1059.004
- attack.t1027
- attack.t1555.001
- attack.t1555.003
- attack.t1548.003
name: MacSync Stealer In-Memory Lure and Credential Access
parameters:
  c2_ips:
    default:
    - 85.206.161.241
    description: Known C2 infrastructure for MacSync.
    from:
      kind: article
      observed: '2026-08-17'
      ref: https://www.huntress.com/blog/fake-claude-macsync
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: default
    type: number
  lure_domains:
    default:
    - claude.ai
    - osalogging.zip
    description: Legitimate or spoofed domains used in the malvertising curl lure.
    from:
      kind: article
      observed: '2026-08-17'
      ref: https://www.huntress.com/blog/fake-claude-macsync
    type: list[domain]
  scope_hosts:
    default: []
    description: Target macOS hosts discovered in the scoping step.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: default
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on macOS endpoints across all departments, especially those using
  AI productivity tools.
references:
- name: "Huntress \u2014 MacSync Stealer: How a Google Search for Claude Led to a\
    \ macOS Infostealer"
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macsync-persistence-and-rat
  reason: This hunt focuses on the initial execution and credential theft; the subsequent
    RAT and screen capture helper are covered in the follow-on hunt.
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
  index: 1
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


# MacSync Stealer In-Memory Lure and Credential Access

This hunt targets the initial access and credential theft phases of the MacSync infostealer. MacSync uses a 'ClickFix' tactic, leveraging shared conversation pages on legitimate AI domains to trick users into executing a curl command. This command delivers a polymorphic zsh loader that executes further stages (AppleScript) entirely in memory to evade detection. The hunt identifies the initial lure execution by looking for curl-to-shell patterns on macOS, stack-counts rare AppleScript UI patterns that phish for passwords or TCC permissions, and corroborates activity across file and network surfaces.

## scope-macos-devices
<!-- Scope macOS Devices -->
Identify all macOS devices in the estate to narrow the behavioral search.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of macOS hosts. Silence means no macOS devices were active in the
  window.
reads:
- hostname
- last_seen
- os_version
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT hostname AS device_hostname, os_version, last_seen FROM hb_devices WHERE LOWER(platform) = 'darwin' AND time >= datetime('now', '-{{lookback_days}} days')
```

## curl-to-shell-loader
<!-- Robust Curl-to-Shell Pattern -->
Find 'ClickFix' lures where curl fetches a script and pipes it to a shell, accounting for whitespace, absolute paths, and lure domains.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lure_domains=lure_domains)
~~~yaml
expected: A process command line showing curl piping to a shell with a lure domain.
  Silence means no such patterns were observed.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl %' AND (LOWER(process_cmd_line) LIKE '%|%zsh%' OR LOWER(process_cmd_line) LIKE '%|%sh%' OR LOWER(process_cmd_line) LIKE '%|%bash%' OR LOWER(process_cmd_line) LIKE '%|%/bin/%')) AND (LOWER(process_cmd_line) LIKE '%claude.ai%' OR LOWER(process_cmd_line) LIKE '%osalogging.zip%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') -- filters on {{lure_domains}}
```

## rare-osascript-dialogs
<!-- Rare UI-Based AppleScript Patterns -->
Stack-count AppleScript UI interactions to find rare phishing or TCC permission requests, reducing noise from dynamic values by grouping on interaction type.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare UI script patterns. Phishing attempts will stand out from common system
  maintenance dialogs.
prevalence:
  by: device_hostname
  key:
  - script_pattern
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT CASE WHEN LOWER(process_cmd_line) LIKE '%display dialog%with title%' THEN 'Dialog with Title' WHEN LOWER(process_cmd_line) LIKE '%display alert%' THEN 'Alert Dialog' WHEN LOWER(process_cmd_line) LIKE '%request permissions%' THEN 'Permission Request' ELSE 'Other UI Script' END AS script_pattern, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS occurrences, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%osascript%' OR LOWER(process_path) LIKE '%osascript%') AND (LOWER(process_cmd_line) LIKE '%display dialog%' OR LOWER(process_cmd_line) LIKE '%display alert%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_pattern HAVING hosts <= 3
```

## corroborate-activity
<!-- Corroborate Stealer Activity -->
parallel:
- → osascript-tcc-patterns
- → suspicious-exfil-files
- → c2-network-connections
join: → triage-macsync

## osascript-tcc-patterns
<!-- AppleScript TCC and Credential Theft -->
Detect specific memory-only commands used by MacSync to request Full Disk Access and steal Safe Storage keys.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines accessing sensitive macOS subsystems via AppleScript.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%osascript%' OR LOWER(process_path) LIKE '%osascript%') AND (LOWER(process_cmd_line) LIKE '%safe storage%' OR LOWER(process_cmd_line) LIKE '%tcc%' OR LOWER(process_cmd_line) LIKE '%login keychain%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-exfil-files
<!-- Exfiltration Artifact Creation -->
Identify the creation of specific staging files like the ZIP archive or the local password store.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Files created by the background loader process for data staging.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/tmp/osalogging.zip' OR LOWER(file_name) = '.mpwd') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-connections
<!-- Network Connections to known C2 IP -->
Correlate behavioral activity with connections to reported MacSync infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to the C2 IP 85.206.161.241.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-macsync
<!-- Triage MacSync Progression -->
```agent target=hunter
cite: required
context:
- curl-to-shell-loader
- rare-osascript-dialogs
- osascript-tcc-patterns
- suspicious-exfil-files
- c2-network-connections
max_iterations: 6
objective: Determine if any macOS host shows the progression from a curl lure on a
  legitimate domain to AppleScript-based credential theft and file staging.
success_criteria: A verdict of 'malicious' for hosts showing at least two distinct
  stages of the MacSync kill chain.
tools:
- endpoint
- network
```

## decision-route
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: macos-process-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. MacSync phishes for admin/keychain credentials and exfiltrates Safe Storage keys; immediate containment is necessary to limit credential exposure.
```
→ analyst-review

## analyst-review
<!-- Credential Rotation and Remediation -->
```manual target=analyst
Confirm the presence of /tmp/osalogging.zip. Force rotation of all passwords entered by the user and invalidate all active browser sessions as Safe Storage keys were likely compromised. Collect the RAT binary from the home folder for further analysis.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the examined macOS hosts and the lack of MacSync indicators. Recommend a periodic re-run as polymorphic loaders evolve.
```
→ end
