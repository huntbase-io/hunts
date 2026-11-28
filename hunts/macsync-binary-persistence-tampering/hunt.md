---
analysis: The MacSync RAT uses polymorphic loaders and mimics legitimate software
  updaters for persistence. This hunt is required because a single signature-based
  rule cannot correlate the existence of a rare LaunchAgent with specific WebSocket
  C2 over TLS and the unique TCC-bypass flags used by the capture helper, especially
  when the malware name rotates per victim.
blind_spots:
- id: endpoint-telemetry-gap
  question: Are there unmanaged macOS devices in the estate that can run the RAT?
  requires: an endpoint agent on every macOS host
  risk: A host without an agent contributes no scheduled job or process rows, leaving
    persistence unobserved.
  stage: persistent-macho-rat
- id: tcc-log-visibility
  question: Did the user accept the TCC prompt for screen recording?
  requires: Unified Log Facility access to com.apple.tcc logs
  risk: The hunt sees the request for permission via process flags but cannot confirm
    if the permission was granted without TCC-specific logs.
  stage: screen-capture-helper
- id: websocket-inspection
  question: What commands were sent over the TLS-encrypted WebSocket channel?
  requires: TLS inspection of WebSocket traffic
  risk: The hunt sees the connection but remains blind to the content of the commands
    or the volume of data exfiltrated.
  stage: persistent-macho-rat
coverage:
- stage: persistent-macho-rat
  status: covered
  steps:
  - rare-launchagents
  - c2-network-activity
  - file-activity-check
- stage: screen-capture-helper
  status: covered
  steps:
  - tcc-bypass-behavior
- stage: wallet-app-trojanization
  status: covered
  steps:
  - wallet-process-check
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: initial-access-clickfix-lure
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: background-zsh-loader
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: dynamic-applescript-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MacSync is a modular macOS infostealer that targets high-value cloud
    and crypto assets; a negative result over the fleet provides assurance against
    an active campaign that bypasses traditional signature-based controls.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term persistence on a macOS host by
  installing a Mach-O RAT via a custom LaunchAgent and is using specialized capture
  agents to bypass TCC permissions and phish for crypto wallet recovery phrases.
labels:
- hunt
- attack.t1543.001
- attack.t1071.001
- attack.t1573.002
- attack.t1113
- attack.t1548.004
- attack.t1539
- attack.t1552
- attack.t1491
name: MacSync Binary Persistence and Application Tampering
parameters:
  c2_ips:
    default:
    - 85.206.161.241
    description: Known MacSync RAT C2 IP addresses.
    from:
      kind: article
      observed: '2026-08-17'
      ref: fake-claude-macsync
    type: list[ip]
  c2_port:
    default: '8443'
    description: The WebSocket port used by the RAT.
    from:
      kind: article
      observed: '2026-08-17'
      ref: fake-claude-macsync
    type: number
  lead_hosts:
    default: []
    description: Hostnames identified in the first step as having rare LaunchAgents;
      paste them here to filter the fan-out.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: analyst-defined
    type: list[host]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Initial hostnames to scope the hunt; leave empty for fleet-wide search.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: analyst-defined
    type: list[host]
  wallet_keywords:
    default:
    - ledger
    - metamask
    - phantom
    - coinbase
    - exodus
    - trustwallet
    - binance
    - keplr
    - solflare
    description: Keywords for common crypto wallets to check for trojanization.
    from:
      kind: article
      observed: '2026-08-17'
      ref: fake-claude-macsync
    type: list[string]
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
rationale: Scope the hunt to macOS systems. Prioritize hosts belonging to developers
  or users with crypto-wallet software installed. Ensure network telemetry covers
  the lookback window to catch ephemeral C2 connections.
references:
- name: "Huntress \u2014 MacSync Stealer: How a Google Search for Claude Led to a\
    \ macOS Infostealer"
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macsync-initial-access-clickfix
  reason: The initial malvertising lure, curl loader, and AppleScript stealer are
    covered in the companion initial-access hunt.
  relation: out-of-scope-alternative
- hunt: macsync-scripted-execution-credential-theft
  relation: follows
scenario:
  stages:
  - name: ClickFix Malvertising Lure
    observables:
    - curl -sL [URL] | zsh
    - claude.ai/share/
    - Google Ads sponsored search for 'Claude Code'
    - Display name 'Apple Support'
    slug: initial-access-clickfix-lure
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.002
    - T1059.004
  - name: Background ZSH Loader
    observables:
    - daemon_function
    - Base64 encoded gzip heredoc
    - /tmp/osalogging.zip
    slug: background-zsh-loader
    tactic: execution
    techniques:
    - T1027
    - T1140
    - T1059.004
  - name: Dynamic AppleScript Stealer
    observables:
    - osascript in-memory execution
    - Chromium Safe Storage AES key extraction
    - TCC prompt for Full Disk Access
    - User password phishing prompt
    - Extraction of login keychain secrets
    slug: dynamic-applescript-theft
    tactic: credential-access
    techniques:
    - T1059.002
    - T1555.001
    - T1548.004
  - name: Mach-O RAT and Persistence
    observables:
    - 85.206.161.241:8443
    - WebSocket over TLS
    - LaunchAgent plist creation in Home folder
    - .mpwd credential file
    - .zshrc modification
    slug: persistent-macho-rat
    tactic: persistence
    techniques:
    - T1543.001
    - T1071.001
    - T1573.002
  - name: Screen Recording Permission Capture
    observables:
    - Capture agent binary with blank icon
    - --tcc-only command line flag
    - -o [path] screenshot output
    - TCC Screen Recording prompt
    slug: screen-capture-helper
    tactic: collection
    techniques:
    - T1113
    - T1548.004
  - name: Crypto Wallet Trojanization
    observables:
    - Modification of 60+ wallet extensions
    - Trojanized Ledger Wallet app
    - Fake recovery phrase phishing HTML
    - Targeting of 21 desktop wallet apps
    slug: wallet-app-trojanization
    tactic: impact
    techniques:
    - T1539
    - T1552
    - T1491
  summary: A malvertising campaign for 'Claude Code' lures users to a legitimate shared
    conversation on claude.ai that instructs them to run a curl one-liner. This executes
    a multi-stage infection chain involving a background zsh loader, a dynamic AppleScript
    stealer that harvests credentials and keychain data, and a persistent Mach-O RAT.
    The attack concludes by gaining screen recording permissions and trojanizing crypto
    wallet applications to phish for recovery phrases.
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


# MacSync Binary Persistence and Application Tampering

This hunt identifies the post-infection binary stages of the MacSync Stealer. It targets the Mach-O RAT's persistence mechanism in the user's LaunchAgents directory, its WebSocket-based C2 channel, and the behavior of its specialized screen-capture helper. The hunt also examines the execution of common crypto-wallet applications to identify potential trojanization or theft activity. By correlating rare persistence entries with specific TCC-bypass command-line flags and known C2 network patterns, we identify compromised macOS systems that standard signature-based rules miss due to the polymorphic nature of the initial infection loaders. The triage phase links these behaviors with specific exfiltration artifacts like the hidden .mpwd credential store.

## rare-launchagents
<!-- Rare LaunchAgent Persistence -->
Identify newly created or modified LaunchAgents in user directories that are rare across the fleet, excluding standard system paths.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rows identify LaunchAgents seen on very few hosts. Legitimate updaters will
  have high counts, while the MacSync RAT mimics these names on single systems within
  the user's library folder.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_path
  rare_below: 3
reads:
- job_name
- job_path
- job_cmd_line
- device_hostname
- job_kind
- job_definition_path
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT job_name, job_path, job_cmd_line, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_scheduled_job WHERE job_kind = 'launchd' AND LOWER(job_definition_path) NOT LIKE '/system/library/launchagents/%' AND LOWER(job_definition_path) LIKE '%/library/launchagents/%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name, job_path, job_cmd_line, device_hostname HAVING host_count < 3
```

## corroborate-behavior
<!-- Corroborate Post-Infection Behavior -->
parallel:
- → c2-network-activity
- → tcc-bypass-behavior
- → file-activity-check
- → wallet-process-check
join: → macsync-triage

## c2-network-activity
<!-- C2 Network Activity -->
Detect network connections to the MacSync RAT infrastructure over the designated WebSocket port on the suspected hosts.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, c2_port=c2_port, lookback_days=lookback_days, lead_hosts=lead_hosts)
~~~yaml
expected: Any connection to the designated IP and port indicates active command and
  control by a MacSync RAT.
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
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND dst_endpoint_port = {{c2_port}} AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## tcc-bypass-behavior
<!-- TCC Bypass Behavior -->
Find processes executing with specific command-line flags used to automate screen capture, filtering for suspicious flag combinations.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, lead_hosts=lead_hosts)
~~~yaml
expected: Process events using specific flags described in the kill chain where -o
  is accompanied by --tcc-only. Legitimate applications rarely combine these flags.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(LOWER(process_cmd_line), '--tcc-only') > 0 AND instr(LOWER(process_cmd_line), ' -o ') > 0) AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-activity-check
<!-- MacSync Exfiltration Artifacts -->
Identify specific hidden credential files and staging archives created by the RAT during theft.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, lead_hosts=lead_hosts)
~~~yaml
expected: Creation or modification of the hidden .mpwd file or the osalogging.zip
  archive. These are strong indicators of exfiltration intent.
reads:
- device_hostname
- file_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_name) = '.mpwd' OR LOWER(file_name) = 'osalogging.zip') AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## wallet-process-check
<!-- Wallet Application Activity -->
Identify activity related to targeted crypto-wallet applications that may be trojanized.

```sqlite target=endpoint role=enrichment params=(wallet_keywords=wallet_keywords, lookback_days=lookback_days, lead_hosts=lead_hosts)
~~~yaml
expected: Execution of wallet applications. When correlated with rare LaunchAgents
  and TCC bypass, this confirms the final stage of the MacSync kill chain.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{wallet_keywords}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{wallet_keywords}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## macsync-triage
<!-- MacSync Triage Agent -->
```agent target=hunter
cite: required
context:
- rare-launchagents
- c2-network-activity
- tcc-bypass-behavior
- file-activity-check
- wallet-process-check
max_iterations: 5
objective: Determine whether a host shows the behavioral pattern of MacSync post-infection
  activity. Look specifically for the existence of the .mpwd file and the osalogging.zip
  staging artifact alongside rare LaunchAgents and TCC-bypass flags to confirm exfiltration
  intent.
success_criteria: A detailed verdict of malicious | suspicious | benign citing row
  evidence for each host deemed suspicious.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host based on the link between a rare LaunchAgent, WebSocket C2 connectivity, and confirmed exfiltration artifacts like .mpwd or osalogging.zip" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: endpoint-telemetry-gap)
else: → close-out-report

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR to stop active WebSocket C2 and file exfiltration. Do not reboot to preserve memory-resident artifacts.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Check for the existence of /tmp/osalogging.zip and the hidden .mpwd file in the user's home folder. Verify the contents of the identified LaunchAgent plist. If wallet applications were executed, initiate rotation of all crypto seeds and credentials.
```
→ close-out-report

## close-out-report
<!-- Close-out Report -->
```manual target=analyst
Record the hunt outcome. If false positives were found on legitimate internal updaters, add their LaunchAgent paths to the exclusion list for the standing detection rule.
```
→ end
