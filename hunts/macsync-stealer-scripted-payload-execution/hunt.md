---
analysis: The loader is polymorphic and the payloads are server-side generated. A
  single detection rule on the curl command would create too much noise from legitimate
  devops tools, and a rule on the script hash would be bypassed by the attacker's
  per-victim encoding. The hunt uses stack-counting (prevalence) to isolate rare,
  suspect script blocks and corroborates them with specific network and process behaviors.
blind_spots:
- id: script-telemetry-gap
  question: Can the endpoint observer see the content of scripts piped directly into
    interpreters?
  requires: hb_script_activity with full stdin/pipe capture
  risk: If the EDR only logs the command line '| zsh' and not the content of the stdin
    stream, the 'daemon_function' will remain invisible.
  stage: execution-zsh-in-memory
- id: ephemeral-file-cleanup
  question: Can we detect the /tmp/osalogging.zip archive before it is deleted by
    the cleanup routine?
  requires: hb_file_activity with low-latency collection
  risk: MacSync aggressively deletes its staging files; if file events are not captured
    in real-time, the most conclusive piece of forensic evidence may be missed.
  stage: credential-access-applescript-stealer
coverage:
- stage: initial-access-clickfix-lure
  status: covered
  steps:
  - curl-to-shell-activity
  - network-to-payload-ip
- stage: execution-zsh-in-memory
  status: covered
  steps:
  - rare-daemon-scripts
- stage: credential-access-applescript-stealer
  status: covered
  steps:
  - rare-daemon-scripts
  - triage-agent
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: persistence-macho-rat
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: collection-screen-recording-helper
  status: out_of_scope
- reason: 'Belongs to another part of the ''MacSync Stealer: How a Google Search for
    Claude Led to a macOS Infostealer'' series.'
  stage: impact-wallet-trojanization
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MacSync Stealer targets high-value developer assets including SSH
    keys, cloud tokens, and crypto wallets. Because the delivery is polymorphic and
    uses in-memory AppleScript, a hunt that correlates behavioral shell activity with
    script prevalence is required to detect it where static rules fail.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using malvertising lures on legitimate domains to trick
  macOS users into executing curl-to-shell commands that deliver polymorphic, in-memory
  AppleScript stealers.
labels:
- hunt
- attack.t1583.008
- attack.t1204.002
- attack.t1059.004
- attack.t1059.002
- attack.t1555.003
- attack.t1056.003
name: 'MacSync Stealer: Scripted Payload Execution'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: standard-retention
    type: number
  payload_hosts:
    default:
    - 85.206.161.241
    description: IP addresses identified as payload delivery servers for MacSync.
    from:
      kind: article
      observed: '2026-08-17'
      ref: huntress-macsync-blog
    type: list[ip]
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
rationale: Limit to 'darwin' platform hosts. The initial delivery is user-driven via
  Terminal, typically appearing during working hours after searches for developer
  tools.
references:
- name: "Huntress \u2014 MacSync Stealer: How a Google Search for Claude Led to a\
    \ macOS Infostealer"
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macsync-persistence-and-rat-activity
  reason: This hunt focuses on the initial scripted execution; the follow-on Mach-O
    RAT and LaunchAgent persistence requires hb_scheduled_job and binary analysis.
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
  index: 1
  slug: macsync-stealer-how-a-google-search-for-claude-led-to-a-macos-infostealer
  title: 'MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer'
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
tlp: clear
type: investigation
---


# MacSync Stealer: Scripted Payload Execution

This hunt focuses on the initial delivery and execution phases of MacSync Stealer. It identifies macOS users who may have been targeted by 'ClickFix' malvertising campaigns (e.g., fake Claude Code download pages). The hunt looks for characteristic 'curl' one-liners piped directly to shell or AppleScript interpreters, the subsequent in-memory execution of ZSH 'daemon_function' scripts featuring base64-encoded heredocs, and the dynamic delivery of AppleScript (osascript) designed to extract browser secrets and TCC permissions. By pivoting between process command lines, script block telemetry, and network connections to known delivery infrastructure, the hunt identifies the 'brains' of the stealer even when the binary hashes vary.

## macos-host-inventory
<!-- Identify macOS fleet -->
Scope the hunt to macOS (Darwin) hosts where the MacSync payload is designed to execute.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of active macOS hostnames. Silence confirms no macOS devices are
  available for scoping.
reads:
- hostname
- device_uid
- os_version
- last_seen
- platform
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT hostname, device_uid, os_version, last_seen FROM hb_devices WHERE LOWER(platform) = 'darwin' AND lifecycle_state = 'running'
```

## curl-to-shell-activity
<!-- Search for curl-to-shell one-liners -->
Detect the initial 'ClickFix' delivery method where curl output is piped into an interpreter, including shell variants and AppleScript.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Process events showing curl output being executed immediately. This captures
  the malvertising lure phase.
reads:
- device_hostname
- user_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, user_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl%' AND (LOWER(process_cmd_line) LIKE '%|%zsh%' OR LOWER(process_cmd_line) LIKE '%|%bash%' OR LOWER(process_cmd_line) LIKE '%|%sh%' OR LOWER(process_cmd_line) LIKE '%|%osascript%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroboration-parallel
<!-- Corroborate on script and network surfaces -->
parallel:
- → rare-daemon-scripts
- → network-to-payload-ip
join: → triage-agent

## rare-daemon-scripts
<!-- Identify rare daemon scripts -->
Find the polymorphic loader by stack-counting script blocks that contain the specific MacSync 'daemon_function' or suspicious base64 heredocs.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Script blocks containing the 'daemon_function' string seen on very few hosts.
  Fleet-wide scripts are likely legitimate management tools.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 3
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT script_content, GROUP_CONCAT(DISTINCT device_hostname) AS affected_hosts, COUNT(DISTINCT device_hostname) AS host_count FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%daemon_function%' OR (LOWER(script_content) LIKE '%<<-eof%' AND LOWER(script_content) LIKE '%base64%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING host_count <= 3
```

## network-to-payload-ip
<!-- Network connections to payload infrastructure -->
Confirm the infection by matching host network activity against the reported payload delivery IP.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, payload_hosts=payload_hosts)
~~~yaml
expected: A host connecting to 85.206.161.241. Silence proves the fleet has not contacted
  the specific reported delivery IP.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{payload_hosts}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Evaluate MacSync kill-chain evidence -->
```agent target=hunter
cite: required
context:
- curl-to-shell-activity
- rare-daemon-scripts
- network-to-payload-ip
max_iterations: 3
objective: Determine if any host has successfully downloaded and executed the MacSync
  'zsh' or 'osascript' payload. Use the presence of 'daemon_function', base64 decoding
  in shell scripts, and connections to the reported IP to distinguish malicious activity
  from legitimate developer workflows.
success_criteria: A per-host verdict (malicious | suspicious | benign) citing evidence
  from at least two surfaces.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: script-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate the infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the device. Immediately initiate password resets for all accounts used in browsers on this device and rotate any local SSH/Cloud keys.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited script blocks. Check for the existence of /tmp/osalogging.zip. Verify if TCC prompts for 'Full Disk Access' were granted in the system log during the suspect time window.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the absence of MacSync-related activity. If curl-to-shell activity was found and determined to be benign management, record the specific command patterns to tune future detection candidates.
```
→ end
