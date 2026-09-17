---
analysis: While individual rules may alert on new LaunchAgents, this hunt correlates
  the specific masquerading behavior (naming after updaters), the presence of .mpwd
  files, and the specialized capture agent flags in one triage window, which is something
  a single rule cannot perform without high false-positive rates.
blind_spots:
- id: missing-telemetry-gap
  owner: Endpoint Engineering
  question: Are all macOS devices reporting scheduled_job and file_activity telemetry?
  remediation: Audit macOS agent coverage and health.
  requires: endpoint-visibility
  risk: A host missing the agent or reporting partial telemetry may successfully persist
    without detection.
  stage: persistence-macho-rat
- id: tcc-prompt-interaction
  owner: Security Engineering
  question: Did the user explicitly allow the TCC prompt?
  remediation: Enable unified logging for TCC interactions where possible.
  requires: TCC system logs
  risk: We can see the helper run, but without TCC logs, we don't know if the capture
    was successful until exfiltration is detected.
  stage: collection-screen-recording-helper
coverage:
- stage: persistence-macho-rat
  status: covered
  steps:
  - launch-agent-check
  - mpwd-file-check
  - c2-connection-check
  - rare-job-baseline
- stage: collection-screen-recording-helper
  status: covered
  steps:
  - tcc-helper-check
- reason: Covered by 'macsync-initial-access-lure' hunt.
  stage: initial-access-clickfix-lure
  status: out_of_scope
- reason: Covered by 'macsync-initial-access-lure' hunt.
  stage: execution-zsh-in-memory
  status: out_of_scope
- reason: Covered by 'macsync-initial-access-lure' hunt.
  stage: credential-access-applescript-stealer
  status: out_of_scope
- reason: Covered by 'macsync-impact-wallet-theft' hunt.
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
  justification: MacSync is a sophisticated infostealer that targets high-value credentials
    and cryptocurrency wallets. Detecting its persistence and collection mechanisms
    is essential to preventing permanent asset loss and long-term backdoor access
    to the macOS fleet.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence on macOS hosts using a LaunchAgent
  named after a legitimate updater and is utilizing a secondary signed helper to abuse
  TCC screen recording permissions.
labels:
- hunt
- attack.t1543.001
- attack.t1071.001
- attack.t1113
name: MacSync RAT Persistence and TCC Helper Detection
parameters:
  c2_ips:
    default:
    - 85.206.161.241
    description: Known MacSync C2 IP addresses.
    from:
      kind: article
      observed: '2026-08-17'
      ref: huntress-fake-claude-macsync
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of historical data to examine.
    from:
      kind: manual
      observed: '2026-08-17'
      ref: hunt-designer
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
rationale: The hunt should initially target all macOS hosts ('darwin' platform). If
  the fleet is large, prioritize hosts where users have recently interacted with AI-related
  search terms or domains.
references:
- name: 'Huntress - MacSync Stealer: How a Google Search for Claude Led to a macOS
    Infostealer'
  url: https://www.huntress.com/blog/fake-claude-macsync
related:
- hunt: macsync-initial-access-lure
  reason: The initial malvertising lure and ZSH loader are handled in the first hunt
    of this series.
  relation: precedes
- hunt: macsync-impact-wallet-theft
  reason: The final stage of wallet trojanization and recovery phrase phishing is
    handled in the third hunt.
  relation: follows
- hunt: macsync-stealer-scripted-payload-execution
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
  index: 2
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


# MacSync RAT Persistence and TCC Helper Detection

This hunt focuses on the middle stages of the MacSync Stealer kill chain. It targets the installation of a Mach-O remote access trojan (RAT) that persists via LaunchAgents and the deployment of a specialized capture agent designed to bypass TCC (Transparency, Consent, and Control) for screen recording. By correlating suspicious LaunchAgent names, unique credential-caching files, and specific command-line flags for TCC abuse across multiple telemetry surfaces, we can identify infected macOS endpoints even if the initial in-memory loader has been purged.

## macos-scoping
<!-- Enumerate macOS Fleet -->
Scope the hunt to macOS devices which are the primary targets of MacSync Stealer.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of macOS hostnames. Absence of Darwin hosts means no scope for this
  hunt.
reads:
- hostname
- device_uid
- os_version
- last_seen
- platform
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT hostname, device_uid, os_version, last_seen FROM hb_devices WHERE platform = 'darwin'
```

## persistence-corroboration
<!-- Corroborate Persistence and C2 Indicators -->
parallel:
- → launch-agent-check
- → mpwd-file-check
- → c2-connection-check
- → tcc-helper-check
- → rare-job-baseline
join: → triage-agent

## launch-agent-check
<!-- New User LaunchAgents -->
Find new LaunchAgents created in user or system Library folders, which MacSync uses for persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A list of recently added LaunchAgents. The RAT often names these after legitimate
  software updaters.
reads:
- device_hostname
- job_name
- job_definition_path
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE (instr(LOWER(job_definition_path), '/library/launchagents/') > 0 OR instr(LOWER(job_definition_path), '/library/launchdaemons/') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mpwd-file-check
<!-- Credential Staging (.mpwd) -->
Detect the creation of the hidden .mpwd file in home directories, where MacSync stages stolen passwords.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Creation of a .mpwd file. This is a high-fidelity indicator for this specific
  RAT.
reads:
- device_hostname
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE file_name = '.mpwd' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-connection-check
<!-- RAT C2 Network Activity -->
Identify WebSocket connections over port 8443 or to the known C2 IP address.

```sqlite target=network role=triage params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Outbound connections to the reported C2 or port 8443 from unusual processes.
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
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 8443) AND time >= datetime('now', '-{{lookback_days}} days')
```

## tcc-helper-check
<!-- TCC Helper Abuse Flags -->
Detect the specialized TCC-abuse helper using specific flags for screen recording provisioning.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Process execution with flags used by the MacSync screenshot helper.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(process_cmd_line, '--tcc-only') > 0 OR instr(process_cmd_line, ' -o ')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-job-baseline
<!-- Rare LaunchAgent Baseline -->
Stack-count LaunchAgent names to find those that are rare across the fleet, highlighting the polymorphic nature of the RAT persistence.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of LaunchAgents appearing on 3 or fewer hosts.
prevalence:
  by: device_hostname
  key:
  - job_name
  rare_below: 3
reads:
- job_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT job_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) as first_seen FROM hb_scheduled_job WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name HAVING host_count <= 3
```

## triage-agent
<!-- Weigh Correlated Indicators -->
```agent target=hunter
cite: required
context:
- macos-scoping
- launch-agent-check
- mpwd-file-check
- c2-connection-check
- tcc-helper-check
- rare-job-baseline
max_iterations: 5
objective: Determine if any host shows overlapping evidence of the MacSync RAT (persistence,
  .mpwd staging, C2 port 8443, or TCC helper flags).
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  rows.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route Based on Verdict -->
if~: "the triage verdict is 'malicious' for one or more hosts showing multiple correlated indicators" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Compromised macOS Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate password rotation for the logged-on user.
```
→ analyst-review

## analyst-review
<!-- Analyst Persistence Review -->
```manual target=analyst
Verify the LaunchAgent plist content and the TCC helper binary. Check for the existence of .mpwd and related exfiltration logs in /tmp.
```
→ close-out

## close-out
<!-- Hunt Completion and Tuning -->
```manual target=analyst
Document discovered updater names used for masquerading. Update internal detection rules for these specific names if they are not legitimate fleet software.
```
→ end
