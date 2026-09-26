---
analysis: A single rule looking for curl piped to a shell generates high noise in
  developer environments. This hunt solves that by pivoting from the execution signal
  to fleet-wide rarity analysis of hidden Application Support folders, confirming
  a malicious pattern that a single rule cannot distinguish from legitimate administrative
  scripting.
blind_spots:
- id: macos-file-visibility
  question: whether the endpoint agent can see file creations in hidden Application
    Support subdirectories
  requires: full hb_file_activity coverage for hidden directories
  risk: The hunt may fail to find persistence artifacts if the agent ignores hidden
    folders or lacks sufficient permissions.
  stage: persistence-via-hidden-application-support
- id: ephemeral-tmp-files
  question: whether the /tmp/out.zip archive was created and deleted before the collector
    could record it
  requires: real-time file monitoring for /tmp
  risk: If AMOS deletes its staging archive immediately after exfiltration, the file
    activity row may be missed if logging is not real-time.
  stage: credential-and-wallet-collection
coverage:
- stage: initial-access-copy-paste-terminal
  status: covered
  steps:
  - terminal-curl-pipe
  - dns-to-amos-domains
- stage: script-execution-and-payload-retrieval
  status: covered
  steps:
  - early-stage-triage
- stage: persistence-via-hidden-application-support
  status: covered
  steps:
  - hidden-app-support-rarity
- stage: credential-and-wallet-collection
  status: covered
  steps:
  - tmp-archive-creation
- reason: This hunt focuses on endpoint lifecycle and local artifacts; exfiltration
    volume and C2 patterns belong to a network-centric hunt.
  stage: c2-exfiltration-over-http
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AMOS is a high-velocity threat targeting administrative credentials
    and cloud tokens on macOS; a phased hunt is required to confirm full infection
    chains rather than just noisy script activity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a macOS host using deceptive Terminal setup
  commands to execute encoded shell scripts, establishing hidden persistence in Application
  Support and staging harvested data in temporary directories.
labels:
- hunt
- attack.t1204.001
- attack.t1059.004
- attack.t1105
- attack.t1543.001
- attack.t1564.001
- attack.t1560.001
- attack.t1555
- attack.t1115
name: Atomic macOS (AMOS) Stealer Activity
parameters:
  amos_domains:
    default:
    - getmacouscloud.com
    - ferncore13.com
    - grove-89.com
    - malware-traffic-analysis.net
    description: Known domains associated with AMOS delivery and infrastructure.
    from:
      kind: article
      observed: '2026-08-05'
      ref: unit42-amos-stealer
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of macOS hostnames to narrow the scope.
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
rationale: The hunt focuses on macOS hosts (Darwin platform). Deceptive Terminal commands
  are a prerequisite for this specific AMOS variant.
references:
- name: Atomic macOS (AMOS) Stealer Activity
  url: https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/
related:
- hunt: macos-hidden-launch-persistence
  reason: A broader hunt for any hidden launchd plists or binaries in unusual system
    directories would complement this AMOS-specific search.
  relation: sibling
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
  index: 1
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
tlp: clear
type: investigation
---


# Atomic macOS (AMOS) Stealer Activity

This hunt targets the Atomic macOS (AMOS) stealer's end-to-end lifecycle on the endpoint. It begins by identifying the initial access vector: users copy-pasting curl-to-shell commands into Terminal. The hunt then moves through a phased flow, assessing early execution evidence before fanning out to search for high-fidelity persistence artifacts in hidden directories and evidence of data staging. By linking deceptive execution with rare file creations in Application Support, an analyst can confirm a successful infection even as malware indicators rotate.

## macos-scope
<!-- Identify macOS hosts -->
Narrow the estate to macOS devices to ensure behavioral queries target the relevant platform.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence suggests no macOS devices are enrolled in the
  monitoring platform.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT hostname FROM hb_devices WHERE (LOWER(platform) = 'darwin' OR LOWER(platform) = 'macos') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early
<!-- Detect early execution signals -->
parallel:
- → terminal-curl-pipe
- → dns-to-amos-domains
join: → early-stage-triage

## terminal-curl-pipe
<!-- Deceptive terminal curl-to-shell -->
Identify instances of curl commands piped directly to a shell within Terminal or Zsh sessions, which is the primary delivery mechanism for AMOS.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process activity showing a user-initiated pipe of remote content to an interpreter.
  This is a high-confidence indicator of the reported technique.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%terminal%' OR LOWER(process_name) LIKE '%zsh%') AND instr(LOWER(process_cmd_line), 'curl') > 0 AND instr(LOWER(process_cmd_line), '|') > 0 AND instr(LOWER(process_cmd_line), 'zsh') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## dns-to-amos-domains
<!-- DNS lookups to AMOS infrastructure -->
Corroborate deceptive commands with network connections to the domains listed in the research.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, amos_domains=amos_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolutions for delivery domains. Silence is expected if the adversary
  has rotated domains, making behavioral queries critical.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{amos_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-triage
<!-- Assess early infection signals -->
```agent target=hunter
cite: required
context:
- terminal-curl-pipe
- dns-to-amos-domains
max_iterations: 4
objective: Determine if any host likely executed a deceptive AMOS installation command
  based on Terminal process activity and related DNS lookups.
success_criteria: A per-host verdict citing specific command lines or domains.
tools:
- endpoint
```

## parallel-follow-on
<!-- Detect persistence and staging -->
parallel:
- → hidden-app-support-rarity
- → tmp-archive-creation
join: → full-infection-triage

## hidden-app-support-rarity
<!-- Rare hidden Application Support paths -->
Identify hidden directories within Application Support masquerading as Apple services, using fleet-wide rarity to filter out legitimate software.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hidden file paths seen on few hosts, such as .com.apple.accountsd or .com.apple.metadata.mds.
  Legitimate app support folders are typically consistent across the fleet.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 5
reads:
- file_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(file_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_path) LIKE '%/application support/.com.apple.%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY LOWER(file_path) HAVING hosts <= 5 ORDER BY hosts ASC
```

## tmp-archive-creation
<!-- Staged collection archive in /tmp -->
Search for the specific staging file AMOS creates to aggregate stolen credentials and wallet data.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing the creation of /tmp/out.zip. Silence confirms this specific
  artifact was not staged during the window.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'out.zip' AND LOWER(file_path) LIKE '%/tmp/%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## full-infection-triage
<!-- Synthesize full infection chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- hidden-app-support-rarity
- tmp-archive-creation
max_iterations: 6
objective: Analyze the full chain of activity, synthesisng the early execution evidence
  with follow-on persistence in hidden Application Support paths and ZIP staging in
  /tmp.
success_criteria: A per-host verdict that classifies the threat as malicious if multiple
  stages of the chain are observed.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on infection verdict -->
if~: "the triage verdict identifies a host with both deceptive Terminal activity and subsequent hidden Application Support persistence" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-forensics
unavailable: → manual-forensics (blind_spot: macos-file-visibility)
else: → close-out

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active cloud provider sessions associated with the user.
```
→ manual-forensics

## manual-forensics
<!-- Perform manual forensics -->
```manual target=analyst
Check the /tmp and Application Support directories for the hidden files identified by the agent. Collect hashes and samples of AccountsHelper or mdworker_shared if present. Review the user's terminal history and keychain for further signs of theft.
```
→ close-out

## close-out
<!-- Close out and document -->
```manual target=analyst
Document the identified hosts and their current status. If the terminal curl-to-shell query proved effective, recommend it for promotion to a detection rule. Note any new hidden paths discovered.
```
→ end
