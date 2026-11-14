---
analysis: A simple detection rule might fire on the Overlord binary name, but this
  hunt uses a phased approach to connect initial execution with later behavioral evidence
  of data exfiltration and anti-forensic cleanup, which provides the context necessary
  to distinguish a real intrusion from a lone suspicious file.
blind_spots:
- id: limited-file-telemetry
  question: Whether the .vscode directory was deleted by the malware or the user.
  requires: comprehensive hb_file_activity with delete events
  risk: Normal developer cleanup of old repositories could be mistaken for malware
    activity without process context for the deletion.
  stage: evasion-artifact-cleanup
- id: websocket-blindness
  question: What commands were sent over the Overlord WebSocket connection.
  requires: deep packet inspection or WebSocket-aware network logs
  risk: The hunt can see that a connection exists, but not the specific modules (browserlogin/companywallet)
    being activated in real-time.
  stage: c2-overlord-framework
coverage:
- stage: credential-access-wallet-theft
  status: covered
  steps:
  - suspicious-overlord-processes
  - evaluate-initial-infection
- stage: c2-overlord-framework
  status: covered
  steps:
  - c2-infrastructure-lookup
  - evaluate-initial-infection
- stage: exfiltration-c2-channel
  status: covered
  steps:
  - exfiltration-traffic-patterns
  - confirm-exfiltration-and-cleanup
- stage: evasion-artifact-cleanup
  status: covered
  steps:
  - malicious-cleanup-actions
  - confirm-exfiltration-and-cleanup
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: initial-access-phishing-repo
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: execution-ide-task-automation
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: persistence-malicious-vsix
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Developer workstations contain sensitive assets like API tokens and
    crypto wallets that are not protected by standard identity controls. A North Korean
    actor-led campaign specifically targeting these assets makes a negative result
    across the estate highly valuable.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A developer has cloned a malicious repository that executed an Overlord-derived
  RAT to steal browser credentials and cryptocurrency wallets before cleaning up its
  own files.
labels:
- hunt
- attack.t1041
- attack.t1071.001
- attack.t1090.003
- attack.t1555
- attack.t1070.004
name: UNK_DeadDrop Credential and Crypto Wallet Theft
parameters:
  c2_domains:
    default:
    - runoptions.runon
    description: C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-05-30'
      ref: proofpoint-unk-deaddrop
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-30'
      ref: hunt-standard
    type: number
  malicious_binaries:
    default:
    - google-update-support-linux-amd64
    - google-update-support-darwin-amd64
    - google-update-support-darwin-arm64
    description: Overlord framework binaries used in the campaign.
    from:
      kind: article
      observed: '2026-05-30'
      ref: proofpoint-unk-deaddrop
    type: list[string]
  scope_hosts:
    default: []
    description: Restrict the detection phase to the identified developer population.
    from:
      kind: manual
      observed: '2026-05-30'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with developer-heavy segments, particularly targeting DeFi or cryptocurrency-related
  projects. Use the identify-developer-hosts query to prioritize workstations with
  VS Code or Cursor IDEs installed.
references:
- name: "Proofpoint \u2014 UNK_DeadDrop phishing campaign targets developers"
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: malicious-vsix-extension-persistence
  reason: This hunt focuses on the post-infection actions of the RAT, while VSIX persistence
    is a separate mechanism needing module load analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing via Malicious GitHub Repository
    observables:
    - github.com/Pulsynk/pulsynk
    - github.com/Trixauvex-org/trixauvex
    - github.com/sr-werney/forge-4626-invariants
    - github.com/skyjum/x402-kit
    - 'Themes: DeFi recruitment, code reviews, technical assignments'
    slug: initial-access-phishing-repo
    tactic: initial-access
    techniques:
    - T1566.002
    - T1195.002
  - name: Automated IDE Task Execution
    observables:
    - tasks.json
    - 'runoptions.runon: folderOpen'
    - vendor/run-update.sh
    - vendor/run-update-hidden-launch.vbs
    - wscript.exe //B //Nologo vendor/run-update-hidden-launch.vbs
    - /bin/bash vendor/run-update.sh
    slug: execution-ide-task-automation
    tactic: execution
    techniques:
    - T1204.002
    - T1059.004
    - T1059.003
  - name: Malicious VSIX Extension Persistence
    observables:
    - google-update-support VSIX extension
    - google-update-support-darwin-arm64
    - google-update-support-linux-amd64
    slug: persistence-malicious-vsix
    tactic: persistence
    techniques:
    - T1546
  - name: Browser and Wallet Credential Theft
    observables:
    - 'Module: browserlogin'
    - 'Module: companywallet'
    - Accessing Chrome/Firefox profile data
    - Targeting browser crypto wallet extensions
    slug: credential-access-wallet-theft
    tactic: credential-access
    techniques:
    - T1555
    - T1539
  - name: C2 over Overlord Framework
    observables:
    - WebSocket persistent connectivity
    - Hardcoded C&C servers
    - Overlord C&C framework (Go-based)
    slug: c2-overlord-framework
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: Exfiltration over C2
    observables:
    - ZIP and upload of wallet data
    - Exfiltration of browser credentials
    slug: exfiltration-c2-channel
    tactic: exfiltration
    techniques:
    - T1041
  - name: Anti-Forensic Artifact Cleanup
    observables:
    - 'Module: cleanup'
    - Deletion of .vscode directory
    - Deletion of vendor/ directory from cloned repo
    slug: evasion-artifact-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: The UNK_DeadDrop campaign by North Korean actors targets developers via
    phishing emails containing links to malicious GitHub repositories. When victims
    open these repositories in IDEs like VS Code or Cursor, automated tasks execute
    platform-specific loaders that install malicious extensions and Go-based or Node.js
    malware designed to steal cryptocurrency wallets and browser credentials.
series:
  index: 2
  slug: unk-deaddrop-phishing-campaign-targets-developers
  title: UNK_DeadDrop phishing campaign targets developers
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


# UNK_DeadDrop Credential and Crypto Wallet Theft

This hunt targets the final stages of the UNK_DeadDrop campaign, an operation attributed to North Korean threat actors. It identifies developer workstations using VS Code or Cursor, then searches for the execution of platform-specific Go binaries from the Overlord framework. The hunt pivots to find evidence of large data transfers and the automated deletion of workspace directories like .vscode and vendor, which the malware uses to hide its tracks. A phased approach ensures that early infection evidence is evaluated before weighing the high-volume exfiltration and cleanup activity to confirm a successful intrusion.

## identify-developer-hosts
<!-- Identify developer hosts -->
Narrow the scope to hosts running developer tools like VS Code or Cursor to prioritize high-value targets.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to developers. Silence suggests no developer
  IDE activity was captured in the window.
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%code%' OR LOWER(process_name) LIKE '%cursor%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-infection-parallel
<!-- Early infection parallel search -->
parallel:
- → suspicious-overlord-processes
- → c2-infrastructure-lookup
join: → evaluate-initial-infection

## suspicious-overlord-processes
<!-- Suspicious Overlord processes -->
Find the execution of the specific Go-based Overlord binaries named in the research on developer hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, malicious_binaries=malicious_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: Specific binary names running from unexpected paths like /tmp/ or cloned
  repository folders.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE instr(',' || '{{malicious_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-infrastructure-lookup
<!-- C2 infrastructure lookup -->
Detect DNS queries to the hardcoded C2 domains used by the Overlord RAT from developer workstations.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: The Overlord binary or a related process resolving the runoptions.runon
  domain.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-initial-infection
<!-- Evaluate initial infection -->
```agent target=hunter
cite: required
context:
- suspicious-overlord-processes
- c2-infrastructure-lookup
max_iterations: 4
objective: Determine if any host shows evidence of the Overlord RAT based on binary
  names and DNS traffic.
success_criteria: A suspicious or malicious verdict citing specific rows for at least
  one host.
tools:
- endpoint
- network
```

## follow-on-activity-parallel
<!-- Follow-on activity parallel search -->
parallel:
- → exfiltration-traffic-patterns
- → malicious-cleanup-actions
join: → confirm-exfiltration-and-cleanup

## exfiltration-traffic-patterns
<!-- Exfiltration traffic patterns -->
Find high-volume outbound network activity representing the exfiltration of wallet and credential data.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound connections with significant aggregate traffic volume (ZIP uploads)
  from unexpected binaries.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes FROM hb_network_connection WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip HAVING total_bytes > 10000000
```

## malicious-cleanup-actions
<!-- Malicious cleanup actions -->
Identify the malware's attempts to hide its presence by deleting the .vscode and vendor directories on Windows, Linux, and macOS.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Deletions of configuration directories by non-IDE processes or the identified
  Overlord binary.
reads:
- device_hostname
- file_path
- process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 4 AND (LOWER(file_path) LIKE '%.vscode%' OR LOWER(file_path) LIKE '%\\.vscode%' OR LOWER(file_path) LIKE '%/vendor/%') AND (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## confirm-exfiltration-and-cleanup
<!-- Confirm exfiltration and cleanup -->
```agent target=hunter
cite: required
context:
- evaluate-initial-infection
- exfiltration-traffic-patterns
- malicious-cleanup-actions
max_iterations: 6
objective: Analyze the relationship between the Overlord RAT signals and the subsequent
  high-volume network traffic and workspace cleanup.
success_criteria: A malicious verdict for any host that shows infection followed by
  exfiltration or automated workspace deletion.
tools:
- endpoint
- network
```

## remediation-route
<!-- Remediation route -->
if~: "the confirm-exfiltration-and-cleanup verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-incident-response
unavailable: → manual-incident-response (blind_spot: limited-file-telemetry)
else: → close-hunt

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and collect memory and browser profile artifacts for forensic analysis.
```
→ manual-incident-response

## manual-incident-response
<!-- Manual incident response -->
```manual target=analyst
Review the cited rows from the Overlord binaries, C2 DNS traffic, and exfiltration logs. Confirm the malicious nature of the IDE workspace cleanup.
```
→ close-hunt

## close-hunt
<!-- Close hunt -->
```manual target=analyst
Document the hosts found with UNK_DeadDrop indicators. Update the malicious_binaries and c2_domains lists with any new findings.
```
→ end
