---
analysis: While rules can flag the specific binary names, this hunt combines process
  presence with the specific behavior of accessing browser profile databases and stack-counting
  rare outbound connections to find stealthy C2 patterns that a single rule would
  miss.
blind_spots:
- id: incomplete-telemetry
  question: Are all relevant hosts reporting process and file activity?
  requires: comprehensive endpoint event collection
  risk: Hosts not enrolled in the telemetry platform may harbor active infections
    undetected.
- id: encrypted-c2-channel
  question: What is the content of the outbound WebSocket/HTTPS traffic?
  requires: TLS decryption/inspection at the network layer
  risk: If the C2 channel is fully encrypted and doesn't use unique domains, the hunt
    relies solely on process and file behavior for detection.
  stage: command-and-control-overlord-rat
coverage:
- stage: command-and-control-overlord-rat
  status: covered
  steps:
  - scope-rat-presence
  - baseline-rare-c2-outbound
  - enrichment-dns-indicators
- stage: credential-theft-and-collection
  status: covered
  steps:
  - behavior-sensitive-file-access
- stage: exfiltration-over-c2
  status: covered
  steps:
  - behavior-sensitive-file-access
  - baseline-rare-c2-outbound
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: initial-access-spearphishing
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: execution-ide-task-automation
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: persistence-malicious-vsix
  status: out_of_scope
- reason: Belongs to another part of the 'UNK_DeadDrop phishing campaign targets developers'
    series.
  stage: defense-evasion-cleanup
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The UNK_DeadDrop campaign specifically targets high-value developer
    assets like crypto wallets and credentials. Confirming the absence of the Overlord
    RAT or its related stealers is essential for protecting financial assets and source
    code integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established a persistent backdoor using the Overlord RAT
  framework or a Node.js-based stealer to harvest browser credentials and cryptocurrency
  wallets for exfiltration.
labels:
- hunt
- attack.t1041
- attack.t1071.001
- attack.t1090.003
- attack.t1555
name: 'UNK_DeadDrop: Overlord RAT and Credential Exfiltration'
parameters:
  c2_domains:
    default:
    - runoptions.runon
    description: Known C2 domains associated with UNK_DeadDrop activity.
    from:
      kind: article
      observed: '2026-05-27'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rat_binaries:
    default:
    - google-update-support-linux-amd64
    - google-update-support-darwin-amd64
    - google-update-support-darwin-arm64
    description: Names of the Overlord RAT binaries observed in the campaign.
    from:
      kind: article
      observed: '2026-05-27'
      ref: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
    type: list[string]
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
rationale: Focus on endpoints used by developers, security researchers, and finance
  staff, as these were the primary targets. Start with systems showing activity in
  IDEs like VS Code or Cursor.
references:
- name: "Proofpoint \u2014 Don\u2019t Fear the Repo: UNK_DeadDrop Phishing Campaign\
    \ Targets Developers"
  url: https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal
related:
- hunt: unk-deaddrop-initial-access
  reason: Initial access via phishing and GitHub cloning is covered in a separate
    hunt.
  relation: out-of-scope-alternative
- hunt: unk-deaddrop-ide-persistence
  reason: Persistence through malicious VSIX extensions and tasks.json is a sibling
    hunt.
  relation: out-of-scope-alternative
- hunt: persistent-ide-extensions-workspace-cleanup
  relation: follows
scenario:
  stages:
  - name: Spearphishing via Fake Developer Lures
    observables:
    - Attacker-controlled sender domains
    - 'URLs to GitHub repositories: pulsynk/pulsynk, Trixauvex-org/trixauvex, PedrinPY/rekt-db,
      wayout4u/rekt-db, Stomp47/rekt-db, sr-werney/forge-4626-invariants, ziobiri/forge-4626-invariants,
      mireles343/forge-4626-invariants, skyjum/x402-kit, rkama411/x402-kit'
    - 'Job titles: Full-Stack Engineer, Agent Lead Developer'
    slug: initial-access-spearphishing
    tactic: initial-access
    techniques:
    - T1566
    - T1195.002
  - name: Execution via IDE Task Automation
    observables:
    - 'File: .vscode/tasks.json'
    - 'Command: runOptions.runOn: folderOpen'
    - 'Process: /bin/bash vendor/run-update.sh'
    - 'Process: wscript.exe //B //Nologo vendor/run-update-hidden-launch.vbs'
    slug: execution-ide-task-automation
    tactic: execution
    techniques:
    - T1204.002
  - name: Persistence via Malicious VSIX Extension
    observables:
    - Malicious VS Code extension (VSIX) masquerading as a Google service
    - Automated activation on editor startup (macOS/Linux)
    slug: persistence-malicious-vsix
    tactic: persistence
    techniques:
    - T1546
  - name: C2 via Overlord RAT
    observables:
    - Go-based Overlord RAT binaries
    - 'File: google-update-support-linux-amd64'
    - 'File: google-update-support-darwin-amd64'
    - 'File: google-update-support-darwin-arm64'
    - WebSocket persistent connectivity to hardcoded C2
    - Multi-hop proxy infrastructure
    slug: command-and-control-overlord-rat
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  - name: Credential Theft and Collection
    observables:
    - 'Overlord module: browserlogin (theft of Chrome and Firefox credentials)'
    - 'Overlord module: companywallet (crypto wallet stealer)'
    - Creation of temporary ZIP files for exfiltration
    slug: credential-theft-and-collection
    tactic: credential-access
    techniques:
    - T1555
  - name: Exfiltration of Wallets and Credentials
    observables:
    - Upload of ZIP files containing decrypted credentials and desktop wallets to
      C2
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  - name: Indicator Removal via Cleanup Module
    observables:
    - 'Overlord module: cleanup'
    - Deletion of workspace artifacts and malicious payloads from cloned repositories
    slug: defense-evasion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: UNK_DeadDrop is a North Korean-aligned phishing campaign targeting developers
    across finance, tech, and crypto sectors via fake recruitment lures and code review
    requests. The campaign employs malicious GitHub repositories that abuse VS Code
    and Cursor IDE task automation to execute platform-specific Go-based loaders (Overlord
    RAT) or Node.js pipelines, resulting in the theft of browser credentials and cryptocurrency
    wallets.
series:
  index: 3
  slug: unk-deaddrop-phishing-campaign-targets-developers
  title: UNK_DeadDrop phishing campaign targets developers
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


# UNK_DeadDrop: Overlord RAT and Credential Exfiltration

This hunt targets the post-exploitation phase of the UNK_DeadDrop campaign, focusing on the Go-based Overlord RAT and the Node.js credential stealer pipeline. It identifies the presence of malicious binaries, monitors for unauthorized access to sensitive browser and wallet data, and detects rare outbound network connections indicative of command-and-control activity or data exfiltration. The hunt uses a sequential analysis of process, file, and network telemetry to identify infected endpoints and weigh the evidence of credential theft.

## scope-rat-presence
<!-- Identify active RAT processes -->
Locate hosts running the specific Overlord RAT binaries or the Windows launcher script identified in the campaign.

```sqlite target=endpoint role=scoping params=(rat_binaries=rat_binaries, lookback_days=lookback_days)
~~~yaml
expected: A match indicates a host likely infected with the UNK_DeadDrop RAT. Silence
  proves no known binaries are currently active.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{rat_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%run-update-hidden-launch.vbs%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## behavior-sensitive-file-access
<!-- Detect access to browser credentials and wallets -->
Identify processes accessing sensitive file paths associated with browser logins and cryptocurrency wallets, and the creation of ZIP files for exfiltration.

```sqlite target=endpoint role=detection-candidate params=(rat_binaries=rat_binaries, lookback_days=lookback_days)
~~~yaml
expected: Any access to browser databases or wallet files by the identified binaries
  or Node.js processes is highly suspicious for credential theft.
reads:
- activity_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%login data%' OR LOWER(file_path) LIKE '%cookies%' OR LOWER(file_path) LIKE '%wallet%' OR LOWER(file_path) LIKE '%.zip') AND (instr(',' || '{{rat_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE 'node%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-rare-c2-outbound
<!-- Baseline rare outbound connections -->
Find unusual network traffic patterns from the identified processes that may indicate C2 communication or multi-hop proxy usage.

```sqlite target=network role=baseline params=(rat_binaries=rat_binaries, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare destination IPs or hostnames contacted by these specific processes
  point to actor-controlled C2 infrastructure.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_hostname
  rare_below: 3
reads:
- device_hostname
- direction
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT dst_endpoint_ip, dst_endpoint_hostname, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS conn_count FROM hb_network_connection WHERE (instr(',' || '{{rat_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE 'node%') AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_hostname HAVING host_count <= 2
```

## enrichment-dns-indicators
<!-- Check for known C2 DNS lookups -->
Confirm activity by matching DNS queries to the specific C2 domain named in the research.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Lookups for runoptions.runon confirm infection. Silence does not disprove
  infection if the actor has rotated infrastructure.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh the evidence -->
```agent target=hunter
cite: required
context:
- scope-rat-presence
- behavior-sensitive-file-access
- baseline-rare-c2-outbound
- enrichment-dns-indicators
max_iterations: 4
objective: Determine if any host shows confirmed signs of RAT infection, credential
  harvesting, or exfiltration based on the correlated findings.
success_criteria: A verdict per host (Malicious, Suspicious, or Benign) with specific
  citations of rows showing binary presence or sensitive file access.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## contain-host
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host immediately to prevent further exfiltration. Revoke all credentials (SSH keys, API tokens, browser passwords) stored on the device as they are likely compromised.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage agent's findings and cited rows. Verify the scope of data access and confirm the containment action. Document any discovered C2 indicators for inclusion in blocking lists.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Log the negative result. Monitor for any future alerts related to the UNK_DeadDrop indicators or unusual developer machine behavior.
```
→ end
