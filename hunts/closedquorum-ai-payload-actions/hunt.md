---
analysis: A single rule for LSASS access or WMI creation exists, but this hunt pivots
  across three independent capabilities (steal, inject, persist) and uses prevalence
  to find the rare behaviors an autonomous implant produces that a static rule would
  miss.
blind_spots:
- id: no-memory-visibility
  owner: Detection Engineering
  question: Was the code injected into a process that has since terminated?
  remediation: Enable high-fidelity process injection events in the EDR.
  requires: EDR memory scanning or thread injection telemetry
  risk: The implant's injection module may leave no persistent process trace after
    its execution cycle completes, making it invisible to point-in-time snapshots.
  stage: process-injection-execution
- id: tls-prompt-invisibility
  owner: Network Security
  question: What reasoning is the AI providing for its actions?
  remediation: Deploy TLS inspection for known AI API endpoints on sensitive hosts.
  requires: TLS inspection for LLM provider domains
  risk: Without inspecting the HTTPS traffic to DeepSeek or Gemini, we cannot see
    the structured JSON decision and reasoning fields being sent to the implant.
coverage:
- stage: persistence-establishment
  status: covered
  steps:
  - wmi-persistence-baseline
- stage: process-injection-execution
  status: covered
  steps:
  - injected-code-detection
- stage: credential-and-wallet-theft
  status: covered
  steps:
  - wallet-access-lead
- reason: 'Belongs to another part of the ''The Closed Quorum: Inside the first reported
    autonomous AI C2 implant'' series.'
  stage: host-discovery-initialization
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Closed Quorum: Inside the first reported
    autonomous AI C2 implant'' series.'
  stage: autonomous-llm-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous AI implants collapse the decision space of an attack,
    requiring response speeds that outpace human analysts; confirming the absence
    of these specific endpoint behaviors ensures no such system is active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous AI implant is performing credential theft, process injection,
  or WMI persistence based on plurality-vote decisions reached by a panel of LLM providers.
labels:
- hunt
- attack.t1003
- attack.t1003.001
- attack.t1047
- attack.t1055
- attack.t1071
- attack.t1566
name: CLOSEDQUORUM AI Payload Actions
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to focus the investigation on; defaults to the whole
      estate.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: analyst-scoping
    type: list[host]
  wallet_targets:
    default:
    - exodus.wallet
    - wallet.dat
    - ethpath
    - metamask
    description: Specific filenames associated with targeted crypto wallet files named
      in the research.
    from:
      kind: article
      observed: '2026-09-22'
      ref: talos-closedquorum
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations and hosts with high-value crypto identities.
  Widen history if the hunt finds any injected code without a lead hit.
references:
- name: 'The Closed Quorum: Inside the first reported autonomous AI C2 implant'
  url: https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
related:
- hunt: autonomous-llm-c2-network-correlation
  reason: This hunt focuses on endpoint actions; correlating the multi-provider network
    traffic requires a separate network-centric hunt.
  relation: out-of-scope-alternative
- hunt: autonomous-llm-decision-loop
  relation: follows
scenario:
  stages:
  - name: Host Discovery and Initialization
    observables:
    - gatherSystemInfo() function call
    - Collection of hostname, Windows version, CPU count, and architecture
    - Admin status check
    slug: host-discovery-initialization
    tactic: discovery
    techniques:
    - T1047
  - name: Autonomous LLM C2 Orchestration
    observables:
    - main.queryLLM() function call
    - ModelOrchestrator polling DeepSeek, Qwen, Mistral, and Google Gemini APIs
    - 'Structured JSON prompts containing ''TARGET: %s'' context'
    - Polling intervals of 5 to 15 minutes
    - Discord webhooks for operator telemetry
    slug: autonomous-llm-c2
    tactic: command-and-control
    techniques:
    - T1071
  - name: WMI Persistence
    observables:
    - establishPersistence() function call
    - WMI event subscription creation
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1047
  - name: Process Injection
    observables:
    - injectProcess() function call
    - earlyBirdInject() function call
    - PEB-walk process hollowing
    - APC injection into suspended processes
    slug: process-injection-execution
    tactic: defense-evasion
    techniques:
    - T1055
  - name: Credential and Wallet Harvesting
    observables:
    - lsassDump() function call
    - dumpBrowserCredentials() targeting Chrome, Edge, and Firefox
    - extractCryptoWallets() function call
    - Access to 'exodus.wallet'
    - Access to MetaMask Chrome extensions
    - Access to 'ethPath' Ethereum wallets
    slug: credential-and-wallet-theft
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  summary: CLOSEDQUORUM is an autonomous Windows implant that uses a panel of commercial
    LLMs (DeepSeek, Mistral, Gemini, Qwen) as its command-and-control infrastructure.
    The malware independently gathers host information, polls the LLM providers for
    instructions, and uses a plurality voting mechanism to execute actions including
    credential theft, process injection, and WMI-based persistence, exfiltrating data
    via Discord webhooks.
series:
  index: 2
  slug: the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant
  title: 'The Closed Quorum: Inside the first reported autonomous AI C2 implant'
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


# CLOSEDQUORUM AI Payload Actions

This hunt identifies the endpoint artifacts of CLOSEDQUORUM decisions: specifically, the steal capability targeting crypto wallets, the inject capability using process hollowing or APC injection, and the persist capability using WMI event subscriptions. The hunt starts with a lead query for wallet access to identify potentially compromised hosts, then fans out to detect fileless code and rare WMI persistence commands across the estate. An agent weighs the combined telemetry to confirm the presence of an autonomous implant session.

## wallet-access-lead
<!-- Lead: Crypto wallet harvesting -->
Identify hosts where a process has accessed file paths or names associated with the implant's steal capability.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, wallet_targets=wallet_targets)
~~~yaml
expected: Rows naming a Go-compiled binary or a suspicious system process reading
  wallet files. Silence suggests the 'steal' module has not executed.
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE (instr(',' || '{{wallet_targets}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR instr(',' || '{{wallet_targets}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-implant-activity
<!-- Corroborate injection and persistence -->
parallel:
- → injected-code-detection
- → wmi-persistence-baseline
join: → triage-quorum-actions

## injected-code-detection
<!-- Detect injected or fileless code -->
Find processes running without a binary on disk to detect the implant's process hollowing and APC injection modules.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Legitimate system processes like svchost.exe or explorer.exe running without
  a corresponding file on disk.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## wmi-persistence-baseline
<!-- WMI event subscription baseline -->
Stack-count WMI commands to isolate rare permanent event consumers created by the implant's persistence module.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare WMI command creating a permanent event consumer. Silence confirms
  no rare WMI persistence was established in the window.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_cmd_line
- device_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%wmic.exe' OR LOWER(process_name) LIKE '%scrcons.exe') AND (LOWER(process_cmd_line) LIKE '%activescripteventconsumer%' OR LOWER(process_cmd_line) LIKE '%commandlineeventconsumer%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 5 ORDER BY host_count ASC
```

## triage-quorum-actions
<!-- Triage quorum actions -->
```agent target=hunter
cite: required
context:
- wallet-access-lead
- injected-code-detection
- wmi-persistence-baseline
max_iterations: 4
objective: Determine if the observed endpoint behavior matches the known 'steal',
  'inject', and 'persist' modules of the CLOSEDQUORUM implant.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows of activity.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host exhibiting wallet access, injected code, or suspicious WMI persistence" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: no-memory-visibility)
else: → forensic-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve memory to analyze the injected thread and LLM API keys.
```
→ forensic-review

## forensic-review
<!-- Forensic review -->
```manual target=analyst
Search the host for a Go-compiled binary (approx 16MB) in user profile or %TEMP% directories. Recover any Discord webhook URLs found in memory or strings.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Record the specific WMI event filter logic and the user account used for wallet access. Document any LLM provider domains observed in network traffic.
```
→ end
