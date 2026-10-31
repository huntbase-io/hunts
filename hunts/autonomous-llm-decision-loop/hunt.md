---
analysis: A single detection rule would struggle to link host-side discovery with
  the specific quorum pattern of sequential DNS lookups. This hunt correlates rare
  discovery processes with infrastructure resolution across three or more providers,
  weighing behavioral prevalence against infrastructure patterns.
blind_spots:
- id: tls-encryption-gap
  question: Are the prompts being sent to LLMs truly the offensive JSON schema described
    in the report?
  requires: TLS inspection or endpoint memory analysis
  risk: Without inspecting the encrypted payload, we can only confirm that a process
    is talking to an LLM provider, not what it is saying.
  stage: autonomous-llm-c2
- id: no-endpoint-telemetry
  question: Did the implant execute discovery on a host with no agent installed?
  requires: hb_process_activity with high coverage
  risk: The hunt only sees discovery and quorum behavior on the enrolled estate.
  stage: host-discovery-initialization
coverage:
- stage: host-discovery-initialization
  status: covered
  steps:
  - discovery-prevalence
- stage: autonomous-llm-c2
  status: covered
  steps:
  - ai-quorum-dns
- reason: 'Belongs to another part of the ''The Closed Quorum: Inside the first reported
    autonomous AI C2 implant'' series.'
  stage: persistence-establishment
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Closed Quorum: Inside the first reported
    autonomous AI C2 implant'' series.'
  stage: process-injection-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Closed Quorum: Inside the first reported
    autonomous AI C2 implant'' series.'
  stage: credential-and-wallet-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous C2 infrastructure using legitimate AI providers evades
    traditional domain-based blocking and allows attackers to maintain persistence
    without active manual intervention.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous implant performs host discovery and then queries multiple
  commercial AI providers to decide its next tactical moves, bypassing traditional
  C2 infrastructure.
labels:
- hunt
- attack.t1071.001
- attack.t1047
- attack.t1003.001
name: Autonomous LLM Decision Loop
parameters:
  ai_domains:
    default:
    - api.deepseek.com
    - dashscope.aliyuncs.com
    - api.mistral.ai
    - generativelanguage.googleapis.com
    description: Commercial LLM provider API endpoints used for autonomous C2.
    from:
      kind: article
      observed: '2026-09-22'
      ref: talos-closed-quorum
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for the full estate.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: default
    type: list[host]
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
rationale: The hunt identifies Windows systems first. Analysts should prioritize developer
  or researcher machines that might legitimately use AI APIs, as the implant aims
  to blend into this traffic.
references:
- name: 'The Closed Quorum: Inside the first reported autonomous AI C2 implant'
  url: https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
related:
- hunt: persistence-establishment-closedquorum
  reason: Specific WMI and registry persistence techniques are handled by a dedicated
    persistence hunt.
  relation: out-of-scope-alternative
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
  index: 1
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


# Autonomous LLM Decision Loop

This hunt identifies the unique LLM-as-C2 architecture used by the CLOSEDQUORUM implant. Instead of contacting a single attacker-controlled domain, the implant queries a quorum of commercial AI providers (DeepSeek, Qwen, Mistral, and Google Gemini) to receive instructions via structured JSON prompts. The hunt correlates initial system discovery commands with sequential DNS queries to these AI providers, identifying hosts where automated reasoning replaces human-directed command and control.

## scope-windows-endpoints
<!-- Scope Windows endpoints -->
Identify Windows systems within the estate that could be targeted by this 64-bit Windows implant.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames representing the Windows fleet. Silence means no Windows
  systems were indexed.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT hostname FROM hb_devices WHERE platform = 'Windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence-gathering
<!-- Gather behavioural and infrastructure evidence -->
parallel:
- → discovery-prevalence
- → ai-quorum-dns
join: → triage-quorum-behavior

## discovery-prevalence
<!-- Rare system discovery commands -->
The hunt finds uncommon processes performing system discovery using wmic or systeminfo, matching the implant's gatherSystemInfo() behavior, while filtering out standard system paths.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Discovery commands executed by non-standard processes across a small number
  of hosts. Fleet-wide management scripts are ignored.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 5
reads:
- process_name
- process_cmd_line
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%wmic%' OR LOWER(process_cmd_line) LIKE '%systeminfo%' OR LOWER(process_cmd_line) LIKE '%hostname%') AND LOWER(process_path) NOT LIKE 'c:\windows\system32\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_cmd_line HAVING host_count <= 5
```

## ai-quorum-dns
<!-- AI provider DNS quorum -->
The hunt identifies processes resolving multiple commercial LLM providers in sequence, representing the plurality voting loop of the implant.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_domains=ai_domains)
~~~yaml
expected: A single process on a host contacting several unique AI providers (DeepSeek,
  Mistral, Gemini) in a short window. This identifies the quorum-polling behavior.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT query_hostname) AS unique_providers, GROUP_CONCAT(DISTINCT query_hostname) AS providers FROM hb_dns_activity WHERE instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_providers >= 3
```

## triage-quorum-behavior
<!-- Triage quorum behavior -->
```agent target=hunter
cite: required
context:
- discovery-prevalence
- ai-quorum-dns
max_iterations: 6
objective: Determine if a single host or process exhibits both system discovery and
  the sequential polling of multiple AI providers. Prioritize processes that performed
  system discovery immediately preceding lookups to three or more distinct AI providers.
success_criteria: A per-host verdict (malicious, suspicious, or benign) citing specific
  process names and resolved domains.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host exhibiting correlated system discovery and AI provider DNS traffic" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: tls-encryption-gap)
else: → close-hunt

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network to stop the autonomous C2 loop and prevent credential exfiltration.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the findings; confirm if the process identified is a legitimate AI tool or the CLOSEDQUORUM implant. Check for the 16.4MB binary and extract any injected API keys.
```
→ close-hunt

## close-hunt
<!-- Close hunt -->
```manual target=analyst
Document the findings, including any confirmed LLM API providers used and the timeframe of the autonomous activity.
```
→ end
