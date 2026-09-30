---
analysis: A single rule could flag the malware hash, but this hunt pivots between
  process injection states, rare AI API DNS resolutions, and high-volume file modifications
  to identify an active, autonomous infection chain that simple static rules would
  miss.
blind_spots:
- id: no-process-visibility
  question: Are the AI-driven processes running on unmanaged hosts?
  requires: endpoint agent process coverage
  risk: A host without an agent performing AI C2 will only be seen as encrypted traffic
    at the network level, which might be missed without DNS or socket telemetry.
  stage: command-and-control-autonomous-ai
- id: encrypted-c2-payload
  question: What instructions were received from the LLM?
  requires: TLS inspection for AI API endpoints
  risk: We can see the connection to api.openai.com, but cannot see the 'jailbreak
    terms' or 'prompt templates' used to orchestrate the attack without network inspection.
  stage: command-and-control-autonomous-ai
coverage:
- stage: command-and-control-autonomous-ai
  status: covered
  steps:
  - suspicious-process-lead
  - rare-ai-infrastructure-dns
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - high-volume-encryption-activity
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: social-engineering-elicitation
  status: out_of_scope
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: trojanised-software-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: defense-evasion-edr-killer
  status: out_of_scope
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: credential-access-infostealer
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous AI-driven malware (CLOSEDQUORUM) represents a tier-shift
    in adversary tradecraft, allowing real-time decision making without human intervention;
    identifying this early prevents large-scale ransomware impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using autonomous AI-driven malware to orchestrate command-and-control
  decisions via LLM API calls, followed by high-volume data encryption for impact.
labels:
- hunt
- attack.t1071
- attack.t1486
name: Autonomous AI Command-and-Control and Impact
parameters:
  ai_api_domains:
    default:
    - api.openai.com
    - api.anthropic.com
    - api.cohere.ai
    - api.groq.com
    description: Known LLM API endpoints used for autonomous C2 orchestration.
    from:
      kind: article
      observed: '2026-09-24'
      ref: https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malware_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    - 540080fea97d88ed902c5e4f9a026b4fcd32ab263706c520e00728f1a29578b8
    - cfa1997682e4ed41bc691ba848d845abbe0b75ec97e640c2b015b4d1624a108a
    - 38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55
    description: Hashes for CLOSEDQUORUM and associated tools.
    from:
      kind: article
      observed: '2026-09-24'
      ref: talos
    type: list[hash]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value developer workstations and servers that might host
  sensitive data or research, as these are primary targets for AI-driven elicitation
  and exfiltration.
references:
- name: "Talos \u2014 Trust and the enticing consultancy offer"
  url: https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/
related:
- hunt: social-engineering-elicitation-on-saas
  reason: The social engineering phase on social media platforms is out of scope and
    requires identity/browser-based telemetry.
  relation: out-of-scope-alternative
- hunt: socially-engineered-endpoint-infection-evasion
  relation: follows
scenario:
  stages:
  - name: Consultancy and Job Lure
    observables:
    - Social media messages offering $300/hour for consultancy
    - Sparse consultant profiles with no employer footprint
    - Fake job offers requiring candidate software installation
    slug: social-engineering-elicitation
    tactic: initial-access
    techniques:
    - T1566
  - name: Execution of Trojanised Installer
    observables:
    - Fake LastPass Authenticator installers
    - SECOH-QAD.exe
    - KMSAuto.exe
    - sample.exe
    - f_000bc7.exe
    - content.js
    - Distribution via GitHub repositories
    slug: trojanised-software-execution
    tactic: execution
    techniques:
    - T1204
    - T1566
  - name: Kernel-Level Security Evasion
    observables:
    - Rapuncel kernel-level EDR killer payload
    - Disabling of remote access and alarms
    slug: defense-evasion-edr-killer
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Rapuncel Infostealing
    observables:
    - Rapuncel stealer searching for credentials
    - Accessing protected systems via found credentials
    slug: credential-access-infostealer
    tactic: credential-access
    techniques:
    - T1555
  - name: Autonomous AI-Driven C2
    observables:
    - CLOSEDQUORUM malware binary
    - Delegation of actions to LLM panels via API calls
    - Autonomous C2 decision making
    slug: command-and-control-autonomous-ai
    tactic: command-and-control
    techniques:
    - T1071
  - name: Data Encryption and Impact
    observables:
    - Qilin ransomware incidents
    - The Gentlemen leak-site listings
    - Encryption of files and manipulation of pumping cycles in utility systems
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: This social engineering campaign targets technical professionals with fake
    consultancy and job offers to distribute trojanised software via platforms like
    GitHub. Successful infections deploy kernel-level EDR killers and 'Rapuncel' infostealers,
    while advanced variants utilize 'CLOSEDQUORUM' for autonomous AI-driven command-and-control
    before final ransomware deployment.
series:
  index: 2
  slug: trust-and-the-enticing-consultancy-offer
  title: Trust and the enticing consultancy offer
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


# Autonomous AI Command-and-Control and Impact

This hunt targets the emerging threat of AI-integrated malware, specifically focusing on the CLOSEDQUORUM implant which delegates C2 decisions to Large Language Models. The hunt identifying suspicious processes matching known malware hashes or fileless execution states, then fanning out to look for connections to AI infrastructure and evidence of ransomware-style file encryption (Qilin). An agent weighs the combined telemetry to differentiate between benign AI research tools and malicious autonomous agents.

## suspicious-process-lead
<!-- Processes matching malware hashes or fileless state -->
Identify potential AI-driven C2 implants based on known hashes or evidence of injection.

```sqlite target=endpoint role=detection-candidate params=(malware_hashes=malware_hashes, lookback_days=lookback_days)
~~~yaml
expected: A process matching a known hash or running without a backing file on disk.
  Silence proves these specific indicators are not running.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_hash_sha256
- user_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_hash_sha256, user_name, on_disk, time FROM hb_process_activity WHERE (instr(',' || '{{malware_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR on_disk = 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate C2 and Impact -->
parallel:
- → rare-ai-infrastructure-dns
- → high-volume-encryption-activity
join: → triage-ai-threat

## rare-ai-infrastructure-dns
<!-- Rare DNS queries to AI API endpoints -->
Identify processes communicating with AI services that are not widespread in the fleet.

```sqlite target=endpoint role=baseline params=(ai_api_domains=ai_api_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes on a few hosts talking to LLM APIs; common usage by developers
  will be filtered by the host count.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT query_hostname, process_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{ai_api_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname, process_name HAVING host_count <= 3
```

## high-volume-encryption-activity
<!-- High-volume file modification activity -->
Detect the impact phase where the malware encrypts local files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A single process touching hundreds of files on a host. Benign processes
  like indexers or updates may appear but will be weighed by the agent.
reads:
- device_hostname
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, COUNT(*) as file_count, MIN(time) as start_time FROM hb_file_activity WHERE activity_id IN (1, 3, 4, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_count > 100
```

## triage-ai-threat
<!-- Weigh AI C2 and Encryption -->
```agent target=hunter
cite: required
context:
- suspicious-process-lead
- rare-ai-infrastructure-dns
- high-volume-encryption-activity
max_iterations: 4
objective: Assess if processes matching known hashes or injected states are communicating
  with AI services and subsequently encrypting files, indicating an autonomous AI
  C2 infection.
success_criteria: A verdict of malicious | suspicious | benign citing specific process,
  DNS, and file activity rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-ai-threat verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: no-process-visibility)
else: → analyst-final-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve memory for forensic analysis of the CLOSEDQUORUM implant.
```
→ analyst-final-review

## analyst-final-review
<!-- Analyst final review -->
```manual target=analyst
Review the DNS queries and file modification counts. Confirm if the AI API usage is consistent with C2 delegation described in the research.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document false positives (e.g., local LLM development) and ensure the detection candidate is promoted if effective.
```
→ end
