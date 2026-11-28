---
analysis: A standard rule might detect large uploads, but this hunt pivots between
  high-frequency HTTP traffic, fileless process state (on_disk = 0), and network baseline
  deviations to distinguish an intrusion from legitimate AI usage.
blind_spots:
- id: no-http-telemetry
  question: Whether the host initiated the connection via a non-HTTP protocol or encrypted
    tunnel.
  requires: hb_http_activity or proxy logs
  risk: A host connecting to a malicious AI skill repository via an SSH tunnel would
    be missed in the initial gate.
  stage: initial-access-ai-enhanced-phishing-and-exploitation
- id: no-endpoint-telemetry
  question: Whether the malicious runtime hijack was fileless or executed from memory.
  requires: hb_process_activity with on_disk state
  risk: Without endpoint-level 'on_disk' data, fileless persistence within an AI interpreter
    is indistinguishable from legitimate process execution.
  stage: persistence-ai-runtime-abuse
coverage:
- stage: initial-access-ai-enhanced-phishing-and-exploitation
  status: covered
  steps:
  - ai-service-leads
  - assess-traffic-volume
- stage: persistence-ai-runtime-abuse
  status: covered
  steps:
  - ai-runtime-anomalies
- stage: exfiltration-automated-data-theft
  status: covered
  steps:
  - exfiltration-volume
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: execution-malicious-ai-skills
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI adoption is outpacing governance; this hunt identifies the misuse
    of AI runtimes and exfiltration channels that bypass traditional signature-based
    detection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised AI runtimes to maintain persistence
  and automate the exfiltration of sensitive data to AI skill repositories.
labels:
- hunt
- attack.t1041
- attack.t1190
- attack.t1566
- attack.t1543
- execution
- exfiltration
- initial access
- persistence
name: AI-Driven Persistence and Automated Data Theft
parameters:
  ai_parent_processes:
    default:
    - chrome.exe
    - firefox.exe
    - msedge.exe
    - gemini.exe
    - python.exe
    - python3.exe
    description: Common parent processes for AI runtimes and browsers.
    from:
      kind: manual
      observed: '2026-06-15'
      ref: promptspy-persistence-research
    type: list[string]
  ai_service_domains:
    default:
    - openai.com
    - anthropic.com
    - gemini.google.com
    - huggingface.co
    - mistral.ai
    description: Known AI provider and skill repository domains.
    from:
      kind: article
      observed: '2026-05-01'
      ref: eset-research-2026
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping lead; leave empty to scan the full
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/cyberthreats-moving-faster-smbs-readiness-must-accelerate/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin by scanning all endpoints for high-frequency AI domain traffic. Focus
  on departments likely to use AI, such as Engineering (coding assistants) and Marketing
  (content generation), as they are primary targets for AI-based persistence and data
  theft.
references:
- name: 'Cyberthreats are moving faster than SMBs: Readiness must accelerate'
  url: https://www.welivesecurity.com/en/business-security/cyberthreats-moving-faster-smbs-readiness-must-accelerate/
related:
- hunt: malicious-ai-skill-execution
  reason: This hunt focuses on runtime hijacks (PromptSpy), while execution of malicious
    plugins belongs in a hunt targeting container and dependency scanning.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Enhanced Phishing and Exploitation
    observables:
    - automated social media reconnaissance
    - personalized phishing messages in local languages
    - rapid exploitation of N-day vulnerabilities in public applications
    - prompt injection via chatbots
    slug: initial-access-ai-enhanced-phishing-and-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1566
  - name: Execution via Malicious AI Skills
    observables:
    - malicious AI skills/plugins
    - download of secondary malware payloads
    - suspicious agent instructions causing unintended actions
    slug: execution-malicious-ai-skills
    tactic: execution
    techniques:
    - T1204.002
  - name: AI Engine Runtime Persistence
    observables:
    - abuse of Google Gemini runtime for persistent execution
    - AI-powered spyware (PromptSpy) persistence mechanisms
    slug: persistence-ai-runtime-abuse
    tactic: persistence
    techniques:
    - T1543
  - name: Automated Data Exfiltration
    observables:
    - data exfiltration over existing C2 channels
    - AI-driven classification and extraction of stolen data
    - high-volume traffic to AI skills repositories
    slug: exfiltration-automated-data-theft
    tactic: exfiltration
    techniques:
    - T1041
  summary: Threat actors are leveraging AI to automate victim reconnaissance, accelerate
    exploit development for public-facing applications, and conduct high-volume personalized
    phishing. The intrusion lifecycle involves the deployment of malicious AI skills
    or plugins that execute malware and exfiltrate data via automated classification
    agents.
severity: medium
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI-Driven Persistence and Automated Data Theft

This hunt identifies the misuse of AI ecosystem components, such as hijacked Google Gemini runtimes and malicious AI skill repositories. It uses a gated flow to first identify hosts with high-frequency AI service interactions before performing deeper process-level and network-volume forensics. The hunt focuses on detecting 'PromptSpy' style persistence where malicious code runs within an AI interpreter and exfiltrates data at scale.

## ai-service-leads
<!-- High-frequency AI service interactions -->
Identify hosts with unusual volumes of HTTP traffic to AI providers as a lead for automated agent abuse.

```sqlite target=web role=scoping params=(lookback_days=lookback_days, ai_service_domains=ai_service_domains)
~~~yaml
expected: Hosts with high request counts suggest automated activity rather than manual
  chat. Silence indicates no large-scale AI service usage observed in HTTP logs.
reads:
- device_hostname
- url_hostname
- user_agent
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, url_hostname, COUNT(*) AS request_count, user_agent, MIN(time) AS first_request, MAX(time) AS last_request FROM hb_http_activity WHERE instr(',' || '{{ai_service_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, user_agent HAVING request_count > 100 ORDER BY request_count DESC
```

## assess-traffic-volume
<!-- Assess traffic automation -->
```agent target=hunter
cite: required
context:
- ai-service-leads
max_iterations: 3
objective: Review the request counts and user agents from ai-service-leads. Mark hosts
  as suspicious if they show persistent, high-frequency requests or use non-standard
  browser user agents.
success_criteria: A per-host verdict of suspicious or benign.
tools:
- endpoint
- network
- web
```

## gate-decision
<!-- Gate: Pursue forensics? -->
if~: "The assessment identifies at least one host where AI interaction is likely automated or malicious." (confidence: medium, judge=hunter)
then: → forensic-fan-out
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: no-http-telemetry)
else: → close-out-report

## forensic-fan-out
<!-- Endpoint and network fan-out -->
parallel:
- → ai-runtime-anomalies
- → exfiltration-volume
join: → final-triage

## ai-runtime-anomalies
<!-- AI runtime process anomalies -->
Identify processes with no binary on disk running under AI-related parents, characteristic of PromptSpy.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, ai_parent_processes=ai_parent_processes, scope_hosts=scope_hosts)
~~~yaml
expected: A process launched from a browser or AI runtime that has since been deleted
  from disk. This is a high-confidence signal for fileless execution.
reads:
- device_hostname
- process_name
- parent_process_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, on_disk, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{ai_parent_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{ai_parent_processes}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (on_disk = 0 OR on_disk = 'false') AND time >= datetime('now', '-{{lookback_days}} days')
```

## exfiltration-volume
<!-- Massive data exfiltration to AI -->
Establish a baseline and identify hosts sending unusually large volumes of data to AI domains.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, ai_service_domains=ai_service_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: Hosts sending more than 50MB to AI domains. Silence suggests no bulk exfiltration
  occurred via these endpoints during the window.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_hostname
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_hostname
- traffic_bytes
- direction
- state_kind
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, dst_endpoint_hostname, SUM(traffic_bytes) AS total_out_bytes, COUNT(*) AS session_count FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{ai_service_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_hostname HAVING total_out_bytes > 50000000
```

## final-triage
<!-- Final intrusion triage -->
```agent target=hunter
cite: required
context:
- assess-traffic-volume
- ai-runtime-anomalies
- exfiltration-volume
max_iterations: 6
objective: Review the correlated evidence. Confirm a malicious verdict if a host shows
  suspicious traffic automation (from assess-traffic-volume), a fileless process anomaly
  (from ai-runtime-anomalies), and a matching exfiltration spike to an AI domain (from
  exfiltration-volume).
success_criteria: A verdict of malicious, suspicious, or benign citing specific event
  rows.
tools:
- endpoint
- network
- web
```

## final-route
<!-- Route for containment -->
if~: "The final triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: no-endpoint-telemetry)
else: → close-out-report

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all active session tokens for AI services (OpenAI, Gemini) used on this device.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Analyst confirmation -->
```manual target=analyst
Review the cited process and network volume rows. Verify if the 'on_disk = 0' process correlates with the network spike to the AI provider. Determine if this represents a rogue AI agent or a legitimate developer activity.
```
→ close-out-report

## close-out-report
<!-- Close out report -->
```manual target=analyst
Summarize the findings. Note any legitimate automated AI tasks that should be excluded from future runs. Update the corporate AI policy if shadow AI usage was discovered.
```
→ end
