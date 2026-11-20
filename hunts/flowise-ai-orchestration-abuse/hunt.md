---
analysis: 'A single rule could fire on access to /api/v1/credentials, but this hunt
  correlates the phased chain: initial fingerprinting, secret harvesting, and the
  semantic abuse of prompts targeting internal resources. This correlation is necessary
  to distinguish an active intrusion from legitimate developer activity.'
blind_spots:
- id: encrypted-http-bodies
  question: whether the 'log_line' column in hb_http_activity contains the request
    body
  requires: TLS decryption at a proxy or application-level request logging
  risk: If traffic is encrypted and the body is not captured, the semantic intent
    of LLM prompts (hijacking) remains invisible, leaving only URL-path metadata.
  stage: unauthenticated-api-reconnaissance
- id: agent-network-isolation
  question: whether the AI server successfully queried internal IPs like 10.0.0.5
  requires: internal VPC flow logs or host-based firewall logs
  risk: If only internet-facing logs are collected, the agent's internal reconnaissance
    against internal databases remains hidden.
  stage: llm-agent-hijacking
coverage:
- stage: vulnerability-inventory
  status: covered
  steps:
  - scope-flowise-hosts
- stage: unauthenticated-api-reconnaissance
  status: covered
  steps:
  - api-recon-and-exfiltration
- stage: credential-harvesting-exfiltration
  status: covered
  steps:
  - api-recon-and-exfiltration
- stage: chatflow-manipulation-callback
  status: covered
  steps:
  - anomalous-outbound-connections
  - llm-hijacking-and-manipulation
- stage: llm-agent-hijacking
  status: covered
  steps:
  - llm-hijacking-and-manipulation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI orchestration platforms bridge the gap between external users
    and internal data vaults; a breach here allows an attacker to bypass traditional
    security boundaries by proxying their intent through the AI model itself.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting unauthenticated Flowise instances to harvest
  stored API credentials and hijack AI agents for internal network reconnaissance
  and financial data exfiltration.
labels:
- hunt
- attack.t1190
- attack.t1041
- attack.t1505.003
- attack.t1552.001
- credential access
- discovery
- exfiltration
- initial access
- persistence
name: Abuse of Flowise AI Orchestration Platforms
parameters:
  callback_ips:
    default:
    - 154.217.251.226
    description: Attacker callback infrastructure identified in the report.
    from:
      kind: article
      observed: '2026-08-30'
      ref: sekoia-flowise-2026
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to restrict the hunt to; leave empty for the whole
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/a-honeypots-tale-deconstructing-an-attack-on-genai-infrastructure
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying hosts with Flowise installed. If no software inventory
  match is found, widen the search to any internal server running Node.js with high
  outbound HTTP traffic volume to AI model providers.
references:
- name: "Sekoia \u2014 Sekoia Honeypot Captures an Attack on GenAI Infrastructure"
  url: https://www.sekoia.com/blog/a-honeypots-tale-deconstructing-an-attack-on-genai-infrastructure
related:
- hunt: prompt-injection-reconnaissance
  reason: This hunt focuses on the compromise of the Flowise platform itself, while
    prompt injection is a broader concern for any LLM-based application.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Flowise Vulnerability Assessment
    observables:
    - Flowise version 2.2.8
    - CVE-2024-31621
    - CVE-2025-59528
    - CVE-2026-41264
    slug: vulnerability-inventory
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthenticated API Reconnaissance
    observables:
    - GET /api/v1/ping
    - GET /api/v1/version
    - GET /api/v1/node-configs
    - GET /api/v1/chatflows
    slug: unauthenticated-api-reconnaissance
    tactic: discovery
    techniques:
    - T1190
  - name: Credential Harvesting and Exfiltration
    observables:
    - GET /api/v1/credentials
    - GET /credentials/{uuid}
    slug: credential-harvesting-exfiltration
    tactic: credential-access
    techniques:
    - T1552.001
  - name: Chatflow Manipulation and Persistent Callback
    observables:
    - POST /api/v1/chatflows/
    - 'chatflow name: System Status'
    - http://154.217.251.226:19999/flowise-hb
    slug: chatflow-manipulation-callback
    tactic: persistence
    techniques:
    - T1505.003
  - name: LLM Agent Hijacking and Internal Probing
    observables:
    - /prediction/{id}
    - /chatflows/{id}/prediction
    - query targeting 10.0.0.5
    - 'prompt: query the RAG store'
    - 'prompt: list all financial records'
    slug: llm-agent-hijacking
    tactic: exfiltration
    techniques:
    - T1041
    - T1567
  summary: A threat actor, likely Chinese-speaking, targeted unauthenticated Flowise
    AI orchestration servers to perform automated reconnaissance and exfiltrate API
    credentials. The campaign involved the creation of malicious chatflows for persistent
    callbacks and attempts to hijack LLM agents to exfiltrate financial data from
    internal databases.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Abuse of Flowise AI Orchestration Platforms

Flowise AI orchestration servers are high-value targets because they consolidate API keys for LLMs and maintain bridges into internal data via RAG pipelines. This hunt follows a phased flow: first, it identifies hosts running Flowise and examines them for unauthenticated API reconnaissance and secret exfiltration; second, it looks for anomalous outbound callbacks to reported attacker infrastructure; third, it analyzes inference logs for malicious prompts that attempt to manipulate the agent into probing internal systems. An agent correlates the early discovery with the follow-on abuse to identify successful platform breaches.

## scope-flowise-hosts
<!-- Identify Flowise Orchestration Instances -->
Find hosts running the Flowise package to define the search space for the rest of the hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running Flowise. If no hosts are returned, the estate may
  not use this specific AI orchestration platform.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT DISTINCT device_hostname, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%flowise%'
```

## early-stage-parallel
<!-- Examine Early-Stage Evidence -->
parallel:
- → api-recon-and-exfiltration
- → anomalous-outbound-connections
join: → early-stage-triage

## api-recon-and-exfiltration
<!-- API Reconnaissance and Secret Access -->
Detect successful GET requests to sensitive Flowise endpoints that expose version data and credentials.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Successful GET requests to credential and metadata routes suggest an attacker
  is harvesting secrets.
reads:
- device_hostname
- url_path
- status_code
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, url_path, status_code, http_method, COUNT(*) as request_count, MIN(time) as first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/api/v1/ping%' OR LOWER(url_path) LIKE '%/api/v1/version%' OR LOWER(url_path) LIKE '%/api/v1/node-configs%' OR LOWER(url_path) LIKE '%/api/v1/chatflows%' OR LOWER(url_path) LIKE '%/api/v1/credentials%' OR LOWER(url_path) LIKE '%/credentials/%') AND status_code = 200 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path, status_code, http_method
```

## anomalous-outbound-connections
<!-- Anomalous Outbound Network Callbacks -->
Identify outbound connections to known attacker infrastructure or rare high ports from the AI servers.

```sqlite target=network role=baseline params=(callback_ips=callback_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound connections to the reported IPs or on port 19999 indicate the creation
  of a persistent callback channel.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{callback_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 19999) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port
```

## early-stage-triage
<!-- Early-Stage Evidence Triage -->
```agent target=hunter
cite: required
context:
- scope-flowise-hosts
- api-recon-and-exfiltration
- anomalous-outbound-connections
max_iterations: 3
objective: Determine if any host has been successfully fingerprinted and established
  a callback to the reported attacker infrastructure.
success_criteria: A per-host verdict citing specific API paths and network destinations.
tools:
- endpoint
- network
- web
```

## llm-hijacking-and-manipulation
<!-- LLM Agent Hijacking and Manipulation -->
Analyze HTTP request payloads for attempts to modify chatflows or hijack the agent via malicious prompts.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Requests containing keywords like 'system status', 'financial', or 'RAG'
  in the payload indicate the agent is being manipulated to exfiltrate internal data.
reads:
- device_hostname
- url_path
- http_method
- log_line
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-20'
~~~
SELECT device_hostname, url_path, http_method, log_line, time FROM hb_http_activity WHERE (http_method IN ('POST', 'PUT', 'PATCH')) AND (LOWER(url_path) LIKE '%/prediction%' OR LOWER(url_path) LIKE '%/chatflows%') AND (LOWER(log_line) LIKE '%system status%' OR LOWER(log_line) LIKE '%154.217.251.226%' OR LOWER(log_line) LIKE '%rag%' OR LOWER(log_line) LIKE '%financial%' OR LOWER(log_line) LIKE '%10.0.0.5%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-compromise-assessment
<!-- Final Compromise Assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- llm-hijacking-and-manipulation
max_iterations: 4
objective: Decide whether the observed activity constitutes a successful breach and
  hijacking of the Flowise orchestration platform.
success_criteria: A final verdict per host citing the sequence of reconnaissance,
  callback creation, and malicious prompting.
tools:
- endpoint
- network
- web
```

## route-on-compromise
<!-- Route on Compromise Verdict -->
if~: "the final-compromise-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: encrypted-http-bodies)
else: → remediation-and-hardening

## isolate-compromised-host
<!-- Isolate Compromised Flowise Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified Flowise host to prevent the attacker from using the LLM agent to probe internal systems (e.g., 10.0.0.5) or exfiltrate RAG data.
```
→ revoke-leaked-credentials

## revoke-leaked-credentials
<!-- Revoke and Rotate Leaked Credentials -->
```manual target=analyst
Flowise stores API keys (OpenAI, Anthropic) and database connection strings. Rotate every credential found in the Flowise store of the affected host.
```
→ remediation-and-hardening

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the hb_http_activity log_line for the identified hosts; look for prompts attempting to list financial data or probe internal network resources that the agent may have flagged as indeterminate.
```
→ remediation-and-hardening

## remediation-and-hardening
<!-- Remediation and Hardening -->
```manual target=analyst
Update Flowise to version 3.1.0 or later to ensure authentication is enforced on all API routes. Place the instance behind a WAF or restrict network access to a management IP whitelist.
```
→ end
