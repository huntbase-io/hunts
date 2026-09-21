---
analysis: A single rule may find a known prompt injection keyword, but this hunt correlates
  those signals with supply-chain artifact changes and memory-resident code execution
  on the specific nodes running AI software, providing a context-aware view of a complex
  attack chain.
blind_spots:
- id: missing-flow-data
  question: Was data exfiltrated via a management or secondary interface not monitored
    by flow logs?
  requires: hb_network_connection with byte counts from all secondary interfaces
  risk: Exfiltration volume cannot be accurately assessed if only the primary interface
    is logged.
  stage: obfuscated-c2-and-exfiltration
- id: http-body-blindness
  question: Did the prompt injection occur in the POST body rather than the URL?
  requires: Full HTTP POST body logging
  risk: Many prompt injections are delivered in JSON bodies; if only URL components
    are visible, the attack will be missed.
  stage: malicious-model-manipulation
coverage:
- stage: supply-chain-compromise-artifacts
  status: covered
  steps:
  - model-artifact-tampering
- stage: malicious-model-manipulation
  status: covered
  steps:
  - prompt-injection-signals
- stage: sensitive-asset-theft
  status: covered
  steps:
  - injected-processes
- stage: obfuscated-c2-and-exfiltration
  status: covered
  steps:
  - bulk-exfiltration
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Edge AI environments hold high-value proprietary model weights and
    sensitive local data; a negative result for artifact poisoning and exfiltration
    provides confidence in the integrity of these autonomous systems.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised the Edge AI supply chain to poison model
  artifacts, then manipulated those models via prompt injection to exfiltrate sensitive
  weights and credentials over high-volume network channels.
labels:
- hunt
- attack.t1195
- attack.t1204.002
- attack.t1528
- attack.t1552
- attack.t1090.003
- attack.t1041
name: Edge AI Artifact Integrity and Data Exfiltration
parameters:
  ai_software_keywords:
    default:
    - pytorch
    - tensorflow
    - ollama
    - cuda
    - npu
    - tensorrt
    - llama
    - onnx
    description: Keywords to identify AI-related software packages on edge devices.
    type: list[string]
  injection_signatures:
    default:
    - ignore prior instructions
    - system prompt
    - dan mode
    - jailbreak
    - developer mode
    description: Common keywords used in prompt injection attacks.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  model_file_paths:
    default:
    - /opt/ai/model.bin
    - /var/lib/ollama/weights.pt
    - C:\\ProgramData\\AI-Models\\config.json
    description: Specific high-value AI model weight or configuration paths to monitor.
    type: list[path]
  scope_hosts:
    default: []
    description: Specific hostnames to focus the hunt on; leave empty to use results
      from the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/04/secure-edge-ai-customer-owned-environments/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should focus on devices identified as AI edge nodes, such as medical
  imaging gateways or industrial controllers with dedicated NPUs/GPUs.
references:
- name: How to secure edge AI in customer-owned environments
  url: https://www.microsoft.com/en-us/security/blog/2026/09/04/secure-edge-ai-customer-owned-environments/
related:
- hunt: ai-agent-autonomous-execution-hijack
  reason: This hunt focuses on data exfiltration; lateral movement via hijacked agent
    tool calls is a separate behavioral chain.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Supply chain compromise of AI artifacts
    observables:
    - Malicious firmware updates
    - Tampered model weights
    - Unsigned binaries in model distribution channels
    - Poisoned model artifacts in local storage
    slug: supply-chain-compromise-artifacts
    tactic: initial-access
    techniques:
    - T1195
  - name: Model behavior manipulation via poisoned input
    observables:
    - Prompt injection payloads in HTTP requests
    - Poisoned retrieval documents (RAG)
    - Malicious agent instructions
    - Unsafe tool calls initiated by AI agents
    slug: malicious-model-manipulation
    tactic: execution
    techniques:
    - T1204.002
  - name: Theft of sensitive AI assets and credentials
    observables:
    - Theft of decrypted model weights from memory or GPU buffers
    - Access to credentials stored in local environment
    - Unprotected accelerator path access (GPU/NPU drivers)
    - Modification of retrieval indexes
    slug: sensitive-asset-theft
    tactic: credential-access
    techniques:
    - T1528
    - T1552
  - name: Obfuscated C2 and asset exfiltration
    observables:
    - Tor network traffic to .onion domains
    - Multi-hop proxy connections (ngrok, tunneling)
    - Bulk exfiltration of large model weight files
    - DNS queries for hidden services
    slug: obfuscated-c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1041
  summary: Edge AI environments are targeted by compromising the supply chain of model
    weights and firmware, followed by runtime manipulation via prompt injection or
    poisoned retrieval data. Attackers then leverage access to the local infrastructure
    to steal decrypted credentials, model IP, and sensitive data, exfiltrating these
    assets through multi-hop proxies like Tor to evade detection in disconnected or
    sovereign environments.
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


# Edge AI Artifact Integrity and Data Exfiltration

This hunt examines the end-to-end lifecycle of an Edge AI compromise using a phased approach. It first identifies hosts running AI workloads and searches for evidence of model artifact tampering and prompt injection attempts. The second phase investigates follow-on activity, specifically focusing on memory-resident (fileless) code execution and large-scale outbound data transfers that suggest the exfiltration of proprietary model weights or local credentials. An agent correlates the early manipulation with the eventual exfiltration to provide a high-confidence verdict.

## identify-ai-hosts
<!-- Identify Edge AI infrastructure -->
Identify hosts that have AI-related software or drivers installed to define the hunt scope.

```sqlite target=endpoint role=scoping params=(ai_software_keywords=ai_software_keywords)
~~~yaml
expected: A list of hostnames identified as Edge AI nodes. Silence means no hosts
  match the criteria.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{ai_software_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0) AND asset_scope = 'endpoint'
```

## parallel-early
<!-- Check for model tampering and injection -->
parallel:
- → model-artifact-tampering
- → prompt-injection-signals
join: → agent-early-triage

## model-artifact-tampering
<!-- Monitor sensitive AI model files -->
Find recent modifications to sensitive AI model weights or configurations on identified hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, model_file_paths=model_file_paths)
~~~yaml
expected: Modifications to protected AI model files on edge nodes. Silence means no
  tracked files were modified.
reads:
- device_hostname
- file_path
- process_name
- activity_id
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, activity_name, time FROM hb_file_activity WHERE instr(',' || '{{model_file_paths}}' || ',', ',' || file_path || ',') > 0 AND activity_id IN (1, 3) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## prompt-injection-signals
<!-- Identify prompt injection signatures -->
Find HTTP requests targeting AI service endpoints that contain known prompt injection keywords.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, injection_signatures=injection_signatures)
~~~yaml
expected: Inbound HTTP traffic containing injection payloads. Silence proves absence
  only for the tracked signatures.
reads:
- device_hostname
- url_query
- http_method
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_query, http_method, src_endpoint_ip, time FROM hb_http_activity WHERE instr(',' || '{{injection_signatures}}' || ',', ',' || LOWER(url_query) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Evaluate early manipulation -->
```agent target=hunter
cite: required
context:
- model-artifact-tampering
- prompt-injection-signals
max_iterations: 3
objective: Determine if any host shows evidence of model poisoning followed by malicious
  instruction inputs.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  HTTP and file events.
tools:
- endpoint
- network
- web
```

## parallel-late
<!-- Check for theft and exfiltration -->
parallel:
- → injected-processes
- → bulk-exfiltration
join: → agent-final-assessment

## injected-processes
<!-- Identify fileless code execution -->
Find processes with on_disk=0 on Edge AI hosts, indicating potential memory-resident theft of decrypted assets.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Running processes with no binary on disk, common in weight theft scenarios.
  Silence proves absence of simple fileless execution.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## bulk-exfiltration
<!-- Detect massive outbound transfers -->
Find large outbound network connections from AI hosts that suggest exfiltration of massive model weights.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hosts sending more than 500MB to a single destination IP. Silence proves
  no bulk transfer occurred during the window.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 2
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- direction
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, SUM(traffic_bytes) AS total_bytes FROM hb_network_connection WHERE direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING total_bytes > 500000000 ORDER BY total_bytes DESC
```

## agent-final-assessment
<!-- Final assessment of attack chain -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- injected-processes
- bulk-exfiltration
max_iterations: 4
objective: Determine if any host shows an end-to-end compromise from model manipulation
  to exfiltration.
success_criteria: A final verdict citing the linkage between manipulation signals
  and exfiltration volume.
tools:
- endpoint
- network
- web
```

## decision-route
<!-- Route on final assessment -->
if~: "the final assessment verdict is malicious for exfiltration on at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-flow-data)
else: → analyst-review

## isolate-host
<!-- Isolate Edge AI Node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host to stop active data exfiltration and preserve memory for analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review of AI compromise -->
```manual target=analyst
Verify if the modified model files match known-good vendor hashes and review the prompt injection strings found in the HTTP logs.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the findings and update any legitimate bulk transfer destination IPs to the trusted baseline.
```
→ end
