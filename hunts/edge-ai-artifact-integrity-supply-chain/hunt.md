---
analysis: A standard detection rule might flag a Tor domain; this hunt combines host-based
  inventory context with file-integrity behavior (tampering with weights) and network
  prevalence to find novel, AI-specific threats that are not yet signatures.
blind_spots:
- id: endpoint-telemetry-gap
  question: Are all proprietary AI gateways or embedded systems enrolled?
  requires: endpoint agent on all Edge hardware
  risk: IoT or specialized hardware without agents will not report file or network
    activity, leaving supply chain tampering invisible.
- id: encrypted-c2-blending
  question: Is exfiltration blending with legitimate model-provider update traffic?
  requires: process-to-url correlation on hb_http_activity
  risk: Data stolen via authorized HTTPS endpoints or cloud storage (e.g., Azure Blob/AWS
    S3) may pass volume checks if the process identity is not verified.
  stage: exfiltration-over-c2
coverage:
- stage: initial-access-supply-chain
  status: covered
  steps:
  - identify-ai-hosts
  - model-artifact-tampering
- stage: execution-model-tampering
  status: covered
  steps:
  - model-artifact-tampering
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - proxy-dns-patterns
- stage: exfiltration-over-c2
  status: covered
  steps:
  - bulk-egress-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Edge AI environments are outside the direct control of providers
    and store sensitive model IP and data. Verifying the integrity of artifacts at
    rest and the legitimacy of runtime behavior is a critical customer obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised the Edge AI supply chain or tampered with
  local model artifacts, using multi-hop proxies to exfiltrate sensitive model weights
  or credentials.
labels:
- hunt
- attack.t1195
- attack.t1041
- attack.t1090.003
name: Edge AI Artifact Integrity and Supply Chain
parameters:
  ai_runtime_packages:
    default:
    - pytorch
    - tensorflow
    - ollama
    - vllm
    - onnx
    - huggingface
    - torch
    - llama-cpp
    description: List of known AI software packages to identify scope.
    from:
      kind: article
      observed: '2026-09-04'
      ref: msrc-edge-ai
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to scope the hunt; empty for all.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-defined
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hosts running PyTorch, Ollama, or TensorFlow as identified via
  software inventory. Exclude development machines if possible to reduce noise from
  legitimate experimentation.
references:
- name: "MSRC \u2014 How to secure edge AI in customer-owned environments"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/04/secure-edge-ai-customer-owned-environments/
related:
- hunt: unauthorized-inference-monitoring
  reason: This hunt focuses on artifact tampering and exfiltration; unauthorized model
    execution requires monitoring for gpu/npu resource utilization or unauthorized
    agent shells.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Supply Chain Compromise
    observables:
    - Malicious firmware updates
    - Tampered model artifacts
    - Infected software packages
    - Modified tool descriptors
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: Model Behavior Manipulation
    observables:
    - Modification of model weights
    - Changes to agent definitions
    - Injection of poisoned retrieval documents
    - Unauthorized updates to local data stores
    slug: execution-model-tampering
    tactic: execution
    techniques:
    - T1195
  - name: Multi-hop Proxy C2
    observables:
    - Connections to Tor exit nodes
    - Onion domain DNS queries
    - Encrypted traffic through VPS/ORB networks
    - Multi-hop proxy chains
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Exfiltration over C2 Channel
    observables:
    - Bulk outbound data transfer from AI runtimes
    - Theft of model weights via existing C2
    - Data encoded in normal protocol traffic
    - Exfiltration of credentials or keys
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Attackers target edge AI environments by compromising the supply chain
    with malicious firmware or model updates, then use prompt injection or tampered
    artifacts to steer model behavior. Once control is established, sensitive assets
    including model weights and customer data are exfiltrated over proxied command-and-control
    channels.
severity: medium
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


# Edge AI Artifact Integrity and Supply Chain

As organizations move AI model execution to the edge, the trust boundary shifts to customer-owned infrastructure. This hunt identifies systems running AI runtimes and monitors for two critical threats: the modification of sensitive AI artifacts (weights, configurations, and agent definitions) by unauthorized processes, and the exfiltration of these assets. We use high-volume network egress and proxy-related DNS activity to corroborate potential data theft and command-and-control masking via Tor or ORB networks.

## identify-ai-hosts
<!-- Identify hosts with AI runtimes -->
Find systems running AI libraries or engines to establish the behavioral scope.

```sqlite target=endpoint role=scoping params=(ai_runtime_packages=ai_runtime_packages)
~~~yaml
expected: A list of hosts likely acting as inference nodes. Silence means no recognized
  AI stack is present via managed inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE instr(',' || '{{ai_runtime_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## corroborate-behavior
<!-- Corroborate behavior across surfaces -->
parallel:
- → model-artifact-tampering
- → bulk-egress-prevalence
- → proxy-dns-patterns
join: → triage-signals

## model-artifact-tampering
<!-- Model artifact tampering -->
Detect modifications to model weights or configurations by identifying writes to sensitive AI file extensions.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unauthorized processes modifying model files. Writes from rare processes
  or shells are suspicious.
reads:
- device_hostname
- process_name
- file_name
- file_path
- activity_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_name, file_path, activity_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (1, 3, 5) AND (LOWER(file_name) LIKE '%.safetensors' OR LOWER(file_name) LIKE '%.pt' OR LOWER(file_name) LIKE '%.pth' OR LOWER(file_name) LIKE '%.onnx' OR LOWER(file_name) LIKE '%.weights' OR LOWER(file_name) LIKE '%.bin' OR LOWER(file_name) LIKE '%.gguf') AND time >= datetime('now', '-{{lookback_days}} days')
```

## bulk-egress-prevalence
<!-- Bulk network egress prevalence -->
Identify high-volume or rare outbound data transfers indicative of weight or credential theft.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound transfers exceeding 50MB to rare destination IPs from Edge AI nodes.
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
- direction
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE state_kind = 'log' AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip HAVING total_bytes > 52428800 ORDER BY total_bytes DESC
```

## proxy-dns-patterns
<!-- Proxy and multi-hop DNS activity -->
Identify C2 masking via Tor or onion services on AI-enabled hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolution of onion domains or proxy services, which are atypical for
  inference workloads.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as query_count FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%exitnode%' OR LOWER(query_hostname) LIKE '%.tor%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## triage-signals
<!-- Triage AI artifact integrity -->
```agent target=hunter
cite: required
context:
- identify-ai-hosts
- model-artifact-tampering
- bulk-egress-prevalence
- proxy-dns-patterns
max_iterations: 5
objective: Determine if unauthorized processes modified AI model artifacts and whether
  that coincided with high-volume outbound traffic or proxy DNS activity. Distinguish
  between standard software updates and potential supply chain/local tampering.
success_criteria: A per-host verdict of Malicious | Suspicious | Benign with row citations.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving suspicious artifact modification and concurrent data egress" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Edge AI node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke credentials used by the AI runtime service account. Collect model weights for hash verification.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the processes that modified model files. Check for evidence of 'poisoned' retrieval documents or unauthorized weight updates. Determine if the egress IP belongs to a legitimate vendor or a multi-hop proxy.
```
→ end

## close-out
<!-- Close hunt and record baseline -->
```manual target=analyst
Record the hosts with AI software and the integrity status of their model artifacts. Update the 'known-good' baseline for future hunts.
```
→ end
