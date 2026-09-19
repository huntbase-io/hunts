---
analysis: A simple rule might catch 'msr' module loading, but this hunt pivots between
  AI software scoping, HTTP exploitation paths, and database lookup baselines to confirm
  the intent and scope of the AI infrastructure compromise.
blind_spots:
- id: container-introspection-gap
  question: Was /proc/1/environ actually read if the EDR agent only monitors host-level
    process launches?
  requires: EDR visibility into /proc filesystem across container namespaces
  risk: Attackers can steal master keys and credentials from the environment block
    without triggering standard process monitoring rules.
  stage: credential-harvesting-runtime-environment
- id: http-body-blindness
  question: What specific command was injected into the MCP rest endpoint?
  requires: hb_http_activity with full POST body capture
  risk: Without the body content, we can confirm the endpoint was accessed but cannot
    distinguish between a legitimate test and a malicious RCE payload (CVE-2026-42271).
  stage: initial-access-ai-gateway-exploitation
coverage:
- stage: initial-access-ai-gateway-exploitation
  status: covered
  steps:
  - identify-ai-infrastructure
  - mcp-exploitation-attempts
- stage: credential-harvesting-runtime-environment
  status: covered
  steps:
  - environment-secret-harvesting
- stage: database-data-collection-exfiltration
  status: covered
  steps:
  - database-exfiltration-lookups
- stage: compute-monetization-cryptomining
  status: covered
  steps:
  - miner-module-tuning
- stage: relay-persistence-and-c2
  status: covered
  steps:
  - persistence-ssh-keys
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI gateways and RAG platforms are high-value 'control planes' that
    concentrate model provider secrets and sensitive backend database access; a single
    compromise can lead to massive credential exposure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting exposed AI gateway services to harvest runtime
  environment secrets, dump backend model databases, and establish persistence or
  resource hijacking via cryptomining.
labels:
- hunt
- attack.t1190
- attack.t1041
- attack.t1496
- attack.t1090.003
name: AI Infrastructure Control Plane Compromise
parameters:
  ai_package_keywords:
    default:
    - litellm
    - ragflow
    - kestra
    description: Keywords for identifying AI gateway and orchestration software.
    from:
      kind: article
      observed: '2026-08-26'
      ref: msrc-blog
    type: list[string]
  db_host_patterns:
    default:
    - postgres.database.azure.com
    - rds.amazonaws.com
    description: Known database host suffixes or exact domains referenced in the report.
    from:
      kind: article
      observed: '2026-08-26'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts identified in hb_software_inventory as running 'litellm' or
  'ragflow'. Focus on containerized environments (Docker/K8s) where secret theft via
  /proc/1/environ is most effective.
references:
- name: 'MSRC Blog: When AI infrastructure becomes the target'
  url: https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/
related:
- hunt: kestra-orchestration-abuse
  reason: Kestra exploitation involves specific workflow/YAML logic not covered by
    the LiteLLM/RAGFlow process patterns.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI Gateway and Orchestrator Exploitation
    observables:
    - CVE-2026-42271
    - CVE-2026-48710
    - CVE-2026-49869
    - POST /mcp-rest/test/connection
    - POST /mcp-rest/test/tools/list
    - Burp Collaborator callback
    - Starlette host-header bypass
    - Kestra workflow shell execution
    slug: initial-access-ai-gateway-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Gateway Runtime Secret Harvesting
    observables:
    - cat /proc/1/environ
    - grep -E 'master|API key|token|password|UI'
    - Python urllib exfiltration
    - curl exfiltration
    - wget exfiltration
    slug: credential-harvesting-runtime-environment
    tactic: exfiltration
    techniques:
    - T1041
  - name: Backend Database Exfiltration
    observables:
    - postgres.database.azure.com
    - DATABASE_URL
    - LiteLLM_ProxyModelTable
    - LiteLLM_VerificationToken
    - base64-encoded exfiltration chunks
    - python3 database dump one-liner
    slug: database-data-collection-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Resource Hijacking and Mining
    observables:
    - XMRig
    - RandomX CPU tuning
    - modprobe msr allow_writes=1
    - crontab miner cleanup
    - silent passwordless-sudo check
    slug: compute-monetization-cryptomining
    tactic: impact
    techniques:
    - T1496
  - name: Relay Persistence and Multi-hop C2
    observables:
    - hidden-file relay execution
    - authorized_keys SSH modification
    - systemd service name masquerading
    - Python hook in TenantLLM configuration
    - chattr +i immutable attributes
    - out-of-band network callbacks
    slug: relay-persistence-and-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Attackers are targeting exposed AI workloads including LiteLLM gateways,
    RAGFlow retrieval engines, and Kestra orchestrators to exploit their role as centralized
    trust points. The campaign involves exploiting unauthenticated remote code execution
    vulnerabilities to harvest model-provider API keys from environment variables,
    exfiltrate backend database records, and deploy cryptominers while establishing
    persistence via hidden multi-hop proxies and SSH keys.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI Infrastructure Control Plane Compromise

This hunt targets the exploitation of AI orchestration layers including LiteLLM, RAGFlow, and Kestra. It identifies vulnerable AI infrastructure, tracks the transition from initial web-based exploitation of gateway endpoints to the harvesting of provider API keys from the container environment, and monitors for the exfiltration of backend database records. Finally, it corroborates these activities with the deployment of cryptominers that use specialized Model-Specific Register (MSR) tuning and unauthorized SSH key modifications.

## identify-ai-infrastructure
<!-- Identify AI infrastructure -->
Locate hosts running LiteLLM, RAGFlow, or Kestra to scope the hunt to the AI control plane.

```sqlite target=endpoint role=scoping params=(ai_package_keywords=ai_package_keywords)
~~~yaml
expected: A list of hostnames known to be running AI gateway or orchestration software.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{ai_package_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%litellm%' OR LOWER(package_name) LIKE '%ragflow%')
```

## mcp-exploitation-attempts
<!-- LiteLLM MCP exploitation attempts -->
Detect access to the specific MCP endpoints used in the CVE-2026-42271 RCE chain.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to these endpoints suggest exploitation of the AI gateway
  test capability.
reads:
- device_hostname
- url_path
- src_endpoint_ip
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, http_method, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/mcp-rest/test/connection%' OR LOWER(url_path) LIKE '%/mcp-rest/test/tools/list%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-behavior-check
<!-- Corroborate post-exploitation behavior -->
parallel:
- → environment-secret-harvesting
- → database-exfiltration-lookups
- → miner-module-tuning
- → persistence-ssh-keys
join: → triage-compromise

## environment-secret-harvesting
<!-- AI gateway secret harvesting -->
Detect processes reading container environment blocks to steal API keys, targeting /proc/1/environ.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes inspecting the container environment block or referencing database
  URLs.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/proc/1/environ%' OR LOWER(process_cmd_line) LIKE '%DATABASE_URL%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## database-exfiltration-lookups
<!-- Anomalous database DNS lookups -->
Identify rare or high-volume DNS lookups to database endpoints from AI infrastructure using reported host patterns.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, db_host_patterns=db_host_patterns)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare database-related lookups from AI hosts; fleet-wide lookups are baseline
  noise.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{db_host_patterns}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.postgres.database.azure.com') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname HAVING hosts <= 3
```

## miner-module-tuning
<!-- Cryptomining preparation (MSR tuning) -->
Detect the loading of the MSR module with write access enabled, a high-fidelity indicator for RandomX/XMRig CPU tuning.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Loading of the 'msr' module with write permissions, atypical for legitimate
  AI application runtimes.
reads:
- device_hostname
- module_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, module_name, process_cmd_line, time FROM hb_module_activity WHERE LOWER(module_name) = 'msr' AND LOWER(process_cmd_line) LIKE '%allow_writes=1%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-ssh-keys
<!-- SSH authorized_keys modification -->
Detect modification of service-account SSH keys used for persistence on AI gateways.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Updates to authorized_keys, suggesting the insertion of an attacker-controlled
  key.
reads:
- device_hostname
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, activity_name, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%/.ssh/authorized_keys' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage AI gateway compromise -->
```agent target=hunter
cite: required
context:
- mcp-exploitation-attempts
- environment-secret-harvesting
- database-exfiltration-lookups
- miner-module-tuning
- persistence-ssh-keys
max_iterations: 5
objective: Determine if an AI workload has been compromised based on the combination
  of web-based exploitation and subsequent malicious runtime behavior.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  process paths, DNS queries, or file touches.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host running AI services" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: container-introspection-gap)
else: → analyst-review

## isolate-host
<!-- Isolate AI host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Revoke the LiteLLM Master Key and LLM provider API keys stored in the environment.
```
→ analyst-review

## analyst-review
<!-- Post-compromise analysis -->
```manual target=analyst
Verify the identified API keys were rotated. Check for unauthorized SSH keys in /home/service_account/.ssh/authorized_keys and inspect for masqueraded systemd services.
```
→ end
