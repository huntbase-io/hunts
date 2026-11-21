---
analysis: A single rule on Ollama's port cannot distinguish between a researcher's
  honeypot and a corporate asset. This hunt correlates external scan data with internal
  behavioural pivots (DNS and API probing) to settle on a compromise verdict.
blind_spots:
- id: missing-http-request-bodies
  owner: Infrastructure Team
  question: whether an /api/pull request contained a path-traversal payload
  remediation: Enable verbose logging for reverse proxies fronting AI infrastructure.
  requires: hb_http_activity with full request body capture
  risk: A simple GET to /api/tags is visible, but the destructive manifest digest
    payload in a POST /api/pull body is often missed by standard proxy logs.
  stage: unauthenticated-api-exposure
- id: egress-telemetry-gap
  owner: Detection Engineering
  question: which specific process initiated the connection to a tunnel provider
  remediation: Deploy endpoint agents to all expensed cloud compute.
  requires: hb_network_connection with process mapping on all VPS hosts
  risk: Without process-to-network mapping on unmanaged VPS hosts, we cannot confirm
    the AI runtime initiated the callback versus a standard developer tool.
  stage: callback-verification-tunnels
coverage:
- stage: unauthenticated-api-exposure
  status: covered
  steps:
  - exposed-ai-scoping
  - suspicious-api-probes
- stage: callback-verification-tunnels
  status: covered
  steps:
  - outbound-tunnel-dns
- reason: This belongs to the second hunt in the series focusing on post-exploitation
    file access.
  stage: path-traversal-file-access
  status: out_of_scope
- reason: Belongs to a separate hunt focusing on ld.so.preload and systemd persistence.
  stage: persistence-and-execution-hijack
  status: out_of_scope
- reason: Belongs to a hunt focusing on cloud billing and subscription abuse.
  stage: resource-hijacking-llmjacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Thousands of AI runtimes are exposed unauthenticated; the model list
    itself becomes a visitors' log of attacker activity. A negative result confirms
    that your compute is not being 'rented' by strangers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is identifying unauthenticated AI runtimes exposed to the
  internet and using them to verify connectivity or establish command-and-control
  via outbound tunneling services.
labels:
- hunt
- attack.t1190
- attack.t1572
- command and control
- credential access
- impact
- initial access
- persistence
name: Exposed AI Runtime Probing and Callbacks
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioural telemetry.
    from:
      kind: manual
      observed: '2024-11-18'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the behavioural search; leave empty
      to hunt across the whole estate.
    from:
      kind: manual
      observed: '2024-11-18'
      ref: analyst-scoping
    type: list[host]
  tunnel_domains:
    default:
    - bore.pub
    - trycloudflare.com
    - ttl.sh
    - pinggy.io
    description: Free tunneling and throwaway registry services used for callbacks
      and reachability verification.
    from:
      kind: article
      observed: '2026-11-18'
      ref: rapid7-exposed-ai
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/tr-self-hosted-ai-renting-compute-exposed-servers
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on cloud and hosting network ranges (OVH, Hetzner, DigitalOcean)
  where developers may have 'expensed' servers outside of standard CMDB oversight.
references:
- name: "Rapid7 \u2014 Open by Default, Already Occupied: Threat Actors are Renting\
    \ your Compute"
  url: https://www.rapid7.com/blog/post/tr-self-hosted-ai-renting-compute-exposed-servers
related:
- hunt: ollama-path-traversal-manifest-digest
  reason: This hunt focuses on the exposure and network plane; path traversal exploitation
    is a separate behavioral hunt on the host surface.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Unauthenticated AI API Exposure
    observables:
    - port:11434
    - port:8888
    - port:8501
    - port:8000
    - url_path:/api/tags
    - url_path:/api/pull
    - url_path:/api/push
    - url_path:/api/kernels
    slug: unauthenticated-api-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Outbound Callback and Tunneling
    observables:
    - domain:bore.pub
    - domain:trycloudflare.com
    - domain:ttl.sh
    - domain:pinggy.io
    - model_name:zzvitals-beacon
    - model_name:verif_sys
    - model_name:ops-verify
    - model_name:*-copy-test
    slug: callback-verification-tunnels
    tactic: command-and-control
    techniques:
    - T1572
  - name: Path Traversal Credential Access
    observables:
    - file_path:/etc/shadow
    - file_path:/etc/passwd
    - file_path:/proc/self/environ
    - file_path:~/.ssh/authorized_keys
    - file_path:~/.ollama/id_ed25519
    - CVE-2024-37032
    slug: path-traversal-file-access
    tactic: credential-access
    techniques:
    - T1555
  - name: Execution Hijack and Persistence
    observables:
    - file_path:/etc/ld.so.preload
    - file_path:override.conf
    - process_name:ollama
    slug: persistence-and-execution-hijack
    tactic: persistence
    techniques:
    - T1574.006
  - name: Resource Hijacking (LLMjacking)
    observables:
    - model_name:gpt-4o
    - model_name:claude-3-opus
    - model_name:llama3.1:8b
    slug: resource-hijacking-llmjacking
    tactic: impact
    techniques:
    - T1496
  summary: Threat actors are targeting unauthenticated Ollama AI servers to hijack
    compute resources and linked cloud model subscriptions (LLMjacking). Beyond resource
    theft, attackers use path traversal vulnerabilities (CVE-2024-37032) to read sensitive
    host files like /etc/shadow and establish persistence via system configuration
    hijacking.
series:
  index: 1
  slug: open-by-default-already-occupied-threat-actors-are-renting-your-compute
  title: 'Open by Default, Already Occupied: Threat Actors are Renting your Compute'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Exposed AI Runtime Probing and Callbacks

This hunt identifies AI runtimes like Ollama and Jupyter exposed to the public internet without authentication. It then searches for evidence of active misuse by correlating this exposure with outbound DNS callbacks to free tunneling services and suspicious HTTP probes against sensitive API endpoints. By combining external exposure data with internal telemetry, the hunt distinguishes between simple misconfiguration and active server-side request forgery (SSRF) or persistence attempts.

## exposed-ai-scoping
<!-- Identify exposed AI services -->
Find hosts that external scanners have already flagged as exposing AI runtimes or related ports.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows naming external IPs and ports of known AI runtimes. Silence suggests
  no current exposure detected by external scanning.
reads:
- domain_or_ip
- port
- product
- provider
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT domain_or_ip, port, product, provider FROM hb_exposed_assets WHERE (LOWER(product) LIKE '%ollama%' OR LOWER(product) LIKE '%jupyter%' OR port IN (11434, 8888, 8501, 8000))
```

## corroborate-misuse
<!-- Corroborate misuse side by side -->
parallel:
- → outbound-tunnel-dns
- → suspicious-api-probes
join: → triage-ai-exposure

## outbound-tunnel-dns
<!-- DNS resolution for tunnel services -->
Detect internal hosts resolving tunnel providers which indicates a successful callback or verification check.

```sqlite target=endpoint role=baseline params=(tunnel_domains=tunnel_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Internal hosts attempting to connect to free tunnel providers. Silence means
  no known tunnel callbacks were initiated.
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
verified_at: '2026-11-19'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## suspicious-api-probes
<!-- Unauthenticated AI API probing -->
Identify external requests to sensitive endpoints that expose server state or model information across several runtimes.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests from external IPs to administrative paths. Silence suggests
  no unauthenticated probing was logged.
reads:
- device_hostname
- url_path
- src_endpoint_ip
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, status_code, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/api/tags%' OR LOWER(url_path) LIKE '/api/pull%' OR LOWER(url_path) LIKE '/api/push%' OR LOWER(url_path) LIKE '/api/kernels%' OR LOWER(url_path) LIKE '/api/contents%' OR LOWER(url_path) LIKE '/api/sessions%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-ai-exposure
<!-- Weigh exposure and callbacks -->
```agent target=hunter
cite: required
context:
- exposed-ai-scoping
- outbound-tunnel-dns
- suspicious-api-probes
max_iterations: 4
objective: Determine if any host with an exposed AI service has also resolved tunnel
  domains or received suspicious API requests indicating misuse.
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  the external probe and the tunnel resolution.
tools:
- endpoint
- web
```

## decide-compromise
<!-- Route on verdict -->
if~: "the triage-ai-exposure verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-forensics
unavailable: → manual-forensics (blind_spot: missing-http-request-bodies)
else: → remediation-hardening

## isolate-host
<!-- Isolate compromised AI host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke any linked Ollama account keys and check for unauthorized cloud spend.
```
→ manual-forensics

## manual-forensics
<!-- Manual forensic review -->
```manual target=analyst
Read the model list on the affected host using the Ollama or Jupyter API. Look for model names prefixed with IP addresses or containing Base64 strings that decode to system paths.
```
→ end

## remediation-hardening
<!-- Remediation and hardening -->
```manual target=analyst
Bind the AI runtime to localhost or a private network. Implement an authenticating reverse proxy or zero-trust layer for remote access.
```
→ end
