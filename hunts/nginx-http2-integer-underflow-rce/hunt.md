---
analysis: A standard rule for 120GB connections would cause excessive noise in high-traffic
  environments. This hunt correlates that extreme volume specifically with NGINX worker
  activity and version inventory, providing a context-aware pivot that a single rule
  cannot perform.
blind_spots:
- id: no-inventory-visibility
  question: Are all Docker-based NGINX instances reporting their version to the host
    agent?
  requires: hb_software_inventory coverage for all containers
  risk: NGINX instances running in unmanaged or non-reporting containers will be missed
    during scoping.
  stage: vulnerability-discovery
- id: no-network-telemetry
  question: Do network flow logs capture the total volume for long-lived, encrypted
    connections?
  requires: hb_network_connection with cumulative traffic_bytes
  risk: If traffic volume is not recorded at the session level, the 120GB flood indicator
    cannot be detected.
  stage: exploitation-traffic-flood
coverage:
- stage: vulnerability-discovery
  status: covered
  steps:
  - vulnerable-nginx-scope
  - evaluate-scope-lead
- stage: exploitation-traffic-flood
  status: covered
  steps:
  - high-volume-traffic
- stage: worker-context-execution
  status: covered
  steps:
  - suspicious-nginx-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: CVE-2026-123007 is a critical unauthenticated RCE on a primary edge
    component. Identifying and validating the required 128GB traffic flood provides
    high confidence in the presence or absence of this specific exploitation attempt.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting a critical integer underflow in NGINX's HTTP/2
  flow control by transmitting a high-volume data flood to corrupt memory and execute
  code within the NGINX worker process context.
labels:
- hunt
- attack.t1190
- execution
- initial access
name: NGINX HTTP/2 Integer Underflow and RCE
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for exploitation traffic and subsequent
      activity.
    type: number
  min_bytes_flood:
    default: '120000000000'
    description: Traffic volume threshold in bytes (approx 120GB) required to trigger
      the counter underflow.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus the exploitation search on; populated
      by the analyst after the scoping step.
    type: list[host]
  vulnerable_versions:
    default:
    - 1.31.0
    - 1.31.1
    - 1.31.2
    - 1.31.3
    - 1.31.4
    - 1.31.5
    - 1.31.6
    - 1.31.7
    - 1.31.8
    - 1.9.5
    - 1.30.0
    - 1.30.1
    - 1.30.2
    - 1.30.3
    - 1.30.4
    - 1.30.5
    - 1.30.6
    description: Known vulnerable versions of NGINX Open Source as reported in the
      disclosure.
    from:
      kind: article
      observed: '2026-11-18'
      ref: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Internet-facing NGINX servers or ingress controllers. Start with
  edge nodes serving HTTPS/2 traffic.
references:
- name: "Rapid7 \u2014 CVE-2026-123007: Critical NGINX HTTP/2 Integer Underflow Leads\
    \ to RCE"
  url: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed
related:
- hunt: nginx-ingress-anomalous-egress
  reason: Monitoring for post-exploitation egress from NGINX containers is a sibling
    hunt that detects the aftermath regardless of the exploit used.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Identification of Vulnerable NGINX Service
    observables:
    - NGINX versions 1.31.0 - 1.31.8
    - NGINX versions 1.9.5 - 1.30.6
    - HTTP/2 protocol enabled
    - TLS/HTTPS enabled
    - Docker image nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da
    slug: vulnerability-discovery
    tactic: initial-access
    techniques:
    - T1190
  - name: High-Volume HTTP/2 Flow-Control Exploit
    observables:
    - Approximately 128 GB of HTTP/2 data transmitted
    - Persistent connection duration between 2.5 and 17 minutes
    - Sustained network traffic over 300 Mbit/s
    - HTTP/2 WINDOW_UPDATE frames
    - HTTP/2 SETTINGS frames with SETTINGS_INITIAL_WINDOW_SIZE changes
    slug: exploitation-traffic-flood
    tactic: initial-access
    techniques:
    - T1190
  - name: NGINX Worker Remote Code Execution
    observables:
    - NGINX worker process crash (memory corruption)
    - Out-of-bounds reads/writes in worker process context
    - Anomalous child processes (e.g., shell or network utilities) spawned by nginx
      worker
    slug: worker-context-execution
    tactic: execution
    techniques:
    - T1190
  summary: An unauthenticated remote attacker exploits a critical integer underflow
    in NGINX's HTTP/2 implementation (CVE-2026-123007) by transmitting approximately
    128 GB of data over a sustained connection. Successful exploitation triggers memory
    corruption in the NGINX worker process, leading to remote code execution during
    response processing.
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
tlp: clear
type: investigation
---


# NGINX HTTP/2 Integer Underflow and RCE

Exploitation requires approximately 128 GB of data to be transmitted to trigger the underflow, which then allows for an out-of-bounds memory copy. The adversary floods the target server with HTTP/2 traffic to corrupt the worker process's memory. This hunt identifies vulnerable NGINX versions and then searches for the characteristic 120GB+ inbound traffic flood and suspicious child processes spawned by NGINX workers. The analyst reviews the correlated evidence to confirm remote code execution.

## vulnerable-nginx-scope
<!-- Scope vulnerable NGINX versions -->
Identify hosts running versions of NGINX known to be vulnerable to the HTTP/2 integer underflow.

```sqlite target=endpoint role=scoping params=(vulnerable_versions=vulnerable_versions)
~~~yaml
expected: A list of hosts and their NGINX versions. None means no known vulnerable
  software is present.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%nginx%' AND (instr(',' || '{{vulnerable_versions}}' || ',', ',' || package_version || ',') > 0)
```

## evaluate-scope-lead
<!-- Evaluate vulnerability lead -->
```agent target=hunter
cite: required
context:
- vulnerable-nginx-scope
max_iterations: 3
objective: Confirm which hosts from the inventory results are running vulnerable versions
  of NGINX as specified in the report.
success_criteria: A list of hosts with confirmed vulnerable NGINX versions.
tools:
- endpoint
- network
```

## gate-vulnerability
<!-- Gate: Proceed to exploitation search -->
if~: "the evaluate-scope-lead verdict is that at least one host is running a vulnerable NGINX version" (confidence: high, judge=hunter)
then: → exploitation-parallel
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-inventory-visibility)
else: → close-out

## exploitation-parallel
<!-- Parallel search for exploitation evidence -->
parallel:
- → high-volume-traffic
- → suspicious-nginx-activity
join: → triage-triage

## high-volume-traffic
<!-- Detect 120GB+ inbound HTTP/2 data floods -->
Identify external source IPs that have transmitted the extreme volumes of data received by the NGINX server to trigger the integer underflow.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, min_bytes_flood=min_bytes_flood)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One or more source IPs sending over 120GB to a single host. A unique IP
  hitting one host is highly suspicious.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- direction
- dst_endpoint_port
- src_endpoint_ip
- state_kind
- time
- traffic_bytes
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, src_endpoint_ip, SUM(traffic_bytes) as total_received_bytes, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE (dst_endpoint_port IN (443, 8443)) AND direction = 'inbound' AND state_kind = 'log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip HAVING total_received_bytes > {{min_bytes_flood}}
```

## suspicious-nginx-activity
<!-- Anomalous NGINX child processes -->
Find shells, network utilities, or staging tools spawned by NGINX processes, indicating successful code execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A shell, downloader, or utility process whose parent is an NGINX worker.
  Silence indicates no obvious RCE took place during the window.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(process_name) LIKE '%nginx%') AND (LOWER(process_name) IN ('sh', 'bash', 'nc', 'curl', 'wget', 'python', 'perl', 'socat', 'cp', 'mv', 'chmod') OR LOWER(process_cmd_line) LIKE '%/dev/tcp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-triage
<!-- Triage exploitation evidence -->
```agent target=hunter
cite: required
context:
- evaluate-scope-lead
- high-volume-traffic
- suspicious-nginx-activity
max_iterations: 6
objective: Weigh the scoping results against the traffic volumes and process executions
  to identify successful CVE-2026-123007 exploitation.
success_criteria: A per-host verdict citing specific rows from the traffic and process
  queries.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route based on verdict -->
if~: "the triage-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve memory and NGINX worker binaries for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review and forensic check -->
```manual target=analyst
Review the high-volume connection logs and the process tree of the NGINX workers. Look for credential access or lateral movement originating from the NGINX host.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record all vulnerable hosts found. If no exploitation was confirmed, prioritize these hosts for immediate NGINX updates to version 1.31.9 or 1.30.7.
```
→ end
