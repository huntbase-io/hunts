---
analysis: This hunt correlates internet exposure, critical vulnerabilities, unauthorized
  file changes (drift), and rare container network egress. A single detection rule
  would likely be too noisy for common container operations; the hunt provides the
  necessary correlation context.
blind_spots:
- id: limited-runtime-telemetry
  owner: Cloud Infrastructure Team
  question: whether unauthorized code was executed in containers not reporting to
    the central collector
  remediation: Deploy the runtime security agent to all worker nodes.
  requires: eBPF-based container monitoring on all nodes
  risk: A compromise in an unmonitored namespace or cluster will be missed, even if
    vulnerabilities are present.
  stage: runtime-process-execution-and-drift
- id: encrypted-c2-blindness
  owner: Network Security Team
  question: whether exfiltration occurred over encrypted channels targeting legitimate-looking
    domains
  remediation: Implement TLS proxying for outbound container traffic.
  requires: hb_http_activity with full TLS inspection
  risk: Attackers using Domain Fronting or legitimate SaaS for C2 will not be caught
    by simple DNS prevalence checks.
  stage: container-network-anomaly
coverage:
- stage: vulnerability-and-identity-exploitation
  status: covered
  steps:
  - vulnerable-exposed-assets
- stage: runtime-process-execution-and-drift
  status: covered
  steps:
  - suspicious-container-processes
  - container-binary-drift
- stage: container-network-anomaly
  status: covered
  steps:
  - rare-container-dns
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Modern cloud workloads are dynamic; static vulnerability scanning
    is insufficient to detect runtime compromises. This hunt provides proof of absence
    for post-exploitation behaviors on vulnerable, internet-exposed assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a public-facing application or container vulnerability
  to gain initial access, subsequently executing suspicious processes and establishing
  outbound C2 via anomalous DNS lookups.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1059
- attack.t1543
- attack.t1071
name: Cloud Workload Intrusion Behavior
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard-window
    type: number
  scope_hosts:
    default: []
    description: Comma-separated list of hostnames to focus the hunt on; leave empty
      for all.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: scoping-parameter
    type: list[host]
  suspicious_interpreters:
    default:
    - bash
    - sh
    - python
    - perl
    - php
    - nc
    - curl
    - wget
    description: List of shell or network utility names to monitor in container contexts.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: common-attack-tooling
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/19/microsoft-named-a-leader-in-the-frost-radar-cloud-workload-protection-platforms-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing production clusters (AKS/EKS/GKE). Focus on
  hosts reporting vulnerabilities with a severity_id >= 4 that are also present in
  the exposed assets inventory.
references:
- name: "Microsoft named a Leader in the Frost Radar\u2122: Cloud Workload Protection\
    \ Platforms, 2026"
  url: https://www.microsoft.com/en-us/security/blog/2026/08/19/microsoft-named-a-leader-in-the-frost-radar-cloud-workload-protection-platforms-2026/
related:
- hunt: kubernetes-audit-log-analysis
  reason: This hunt focuses on runtime/endpoint signals; a sibling hunt is required
    to examine control-plane/audit logs for identity abuse.
  relation: sibling
scenario:
  stages:
  - name: Vulnerability and Identity Exploitation
    observables:
    - Exploitation of web servers or Kubernetes services
    - Over-permissioned identities (GitHub, AWS, Azure, GCP)
    - Prompt injection against AI models (Azure OpenAI, Google Vertex AI)
    - Misconfigured container images with known vulnerabilities
    slug: vulnerability-and-identity-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1078
  - name: Runtime Process Execution and Drift
    observables:
    - Suspicious process execution in Kubernetes containers
    - Binary drift (unauthorized binary or file changes mid-run)
    - Malicious code execution detected via eBPF-based sensors
    - Suspicious access to AI workloads (Azure AI Foundry, Bedrock)
    slug: runtime-process-execution-and-drift
    tactic: execution
    techniques:
    - T1059
    - T1543
  - name: Container Network Anomaly
    observables:
    - Anomalous DNS queries originating from Kubernetes clusters (AKS, EKS, GKE)
    - Outbound network connections to suspicious domains or IPs from containers
    slug: container-network-anomaly
    tactic: discovery
    techniques:
    - T1071
  summary: Cloud-native compromises often begin with the exploitation of vulnerabilities
    in public-facing applications or the use of over-permissioned identities to gain
    access to running workloads. Once active, attackers execute suspicious processes
    and modify binaries mid-run (drift) to maintain presence, while exhibiting anomalous
    network patterns such as specialized DNS queries for discovery or command and
    control.
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
tlp: clear
type: investigation
---


# Cloud Workload Intrusion Behavior

This hunt identifies multi-stage cloud workload compromises by correlating internet exposure and known vulnerabilities with runtime anomalies. It specifically looks for 'binary drift' (unauthorized file modifications), rare process executions such as shells in container environments, and outbound network patterns that deviate from the established fleet baseline. By spanning the vulnerability, execution, and network planes, it provides the context necessary to distinguish a production incident from a routine scan.

## vulnerable-exposed-assets
<!-- Identify Vulnerable and Exposed Assets -->
Find hosts that are both internet-exposed and have high-severity vulnerabilities to scope the hunt to the most likely entry points.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts that are internet-exposed and contain critical vulnerabilities.
  Silence implies no known exposed critical vulnerabilities.
reads:
- device_uid
- cve_uid
- severity
- severity_id
- status
- affected_package_name
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT v.cve_uid, d.hostname AS device_hostname, e.port, v.severity, v.affected_package_name FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid JOIN hb_exposed_assets e ON d.ip_address = e.ip_address WHERE v.severity_id >= 4 AND v.status != 'suppressed' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || d.hostname || ',') > 0)
```

## runtime-parallel-check
<!-- Parallel Runtime Investigation -->
parallel:
- → suspicious-container-processes
- → container-binary-drift
- → rare-container-dns
join: → triage-signals

## suspicious-container-processes
<!-- Suspicious Interpreter Execution in Containers -->
Detect the execution of shells or utilities inside containerized environments which often indicate post-exploitation activity.

```sqlite target=endpoint role=detection-candidate params=(suspicious_interpreters=suspicious_interpreters, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes like 'bash' or 'nc' running within container storage paths on
  the host. Benign activity is usually limited to build/CI agents.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_path, time FROM hb_process_activity WHERE (instr(',' || '{{suspicious_interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (LOWER(process_path) LIKE '%/var/lib/docker%' OR LOWER(process_path) LIKE '%/var/lib/containerd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## container-binary-drift
<!-- Identify Container Binary Drift -->
Find file creations, modifications, or deletions in sensitive system directories within container workloads, signaling malware persistence or unauthorized updates.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Unexpected file activity in binary directories within container paths. This
  includes deletions used to clean up tools.
reads:
- device_hostname
- file_path
- activity_name
- activity_id
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, activity_name, process_name, time FROM hb_file_activity WHERE activity_id IN (1, 3, 4, 5) AND (LOWER(file_path) LIKE '%/bin/%' OR LOWER(file_path) LIKE '%/usr/local/bin/%') AND (LOWER(file_path) LIKE '%/var/lib/docker%' OR LOWER(file_path) LIKE '%/var/lib/containerd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-container-dns
<!-- Rare DNS Lookups from Containers -->
Baseline DNS activity from container processes to find rare outbound connections that could indicate C2 or data exfiltration.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outlier DNS queries originating specifically from container processes. High-frequency
  infrastructure domains are filtered by rarity.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
- pid
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dns.query_hostname, COUNT(DISTINCT dns.device_hostname) AS host_count, MIN(dns.time) AS first_seen FROM hb_dns_activity dns JOIN hb_process_activity p ON dns.pid = p.pid AND dns.device_hostname = p.device_hostname WHERE (LOWER(p.process_path) LIKE '%/var/lib/docker%' OR LOWER(p.process_path) LIKE '%/var/lib/containerd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dns.device_hostname || ',') > 0) AND dns.time >= datetime('now', '-{{lookback_days}} days') GROUP BY dns.query_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## triage-signals
<!-- Triage Workload Anomalies -->
```agent target=hunter
cite: required
context:
- vulnerable-exposed-assets
- suspicious-container-processes
- container-binary-drift
- rare-container-dns
max_iterations: 5
objective: Review the correlated signals. Does a host with a high-severity vulnerability
  also show suspicious shell execution, binary drift (including deletions), or rare
  DNS lookups originating from container paths? Determine if the activity represents
  a coordinated attack chain.
success_criteria: A verdict of malicious | suspicious | benign per host with citations
  of specific rows.
tools:
- endpoint
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one workload host" (confidence: high, judge=hunter)
then: → isolate-workload
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-runtime-telemetry)
else: → close-out

## isolate-workload
<!-- Isolate Affected Workload -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host via EDR or cloud network security group. If a container, pause the container and initiate forensic snapshot of the volume.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the cited rows for the malicious/suspicious hosts. Determine if the shell execution was a legitimate administrative action or part of a deployment pipeline. Confirm whether binary drift matches a known update schedule.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the hosts examined and the evidence of absence for the remaining estate. If suspicious but benign patterns were found, update the 'suspicious_interpreters' list or tuning notes.
```
→ end
