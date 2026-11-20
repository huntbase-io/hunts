---
analysis: A standard detection rule might fire on the SPIRE socket interaction, but
  it cannot determine whether the attacker successfully used the identity for mTLS
  or spoofed cgroups. This hunt correlates the initial tampering behavior with cross-host
  network impersonation across three different telemetry surfaces.
blind_spots:
- id: no-ebpf-proc-monitoring
  owner: Cloud Engineering
  question: whether an attacker used a kernel-level tool or direct syscalls to spoof
    cgroup info without spawning a shell
  remediation: Enable kernel-level auditing for sensitive /proc filesystem access.
  requires: eBPF-based monitoring of /proc/self/cgroup access
  risk: Stealthy manipulation that doesn't leave command-line traces would only be
    visible at the agent log or kernel level.
  stage: cgroup-metadata-spoofing
- id: agent-memory-exposure
  owner: Security Operations
  question: whether the harvesting occurred entirely within the agent's memory response
  remediation: Configure SPIRE agents to log FetchSVID request metadata including
    calling PID.
  requires: SPIRE agent memory auditing
  risk: Identity harvesting often occurs in-memory (FetchSVID response), leaving no
    trace on the filesystem for standard file logs to capture.
  stage: svid-credential-harvesting
coverage:
- reason: Exploitation of public-facing applications is covered by existing standing
    rules for RCE and shell execution.
  stage: initial-node-compromise
  status: existing_rule
- stage: spire-agent-socket-access
  status: covered
  steps:
  - socket-interaction
  - triage-tampering
- stage: cgroup-metadata-spoofing
  status: covered
  steps:
  - metadata-tampering
  - triage-tampering
- blind_spot: agent-memory-exposure
  reason: Retrieval of JWTs and certificates through the agent socket protocol is
    not visible in process or file activity logs.
  stage: svid-credential-harvesting
  status: not_visible
- stage: mtls-identity-misuse
  status: covered
  steps:
  - network-impersonation
  - assess-misuse
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: SPIFFE/SPIRE is the foundational trust mechanism for service communication.
    If an attacker can impersonate co-located workloads, they bypass all service-level
    authorization. Confirming node identity integrity is a high-priority obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker with root access on a Kubernetes node is spoofing cgroup metadata
  to trick the SPIRE agent into issuing identities belonging to co-located workloads
  for unauthorized service impersonation.
labels:
- hunt
- attack.t1190
- attack.t1090.003
name: SPIFFE/SPIRE Workload Identity Spoofing
parameters:
  cgroup_indicators:
    default:
    - spooffe
    - cgroup-tool
    description: Exact names of tools or indicators related to cgroup manipulation.
    from:
      kind: article
      observed: '2026-09-10'
      ref: https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
    type: list[string]
  interactive_tools:
    default:
    - bash
    - sh
    - zsh
    - curl
    - socat
    - nc
    - python
    - perl
    description: Interactive tools or shells that should not typically communicate
      with the SPIRE agent.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: The Kubernetes nodes identified as running SPIRE agents; leave empty
      for fleet-wide.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should start with Kubernetes worker nodes running SPIRE agents.
  Use the first scoping query to identify these hosts, then use that list to filter
  subsequent behavioral queries.
references:
- name: 'The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE'
  url: https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
related:
- hunt: kubernetes-container-escape
  reason: Container escape to the node is a standard precursor to obtaining the root
    access needed for this identity spoofing technique.
  relation: precedes
scenario:
  stages:
  - name: Initial Node Compromise
    observables:
    - Exploitation of web servers or containers to gain root access on a Kubernetes
      node
    slug: initial-node-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: SPIRE Agent Socket Interaction
    observables:
    - Interaction with the SPIRE Workload API Unix socket at /run/spire/sockets/agent.sock
    - Process calling FetchJWTSVID or FetchX509SVID
    slug: spire-agent-socket-access
    tactic: execution
  - name: Cgroup Metadata Spoofing
    observables:
    - Manipulation of /proc/self/cgroup or /proc/self/mountinfo
    - Use of the Spooffe tool to automate identity extraction
    - Process strings containing /kubepods.slice/ or /kubepods-besteffort.slice/
    slug: cgroup-metadata-spoofing
    tactic: defense-evasion
  - name: SVID Credential Harvesting
    observables:
    - Retrieval of X.509 SVIDs (certificates) or JWT tokens belonging to co-located
      pods
    - Anomalous requests for multiple distinct SPIFFE IDs from a single node process
    slug: svid-credential-harvesting
    tactic: credential-access
  - name: mTLS Identity Misuse
    observables:
    - Establishment of mTLS connections using stolen SVIDs to impersonate frontend/backend
      services
    slug: mtls-identity-misuse
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An attacker with root access on a Kubernetes node manipulates cgroup metadata
    to spoof co-located workload identities, tricking the SPIRE agent into issuing
    SVIDs (X.509 or JWT). This allows the attacker to harvest machine identities and
    perform unauthorized cross-service communication by impersonating trusted pods.
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


# SPIFFE/SPIRE Workload Identity Spoofing

This research highlights a post-exploitation vulnerability in SPIFFE/SPIRE where an attacker with root access on a Kubernetes node can spoof cgroup metadata. By manipulating the Linux control group identifiers used during workload attestation, the attacker tricks the local SPIRE agent into issuing identities (SVIDs) belonging to co-located pods. This bypasses cross-workload identity boundaries and allows unauthorized mTLS communication to other services. The hunt follows a phased flow to detect this behavior: it first identifies nodes running SPIRE agents, then looks for suspicious interactions with the agent's Unix socket alongside rare cgroup-related process command lines, and finally correlates these findings with subsequent mTLS traffic from those processes to confirm identity misuse.

## scoping-spire-nodes
<!-- Identify SPIRE-enabled nodes -->
Find nodes that run the SPIRE agent to narrow the hunt scope and reduce noise from non-Kubernetes hosts.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where identity spoofing is possible due to the presence
  of SPIRE software. Silence suggests the estate may not use SPIRE.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%spire-agent%' OR LOWER(package_name) LIKE '%spiffe%')
```

## early-tampering
<!-- Investigate identity tampering -->
parallel:
- → socket-interaction
- → metadata-tampering
join: → triage-tampering

## socket-interaction
<!-- Interactive tools accessing SPIRE socket -->
Find shells or networking tools touching the agent socket, which is non-standard behavior for automated workloads.

```sqlite target=endpoint role=detection-candidate params=(interactive_tools=interactive_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Interactive shells like bash or tools like curl interacting with the agent
  socket. Silence proofs absence of manual socket misuse.
reads:
- device_hostname
- process_name
- file_path
- time
- actor_user_name
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, time, actor_user_name FROM hb_file_activity WHERE instr(LOWER(file_path), 'agent.sock') > 0 AND instr(',' || '{{interactive_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## metadata-tampering
<!-- Rare cgroup-related process activity -->
Identify processes referencing Kubernetes cgroup slices or the Spooffe research tool in their command lines.

```sqlite target=endpoint role=baseline params=(cgroup_indicators=cgroup_indicators, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process command line attempting to reference pod slices. Common noise
  from agent components is filtered.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%kubepods.slice%' OR LOWER(process_cmd_line) LIKE '%kubepods-besteffort.slice%' OR instr(',' || '{{cgroup_indicators}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND LOWER(process_name) NOT LIKE '%spire-agent%' AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING host_count <= 3
```

## triage-tampering
<!-- Triage identity tampering evidence -->
```agent target=hunter
cite: required
context:
- socket-interaction
- metadata-tampering
max_iterations: 4
objective: Identify processes attempting to spoof Kubernetes workload selectors to
  trick the local SPIRE agent.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  PIDs and tool names.
tools:
- endpoint
- network
```

## network-impersonation
<!-- Detect mTLS service impersonation -->
Corroborate the tampering by finding subsequent mTLS network traffic from the same suspicious processes.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: mTLS network connections from processes that previously interacted with
  the SPIRE socket or cgroup metadata. Silence may indicate harvested tokens were
  not used.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (dst_endpoint_port = 443 OR dst_endpoint_port = 8443) AND LOWER(process_name) NOT LIKE '%spire-agent%' AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-misuse
<!-- Assess identity misuse and impersonation -->
```agent target=hunter
cite: required
context:
- triage-tampering
- network-impersonation
max_iterations: 4
objective: Confirm workload identity theft by correlating metadata tampering with
  subsequent service-to-service network traffic.
success_criteria: A final malicious verdict for any host where a process both tampered
  with the agent and initiated mTLS traffic.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on impersonation verdict -->
if~: "the assess-misuse verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: no-ebpf-proc-monitoring)
else: → close-out

## isolate-host
<!-- Isolate compromised Kubernetes node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised Kubernetes node and revoke its SVID at the SPIRE server to invalidate any harvested identities.
```
→ forensic-review

## forensic-review
<!-- Forensic deep-dive -->
```manual target=analyst
Inspect the node for the Spooffe research tool or evidence of /proc manipulation. Review SPIRE agent logs for anomalous FetchSVID requests originating from interactive shells or non-standard container PIDs.
```
→ policy-update

## policy-update
<!-- Update workload selectors -->
```manual target=analyst
Document the identified gaps in workload selectors. Transition registration entries from weak selectors (like namespace only) to stronger ones (like service account and container image hash).
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the examined hosts and findings. If no identity misuse was found, confirm node-level trust for the period.
```
→ end
