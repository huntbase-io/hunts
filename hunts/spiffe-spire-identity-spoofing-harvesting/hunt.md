---
analysis: This hunt combines behavioral signals (metadata interrogation) with fleet-wide
  stack counting and cross-surface corroboration (process vs file/socket) that a single
  detection rule cannot reliably do without high false positives.
blind_spots:
- id: missing-socket-telemetry
  question: Which specific process opened the SPIRE socket?
  remediation: Deploy eBPF-based monitoring to capture Unix socket access.
  requires: hb_file_activity with socket support
  risk: Without socket file-open events, we must rely on process command-line keywords
    which are easily obfuscated.
  stage: svid-credential-harvesting
- id: direct-syscall-metadata-access
  question: Did the process read /proc directly via syscalls?
  requires: syscall-level logging
  risk: Compiled tools like Spooffe can read /proc/cgroups without spawning shell
    utilities, bypassing process command-line monitoring.
  stage: workload-metadata-enumeration
coverage:
- stage: initial-k8s-node-compromise
  status: covered
  steps:
  - identify-spire-nodes
- stage: workload-metadata-enumeration
  status: covered
  steps:
  - detect-proc-interrogation
- stage: spire-attestation-spoofing
  status: covered
  steps:
  - rare-spire-processes
- stage: svid-credential-harvesting
  status: covered
  steps:
  - socket-file-activity
- reason: 'Belongs to another part of the ''The Machine With Many Faces: Post-Exploitation
    Identity Misuse in SPIFFE/SPIRE'' series.'
  stage: lateral-workload-impersonation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: SPIFFE/SPIRE provides the backbone for workload identity in Kubernetes.
    A single node compromise allowing identity spoofing threatens the security of
    the entire cluster.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker with root access on a Kubernetes node is interrogating /proc
  metadata to spoof workload selectors and harvest SVID credentials from the SPIRE
  agent.
labels:
- hunt
- attack.t1090.003
- attack.t1190
name: SPIFFE/SPIRE Identity Spoofing and Harvesting
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
    type: list[host]
  spire_socket_paths:
    default:
    - /run/spire/sockets/agent.sock
    - /var/lib/spire/agent.sock
    description: Common paths for the SPIRE Workload API socket.
    from:
      kind: article
      observed: '2026-09-10'
      ref: unit42-spiffe-spire
    type: list[path]
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
rationale: Scope to nodes running spire-agent. The initial access often happens via
  an exploit on a public application; prioritize nodes with internet exposure.
references:
- name: "Unit 42 \u2014 The Machine With Many Faces: Post-Exploitation Identity Misuse\
    \ in SPIFFE/SPIRE"
  url: https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
related:
- hunt: lateral-workload-impersonation
  reason: Detection of harvested SVID use in other services (e.g. at the API Gateway)
    is outside the scope of host-level harvesting.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Kubernetes Node Initial Access
    observables:
    - exploit of public-facing application
    - root access on Kubernetes node
    slug: initial-k8s-node-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: Workload Metadata Discovery
    observables:
    - /proc/[pid]/cgroups
    - /proc/[pid]/mountinfo
    - kubepods.slice
    - kubepods-besteffort.slice
    - pod UID identification
    - container ID identification
    slug: workload-metadata-enumeration
    tactic: discovery
  - name: SPIRE Attestation Spoofing
    observables:
    - Spooffe tool
    - cgroup metadata manipulation
    - spoofing GetPodUIDAndContainerID calls
    - impersonating workload selectors
    slug: spire-attestation-spoofing
    tactic: defense-evasion
  - name: SVID Identity Extraction
    observables:
    - /run/spire/sockets/agent.sock
    - FetchJWTSVID
    - FetchX509SVID
    - X.509 SVID extraction
    - JWT SVID harvesting
    - SPIRE Workload API interaction
    slug: svid-credential-harvesting
    tactic: credential-access
  - name: Workload Identity Misuse
    observables:
    - mTLS handshake with stolen SVID
    - spiffe://example.com/
    - spiffe://example.org/
    - unauthorized service-to-service authentication
    slug: lateral-workload-impersonation
    tactic: lateral-movement
    techniques:
    - T1090.003
  summary: An attacker with root access on a Kubernetes node exploits the trust assumptions
    of the SPIFFE/SPIRE identity framework by spoofing Linux cgroup and mountinfo
    metadata. By manipulating how the SPIRE agent attests processes, the attacker
    can harvest short-lived SVID credentials (X.509 or JWT) belonging to co-located
    workloads, enabling unauthorized cross-workload impersonation and lateral movement.
series:
  index: 1
  slug: the-machine-with-many-faces-post-exploitation-identity-misuse-in-spiffe-spire
  title: 'The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE'
  total: 2
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
tlp: clear
type: investigation
---


# SPIFFE/SPIRE Identity Spoofing and Harvesting

This hunt identifies post-exploitation activity where an attacker attempts to impersonate Kubernetes workloads by spoofing Linux control group (cgroup) information used during SPIRE workload attestation. By identifying ad-hoc interrogation of /proc/cgroups and /proc/mountinfo and correlating this with rare processes accessing the SPIRE agent's Unix domain socket, the hunt detects attempts to harvest short-lived X.509 and JWT identities (SVIDs).

## identify-spire-nodes
<!-- Identify nodes running SPIRE components -->
Scope the hunt to nodes that are actually running the SPIRE agent or relevant container runtimes.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to Kubernetes nodes and SPIRE agent hosts.
  Silence here suggests SPIRE is not deployed using standard package names.
reads:
- device_hostname
- package_name
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%spire-agent%' OR LOWER(package_name) LIKE '%kubelet%' OR LOWER(package_name) LIKE '%containerd%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## detect-proc-interrogation
<!-- Detect suspicious /proc interrogation -->
Identify non-standard processes reading cgroup or mount metadata, which are the selectors used for SPIRE workload attestation.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Ad-hoc interrogation of /proc by shell utilities or unknown binaries. This
  is a high-confidence signal for manual discovery of workload metadata.
reads:
- device_hostname
- process_cmd_line
- process_path
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, process_path, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%/proc/%/cgroup%' OR LOWER(process_cmd_line) LIKE '%/proc/%/mountinfo%') AND NOT (LOWER(process_path) LIKE '%/kube%' OR LOWER(process_path) LIKE '%/spire-agent%' OR LOWER(process_path) LIKE '%/containerd%' OR LOWER(process_path) LIKE '%/containerd-shim%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroboration-parallel
<!-- Corroborate via socket interaction and prevalence -->
parallel:
- → rare-spire-processes
- → socket-file-activity
join: → triage-agent

## rare-spire-processes
<!-- Identify rare processes and SPIRE indicators -->
Find rare processes whose command lines contain spoofing keywords like 'Spooffe' or SVID fetching operations.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes or scripts referencing SVID fetching that are not fleet-wide sidecars.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 4
reads:
- process_name
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%spooffe%' OR LOWER(process_cmd_line) LIKE '%fetchx509svid%' OR LOWER(process_cmd_line) LIKE '%fetchjwtsvid%' OR LOWER(process_cmd_line) LIKE '%kubepods.slice%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_cmd_line HAVING hosts <= 3 ORDER BY hosts ASC
```

## socket-file-activity
<!-- File activity on SPIRE agent sockets -->
Confirm which processes are directly opening the SPIRE socket to request identities.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, spire_socket_paths=spire_socket_paths, lookback_days=lookback_days)
~~~yaml
expected: A list of processes that touched the SPIRE socket. Combined with the prevalence
  query, this isolates unknown actors from legitimate sidecars.
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{spire_socket_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage identity harvesting activity -->
```agent target=hunter
cite: required
context:
- detect-proc-interrogation
- rare-spire-processes
- socket-file-activity
max_iterations: 5
objective: Determine if any host shows evidence of metadata interrogation concurrent
  with access to the SPIRE agent socket by a rare or suspicious process.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  process and file rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for identity spoofing or harvesting" (confidence: high, judge=hunter)
then: → isolate-node
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-socket-telemetry)
else: → analyst-review

## isolate-node
<!-- Isolate compromised Kubernetes node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and immediately alert the Kubernetes platform team. Review the pod inventory for any co-located workloads whose identities may have been harvested.
```
→ analyst-review

## analyst-review
<!-- Analyst review and manual triage -->
```manual target=analyst
Review the processes flagged for /proc interrogation. Check for presence of the 'Spooffe' tool or similar compiled binaries. If benign, refine the 'detect-proc-interrogation' exclusions list.
```
→ end
