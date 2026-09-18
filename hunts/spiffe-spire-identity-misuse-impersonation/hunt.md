---
analysis: A standard rule cannot distinguish between a legitimate SPIFFE authentication
  and one performed by an attacker with a harvested SVID. This hunt uses fleet-wide
  prevalence (rare IP for a workload) and host-level forensics (root procfs enumeration)
  to weigh the intent behind the authentication.
blind_spots:
- id: incomplete-proc-logging
  question: Did the attacker use a tool that read procfs but finished before a snapshot
    was taken?
  remediation: Enable high-frequency process event logging or auditd for procfs access.
  requires: EDR process command line capture for short-lived processes
  risk: Short-lived harvesting tools may not appear in hb_process_activity snapshots.
  stage: lateral-workload-impersonation
- id: short-lived-svid-reuse
  question: Was the stolen SVID used for an mTLS connection that is not logged as
    a discrete sign-in event?
  remediation: Correlate hb_network_connection with workload identity metadata.
  requires: mTLS handshake telemetry in hb_auth_signin
  risk: Identity misuse may occur at the transport layer without triggering a normalized
    auth event.
  stage: lateral-workload-impersonation
coverage:
- stage: lateral-workload-impersonation
  status: covered
  steps:
  - spiffe-auth-anomalies
  - root-cgroup-enumeration
  - triage-misuse
- reason: 'Belongs to another part of the ''The Machine With Many Faces: Post-Exploitation
    Identity Misuse in SPIFFE/SPIRE'' series.'
  stage: initial-k8s-node-compromise
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Machine With Many Faces: Post-Exploitation
    Identity Misuse in SPIFFE/SPIRE'' series.'
  stage: workload-metadata-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Machine With Many Faces: Post-Exploitation
    Identity Misuse in SPIFFE/SPIRE'' series.'
  stage: spire-attestation-spoofing
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Machine With Many Faces: Post-Exploitation
    Identity Misuse in SPIFFE/SPIRE'' series.'
  stage: svid-credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: A root-level compromise of a SPIRE node invalidates the security
    of all co-located workloads. A negative result confirms that identity-based boundaries
    within the service mesh remain intact following node-level exposure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker with root on a Kubernetes node is using harvested SPIFFE SVIDs
  to authenticate as co-located workloads, moving laterally across the service mesh.
labels:
- hunt
- attack.t1090.003
- attack.t1190
name: SPIFFE/SPIRE Identity Misuse and Workload Impersonation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames (from scoping step) to focus subsequent
      queries.
    type: list[host]
  spiffe_trust_domains:
    default:
    - example.com
    - example.org
    description: The SPIFFE trust domains configured in the environment.
    from:
      kind: article
      observed: '2026-09-10'
      ref: unit42-machine-faces
    type: list[domain]
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
rationale: Target all Kubernetes worker nodes and virtual machines participating in
  the SPIFFE/SPIRE mesh. The scoping step specifically filters for the presence of
  'spire-agent' to focus on where the identity mechanism is active.
references:
- name: 'Unit 42: The Machine With Many Faces: Post-Exploitation Identity Misuse in
    SPIFFE/SPIRE'
  url: https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/
related:
- hunt: kubernetes-privileged-container-audit
  reason: Finding privileged containers is a prerequisite for the root-level node
    access required for this technique.
  relation: precedes
- hunt: spiffe-spire-identity-spoofing-harvesting
  relation: follows
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
  index: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# SPIFFE/SPIRE Identity Misuse and Workload Impersonation

This hunt identifies the misuse of SPIFFE identities for lateral movement following a node compromise. By exploiting root access to manipulate cgroup metadata, an attacker can trick a SPIRE agent into issuing certificates (SVIDs) for any workload on that node. We analyze authentication logs for rare SPIFFE ID-to-source-IP mappings and investigate suspicious root-level process activity that indicates metadata spoofing or credential harvesting.

## scoping-spire-nodes
<!-- Identify nodes running SPIRE agents -->
Identify the subset of the fleet that is participating in the SPIFFE/SPIRE identity mesh.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of Kubernetes nodes or VMs. These are the locations where SVID harvesting
  via selector spoofing is possible.
reads:
- device_hostname
- package_version
- vendor_name
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%spire-agent%'
```

## parallel-gathering
<!-- Gather identity and process evidence -->
parallel:
- → spiffe-auth-anomalies
- → root-cgroup-enumeration
join: → triage-misuse

## spiffe-auth-anomalies
<!-- Anomalous SPIFFE ID authentication -->
Find SPIFFE identities being used from rare source IPs, suggesting that an SVID has been moved from its original node.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, spiffe_trust_domains=spiffe_trust_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: SPIFFE IDs that appear on multiple source IPs or on an IP not traditionally
  associated with that specific workload namespace.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, COUNT(*) as auth_count, MIN(time) as first_seen FROM hb_auth_signin WHERE actor_user_name LIKE 'spiffe://%' AND (instr(',' || '{{spiffe_trust_domains}}' || ',', ',' || SUBSTR(actor_user_name, 10, INSTR(SUBSTR(actor_user_name, 10) || '/', '/') - 1) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name
```

## root-cgroup-enumeration
<!-- Suspicious root-level metadata inspection -->
Detect the technical mechanics of cgroup spoofing where a root process inspects other containers' metadata to impersonate them.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unusual processes (not Kubelet or known monitoring agents) running as root
  and reading procfs metadata for other PIDs.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND user_name = 'root' AND (process_cmd_line LIKE '%/proc/%/cgroup%' OR process_cmd_line LIKE '%/proc/%/mountinfo%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-misuse
<!-- Triage workload identity misuse -->
```agent target=hunter
cite: required
context:
- scoping-spire-nodes
- spiffe-auth-anomalies
- root-cgroup-enumeration
max_iterations: 6
objective: Evaluate whether anomalous SPIFFE authentication (identities used from
  multiple source IPs) correlates with nodes where root-level procfs metadata was
  enumerated.
success_criteria: A per-host verdict of malicious, suspicious, or benign with citations
  for specific SPIFFE IDs and process command lines.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-node
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-proc-logging)
else: → close-out

## isolate-node
<!-- Isolate compromised node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate an incident response plan for Kubernetes node compromise. Revoke all SVIDs that were present on this node.
```
→ analyst-review

## analyst-review
<!-- Analyst final review -->
```manual target=analyst
Verify the cited auth sign-ins against the expected source IPs for those SPIFFE identities. Confirm if the root process activity was legitimate administrative maintenance.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record what was examined and if any new nodes need SPIRE agent coverage.
```
→ end
