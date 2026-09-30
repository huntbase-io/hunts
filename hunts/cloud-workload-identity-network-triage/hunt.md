---
analysis: A single rule can find known C2 domains; this hunt stack-counts DNS lookups
  specifically for container hosts identified in inventory and correlates them with
  administrative identity activity.
blind_spots:
- id: encrypted-c2-blindspot
  question: Is the rare outbound traffic legitimate API usage or encrypted C2?
  requires: TLS inspection or application-proxy logs
  risk: Encrypted C2 traffic over standard ports may appear as legitimate workload
    traffic to unknown external APIs.
  stage: outbound-command-and-control
- id: missing-k8s-audit-logs
  question: Did the identity modify K8s configurations or secrets?
  requires: hb_auth_signin enrichment with K8s API audit data
  risk: Adversaries can modify the orchestration plane (K8s API) without generating
    a standard cloud login event, leaving the initial compromise steps invisible.
  stage: over-permissioned-identity-access
coverage:
- stage: over-permissioned-identity-access
  status: covered
  steps:
  - cloud-identity-signins
  - triage-risk
- stage: outbound-command-and-control
  status: covered
  steps:
  - rare-workload-dns
  - triage-risk
- reason: "Belongs to another part of the 'Microsoft named a Leader in the Frost Radar\u2122\
    : Cloud Workload Protection Platforms, 2026' series."
  stage: initial-access-exploit
  status: out_of_scope
- reason: "Belongs to another part of the 'Microsoft named a Leader in the Frost Radar\u2122\
    : Cloud Workload Protection Platforms, 2026' series."
  stage: runtime-container-execution
  status: out_of_scope
- reason: "Belongs to another part of the 'Microsoft named a Leader in the Frost Radar\u2122\
    : Cloud Workload Protection Platforms, 2026' series."
  stage: persistence-through-drift
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The 2026 Frost Radar highlights that a vulnerability is only a risk
    if it is running and reachable; this hunt correlates identity abuse with the runtime
    network telemetry needed to prioritize real intrusions.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses over-permissioned cloud identities to compromise container
  workloads, establishing persistence through rare outbound network channels that
  bypass standard scanning.
labels:
- hunt
- attack.t1078.004
- attack.t1071.001
- attack.t1190
name: Cloud Workload Identity and Network Triage
parameters:
  cloud_providers:
    default:
    - aws
    - azure
    - gcp
    description: Cloud providers to monitor for control plane access.
    from:
      kind: article
      observed: '2026-08-19'
      ref: msrc-blog-frost-radar-2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Target hostnames found in the scoping step; leave empty to scan all
      cloud instances.
    from:
      kind: manual
      observed: '2026-08-19'
      ref: analyst-defined-scope
    type: list[host]
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
rationale: Target workloads running Docker, Kubelet, or Containerd. Use the hostnames
  identified in the scoping step to narrow the network investigation in the parallel
  branches.
references:
- name: 'Microsoft named a Leader in the Frost Radar: Cloud Workload Protection Platforms,
    2026'
  url: https://www.microsoft.com/en-us/security/blog/2026/08/19/microsoft-named-a-leader-in-the-frost-radar-cloud-workload-protection-platforms-2026/
related:
- hunt: kubernetes-drift-analysis
  reason: Detection of execution within the container itself via runtime drift is
    handled by a separate hunt.
  relation: out-of-scope-alternative
- hunt: cloud-workload-runtime-exploitation-behavior
  relation: follows
scenario:
  stages:
  - name: Exploit Public-Facing Application
    observables:
    - Incoming HTTP requests to vulnerable web applications
    - Presence of known vulnerabilities on internet-exposed assets
    - Misconfigured cloud infrastructure services
    slug: initial-access-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Process Execution in Containers
    observables:
    - Suspicious process launches in Kubernetes pods
    - eBPF-detected anomalous runtime events
    - Interactive shell execution within running containers
    slug: runtime-container-execution
    tactic: execution
    techniques:
    - T1059
  - name: Container Binary Drift
    observables:
    - Unauthorized binary changes mid-run (drift)
    - Modifications to files within running container layers
    - Unexpected process activity from modified binaries
    slug: persistence-through-drift
    tactic: defense-evasion
    techniques:
    - T1542
  - name: Abuse of Over-Permissioned Identities
    observables:
    - Authentication using high-privilege service accounts
    - Anomalous sign-ins to cloud control planes (Azure, AWS, GCP)
    - Identity-linked access to Kubernetes API and resources
    slug: over-permissioned-identity-access
    tactic: credential-access
    techniques:
    - T1078
  - name: Outbound Command and Control
    observables:
    - DNS queries from Kubernetes pods to external domains
    - Outbound network connections to suspicious IP addresses
    - High-volume data transfer from container workloads
    slug: outbound-command-and-control
    tactic: command-and-control
    techniques:
    - T1071
  summary: This campaign involves the exploitation of public-facing applications to
    gain initial access to cloud workloads, particularly Kubernetes environments.
    Once inside, attackers execute malicious processes, leverage over-permissioned
    identities, and establish persistence through binary drift and outbound command-and-control
    traffic.
series:
  index: 2
  slug: microsoft-named-a-leader-in-the-frost-radar-cloud-workload-protection-platforms-2026
  title: "Microsoft named a Leader in the Frost Radar\u2122: Cloud Workload Protection\
    \ Platforms, 2026"
  total: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Cloud Workload Identity and Network Triage

This hunt identifies and correlates identity-based control plane abuse with network-level anomalies in running container environments. By combining software inventory to scope container hosts, cloud authentication logs to identify identity abuse, and stack-counted DNS activity to find rare command-and-control targets, the hunt provides a unified view of post-exploitation risk in cloud-native workloads.

## scope-container-workloads
<!-- Scope container workloads -->
Find the hosts running container orchestration and runtime software to narrow the hunt's focus to workloads.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames associated with container infrastructure. Silence means
  no container engines were identified in the current inventory.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%docker%' OR LOWER(package_name) LIKE '%kube%' OR LOWER(package_name) LIKE '%containerd%') OR (LOWER(vendor_name) LIKE '%kubernetes%' OR LOWER(vendor_name) LIKE '%docker%')
```

## investigate-identity-and-egress
<!-- Investigate identity and egress -->
parallel:
- → cloud-identity-signins
- → rare-workload-dns
join: → triage-risk

## cloud-identity-signins
<!-- Cloud identity sign-ins -->
Identify administrative sign-ins to cloud control planes that could precede workload modifications.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, cloud_providers=cloud_providers)
~~~yaml
expected: Successful logins to AWS, Azure, or GCP consoles and APIs. Unusual source
  IPs for admin users are higher risk.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, time FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{cloud_providers}}' || ',', ',' || LOWER(provider) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-workload-dns
<!-- Rare workload DNS activity -->
Stack-count DNS queries across the workload fleet to find rare destinations indicative of C2 persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS hostnames queried by only a few container workloads. Silence on this
  surface may indicate IP-direct communication.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING hosts <= 3 ORDER BY hosts ASC, lookups DESC
```

## triage-risk
<!-- Triage workload risk -->
```agent target=hunter
cite: required
context:
- cloud-identity-signins
- rare-workload-dns
max_iterations: 6
objective: Determine if any successful administrative sign-in originated from a source
  IP or occurred at a time that corresponds with the first appearance of a rare DNS
  destination from a container host. Assess if the over-permissioned account likely
  modified the workload.
success_criteria: A per-host and per-identity verdict of malicious | suspicious |
  benign, citing specific rows and timestamps.
tools:
- endpoint
- identity
```

## route-risk
<!-- Route on risk -->
if~: "the triage-risk verdict is malicious for at least one workload-identity pair" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-c2-blindspot)
else: → close-out

## isolate-and-revoke
<!-- Isolate and revoke -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified container host and revoke all active session tokens for the compromised cloud identity.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from the triage agent. Verify if the rare DNS queries represent legitimate new application dependencies or known malicious domains.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts and identities examined. Note any visibility gaps such as missing Kubernetes audit logs for future platform hardening.
```
→ end
