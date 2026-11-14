---
analysis: A single rule on privileged pods triggers high noise from system pods; a
  rule on token access misses the context. This hunt joins the 'why' (discovery) and
  'how' (token harvest) with 'impact' (privileged deployment) to create a high-fidelity
  attack chain.
blind_spots:
- id: missing-k8s-audit-logs
  question: What commands were executed via 'kubectl exec'?
  remediation: Enable and ingest Kubernetes API audit logs with request detail.
  requires: Kubernetes Audit Logs (ResponseComplete stage)
  risk: Attackers can perform interaction and escape without leaving a trace in standard
    runtime process events if they use API-based methods.
  stage: pod-exec-interaction
- id: ephemeral-pod-visibility
  question: Did a pod exist only for a few seconds during the escape attempt?
  remediation: Move from periodic inventory snapshots to an event-driven pod creation
    stream.
  requires: Continuous pod inventory (live stream)
  risk: Snapshot-based inventory like kubernetes_pod may miss short-lived attack pods
    used for one-off commands.
  stage: privileged-pod-deployment
coverage:
- stage: workload-service-account-discovery
  status: covered
  steps:
  - discovery-tool-prevalence
- stage: token-credential-harvesting
  status: covered
  steps:
  - token-harvesting-activity
- stage: privileged-pod-deployment
  status: covered
  steps:
  - privileged-pod-deployment
- blind_spot: missing-k8s-audit-logs
  reason: Requires Kubernetes audit logs to see decoded requestURIs for exec commands;
    not present in available hb_ surfaces.
  stage: pod-exec-interaction
  status: not_visible
- reason: Escape wrappers nsenter/chroot in URI format require API audit logs; hb_process_activity
    may see them if run as host processes, but the API interaction is invisible.
  stage: container-escape-attempt
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kubernetes container escape allows an attacker to pivot from a single
    compromised container to the entire physical host, bypassing isolation boundaries.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has harvested a service account token from a compromised pod
  and is using it to deploy a privileged pod for container escape, bypassing standard
  runtime process detection.
labels:
- hunt
- attack.t1613
- attack.t1552.006
- attack.t1610
- attack.t1609
- attack.t1611
name: Kubernetes Service Account Abuse and Escape
parameters:
  discovery_commands:
    default:
    - kubectl
    - kube-hunter
    - kube-bench
    - microk8s
    - k3s
    description: Common Kubernetes discovery tools and command fragments.
    type: list[string]
  k8s_secret_paths:
    default:
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    description: Paths to Kubernetes service account secrets.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on namespaces hosting public-facing services. Use the software inventory
  step to identify worker nodes running K8s system packages (deb/rpm only).
references:
- name: "Elastic Security Labs \u2014 How to correlate Kubernetes audit logs with\
    \ container runtime data"
  url: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
related:
- hunt: cloud-control-plane-credential-abuse
  reason: This hunt focuses on the Kubernetes plane; abuse of cloud provider identity
    (IMDS) is a separate scenario.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Service account discovery
    observables:
    - kubectl get pods
    - system:serviceaccount identifier
    - API discovery verbs
    slug: workload-service-account-discovery
    tactic: discovery
    techniques:
    - T1613
  - name: Service account token harvesting
    observables:
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    slug: token-credential-harvesting
    tactic: credential-access
    techniques:
    - T1552.006
  - name: Privileged pod deployment
    observables:
    - 'objectRef.resource: pods'
    - 'kubernetes.audit.verb: create'
    - 'privileged: true security context'
    slug: privileged-pod-deployment
    tactic: execution
    techniques:
    - T1610
  - name: Interactive pod shell
    observables:
    - 'kubernetes.audit.objectRef.subresource: exec'
    - requestURI containing command list
    slug: pod-exec-interaction
    tactic: execution
    techniques:
    - T1609
  - name: Container escape via host utilities
    observables:
    - nsenter
    - chroot
    - requestURI containing escape wrappers
    slug: container-escape-attempt
    tactic: privilege-escalation
    techniques:
    - T1611
  summary: An attacker leverages a compromised service account to perform discovery
    and harvest authentication tokens from the container filesystem. Using these credentials,
    they deploy a privileged pod and attempt a container escape using utilities like
    nsenter and chroot, a multi-plane attack requiring correlation between runtime
    telemetry and Kubernetes audit logs.
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
  kubernetes:
    category: siem
    huntbase:
      product: kubernetes
    name: kubernetes
tlp: clear
type: investigation
---


# Kubernetes Service Account Abuse and Escape

This hunt correlates early-stage discovery and credential harvesting inside containers with follow-on control-plane abuse. It moves from process-level discovery and file-level token access to identifying privileged pod configurations that facilitate escape. By joining endpoint telemetry with Kubernetes pod manifests, we identify the complete progression from a beachhead to a potential host-level compromise.

## k8s-infrastructure-scope
<!-- Identify Kubernetes infrastructure -->
Locate hosts running Kubernetes or container runtimes to focus the hunt, filtering out unrelated system packages.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames hosting Kubernetes components. Silence means no K8s-related
  system packages are installed.
reads:
- device_hostname
- package_name
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%kube%' OR LOWER(package_name) LIKE '%docker%' OR LOWER(package_name) LIKE '%containerd%') AND (package_type = 'deb' OR package_type = 'rpm') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## gather-early-evidence
<!-- Gather discovery and harvesting evidence -->
parallel:
- → discovery-tool-prevalence
- → token-harvesting-activity
join: → early-stage-triage

## discovery-tool-prevalence
<!-- Discovery tool prevalence -->
Find evidence of cluster enumeration using common tools, checking for rare executions that indicate manual intervention.

```sqlite target=endpoint role=baseline params=(discovery_commands=discovery_commands, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process execution indicating manual discovery. Silence suggests no
  common tools were run via monitored process events.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 5
reads:
- process_name
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/kubectl' OR LOWER(process_name) LIKE '%/kube-hunter' OR LOWER(process_name) LIKE '%/kube-bench' OR instr(',' || '{{discovery_commands}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%get pods%' OR LOWER(process_cmd_line) LIKE '%get secrets%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY process_name, process_cmd_line HAVING hosts <= 5 ORDER BY hosts
```

## token-harvesting-activity
<!-- Service account token harvesting -->
Detect access to Kubernetes service account tokens, which are the target for attackers seeking to abuse the API.

```sqlite target=endpoint role=detection-candidate params=(k8s_secret_paths=k8s_secret_paths, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes reading tokens from /var/run/secrets. Access from non-system processes
  is a high-fidelity indicator.
reads:
- device_hostname
- process_name
- process_cmd_line
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, file_path, time FROM hb_file_activity WHERE instr(',' || '{{k8s_secret_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-triage
<!-- Triage early-stage activity -->
```agent target=hunter
cite: required
context:
- discovery-tool-prevalence
- token-harvesting-activity
max_iterations: 3
objective: Determine if the same container or host that ran Kubernetes discovery tools
  also accessed sensitive service account tokens.
success_criteria: Identification of a compromised pod identity and host context.
tools:
- endpoint
- kubernetes
```

## privileged-pod-deployment
<!-- Identify privileged pod deployments -->
Find pods with high-risk configurations that facilitate container escape by sharing host namespaces.

```sqlite target=kubernetes role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Pods created with host namespace permissions. Silence means no pods with
  these dangerous settings were detected in the current inventory.
reads:
- hostname
- host_pid
- host_network
- host_ipc
- creation_timestamp
- context_name
silence: evidence_of_absence
source: kubernetes_pod
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname, host_pid, host_network, host_ipc, creation_timestamp, context_name FROM kubernetes_pod WHERE (host_pid = 1 OR host_network = 1 OR host_ipc = 1) AND creation_timestamp >= datetime('now', '-{{lookback_days}} days')
```

## final-intrusion-assessment
<!-- Final intrusion assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- privileged-pod-deployment
max_iterations: 4
objective: Weigh the early-stage discovery findings against the appearance of privileged
  pods. Does the timing and identity suggest the discovery led to this deployment?
success_criteria: A final verdict of malicious | suspicious for the investigated hosts.
tools:
- endpoint
- kubernetes
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-intrusion-assessment verdict is malicious for at least one host following token harvesting" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-k8s-audit-logs)
else: → close-out

## isolate-host
<!-- Isolate host and revoke SA -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint running the Kubelet. Coordinate with DevOps to delete the privileged pod and revoke the compromised service account token immediately.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the process timeline leading to token harvesting. Check for other pods created by the same service account. Verify if escape wrappers like nsenter were executed by checking direct host process activity.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. If token harvesting was confirmed, promote the file-activity query to a permanent detection rule.
```
→ end
