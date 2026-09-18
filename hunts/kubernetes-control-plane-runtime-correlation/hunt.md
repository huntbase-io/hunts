---
analysis: "A standard rule might fire on 'chroot' execution, but this hunt pivots\
  \ to the Service Account that initiated it via the API and checks for concurrent\
  \ token access\u2014a cross-surface join that filters out noise from administrative\
  \ tasks."
blind_spots:
- id: incomplete-audit-logs
  question: whether the 'exec' command contained escape tools in the requestURI
  requires: Kubernetes Audit Logs (ResponseComplete level)
  risk: If audit logs are not configured to capture the request body or full URI (Metadata
    only), the escape command is hidden from the control plane view.
  stage: exec-and-container-escape
- id: in-memory-token-usage
  question: whether the token was used by a process that already had a handle to the
    file
  requires: hb_file_activity
  risk: File activity logs typically only capture the 'open' call; a process that
    keeps the file descriptor open may bypass subsequent read-based alerts.
  stage: token-credential-access
coverage:
- stage: api-discovery-and-recon
  status: covered
  steps:
  - k8s-audit-api-activity
- stage: token-credential-access
  status: covered
  steps:
  - detect-sa-token-access
- stage: malicious-pod-deployment
  status: covered
  steps:
  - k8s-audit-api-activity
- stage: exec-and-container-escape
  status: covered
  steps:
  - rare-escape-tool-execution
  - k8s-audit-api-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kubernetes control plane intrusions often pivot into the node using
    techniques (like chroot) that bypass traditional runtime process monitoring. Correlation
    between the API plane (HTTP logs) and the host plane (File/Process logs) is necessary
    to detect container escapes.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a workload, accessed its service account
  token, and is using the Kubernetes API to deploy privileged pods or escape containers,
  leaving traces in audit logs and rare process executions.
labels:
- hunt
- attack.t1613
- attack.t1087.002
- attack.t1552.001
- attack.t1610
- attack.t1609
- attack.t1611
name: Kubernetes Control Plane and Runtime Correlation
parameters:
  escape_tools:
    default:
    - nsenter
    - chroot
    description: Tools commonly used for container escapes.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  sa_token_paths:
    default:
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    description: Standard paths for Kubernetes Service Account secrets.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
    type: list[path]
  scope_hosts:
    default: []
    description: List of Kubernetes node hostnames to focus on; leave empty for estate-wide.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize nodes running internet-facing workloads or those identified
  in vulnerability scans as having critical findings. If no Kubernetes components
  are found in software inventory, widen to all Linux hosts.
references:
- name: "Elastic Security Labs \u2014 How to correlate Kubernetes audit logs with\
    \ container runtime data"
  url: https://www.elastic.co/security-labs/threat-command/kubernetes-audit-logs-container-escape
related:
- hunt: kubernetes-privilege-escalation
  reason: Escaping a container is often the step before host-level privilege escalation.
  relation: follows
scenario:
  stages:
  - name: Service Account API Discovery
    observables:
    - 'user.name: system:serviceaccount:*'
    - 'kubernetes.audit.verb: list'
    - 'kubernetes.audit.verb: get'
    - 'objectRef.resource: secrets'
    slug: api-discovery-and-recon
    tactic: discovery
    techniques:
    - T1613
    - T1087.002
  - name: Service Account Token Access
    observables:
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - 'file.path: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    - 'process.interactive: true'
    slug: token-credential-access
    tactic: credential-access
    techniques:
    - T1552.001
  - name: Privileged Pod Deployment
    observables:
    - 'kubernetes.audit.verb: create'
    - 'objectRef.resource: pods'
    - 'requestObject.spec.containers.securityContext.privileged: true'
    slug: malicious-pod-deployment
    tactic: persistence
    techniques:
    - T1610
  - name: Container Exec and Escape Attempt
    observables:
    - 'objectRef.subresource: exec'
    - nsenter
    - chroot
    - kubernetes.audit.requestURI
    slug: exec-and-container-escape
    tactic: defense-evasion
    techniques:
    - T1609
    - T1611
  summary: A compromised Kubernetes service account is used for discovery and secret
    access, leading to the theft of service account tokens from the filesystem. The
    attacker then deploys a privileged pod and uses the exec subresource to attempt
    a container escape using nsenter and chroot, a sequence that is only fully detectable
    by correlating Kubernetes API audit logs with container runtime process and file
    events.
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
  kubernetes:
    category: siem
    huntbase:
      product: kubernetes
    name: kubernetes
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Kubernetes Control Plane and Runtime Correlation

This hunt bridges the visibility gap between Kubernetes API activity (control plane) and container behavior (endpoint plane). It identifies the access of Service Account tokens, tracks rare execution of container escape tools like nsenter or chroot, and correlates these with Kubernetes audit logs captured in HTTP traffic. By joining the API request parameters with runtime process stack-counts, the hunt uncovers lateral movement into the cluster fabric that single-surface detections miss.

## find-k8s-nodes
<!-- Find Kubernetes nodes -->
Identify hosts running Kubernetes components to narrow the hunt to the relevant container environment.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to Kubernetes nodes. If empty, the organization
  may not be running Kubernetes or the software inventory is not captured.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%kubelet%' OR LOWER(package_name) LIKE '%kubernetes%'
```

## detect-sa-token-access
<!-- Service Account token access -->
Detect processes accessing the Service Account token, which is the required credential for control-plane abuse.

```sqlite target=endpoint role=detection-candidate params=(sa_token_paths=sa_token_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Access events for token files. Standard agents (e.g. cloud-init, kubelet)
  should be common; interactive shells or rare binaries (e.g. curl) are high-confidence
  leads.
reads:
- device_hostname
- actor_user_name
- process_name
- process_cmd_line
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, process_name, process_cmd_line, file_path, time FROM hb_file_activity WHERE (instr(',' || '{{sa_token_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-escape-tool-execution
<!-- Rare execution of escape tools -->
Stack-count the execution of tools like nsenter and chroot across the fleet to find anomalous container escape attempts.

```sqlite target=endpoint role=baseline params=(escape_tools=escape_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare instances of escape tools. Legitimate use by cluster administrators
  or node maintenance scripts should appear across many hosts or at fixed intervals.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS execution_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{escape_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## correlate-activity
<!-- Correlate API and Inventory -->
parallel:
- → k8s-audit-api-activity
- → active-pod-inventory
join: → triage-agent

## k8s-audit-api-activity
<!-- Kubernetes Audit API activity -->
Examine the API control plane for Service Account discovery, pod creation, or exec calls containing escape tools.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: API requests directed at the Kubernetes API server where Service Accounts
  are used to list secrets or execute commands containing 'nsenter' or 'chroot'.
reads:
- device_hostname
- url_path
- url_query
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, url_query, actor_user_name, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/exec%' OR LOWER(url_path) LIKE '%/secrets%' OR LOWER(url_path) LIKE '%/pods%') AND (LOWER(url_query) LIKE '%nsenter%' OR LOWER(url_query) LIKE '%chroot%' OR LOWER(url_path) LIKE '%/secrets%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## active-pod-inventory
<!-- Active pod inventory -->
Identify current pods and containers on the nodes to map runtime process findings to specific orchestrator resources.

```sqlite target=kubernetes role=enrichment params=(scope_hosts=scope_hosts)
~~~yaml
expected: A snapshot of running pods, allowing the analyst to correlate 'device_hostname'
  from endpoint logs with specific container names and namespaces.
reads:
- hostname
- host_ip
- creation_timestamp
- containers
- _ctx
silence: not_evidence_of_absence
source: kubernetes_pod
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, host_ip, creation_timestamp, containers, _ctx FROM kubernetes_pod WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0)
```

## triage-agent
<!-- Triage cross-plane activity -->
```agent target=hunter
cite: required
context:
- detect-sa-token-access
- rare-escape-tool-execution
- k8s-audit-api-activity
- active-pod-inventory
max_iterations: 5
objective: Determine if a Service Account principal used its token to perform discovery
  or execute escape commands ('nsenter', 'chroot') on any pod. Cross-reference the
  'device_hostname' from endpoint logs with the 'hostname' in pod inventory.
success_criteria: A verdict of malicious | suspicious | benign per host/pod, citing
  the correlated API verb and runtime process.
tools:
- endpoint
- kubernetes
- web
```

## decide-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one service account or pod" (confidence: high, judge=hunter)
then: → isolate-pod
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-audit-logs)
else: → close-out

## isolate-pod
<!-- Isolate pod and node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the node host. Use kubectl to delete the suspicious pod and rotate the credentials for the compromised Service Account.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the API requests logged in the HTTP activity. Determine if other objects (Secrets, ConfigMaps) were listed or retrieved by the Service Account. Record a tuning note if the chroot/nsenter activity was legitimate.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no multi-plane correlation of SA abuse was found within the window. Ensure 'escape_tools' and 'sa_token_paths' were correctly examined.
```
→ end
