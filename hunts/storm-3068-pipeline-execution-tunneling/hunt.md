---
analysis: A simple rule might alert on a Chisel binary, but this hunt provides the
  critical context of an unauthorized pipeline modification leading to that execution,
  distinguishing it from legitimate developer activity.
blind_spots:
- id: ephemeral-build-telemetry
  owner: Cloud Platforms Team
  question: Did the malicious script execute in an ephemeral container that was deleted
    before telemetry was collected?
  remediation: Enable continuous log streaming for all build environments to a centralized
    lake.
  requires: off-host log streaming from build agents
  risk: Attackers can run malicious jobs in short-lived runners that evade periodic
    inventory or process snapshots.
  stage: malicious-pipeline-execution
- id: missing-git-diffs
  owner: DevSecOps Team
  question: What specific code was added to the pipeline to harvest credentials?
  remediation: Configure automated security analysis for all pipeline YAML changes.
  requires: Azure DevOps Git audit logs with diff content
  risk: Standard audit logs often confirm a file was modified but do not show the
    actual malicious script content, requiring manual forensic effort to recover the
    intent.
  stage: malicious-pipeline-execution
coverage:
- stage: malicious-pipeline-execution
  status: covered
  steps:
  - pipeline-api-changes
  - identify-rmm-execution
- stage: remote-access-tooling
  status: covered
  steps:
  - identify-rmm-execution
  - rare-outbound-tunnels
- reason: 'Belongs to another part of the ''\u200b\u200bBeyond source code: A path
    to the keys to the kingdom'' series.'
  stage: identity-compromise-sspr
  status: out_of_scope
- reason: 'Belongs to another part of the ''\u200b\u200bBeyond source code: A path
    to the keys to the kingdom'' series.'
  stage: azure-devops-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''\u200b\u200bBeyond source code: A path
    to the keys to the kingdom'' series.'
  stage: credential-harvesting-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Build pipelines connect development code to production cloud infrastructure;
    ensuring their integrity is a critical obligation for protecting the organization's
    cloud environment and secrets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has modified build pipelines to execute malicious code on
  agents, deploying RMM tools and establishing tunnels to exfiltrate Kubernetes credentials.
labels:
- hunt
- attack.t1059
- attack.t1190
- attack.t1219
- attack.t1572
- command and control
- credential access
- discovery
- execution
- initial access
name: Storm-3068 Build Pipeline Execution and Tunneling
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  pipeline_ops:
    default:
    - CreatePipeline
    - UpdatePipeline
    - RunPipeline
    description: Operations in Azure DevOps that indicate pipeline modifications.
    type: list[string]
  rmm_tools:
    default:
    - chisel
    - atera
    description: Base names for tunneling and remote management tools to monitor.
    from:
      kind: article
      observed: '2026-09-29'
      ref: msrc-blog-storm-3068
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; populate from the
      scoping step results.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the search on hosts indexed in the software inventory as build agents
  (vsts-agent) or cluster nodes (kube-proxy). Use the Azure DevOps workload filter
  in cloud logs to reduce noise from other Office 365 services.
references:
- name: 'Beyond source code: A path to the keys to the kingdom'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/
related:
- hunt: storm-3068-identity-compromise-sspr
  reason: This hunt assumes the identity is already compromised and focuses on the
    subsequent execution within the pipeline.
  relation: out-of-scope-alternative
- hunt: cloud-identity-takeover-devops-enumeration
  relation: follows
scenario:
  stages:
  - name: Identity Takeover via SSPR
    observables:
    - self-service password reset activity
    - registration of new authentication methods
    - MFA registration bypass
    slug: identity-compromise-sspr
    tactic: initial-access
    techniques:
    - T1566
    - T1078
  - name: Azure DevOps Environment Discovery
    observables:
    - enumeration of repositories, projects, pipelines, and deployment environments
    - automated scripts mapping cloud resources
    slug: azure-devops-enumeration
    tactic: discovery
    techniques:
    - T1087
    - T1018
  - name: Malicious Pipeline Deployment
    observables:
    - creation of malicious pipeline
    - deployment of kube agent
    - modification of pipeline scripts
    - execution of pipeline jobs to collect kubeconfig files
    slug: malicious-pipeline-execution
    tactic: execution
    techniques:
    - T1059
    - T1190
  - name: RMM and Tunneling Tooling
    observables:
    - Atera remote management agent installation
    - Chisel tunneling utility download
    - chisel commands establishing reverse tunnel to external IP
    slug: remote-access-tooling
    tactic: command-and-control
    techniques:
    - T1219
    - T1572
  - name: Kubernetes Credential Harvesting
    observables:
    - harvesting of kubeconfig files
    - addition of stolen kubeconfig files to a Git repository
    - Git version history modification
    slug: credential-harvesting-exfiltration
    tactic: credential-access
    techniques:
    - T1552.001
  summary: Storm-3068 compromised a user identity through a self-service password
    reset and registered their own MFA to gain persistent access. The actor pivoted
    to Azure DevOps to enumerate repositories and pipelines, then created a malicious
    pipeline to harvest Kubernetes credentials (kubeconfig) and establish remote access
    via Atera and Chisel protocol tunneling.
series:
  index: 2
  slug: beyond-source-code-a-path-to-the-keys-to-the-kingdom
  title: "\u200B\u200BBeyond source code: A path to the keys to the kingdom"
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Storm-3068 Build Pipeline Execution and Tunneling

This hunt focuses on the lateral movement and persistence phase of the Storm-3068 intrusion. It targets the execution of malicious code on build agents and Kubernetes workloads, where adversaries modify pipelines to harvest credentials. The hunt fanned out to identify the execution of Remote Monitoring and Management (RMM) tools like Atera and tunneling utilities like Chisel, while correlating these host-level signals with Azure DevOps pipeline configuration changes. By analyzing process, network, and cloud API telemetry together, the hunt identifies the path from a compromised pipeline to stolen Kubernetes secrets.

## find-build-infrastructure
<!-- Identify build infrastructure -->
Identify hosts running Kubernetes or DevOps agent software to focus host-level queries on relevant assets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames serving as build agents or cluster nodes. Silence suggests
  no such software is indexed in the inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%kube%' OR LOWER(package_name) LIKE '%vsts%' OR LOWER(package_name) LIKE '%devops%' OR LOWER(package_name) LIKE '%docker%')
```

## corroborate-activity
<!-- Corroborate activity across surfaces -->
parallel:
- → identify-rmm-execution
- → rare-outbound-tunnels
- → pipeline-api-changes
join: → triage-evidence

## identify-rmm-execution
<!-- Tunneling and RMM tool execution -->
Detect the launch of Chisel or Atera binaries, checking both file paths and original filenames to catch renamed evasive binaries.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rmm_tools=rmm_tools)
~~~yaml
expected: Execution of Atera or Chisel binaries on build infrastructure. Matching
  on original_file_name catches binaries renamed to evade path-based detection.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{rmm_tools}}' != '') AND (LOWER(process_name) LIKE '%chisel%' OR LOWER(process_name) LIKE '%atera%' OR LOWER(process_original_file_name) LIKE '%chisel%' OR LOWER(process_original_file_name) LIKE '%atera%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-tunnels
<!-- Rare outbound network tunnels -->
Identify reverse tunnels to rare external IPs that do not correspond to known service endpoints.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to external IPs seen on three or fewer hosts. This isolates
  bespoke C2 or tunnel endpoints from fleet-wide update traffic.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING hosts <= 3
```

## pipeline-api-changes
<!-- Azure DevOps pipeline anomalies -->
Audit cloud activity for unauthorized pipeline changes, narrowing the scope to the Azure DevOps workload to reduce noise.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, pipeline_ops=pipeline_ops)
~~~yaml
expected: Cloud logs showing an identity creating or updating pipelines, potentially
  indicating the insertion of the malicious agent code.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
- api_service_name
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE api_service_name = 'AzureDevOps' AND (instr(',' || '{{pipeline_ops}}' || ',', ',' || api_operation || ',') > 0 OR LOWER(resource_name) LIKE '%pipeline%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage evidence of compromise -->
```agent target=hunter
cite: required
context:
- identify-rmm-execution
- rare-outbound-tunnels
- pipeline-api-changes
max_iterations: 6
objective: Determine if the observed RMM tool execution and network tunneling are
  the result of unauthorized pipeline modifications in Azure DevOps.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing temporal
  alignment between pipeline edits and process execution.
tools:
- endpoint
- network
```

## route-intrusion
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host, indicating a compromised pipeline deploying RMM tools." (confidence: high, judge=hunter)
then: → contain-and-rotate
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: ephemeral-build-telemetry)
else: → close-out

## contain-and-rotate
<!-- Isolate host and rotate credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host. Immediately revoke all Azure DevOps service principal tokens and Kubernetes secrets associated with the affected pipelines to stop exfiltration.
```
→ forensic-review

## forensic-review
<!-- Forensic review of pipeline code -->
```manual target=analyst
Manually review the Azure DevOps pipeline script history for the affected projects. Search for the addition of kube agent deployment steps or shell scripts targeting kubeconfig files. Cross-reference with Git commit logs for unauthorized author identities.
```
→ close-out

## close-out
<!-- Close out and hardening -->
```manual target=analyst
Summarize the hunt findings and record any identified blind spots. Recommend enforcing branch protection and mandatory code reviews for all build pipeline modifications in the affected Azure DevOps project.
```
→ end
