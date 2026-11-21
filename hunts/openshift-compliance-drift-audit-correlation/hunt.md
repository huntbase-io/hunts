---
analysis: A standard rule alerts on a failed check; this hunt correlates findings
  from three surfaces (Compliance findings, API audit, and node-level Process) to
  identify the actor and timing, which no single rule can automate.
blind_spots:
- id: compliance-operator-down
  question: Is the cluster passing, or is the compliance operator failing to report?
  requires: OpenShift Compliance Operator running and reporting to hb_compliance_finding
  risk: A failed scan process results in zero reported failures in the lead query,
    leaving drift completely unobserved.
  stage: compliance-violation-detection
- id: insufficient-audit-detail
  question: What specifically changed in the resource patch that triggered the violation?
  requires: hb_cloud_api_activity with full Kubernetes audit verbosity
  risk: Audit logs that record the action but not the patch payload require live cluster
    inspection to confirm the drift cause.
  stage: unauthorized-resource-modification
- id: node-agent-coverage
  question: Was a CLI tool executed interactively on a node without an agent?
  requires: Elastic Agent coverage on every OpenShift node
  risk: Process execution on worker nodes remains invisible without node-level telemetry,
    masking interactive tampering.
  stage: unauthorized-resource-modification
coverage:
- stage: unauthorized-resource-modification
  status: covered
  steps:
  - audit-api-modifications
  - rare-cluster-ops
- stage: compliance-violation-detection
  status: covered
  steps:
  - compliance-drift-lead
- stage: root-cause-investigation
  status: covered
  steps:
  - triage-root-cause
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Compliance drift in regulated environments is a primary indicator
    of cluster persistence; tracing it to an actor ensures security accountability.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Unauthorized changes to OpenShift resources such as pods or service accounts
  trigger compliance violations that the hunt traces to a specific actor by correlating
  scan failures with Kubernetes API audit logs.
labels:
- hunt
- attack.t1610
- attack.t1059.004
- attack.t1613
- attack.t1562
- discovery
- execution
- impact
name: OpenShift Compliance Drift and Audit Correlation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for audit and process telemetry.
    from:
      kind: manual
      observed: '2024-11-19'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the node-level process baseline.
    from:
      kind: manual
      observed: '2024-11-19'
      ref: analyst-defined-scope
    type: list[host]
  sensitive_resources:
    default:
    - pods
    - serviceaccounts
    - rolebindings
    - complianceremediations
    - clusterroles
    description: Kubernetes resource types monitored for unauthorized modifications.
    from:
      kind: article
      observed: '2024-11-19'
      ref: https://www.elastic.co/security-labs/blog/openshift-compliance-elastic-agent-builder
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/openshift-compliance-elastic-agent-builder
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target clusters with high-severity failed scan results in hb_compliance_finding
  first. Use the associated node hostnames to narrow the scope of the rare process
  activity baseline.
references:
- name: 'From posture to root cause: Investigate OpenShift compliance with Elastic
    Agent Builder'
  url: https://www.elastic.co/security-labs/blog/openshift-compliance-elastic-agent-builder
related:
- hunt: kubernetes-rbac-tampering-investigation
  reason: This hunt correlates scan results; general RBAC monitoring requires a broader
    audit independent of compliance drift.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Unauthorized Cluster Resource Modification
    observables:
    - API calls to create or patch 'pods', 'serviceaccounts', or 'rolebindings'
    - oc CLI commands targeting cluster configuration
    - Deployment of workloads with specs violating CIS Benchmarks or NIST 800-53 moderate
      controls
    - metadata.name
    - app.kubernetes.io
    slug: unauthorized-resource-modification
    tactic: execution
    techniques:
    - T1610
    - T1059.004
  - name: Compliance Violation Detection
    observables:
    - Resource results in 'compliancecheckresults.compliance.openshift.io'
    - Status changes to 'FAIL' in 'compliancescans.compliance.openshift.io'
    - Manual rule evaluation using Common Expression Language (CEL) custom rules
    - oc get compliancecheckresult
    - orchestrator.cluster.name
    slug: compliance-violation-detection
    tactic: discovery
    techniques:
    - T1613
  - name: Root Cause Investigation and Remediation
    observables:
    - oc create token elastic-agent
    - API activity involving 'complianceremediations.compliance.openshift.io'
    - Correlation of 'actor_user_name' in Kubernetes audit logs with timestamps of
      failed checks
    - Automated annotation of manual rules via Elastic Workflows
    - pods.items.all
    - spec.id
    slug: root-cause-investigation
    tactic: impact
    techniques:
    - T1562
  summary: An unauthorized or non-compliant configuration change in an OpenShift cluster
    triggers a policy violation detected by the Compliance Operator. Defenders use
    centralized telemetry to correlate these scan results with Kubernetes audit logs,
    tracing the root cause back to the responsible principal and specific resource
    modifications that caused the policy drift.
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
tlp: clear
type: investigation
---


# OpenShift Compliance Drift and Audit Correlation

This hunt identifies security posture drift in OpenShift environments by correlating Compliance Operator scan results with Kubernetes API audit logs and node-level process telemetry. It begins with a scoping query of the compliance findings to identify failures, then gates a more resource-intensive analysis of audit logs and rare process executions to determine the root cause of the unauthorized modification.

## compliance-drift-lead
<!-- Lead: Identify Failed Compliance Controls -->
Find clusters and specific resources that have failed compliance checks according to the OpenShift Compliance Operator.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows indicate failed CIS or NIST controls. Silence provides evidence that
  the operator reports no active violations across the estate.
reads:
- resource_uid
- resource_name
- check_name
- status
- severity
- framework_refs
silence: evidence_of_absence
source: hb_compliance_finding
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT resource_uid, resource_name, check_name, status, severity, framework_refs FROM hb_compliance_finding WHERE LOWER(provider) = 'openshift' AND LOWER(status) = 'fail'
```

## analyze-compliance-status
<!-- Initial Assessment of Failures -->
```agent target=hunter
cite: required
context:
- compliance-drift-lead
max_iterations: 3
objective: Summarize which clusters and resources have high-severity failures and
  provide a prioritized list for the gate decision.
success_criteria: A verdict on whether the failures justify audit correlation.
tools:
- endpoint
```

## gate-on-violations
<!-- Gate: Proceed to Audit? -->
if~: "the analysis shows active compliance failures on production clusters for sensitive resource types" (confidence: high, judge=hunter)
then: → audit-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: compliance-operator-down)
else: → close-out

## audit-fan-out
<!-- Corroborate with API and Process Activity -->
parallel:
- → audit-api-modifications
- → rare-cluster-ops
join: → triage-root-cause

## audit-api-modifications
<!-- Kubernetes API Resource Modifications -->
Find recent create or patch operations on sensitive resources that likely caused the compliance drift.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, sensitive_resources=sensitive_resources)
~~~yaml
expected: API activity identifying the actor who modified the resource. Signal is
  validated when it precedes the compliance scan failure.
reads:
- time
- actor_user_name
- api_operation
- resource_type
- resource_name
- cloud_account_uid
- src_endpoint_ip
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT time, actor_user_name, api_operation, resource_type, resource_name, cloud_account_uid, src_endpoint_ip FROM hb_cloud_api_activity WHERE provider = 'kubernetes' AND (LOWER(api_operation) = 'create' OR LOWER(api_operation) = 'patch') AND instr(',' || '{{sensitive_resources}}' || ',', ',' || LOWER(resource_type) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-cluster-ops
<!-- Rare CLI Tool Execution on Nodes -->
Identify rare interactive usage of cluster tools like oc or kubectl directly on nodes, indicating manual tampering.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process execution path for a cluster CLI tool. Silence suggests normal
  automated operations.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) = 'oc' OR LOWER(process_name) = 'kubectl') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count < 3
```

## triage-root-cause
<!-- Triage: Correlate Findings -->
```agent target=hunter
cite: required
context:
- analyze-compliance-status
- audit-api-modifications
- rare-cluster-ops
max_iterations: 6
objective: Determine if any resource modification in the audit results explains a
  failed control found in the lead status assessment.
success_criteria: A per-cluster verdict identifying the actor and the infringing resource
  change.
tools:
- endpoint
```

## route-remediation
<!-- Route to Remediation -->
if~: "the triage links a specific unauthorized modification to the timing of a compliance failure with high confidence" (confidence: high, judge=hunter)
then: → apply-remediation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-audit-detail)
else: → close-out

## apply-remediation
<!-- Revert Resource Modification -->
```action target=endpoint
~~~yaml
approval: required
~~~
Revert the unauthorized pod, service account, or rolebinding configuration. If a compliance remediation object exists for the failed check, apply it.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Verify the actor_user_name in audit logs against internal change requests. Ensure the scan status for the cluster moves back to PASS.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record the specific resource and actor that caused the drift. If the modification was a common vector, promote the audit query to a detection rule.
```
→ end
