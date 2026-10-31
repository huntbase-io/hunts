---
analysis: A simple detection for the run_script API would flood with legitimate alerts.
  This hunt provides the necessary context by baselining the 6-hour workflow cadence
  and correlating it with endpoint-side file modifications to find orchestration anomalies.
blind_spots:
- id: kibana-internal-workflow-triggers
  question: Which specific Workflow ID initiated the reconciliation loop?
  requires: Kibana application-level audit logs
  risk: Manual API abuse by a compromised administrator may appear identical to the
    automated workflow at the HTTP layer.
  stage: workflow-scheduling
- id: http-payload-script-id
  question: What is the scriptId being passed in the run_script POST body?
  requires: Deep packet inspection or Kibana audit logs with request body content
  risk: Without the POST body, we cannot distinguish the legitimate reconciliation
    script from an adversary's malicious script using the same API endpoint.
  stage: remote-script-execution
coverage:
- blind_spot: kibana-internal-workflow-triggers
  reason: Internal Kibana workflow triggers are application-level events not captured
    by the provided network or endpoint surfaces.
  stage: workflow-scheduling
  status: not_visible
- stage: endpoint-inventory-query
  status: covered
  steps:
  - api-discovery-calls
- stage: pending-action-deduplication
  status: covered
  steps:
  - api-discovery-calls
- stage: remote-script-execution
  status: covered
  steps:
  - api-execution-calls
  - endpoint-config-touches
  - edr-script-execution
- reason: Belongs to another part of the "No MDM for Linux? A 68-line Elastic workflow
    keeps every endpoint's config current" series.
  stage: configuration-file-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Mass remote execution via EDR control planes is a highly sensitive
    capability. Continuous reconciliation ensures this automation is not subverted
    for fleet-wide payload delivery.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a management principal or repurposed an Elastic
  workflow to perform mass remote execution across the Linux fleet, masquerading as
  a legitimate configuration reconciliation loop.
labels:
- hunt
- attack.t1018
- attack.t1083
- attack.t1059.004
- attack.t1053.003
- discovery
- execution
- persistence
name: Automated EDR Response Action Reconciliation
parameters:
  config_paths:
    default:
    - /etc/codex/managed_config.toml
    - /etc/codex/requirements.toml
    - /etc/cursor/hooks.json
    - /usr/local/share/ai-hooks
    description: File paths modified by the reconciliation deployment script.
    from:
      kind: article
      observed: '2026-09-29'
      ref: elastic-security-labs
    type: list[path]
  discovery_paths:
    default:
    - /api/endpoint/metadata
    - /api/endpoint/action
    description: API paths used for endpoint discovery and pending action checks.
    from:
      kind: article
      observed: '2026-09-29'
      ref: elastic-security-labs
    type: list[path]
  linux_distros:
    default:
    - debian
    - redhat
    - arch
    - suse
    - fedora
    - linux
    description: Target Linux distributions named in the reconciliation workflow.
    from:
      kind: article
      observed: '2026-09-29'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Filter results to specific hostnames.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/linux-endpoint-management-elastic-workflows
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets the Kibana management server for control plane activity
  and the enrolled Linux workstations for host-side artifacts. Focus first on distro
  families mentioned in the article.
references:
- name: "Elastic Security Labs \u2014 No MDM for Linux? A 68-line Elastic workflow\
    \ keeps every endpoint's config current"
  url: https://www.elastic.co/security-labs/blog/linux-endpoint-management-elastic-workflows
related:
- hunt: configuration-file-deployment-anomalies
  reason: That hunt focuses on the content of the configuration files rather than
    the orchestration loop used to deploy them.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Scheduled Workflow Trigger
    observables:
    - 'every: 6h'
    - reconcile-managed-config-linux
    slug: workflow-scheduling
    tactic: execution
    techniques:
    - T1053.003
  - name: Linux Endpoint Discovery
    observables:
    - GET /api/endpoint/metadata
    - 'kuery: ''united.agent.local_metadata.os.family : ("debian" or "redhat" or "arch"
      or "suse" or "fedora")'''
    slug: endpoint-inventory-query
    tactic: discovery
    techniques:
    - T1018
  - name: Pending Action State Check
    observables:
    - GET /api/endpoint/action
    - 'commands: runscript'
    - 'statuses: pending'
    slug: pending-action-deduplication
    tactic: discovery
    techniques:
    - T1083
  - name: EDR Response Action Execution
    observables:
    - POST /api/endpoint/action/run_script
    - 'comment: ''Managed configuration reconciliation'''
    - 'scriptId: <script-library-entry-id>'
    slug: remote-script-execution
    tactic: execution
    techniques:
    - T1059.004
  - name: System Configuration Persistence
    observables:
    - /etc/codex/managed_config.toml
    - /etc/codex/requirements.toml
    - /etc/cursor/hooks.json
    - /usr/local/share/ai-hooks
    slug: configuration-file-deployment
    tactic: persistence
    techniques:
    - T1546
  summary: Elastic uses a scheduled Kibana workflow to perform reconciliation-based
    configuration management for Linux endpoints. The workflow queries the Elastic
    Defend API to identify Linux hosts and trigger response actions that deploy specific
    Codex and Cursor configuration files, ensuring hosts remain configured without
    manual intervention or redundant task queuing.
series:
  index: 1
  slug: no-mdm-for-linux-a-68-line-elastic-workflow-keeps-every-endpoint-s-config-current
  title: No MDM for Linux? A 68-line Elastic workflow keeps every endpoint's config
    current
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Automated EDR Response Action Reconciliation

This hunt identifies unauthorized remote code execution by analyzing the reconciliation loop pattern used for Linux endpoint management. It follows a phased approach: first, it baselines the cadence and source of management API calls used for endpoint discovery and tasking; second, it correlates those API triggers with host-side process execution and configuration file modifications. By distinguishing the 6-hour automated cadence of the Elastic reconciliation workflow from high-volume exploitation or ad-hoc admin abuse, the hunt isolates actors who use administrative orchestration for persistence or lateral movement.

## linux-host-scope
<!-- Identify Linux fleet -->
Identify the Linux endpoints potentially managed by the automated reconciliation workflow.

```sqlite target=endpoint role=scoping params=(linux_distros=linux_distros, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence proves no Linux assets matching the workflow
  criteria are present in the inventory.
reads:
- hostname
- platform
- os_name
- time
silence: evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT DISTINCT hostname, platform, os_name FROM hb_devices WHERE (instr(',' || '{{linux_distros}}' || ',', ',' || LOWER(platform) || ',') > 0 OR instr(',' || '{{linux_distros}}' || ',', ',' || LOWER(os_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## api-recon-parallel
<!-- Analyze control plane activity -->
parallel:
- → api-discovery-calls
- → api-execution-calls
join: → api-orchestration-agent

## api-discovery-calls
<!-- Baseline discovery API traffic -->
Identify the source IP and cadence for endpoint inventory and pending action queries.

```sqlite target=web role=baseline params=(discovery_paths=discovery_paths, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single management IP performing requests every 6 hours. Multiple source
  IPs or non-standard timing indicate a compromised principal.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- url_path
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT src_endpoint_ip, url_path, http_method, COUNT(*) as call_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_http_activity WHERE (instr(',' || '{{discovery_paths}}' || ',', ',' || url_path || ',') > 0) AND http_method = 'GET' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_path, http_method
```

## api-execution-calls
<!-- Monitor script execution triggers -->
Identify requests that trigger the run_script response action across the fleet.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: POST requests to the execution endpoint following the discovery hits. Silence
  proves no mass remote execution was initiated via this API during the window.
reads:
- src_endpoint_ip
- url_hostname
- url_path
- time
- user_agent
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT src_endpoint_ip, url_hostname, url_path, time, user_agent FROM hb_http_activity WHERE url_path = '/api/endpoint/action/run_script' AND http_method = 'POST' AND time >= datetime('now', '-{{lookback_days}} days')
```

## api-orchestration-agent
<!-- Evaluate API orchestration cadence -->
```agent target=hunter
cite: required
context:
- api-discovery-calls
- api-execution-calls
max_iterations: 4
objective: Confirm if the observed GET and POST traffic follows a periodic 6-hour
  pattern from a stable source IP.
success_criteria: A list of IPs categorized as authorized-reconciliation or suspicious-manual-abuse,
  citing timing intervals.
tools:
- endpoint
- web
```

## host-execution-parallel
<!-- Analyze host-side effects -->
parallel:
- → endpoint-config-touches
- → edr-script-execution
join: → chain-reconciliation-agent

## endpoint-config-touches
<!-- Verify configuration file modifications -->
Find changes to Codex and Cursor configuration files on the Linux fleet.

```sqlite target=endpoint role=detection-candidate params=(config_paths=config_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File touches on the managed TOML and JSON paths. These should correlate
  with the 6-hour API cadence.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (instr(',' || '{{config_paths}}' || ',', ',' || file_path || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## edr-script-execution
<!-- Capture EDR script execution -->
Identify Unix Shell script blocks executed by the EDR agent on endpoints.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing Codex or Cursor deployment logic. Silence on a
  host that received an API execution command is suspicious.
reads:
- device_hostname
- script_path
- script_type
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, script_path, script_type, script_content, time FROM hb_script_activity WHERE script_type = 'Unix Shell' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## chain-reconciliation-agent
<!-- Correlate full attack chain -->
```agent target=hunter
cite: required
context:
- api-orchestration-agent
- endpoint-config-touches
- edr-script-execution
max_iterations: 6
objective: Verify if the script content and file modifications on endpoints match
  the scope of the authorized MDM reconciliation loop.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the link between the API IP and host changes.
tools:
- endpoint
- web
```

## verdict-decision
<!-- Route on reconciliation verdict -->
if~: "the chain-reconciliation-agent identifies malicious or suspicious orchestration activity inconsistent with the 6-hour workflow" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → audit-principal
unavailable: → audit-principal (blind_spot: kibana-internal-workflow-triggers)
else: → documentation-task

## isolate-endpoint
<!-- Isolate compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the Infosec team to revoke the Kibana API principal's credentials.
```
→ audit-principal

## audit-principal
<!-- Audit management principal -->
```manual target=analyst
Locate the Workflow ID or API key in Kibana audit logs; verify if the trigger source matches the reconcile-managed-config-linux configuration.
```
→ documentation-task

## documentation-task
<!-- Hunt documentation -->
```manual target=analyst
Document the legitimate source IPs as known-good and record any unauthorized execution attempts as a high-severity security incident.
```
→ end
