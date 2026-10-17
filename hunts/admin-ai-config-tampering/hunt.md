---
analysis: A simple detection rule fires on any change to /etc. This hunt pivots to
  identify the rare actor and process context, distinguishing the automated reconciliation
  workflow from manual tampering.
blind_spots:
- id: missing-process-telemetry
  question: Which script or parent initiated the file write?
  requires: hb_process_activity parent lineage
  risk: If the agent uses a generic bash wrapper, we may not distinguish an agent-led
    change from a local root user change using the same wrapper.
  stage: configuration-file-deployment
- id: file-content-visibility
  question: What specific requirements were disabled in requirements.toml?
  requires: file content snapshots
  risk: We see the file touch but not the delta, requiring manual retrieval to confirm
    malicious intent.
  stage: configuration-file-deployment
coverage:
- stage: configuration-file-deployment
  status: covered
  steps:
  - identify-file-touches
  - rare-actor-stacking
  - process-context-check
- reason: Belongs to the workflow control-plane hunt.
  stage: workflow-scheduling
  status: out_of_scope
- reason: Belongs to another part of the "No MDM for Linux? A 68-line Elastic workflow
    keeps every endpoint's config current" series.
  stage: endpoint-inventory-query
  status: out_of_scope
- reason: Belongs to another part of the "No MDM for Linux? A 68-line Elastic workflow
    keeps every endpoint's config current" series.
  stage: pending-action-deduplication
  status: out_of_scope
- reason: Belongs to another part of the "No MDM for Linux? A 68-line Elastic workflow
    keeps every endpoint's config current" series.
  stage: remote-script-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI agent configurations control code-completion policies and system-wide
    execution hooks; unauthorized modification allows for silent persistence and data
    exfiltration through AI tools.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has modified system-wide AI configuration files or hooks
  on a Linux endpoint to bypass security constraints or establish persistence outside
  the managed reconciliation workflow.
labels:
- hunt
- attack.t1546
- discovery
- execution
- persistence
name: Administrative AI Configuration File Tampering
parameters:
  config_paths:
    default:
    - /etc/codex/managed_config.toml
    - /etc/codex/requirements.toml
    - /etc/cursor/hooks.json
    - /usr/local/share/ai-hooks
    description: Sensitive AI agent configuration paths.
    from:
      kind: article
      observed: '2026-09-29'
      ref: elastic-security-labs-linux-mdm
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead query to focus analysis; leave empty
      to scan all.
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
rationale: Focus on Linux developer workstations identified via hb_devices (platform
  = 'Linux').
references:
- name: No MDM for Linux? A 68-line Elastic workflow keeps every endpoint's config
    current
  url: https://www.elastic.co/security-labs/blog/linux-endpoint-management-elastic-workflows
related:
- hunt: remote-script-execution-elastic-agent
  reason: The execution logic of the response action script is handled by another
    hunt focusing on hb_process_activity and agent logs.
  relation: out-of-scope-alternative
- hunt: automated-edr-response-action-reconciliation
  relation: follows
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
  index: 2
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
tlp: clear
type: investigation
---


# Administrative AI Configuration File Tampering

While these files are managed by a scheduled Elastic workflow, manual tampering or the insertion of malicious system hooks can enable unauthorized data access or persistence. The adversary modifies system-wide AI configuration files to bypass constraints or establish persistence. This hunt identifies endpoints where non-agent processes touch managed paths. We stack-count these processes to find rare modifications and inspect their integrity. Finally, an analyst reviews the specific content changes to confirm unauthorized tampering.

## identify-file-touches
<!-- Identify administrative file modifications -->
Find all hosts and processes modifying the managed AI configuration files to establish a baseline of activity.

```sqlite target=endpoint role=scoping params=(config_paths=config_paths, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and processes. The Elastic Agent is the expected actor;
  any other process like vi, nano, or unknown binaries are leads.
reads:
- activity_name
- actor_user_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, activity_name, time FROM hb_file_activity WHERE (instr(',' || '{{config_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-anomalies
<!-- Analyze actors and process context -->
parallel:
- → rare-actor-stacking
- → process-context-check
join: → triage-integrity

## rare-actor-stacking
<!-- Stack-count processes touching config -->
Find rare or unauthorized processes modifying these paths across the scoped fleet.

```sqlite target=endpoint role=baseline params=(config_paths=config_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One-off processes touching these files. Authorized management tools should
  appear on almost all hosts; manual edits appear on one or two.
prevalence:
  by: device_hostname
  key:
  - process_name
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT process_name, actor_user_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (instr(',' || '{{config_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, actor_user_name HAVING host_count < 3
```

## process-context-check
<!-- Inspect process integrity and command lines -->
Identify processes with suspicious characteristics (like being deleted from disk) that interacted with the AI configuration.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any process with on_disk = 0 or suspicious shell-parentage modifying the
  files. Silence means no suspicious integrity signals were captured for these commands.
reads:
- device_hostname
- on_disk
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, on_disk, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%/etc/codex/%' OR LOWER(process_cmd_line) LIKE '%/etc/cursor/%' OR LOWER(process_cmd_line) LIKE '%ai-hooks%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-integrity
<!-- Weigh modification evidence -->
```agent target=hunter
cite: required
context:
- identify-file-touches
- rare-actor-stacking
- process-context-check
max_iterations: 5
objective: Review the file modifications and process characteristics. Identify any
  modifications made by users or processes that are not part of the standard Elastic
  Agent configuration workflow. Pay special attention to changes in requirements.toml
  or hooks.json.
success_criteria: A per-host verdict citing specific rows that indicate unauthorized
  tampering.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving hooks.json or requirements.toml" (confidence: medium, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the contents of the modified configuration files for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Manual configuration audit -->
```manual target=analyst
The analyst compares file hashes and content against the gold standard in the Elastic script library. Search for unauthorized shell commands in hooks.json.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record findings. If the analyst finds legitimate but unauthorized activity, remind the user of the reconciliation policy.
```
→ end
