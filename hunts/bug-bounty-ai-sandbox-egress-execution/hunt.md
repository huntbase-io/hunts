---
analysis: This hunt pivots from host inventory to untrusted process behavior and network
  prevalence. A single rule would struggle with the 'expected' noise of a reproduction
  script; the hunt uses the 'tester' container context and rarity to weigh maliciousness.
blind_spots:
- id: container-telemetry-gap
  question: Are processes inside 'tester' distinguishable from host-level escapes?
  requires: hb_process_activity with container_id mapping
  risk: A sophisticated escape might look like a legitimate orchestrator process if
    container boundaries are not clearly mapped.
  stage: untrusted-code-reproduction
- id: short-retention-ephemerality
  question: Do we have telemetry for VMs that only live for <10 minutes?
  requires: external log preservation outside the VM
  risk: If an attacker finishes their goal before telemetry is shipped, the activity
    is invisible.
  stage: ephemeral-sandbox-provisioning
coverage:
- reason: Initial report ingestion is handled by existing platform monitoring.
  stage: vulnerability-report-ingestion
  status: existing_rule
- stage: ephemeral-sandbox-provisioning
  status: covered
  steps:
  - find-triage-vms
- stage: untrusted-code-reproduction
  status: covered
  steps:
  - untrusted-host-processes
  - check-whitelist-indicators
- stage: network-egress-and-proxy-bypass
  status: covered
  steps:
  - rare-egress-destinations
  - metadata-api-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Automated triage pipelines execute untrusted researcher code. A negative
    result confirms that sandbox and proxy controls are effectively containing this
    execution.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has escaped the reproduction sandbox during automated triage
  or is abusing the ephemeral VM's egress to tunnel C2 traffic.
labels:
- hunt
- attack.t1090.003
- attack.t1190
- attack.t1059
- attack.t1497
name: Bug Bounty AI Sandbox Egress and Execution
parameters:
  lookback_days:
    default: '7'
    description: Days of triage history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames identified in the scoping step.
    type: list[host]
  whitelist_patterns:
    default:
    - reindex.remote.whitelist
    - xpack.http.whitelist
    description: Configuration keywords often targeted for bypass in reproduction
      scripts.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should be restricted to the GCP project and VM families (e2-standard)
  used for the bug bounty triage pipeline.
references:
- name: 'Agents vs. agents: how we triage HackerOne reports'
  url: https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone
related:
- hunt: hackerone-integration-abuse
  reason: This hunt focuses on execution; a sibling hunt could examine ingestion for
    malicious report payloads (T1190).
  relation: sibling
scenario:
  stages:
  - name: HackerOne Report Ingestion
    observables:
    - 'HackerOne report status: send_to_validation'
    - 'Source: hackerone integration'
    slug: vulnerability-report-ingestion
    tactic: initial-access
    techniques:
    - T1190
  - name: Ephemeral VM Sandbox Provisioning
    observables:
    - 'GCP machine type: e2-standard-2'
    - 'GCP machine type: e2-standard-4'
    - Docker Compose provisioning on e2-standard-4
    - 30-minute VM auto-shutdown timer
    slug: ephemeral-sandbox-provisioning
    tactic: execution
    techniques:
    - T1497
  - name: Untrusted Script Execution
    observables:
    - 'Container name: tester'
    - Researcher-described scripts executed in sandbox
    - Packer-built VM images
    slug: untrusted-code-reproduction
    tactic: execution
    techniques:
    - T1059
  - name: Network Egress and Proxy Bypass
    observables:
    - Squid proxy egress filtering
    - reindex.remote.whitelist bypass attempts
    - xpack.http.whitelist bypass attempts
    - VPC egress filter logs
    - Watcher HTTP input requests
    slug: network-egress-and-proxy-bypass
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1190
  summary: An automated AI triage system for bug bounty reports processes submissions
    through an eight-stage analysis pipeline and an ephemeral sandbox reproduction
    phase. The system utilizes ephemeral GCP virtual machines and Docker containers
    to execute researcher-provided reproduction scripts while enforcing 30-minute
    self-destruction and network egress filtering through a proxy.
severity: medium
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Bug Bounty AI Sandbox Egress and Execution

This hunt examines telemetry from automated vulnerability triage environments (GCP ephemeral VMs). It focuses on identifying processes escaping the 'tester' container, host-level execution of unauthorized scripts, and network activity targeting GCP metadata or external C2 that bypasses the Squid proxy.

## find-triage-vms
<!-- Identify ephemeral triage sandboxes -->
Locate the GCP VMs matching the e2-standard profile used for AI triage and reproduction.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hostnames corresponding to the 30-minute ephemeral VMs. Silence indicates
  no triage activity.
reads:
- cloud_instance_id
- first_seen
- hardware_model
- hostname
- last_seen
- provider
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, hardware_model, cloud_instance_id, first_seen, last_seen FROM hb_devices WHERE provider = 'gcp' AND (hardware_model = 'e2-standard-2' OR hardware_model = 'e2-standard-4') AND time >= datetime('now', '-{{lookback_days}} days')
```

## untrusted-host-processes
<!-- Detect escape or host-level execution -->
Identify processes on the host that are not part of the standard Docker daemon or orchestrator.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of shell/python scripts outside the container context. Silence
  suggests effective isolation.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%tester%' OR LOWER(process_path) NOT LIKE '/usr/bin/docker%') AND LOWER(user_name) != 'root' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Corroborate egress and bypass attempts -->
parallel:
- → rare-egress-destinations
- → check-whitelist-indicators
- → metadata-api-access
join: → triage-agent

## rare-egress-destinations
<!-- Rare network egress from triage VMs -->
Find connections to unique IPs that indicate report-specific C2 or non-standard ports.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound IPs seen from very few sandboxes.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2 ORDER BY host_count ASC
```

## check-whitelist-indicators
<!-- Detect whitelist manipulation scripts -->
Identify scripts or processes explicitly named after the settings researchers attempt to bypass.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, whitelist_patterns=whitelist_patterns)
~~~yaml
expected: Process names matching 'reindex.remote.whitelist' or 'xpack.http.whitelist'.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{whitelist_patterns}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## metadata-api-access
<!-- GCP Metadata and Internal API access -->
Identify HTTP requests targeting GCP internals, suggesting a container escape or SSRF.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to metadata services or internal GCP names.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (url_hostname = '169.254.169.254' OR url_hostname LIKE '%.internal%' OR url_hostname LIKE 'metadata%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Evaluate sandbox integrity -->
```agent target=hunter
cite: required
context:
- untrusted-host-processes
- rare-egress-destinations
- check-whitelist-indicators
- metadata-api-access
max_iterations: 3
objective: Determine if activity on triage VMs exceeds authorized scope (e.g., trying
  to access VM credentials or bypassing egress proxy).
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign citing specific
  rows.
tools:
- endpoint
- network
- web
```

## verdict-decision
<!-- Route based on sandbox verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-vm-project
indeterminate: → analyst-triage-review
unavailable: → analyst-triage-review (blind_spot: container-telemetry-gap)
else: → analyst-triage-review

## isolate-vm-project
<!-- Quarantine the GCP project -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised triage VM and lock down VPC egress in the GCP project immediately.
```
→ analyst-triage-review

## analyst-triage-review
<!-- Review AI triage logs -->
```manual target=analyst
Compare untrusted-host-processes results against the expected 'tester' container commands. Cross-reference destination IPs from rare-egress-destinations with the researcher's report on HackerOne.
```
→ end
