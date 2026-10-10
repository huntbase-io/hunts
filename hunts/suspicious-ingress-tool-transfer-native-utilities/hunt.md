---
analysis: A standard detection rule for curl or wget is too noisy for a cloud fleet.
  This hunt uses fleet-wide prevalence to baseline normal automation and employs an
  agent to filter out known platform services, prioritizing only the rarest transfer
  behaviors.
blind_spots:
- id: no-network-process-mapping
  owner: Infrastructure Team
  question: Can we definitively link a network connection to a specific curl process?
  remediation: Enable eBPF-based socket instrumentation on all Linux hosts.
  requires: hb_network_connection with pid mapping
  risk: On some systems, network telemetry may lack the process identifier, forcing
    the analyst to correlate based on timestamp, which is less reliable.
  stage: ingress-tool-transfer-via-native-utilities
- id: obfuscated-utility-names
  owner: Detection Engineering
  question: Was the utility renamed to avoid detection?
  remediation: Incorporate PE/ELF original filename metadata into the process activity
    surface.
  requires: hb_process_activity with original_file_name
  risk: If an adversary renames curl or wget, this hunt will not observe the activity.
    We rely on the process name being unchanged.
  stage: ingress-tool-transfer-via-native-utilities
coverage:
- stage: ingress-tool-transfer-via-native-utilities
  status: covered
  steps:
  - scope-utility-inventory
  - rare-utility-executions
  - external-utility-connections
  - agent-triage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ingress Tool Transfer is the precursor to most post-exploitation
    stages; stopping an adversary from bringing their toolkit into the environment
    breaks the attack chain.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using native Linux or macOS utilities like curl or wget
  to download malicious payloads from external infrastructure, hiding their activity
  within the high volume of legitimate cloud automation.
labels:
- hunt
- attack.t1105
name: Suspicious ingress tool transfer via native utilities
parameters:
  cloud_metadata_ips:
    default:
    - 169.254.169.254
    - 168.63.129.16
    description: Cloud metadata and platform IPs to ignore in network telemetry.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-23'
      ref: hunt-standard
    type: number
  rare_below:
    default: '5'
    description: The maximum number of hosts a command line can appear on to be considered
      rare.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt.
    from:
      kind: manual
      observed: '2026-07-23'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with Linux cloud workloads and Kubernetes node groups; widen to CI/CD
  runners if network noise is low.
references:
- name: How Elasticsearch ES|QL COMPLETION turns noisy curl and wget rules into high-fidelity
    cloud security alerts
  url: https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage
related:
- hunt: script-based-ingress-transfer
  reason: Adversaries may use Python, Perl or Ruby to perform similar downloads, which
    requires script-block monitoring.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Ingress Tool Transfer via Curl or Wget
    observables:
    - process.name IN ("curl", "wget")
    - process.args containing URLs
    - process.command_line
    - process.title
    - destination_host IP 168.63.129.16
    - destination_host IP 169.254.169.254
    - destination_host domains like acs-mirror.azureedge.net, packages.aks.azure.com,
      api.github.com
    - process.parent.executable
    slug: ingress-tool-transfer-via-native-utilities
    tactic: command-and-control
    techniques:
    - T1105
  summary: Adversaries leverage common Linux utilities such as curl and wget to download
    malicious tools or payloads into compromised cloud environments. This technique,
    classified as Ingress Tool Transfer (T1105), is often blended into legitimate
    cloud automation and CI/CD activity, requiring deterministic filtering and behavior-based
    triage.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Suspicious ingress tool transfer via native utilities

This hunt identifies suspicious file transfers performed by native utilities. It starts by scoping the estate to hosts with these utilities installed, then applies a dual-surface fan-out to identify rare command lines and verify network connections that target external IPs instead of standard cloud metadata and platform services. An agent triages the results to distinguish genuine threats from expected automation like package updates or CI/CD tasks.

## scope-utility-inventory
<!-- Scope: Identify hosts with transfer utilities -->
Identify the subset of the estate where curl or wget are installed to narrow the scope of the behavioral queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that have the target utilities in their package inventory.
  No rows mean the utilities are not managed via standard package managers.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%curl%' OR LOWER(package_name) LIKE '%wget%'
```

## fan-out-telemetry
<!-- Parallel corroboration -->
parallel:
- → rare-utility-executions
- → external-utility-connections
join: → agent-triage

## rare-utility-executions
<!-- Rare utility command lines -->
Identify curl and wget executions that are rare across the fleet, suggesting manual activity rather than common automation.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rare_below=rare_below)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare command lines; entries appearing on only one host are high
  interest. Silence proves that all utility executions are fleet-wide automation.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_cmd_line
- user_name
- device_hostname
- time
- process_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, user_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) = 'curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) = 'wget') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts < {{rare_below}} ORDER BY hosts, runs
```

## external-utility-connections
<!-- Utility connections to non-cloud IPs -->
Identify utility network connections that target external IPs instead of standard cloud platform services.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, cloud_metadata_ips=cloud_metadata_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from curl or wget to unexpected external IPs. Silence suggests
  utilities are only used for internal or platform communications.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) = 'curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) = 'wget') AND NOT (instr(',' || '{{cloud_metadata_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Agent: Triage tool transfer -->
```agent target=hunter
cite: required
context:
- rare-utility-executions
- external-utility-connections
max_iterations: 4
objective: Determine if the observed curl/wget activity represents an adversary transferring
  tools. Weight rare command lines combined with external network connections as high
  risk, but ignore standard package mirrors or known cloud service endpoints.
success_criteria: A structured verdict (malicious | suspicious | benign) per host,
  citing specific command lines and destination IPs.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-process-mapping)
else: → close-out

## isolate-host
<!-- Action: Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and begin incident response to identify the nature of the downloaded file.
```
→ analyst-review

## analyst-review
<!-- Task: Analyst verification -->
```manual target=analyst
Review the agent's verdict and cited rows. If the activity is legitimate automation, update the cloud_metadata_ips or add a new exclusion filter to the query. If malicious, escalate to the IR team.
```
→ close-out

## close-out
<!-- Task: Close out -->
```manual target=analyst
Record the hunt results. If high-fidelity rare executions were identified, promote the rare-utility-executions query to a permanent detection rule.
```
→ end
