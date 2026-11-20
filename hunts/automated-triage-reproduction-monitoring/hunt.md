---
analysis: This hunt correlates ingestion metadata (HackerOne report state) with ephemeral
  infrastructure lifecycle (GCP machine types) and behavioral execution context (researcher
  scripts). A single rule cannot distinguish between a researcher running environment
  discovery to prove a point and an attacker attempting a sandbox escape.
blind_spots:
- id: no-container-visibility
  question: what processes ran inside the reproduction sandbox that did not generate
    host-level logs
  requires: endpoint agent inside the docker container
  risk: A kernel or container engine exploit may occur without triggering the high-level
    script monitoring on the VM host.
  stage: sandboxed-exploit-reproduction
- id: egress-proxy-blindness
  question: whether encrypted traffic reached internal GCP services via the proxy
  requires: squid proxy access logs
  risk: If host-level DNS activity misses a local metadata request, the proxy is the
    last line of defense; without its logs, the egress check is incomplete.
  stage: monitored-network-egress
coverage:
- stage: hackerone-report-ingestion
  status: covered
  steps:
  - validated-h1-reports
- stage: reproduction-environment-provisioning
  status: covered
  steps:
  - triage-vm-provisioning
- stage: sandboxed-exploit-reproduction
  status: covered
  steps:
  - docker-tester-startup
  - reproduction-script-execution
- stage: monitored-network-egress
  status: covered
  steps:
  - unauthorized-dns-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Automated triage systems introduce a new attack surface by executing
    untrusted researcher code. Monitoring this lifecycle is essential to prevent bug
    bounty submissions from becoming a successful initial access vector.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has submitted an exploit in a HackerOne report that successfully
  escapes the ephemeral reproduction sandbox or bypasses network egress filters during
  automated triage.
labels:
- hunt
- attack.t1190
- attack.t1203
- attack.t1059
- attack.t1090.003
name: Automated Triage Reproduction Monitoring
parameters:
  h1_validation_status:
    default: send_to_validation
    description: HackerOne status value that triggers the internal triage pipeline.
    from:
      kind: article
      observed: '2026-08-04'
      ref: https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-04'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Specific GCP VM hostnames to focus on; leave empty to hunt across
      all ephemeral hosts.
    from:
      kind: manual
      observed: '2026-08-04'
      ref: analyst-provisioning-read
    type: list[host]
  whitelist_domains:
    default:
    - reindex.remote.whitelist
    - xpack.http.whitelist
    description: Authorized HTTP request destinations for reindex and xpack features.
    from:
      kind: article
      observed: '2026-08-04'
      ref: https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone
    type: list[domain]
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
    model: hb_google/gemini-3-flash-preview
rationale: Identify all HackerOne reports tagged for validation in the last 14 days.
  Use the timestamps to isolate GCP e2-standard VM inventory changes.
references:
- name: "Elastic Security Labs \u2014 Agents vs. Agents"
  url: https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone
related:
- hunt: gcp-compute-instance-forensics
  reason: If a compromise is confirmed, forensic analysis of the ephemeral disk is
    the next logical step.
  relation: follows
scenario:
  stages:
  - name: HackerOne Report Ingestion
    observables:
    - HackerOne vulnerability reports
    - send_to_validation tag
    - Elasticsearch alert rule trigger
    slug: hackerone-report-ingestion
    tactic: initial-access
    techniques:
    - T1190
  - name: Reproduction VM Provisioning
    observables:
    - e2-standard-4 VM
    - e2-standard-2 VM
    - ephemeral GCP virtual machines
    - 30-minute auto-shutdown timer
    slug: reproduction-environment-provisioning
    tactic: execution
    techniques:
    - T1203
  - name: Sandboxed Exploit Reproduction
    observables:
    - Docker Compose
    - tester container
    - researcher-provided scripts
    - reproduction-described steps
    slug: sandboxed-exploit-reproduction
    tactic: execution
    techniques:
    - T1059
  - name: Monitored Network Egress
    observables:
    - Squid proxy egress
    - reindex.remote.whitelist
    - xpack.http.whitelist
    - Elasticsearch HTTP requests
    slug: monitored-network-egress
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Elastic's automated bug bounty triage system utilizes AI to analyze HackerOne
    reports and reproduces them in ephemeral, sandboxed GCP environments. The architecture
    employs isolated VMs for analysis and reproduction, executing untrusted researcher
    code within Docker containers while monitoring for malicious network activity
    through a Squid proxy and specific whitelist configurations.
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
tlp: clear
type: investigation
---


# Automated Triage Reproduction Monitoring

This hunt examines the lifecycle of an automated bug bounty triage system. It correlates the ingestion of validated HackerOne reports with the provisioning of ephemeral GCP virtual machines and the subsequent execution of researcher-provided scripts. By monitoring the 30-minute reproduction window and comparing network egress against a strict whitelist, the hunt identifies sandbox escapes where untrusted code reaches internal services or unauthorized external destinations.

## validated-h1-reports
<!-- Validated HackerOne report ingestion -->
Identify which reports reached the internal triage pipeline based on the status mapping for validation.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, h1_validation_status=h1_validation_status)
~~~yaml
expected: Vulnerability findings that reached the triage workflow. Their collected_at
  timestamps must match the subsequent GCP VM creation times.
reads:
- collected_at
- finding_uid
- provider
- resource_uid
- status
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT resource_uid, finding_uid, title, status, collected_at FROM hb_vulnerability_finding WHERE (LOWER(title) LIKE '%hackerone%' OR LOWER(provider) = 'github') AND LOWER(status) = LOWER('{{h1_validation_status}}') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## provisioning-fanout
<!-- Fan-out to provisioning evidence -->
parallel:
- → triage-vm-provisioning
- → docker-tester-startup
join: → early-stage-triage-assessment

## triage-vm-provisioning
<!-- Ephemeral triage VM provisioning -->
Identify the provisioning of e2-standard-2 and e2-standard-4 instances used by the triage pipeline.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Device inventory rows naming the specific triage machine types. None means
  no such VMs were provisioned.
reads:
- cloud_instance_id
- hardware_model
- hostname
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname, hardware_model, cloud_instance_id, time FROM hb_devices WHERE (LOWER(hardware_model) LIKE '%e2-standard-2%' OR LOWER(hardware_model) LIKE '%e2-standard-4%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## docker-tester-startup
<!-- Docker tester container startup -->
Detect the specific Docker Compose execution for the sandboxed reproduction environment.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process activity showing the startup of the tester container. Silence suggests
  no reproduction attempts occurred.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%docker-compose%' AND LOWER(process_cmd_line) LIKE '%tester%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage-assessment
<!-- Correlate reports and provisioning -->
```agent target=hunter
cite: required
context:
- validated-h1-reports
- triage-vm-provisioning
- docker-tester-startup
max_iterations: 4
objective: Correlate the collected_at time of HackerOne reports with the provisioning
  of e2-standard VMs and the execution of tester containers. Confirm each session
  occurred within a 30-minute window of the report ingestion.
success_criteria: A verdict of legitimate | rogue | late-shutdown for each host.
tools:
- endpoint
```

## execution-fanout
<!-- Fan-out to execution evidence -->
parallel:
- → reproduction-script-execution
- → unauthorized-dns-prevalence
join: → follow-on-reproduction-assessment

## reproduction-script-execution
<!-- Researcher-provided script activity -->
Identify scripts that attempt environment discovery or escape the Docker sandbox.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Scripts performing environment enumeration or container breakout attempts.
  Legitimate reproductions may use these; correlation is required.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%/proc/%' OR LOWER(script_content) LIKE '%docker.sock%' OR LOWER(script_content) LIKE '%nsenter%' OR LOWER(script_content) LIKE '%mount %') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## unauthorized-dns-prevalence
<!-- Unauthorized DNS resolution prevalence -->
Detect DNS queries to non-whitelisted domains that may indicate tunneling or exfiltration, stack-counted across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, whitelist_domains=whitelist_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS queries to external domains not in the approved policy. Rare domains
  seen on single triage VMs indicate potential exfiltration.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(query_hostname) AS domain, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE NOT (instr(',' || '{{whitelist_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(query_hostname) ORDER BY hosts ASC
```

## follow-on-reproduction-assessment
<!-- Analyze reproduction outcomes -->
```agent target=hunter
cite: required
context:
- early-stage-triage-assessment
- reproduction-script-execution
- unauthorized-dns-prevalence
max_iterations: 5
objective: Analyze the script activity and rare DNS egress to determine if the reproduction
  phase was used to escape the sandbox or reach unauthorized resources, building on
  the initial environment verdict.
success_criteria: A per-host verdict of compromised | safe | rogue-egress.
tools:
- endpoint
```

## compromise-decision
<!-- Route on compromise verdict -->
if~: "the follow-on-reproduction-assessment verdict is compromised for at least one host" (confidence: high, judge=hunter)
then: → shutdown-vm
indeterminate: → analyst-triage-review
unavailable: → analyst-triage-review (blind_spot: no-container-visibility)
else: → hunt-closeout

## shutdown-vm
<!-- Shutdown compromised triage VM -->
```action target=endpoint
~~~yaml
approval: required
~~~
Shut down the GCP VM instance identified in the verdict. Revoke any temporary API credentials provided to the triage orchestrator for that specific session.
```
→ analyst-triage-review

## analyst-triage-review
<!-- Analyst triage review -->
```manual target=analyst
Review the researcher's report and the script logs. Determine if the observed behavior was a necessary part of a legitimate reproduction or a genuine threat. Update the domain whitelist if the egress was authorized.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout -->
```manual target=analyst
Record the results. If no compromise was found, verify that the 30-minute auto-shutdown timer correctly terminated every triage VM in the lookback window.
```
→ end
