---
analysis: A single detection rule cannot correlate the internet-exposed scoping with
  specific sensitive keyword discovery and rare archive staging behavior; this hunt
  uses three telemetry surfaces and a phased flow to distinguish a breach from normal
  engineering maintenance.
blind_spots:
- id: limited-endpoint-visibility
  question: Are the PLC or SCADA controllers themselves logging process and file activity?
  requires: Endpoint telemetry on legacy ICS controllers
  risk: An actor moving directly to a controller via a legacy protocol may be invisible
    to endpoint-based file and process monitoring.
  stage: initial-access-integrator-pivot
- id: exfil-payload-opacity
  question: Are the network connections carrying the staged ZIP files or benign maintenance
    data?
  requires: DPI or TLS inspection
  risk: The hunt relies on byte counts; without inspection, we cannot prove the content
    of the transfer.
  stage: exfiltration-c2-channel
coverage:
- stage: initial-access-integrator-pivot
  status: covered
  steps:
  - exposed-asset-inventory
  - auth-logins-from-integrators
  - external-inbound-connections
- stage: discovery-sensitive-keywords
  status: covered
  steps:
  - discovery-by-keywords
- stage: collection-archive-staging
  status: covered
  steps:
  - archive-creation-prevalence
- stage: exfiltration-c2-channel
  status: covered
  steps:
  - exfiltration-traffic-peaks
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protecting critical infrastructure from supply chain compromise is
    a primary obligation; this hunt validates the integrity of integrator access to
    sensitive SCADA data.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A malicious actor has pivoted from a compromised third-party integrator
  network into the ICS environment, searched for SCADA schematics using sensitive
  keywords, and staged them in archives for exfiltration.
labels:
- hunt
- attack.t1195
- attack.t1190
- attack.t1083
- attack.t1560
- attack.t1041
name: Integrator Supply Chain Compromise and SCADA Data Exfiltration
parameters:
  integrator_ips:
    default: []
    description: Known IP ranges of third-party integrators; if empty, the hunt checks
      all external successes.
    from:
      kind: manual
      observed: '2026-09-23'
      ref: customer-inventory
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-23'
      ref: standard-baseline
    type: number
  scada_keywords:
    default:
    - scada
    - customer
    - customers
    - schematic
    - plc
    - diagram
    description: Keywords potentially used in filenames during the discovery phase.
    from:
      kind: article
      observed: '2026-09-23'
      ref: cisa-advisory-integrators
    type: list[string]
  scope_hosts:
    default: []
    description: Hosts identified in the scoping query to narrow the second-stage
      search.
    from:
      kind: manual
      observed: '2026-09-23'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/resources-tools/resources/considerations-critical-infrastructure-operators-working-third-party-ics-integrators
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on engineering workstations, jump hosts, and jump servers that are
  accessible to third-party integrators. Use the internet-exposed inventory to identify
  potential entry points.
references:
- name: 'CISA Advisory: Considerations for Critical Infrastructure Operators Working
    With Third-Party ICS Integrators'
  url: https://www.cisa.gov/resources-tools/resources/considerations-critical-infrastructure-operators-working-third-party-ics-integrators
related:
- hunt: lateral-movement-via-engineering-tools
  reason: Once an integrator's beachhead is established, lateral movement using legitimate
    engineering tools is the next likely step.
  relation: follows
scenario:
  stages:
  - name: Supply Chain or Exploit Access
    observables:
    - Remote access connections from integrator networks
    - Exploitation of public-facing applications
    - Industrial automation solution company network access
    slug: initial-access-integrator-pivot
    tactic: initial-access
    techniques:
    - T1195
    - T1190
  - name: File and Keyword Discovery
    observables:
    - 'Search terms: ''customers'''
    - 'Search terms: ''SCADA'''
    - Access to ICS device details and schematics
    slug: discovery-sensitive-keywords
    tactic: discovery
    techniques:
    - T1083
  - name: Data Staging in ZIP Archives
    observables:
    - Creation of nine .zip files
    - Bundling of approximately 800 files
    - Archive names containing SCADA or customer information
    slug: collection-archive-staging
    tactic: collection
    techniques:
    - T1560
  - name: Exfiltration over C2
    observables:
    - Outbound transfer of ZIP archives
    - Communication with external infrastructure
    slug: exfiltration-c2-channel
    tactic: exfiltration
    techniques:
    - T1041
  summary: Foreign cyber actors compromised a U.S. industrial automation solutions
    provider to gain access to downstream critical infrastructure customer data. The
    actors searched for SCADA configurations and schematics, bundled them into ZIP
    archives, and exfiltrated the data to enable future disruptive attacks against
    ICS environments.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Integrator Supply Chain Compromise and SCADA Data Exfiltration

This hunt follows a phased flow to detect the end-to-end attack chain reported by FBI and CISA. The hunt first identifies internet-exposed assets and triages early access markers like logins from integrator-owned IPs or anomalous inbound traffic. If the hunt identifies an early beachhead, it fans out to look for follow-on discovery behavior like keyword searches for SCADA and customers, rare data staging in .zip archives, and significant outbound traffic spikes. This mirrors the activity where an adversary compromised a U.S. industrial automation company to reach power and transportation utility customers. One agent evaluates the early signs of breach, while a second agent weighs the complete chain to confirm exfiltration. Finally, an analyst reviews the findings to isolate the host and revoke credentials.

## exposed-asset-inventory
<!-- Identify internet-exposed assets -->
Find the assets that are externally reachable and serve as the most likely pivot points from an integrator.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames or IPs with internet exposure. Silence means no assets
  are currently cataloged as exposed.
reads:
- domain_or_ip
- product
- asset_type
- port
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT domain_or_ip, product, asset_type, port FROM hb_exposed_assets WHERE asset_type = 'service'
```

## early-access-fan-out
<!-- Triage early access markers -->
parallel:
- → auth-logins-from-integrators
- → external-inbound-connections
join: → early-access-triage

## auth-logins-from-integrators
<!-- Authentication from integrator sources -->
Check for successful logins from the integrator's network or external sources into the estate.

```sqlite target=identity role=enrichment params=(integrator_ips=integrator_ips, lookback_days=lookback_days)
~~~yaml
expected: Rows mapping users and IPs to successful logins. If integrator_ips is empty,
  any external-to-internal successful auth is returned.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE status_id = 1 AND ('{{integrator_ips}}' = '' OR instr(',' || '{{integrator_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## external-inbound-connections
<!-- Anomalous inbound network sessions -->
Identify inbound log sessions from external IPs that might signify exploitation of a public application.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Evidence of external IP addresses establishing connections to internal endpoints.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_port
- time
- direction
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE direction = 'inbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-access-triage
<!-- Triaging early access -->
```agent target=hunter
cite: required
context:
- exposed-asset-inventory
- auth-logins-from-integrators
- external-inbound-connections
max_iterations: 3
objective: Determine if any host in the scope has received suspicious logins or network
  traffic from external sources.
success_criteria: A verdict citing specific rows for any host with external login
  success or anomalous inbound traffic.
tools:
- endpoint
- identity
- network
```

## follow-on-fan-out
<!-- Search for follow-on behavior -->
parallel:
- → discovery-by-keywords
- → archive-creation-prevalence
- → exfiltration-traffic-peaks
join: → follow-on-triage

## discovery-by-keywords
<!-- Sensitive keyword file access -->
Detect an actor searching for SCADA schematics or customer data as mentioned in the advisory.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, scada_keywords=scada_keywords, lookback_days=lookback_days)
~~~yaml
expected: A process accessing or creating files with keywords like 'SCADA' or 'customer'.
  None means those exact terms were not observed in filenames.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{scada_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## archive-creation-prevalence
<!-- Rare archive creation prevalence -->
Find the staging of multiple files into archives, which is rare across the fleet.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host where a process creates multiple archives. Baseline analysis highlights
  those that are rare.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) AS archive_count, MIN(time) AS first_seen FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%.zip' OR LOWER(file_path) LIKE '%.7z') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING archive_count > 1
```

## exfiltration-traffic-peaks
<!-- Exfiltration traffic peaks -->
Identify significant outbound data transfers that match the expected staging size.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A host sending more than 5MB of data to an external IP. Silence proofs absence
  of large transfers to single destinations.
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- direction
- state_kind
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, dst_endpoint_ip, SUM(traffic_bytes) AS total_bytes FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING total_bytes > 5000000
```

## follow-on-triage
<!-- Full chain verdict -->
```agent target=hunter
cite: required
context:
- early-access-triage
- discovery-by-keywords
- archive-creation-prevalence
- exfiltration-traffic-peaks
max_iterations: 5
objective: Decide if the observed behavior on a host constitutes a successful exfiltration
  of sensitive industrial data following an integrator pivot.
success_criteria: A per-host verdict citing the beachhead markers followed by keyword-specific
  file access or rare staging behavior.
tools:
- endpoint
- identity
- network
```

## incident-decision
<!-- Route on full verdict -->
if~: "the follow-on-triage verdict identifies a host with both early-access markers and subsequent discovery or staging behavior" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-endpoint-visibility)
else: → close-out

## contain-host
<!-- Contain suspected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any associated integrator credentials.
```
→ analyst-review

## analyst-review
<!-- Analyst final review -->
```manual target=analyst
Review the file paths and process command lines for the keywords; confirm the destination of the exfiltration traffic.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document that the integrator pivot and SCADA exfiltration scenario was not observed for the given scope and window.
```
→ end
