---
analysis: A standard detection rule might flag any archive creation in Temp, but this
  hunt pivots between the file system, rare outbound network prevalence, and behavioral
  DNS to find the connected attack path.
blind_spots:
- id: no-process-to-network-mapping
  question: Which process initiated the rare outbound connection?
  requires: endpoint agent with process-to-socket correlation
  risk: If only flow logs are available, the analyst cannot definitively link the
    process creating archives to the process communicating externally.
  stage: network-exfiltration-c2
- id: encrypted-exfiltration
  question: What was the content of the outbound data transfer?
  requires: TLS decryption/inspection at the perimeter
  risk: Adversaries using HTTPS or custom encryption hide the volume and nature of
    exfiltrated data.
  stage: network-exfiltration-c2
coverage:
- stage: file-system-data-staging
  status: covered
  steps:
  - identify-data-staging
- stage: network-exfiltration-c2
  status: covered
  steps:
  - rare-outbound-connections
  - rare-dns-lookups
- reason: Handled by the first hunt in this series focusing on perimeter vulnerabilities.
  stage: initial-access-web-exploit
  status: out_of_scope
- reason: Identity-based pivots are handled in the Cross-Environment Pivot hunt.
  stage: identity-account-manipulation
  status: out_of_scope
- reason: Cloud control plane changes belong to a cloud-focused hunt.
  stage: cloud-resource-reconfiguration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Data staging and exfiltration represent the completion of an adversary's
    mission. Detecting these behaviors across the endpoint and network surfaces is
    the final opportunity to prevent material impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has staged sensitive information in temporary directories
  and is exfiltrating that data via rare outbound network connections or DNS lookups.
labels:
- hunt
- attack.t1074.001
- attack.t1041
- attack.t1071.001
name: Endpoint Data Staging and Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: hunt-parameters
    type: number
  rare_threshold:
    default: '3'
    description: The maximum number of hosts a value can appear on to be considered
      rare.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: hunt-parameters
    type: number
  scope_hosts:
    default: []
    description: Comma-separated hostnames to narrow the search; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: hunt-parameters
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations and servers with access to sensitive repositories
  first. Use a 14-day lookback to capture both staging and exfiltration, which often
  occur with a significant time gap.
references:
- name: 'Inside the Modern SOC: Defending the Cross-Environment Pivot'
  url: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
related:
- hunt: cloud-storage-exfiltration
  reason: This hunt focuses on direct network exfiltration; exfiltration via cloud
    synchronization requires cloud-native audit logs.
  relation: out-of-scope-alternative
- hunt: identity-cloud-pivot-web-exploits
  relation: follows
scenario:
  stages:
  - name: Web Application Exploitation
    observables:
    - exploitation of internet-facing web servers
    - malicious http requests to public-facing applications
    slug: initial-access-web-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: SaaS and Identity Manipulation
    observables:
    - unfamiliar applications requesting elevated permissions
    - permissions changes within SaaS applications
    - OAuth or SAML authentication anomalies
    slug: identity-account-manipulation
    tactic: privilege-escalation
    techniques:
    - T1098
  - name: Cloud Environment Provisioning
    observables:
    - provisioning of cloud resources outside of normal activity
    - reconfiguration of cloud assets by unusual administrator accounts
    slug: cloud-resource-reconfiguration
    tactic: persistence
    techniques:
    - T1078
  - name: Data Staging for Exfiltration
    observables:
    - staging of sensitive data in temporary or unusual directories
    - unexpected file creation patterns on endpoints
    slug: file-system-data-staging
    tactic: collection
    techniques:
    - T1074
  - name: Exfiltration over Command and Control
    observables:
    - new network connections between systems that rarely communicate
    - data transfer to unfamiliar external IP addresses
    - C2 communication over established protocols
    slug: network-exfiltration-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Adversaries exploit internet-facing applications to gain a foothold before
    pivoting across cloud and SaaS environments using compromised credentials. The
    attack culminates in the staging of sensitive data on endpoints and exfiltration
    via command-and-control channels.
series:
  index: 2
  slug: inside-the-modern-soc-defending-the-cross-environment-pivot
  title: 'Inside the Modern SOC: Defending the Cross-Environment Pivot'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Endpoint Data Staging and Exfiltration

This hunt targets the final stages of an intrusion: collection and exfiltration. It identifies the creation of compressed archives in user-writable paths like Public or Temp on Windows and /tmp or /dev/shm on Linux, then correlates that activity with rare outbound network connections and behavioral DNS anomalies. An agent evaluates the combined evidence to distinguish administrative archiving from malicious data theft.

## identify-data-staging
<!-- Unusual archive creation in staging paths -->
Locate hosts with archives created in writable directories.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows naming archives created in user-writable paths. Silence suggests no
  common staging activity occurred.
reads:
- device_hostname
- file_path
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%.zip' OR LOWER(file_path) LIKE '%.7z' OR LOWER(file_path) LIKE '%.rar') AND (LOWER(file_path) LIKE '%\\users\\public\\%' OR LOWER(file_path) LIKE '%\\temp\\%' OR LOWER(file_path) LIKE '%\\appdata\\local\\temp\\%' OR LOWER(file_path) LIKE '/tmp/%' OR LOWER(file_path) LIKE '/var/tmp/%' OR LOWER(file_path) LIKE '/dev/shm/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Corroborate with network and DNS activity -->
parallel:
- → rare-outbound-connections
- → rare-dns-lookups
join: → triage-exfiltration

## rare-outbound-connections
<!-- Rare outbound network connections -->
Find connections to external IP addresses that appear on fewer than the threshold number of hosts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, rare_threshold=rare_threshold, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An IP address visited by only one or two hosts, potentially representing
  an exfiltration drop site.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - process_name
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- direction
- disposition
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_ip, process_name, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS connection_count, GROUP_CONCAT(DISTINCT device_hostname) AS affected_hosts FROM hb_network_connection WHERE direction = 'outbound' AND disposition = 'Allowed' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.16.%' AND dst_endpoint_ip NOT LIKE '172.17.%' AND dst_endpoint_ip NOT LIKE '172.18.%' AND dst_endpoint_ip NOT LIKE '172.19.%' AND dst_endpoint_ip NOT LIKE '172.2%.%' AND dst_endpoint_ip NOT LIKE '172.3%.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, process_name HAVING host_count <= {{rare_threshold}}
```

## rare-dns-lookups
<!-- Rare behavioral DNS queries -->
Identify rare domain queries on suspect hosts that might indicate C2 or exfiltration endpoints.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rare_threshold=rare_threshold, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Domain queries unique to a small set of hosts. Silence suggests no unusual
  DNS patterns for the lookback period.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, GROUP_CONCAT(DISTINCT device_hostname) AS hosts, GROUP_CONCAT(DISTINCT process_name) AS processes FROM hb_dns_activity WHERE query_hostname NOT LIKE '%.local' AND query_hostname NOT LIKE '%.internal' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= {{rare_threshold}}
```

## triage-exfiltration
<!-- Evaluate exfiltration path -->
```agent target=hunter
cite: required
context:
- identify-data-staging
- rare-outbound-connections
- rare-dns-lookups
max_iterations: 5
objective: Review the staging file events, rare network connections, and DNS lookups.
  Identify if a single host performed all three or if the process creating the archives
  also initiated the rare network traffic. Provide a verdict of malicious, suspicious,
  or benign.
success_criteria: A per-host verdict citing specific rows from all three inputs.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on triage results -->
if~: "The triage verdict is malicious for at least one host based on the correlation of archive creation and outbound exfiltration signals." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-investigation
unavailable: → manual-investigation (blind_spot: no-process-to-network-mapping)
else: → hunt-completion

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to halt exfiltration. Collect the archives identified in the staging step for forensic analysis.
```
→ manual-investigation

## manual-investigation
<!-- Manual analyst review -->
```manual target=analyst
Review the correlated events. Check the process parentage for the archive creation. Determine if the rare IP addresses belong to legitimate business services not yet in the baseline.
```
→ hunt-completion

## hunt-completion
<!-- Hunt close-out -->
```manual target=analyst
Log the results. If legitimate tools were identified as rare, add their destination IPs to the exclusion list. Update the staging directory patterns if new adversary tradecraft was observed.
```
→ end
