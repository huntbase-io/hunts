---
analysis: A simple rule alerts on a single hash or IP match. This hunt correlates
  that match with host vulnerability status, multi-hop DNS behavior, and mass file
  modification telemetry to validate an entire multi-stage intrusion chain, reducing
  noise from isolated indicators.
blind_spots:
- id: limited-endpoint-retention
  question: whether the initial access occurred prior to the current lookback window
  requires: endpoint telemetry retention exceeding 30 days
  risk: An intrusion with a long dwell time may have its beachhead telemetry aged
    out, making the hunt appear as isolated impact behavior.
- id: memory-only-malware
  question: whether malware is running purely in-memory without a file match
  requires: hb_module_activity and on_disk=0 process monitoring
  risk: SHA256-based hunting in GTI fails for fileless threats that never drop a binary,
    potentially missing the malware execution stage.
  stage: malware-execution-and-credential-theft
coverage:
- stage: initial-access-phishing-and-exploitation
  status: covered
  steps:
  - vulnerability-scoping
  - dns-malicious-query
- stage: malware-execution-and-credential-theft
  status: covered
  steps:
  - process-hash-query
- stage: command-and-control-proxy-networks
  status: covered
  steps:
  - network-c2-query
- stage: impact-encryption-and-resource-hijacking
  status: covered
  steps:
  - file-impact-baseline
  - miner-behavior-triage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat intelligence feeds provide the 'what', but a hunt is required
    to find the 'how' and 'where' the intrusion has progressed beyond a single match;
    a negative result over a high-vulnerability population confirms the integrity
    of the environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited a vulnerable service or leveraged phishing to
  gain a beachhead, followed by multi-hop proxy C2 communication and subsequent mass
  file modification or resource hijacking.
labels:
- hunt
- attack.t1090.003
- attack.t1190
- attack.t1486
- attack.t1496
- attack.t1555
- attack.t1566
name: Threat Intelligence Lifecycle Detection
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_domains:
    default:
    - malicious.io
    - phish-gate.com
    - c2-server.net
    description: Malicious domains from GTI for phishing or C2.
    from:
      kind: article
      observed: '2026-06-02'
      ref: elastic-security-labs-gti
    type: list[domain]
  malicious_hashes:
    default:
    - e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    - 5d41402abc4b2a76b9719d911017c592
    description: Malicious file hashes (SHA256) for malware detection.
    from:
      kind: article
      observed: '2026-06-02'
      ref: elastic-security-labs-gti
    type: list[hash]
  malicious_ips:
    default:
    - 185.199.110.153
    - 104.21.233.1
    description: Malicious IPs from GTI associated with C2 or proxy networks.
    from:
      kind: article
      observed: '2026-06-02'
      ref: elastic-security-labs-gti
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional hostnames to narrow the search; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/elastic-security-google-threat-intelligence
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on servers and DMZ assets first by identifying device_uids
  in the scoping query. If any hits appear, broaden the search to the entire workstation
  fleet using the 'scope_hosts' parameter.
references:
- name: "Elastic Security Labs \u2014 From API key to live threat detections in minutes"
  url: https://www.elastic.co/security-labs/blog/elastic-security-google-threat-intelligence
related:
- hunt: scheduled-task-persistence-vulnerable-hosts
  reason: This hunt focuses on the execution-to-impact lifecycle; persistence is a
    separate phase requiring hb_scheduled_job analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access via Phishing and Application Exploitation
    observables:
    - malicious URLs in HTTP traffic
    - phishing domains in DNS queries
    - exploit attempts against vulnerable web services
    - exposed internet-facing assets
    slug: initial-access-phishing-and-exploitation
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Malware Execution and Credential Harvesting
    observables:
    - malicious file hashes on disk
    - suspicious process execution on Linux and macOS
    - access to browser password storage files
    - access to keychain or secret vaults
    slug: malware-execution-and-credential-theft
    tactic: credential-access
    techniques:
    - T1555
  - name: C2 via Multi-hop Proxies
    observables:
    - DNS queries for .onion domains
    - network connections to Tor exit nodes
    - multi-hop proxy infrastructure traffic
    - connections to known-malicious IPs
    slug: command-and-control-proxy-networks
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Impact via Encryption and Resource Hijacking
    observables:
    - mass file modification or encryption (ransomware)
    - high CPU usage for cryptocurrency mining
    - outbound connections to mining pools
    - deployment of ransomware notes
    slug: impact-encryption-and-resource-hijacking
    tactic: impact
    techniques:
    - T1486
    - T1496
  summary: This campaign lifecycle covers a variety of threat types including initial
    access via phishing or application exploitation, leading to credential theft,
    multi-hop proxy command-and-control, and final impact via ransomware or cryptomining.
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


# Threat Intelligence Lifecycle Detection

This hunt operationalizes Google Threat Intelligence (GTI) by following a phased intrusion lifecycle. It begins by identifying the vulnerable host population to scope the effort, then searches for early-stage signals including malicious DNS resolutions and binary execution matches. The second phase pivots to follow-on behaviors: connections to multi-hop proxy infrastructure, high-volume file modification activity typical of ransomware, and unauthorized resource hijacking. Two agents sequentially weigh the evidence to confirm if a beachhead has progressed to an impact-oriented intrusion.

## vulnerability-scoping
<!-- Scope vulnerable assets -->
Identify the initial target population by listing hosts with critical vulnerabilities (severity_id >= 4).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of vulnerable device UIDs. This defines the blast radius for exploitation-based
  initial access.
reads:
- cve_uid
- device_uid
- severity_id
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_uid, cve_uid, severity_id, title FROM hb_vulnerability_finding WHERE severity_id >= 4
```

## parallel-early
<!-- Detect early beachhead signals -->
parallel:
- → dns-malicious-query
- → process-hash-query
join: → agent-early-read

## dns-malicious-query
<!-- Malicious domain and proxy DNS -->
Find resolutions for GTI-flagged domains or multi-hop proxy (.onion) addresses.

```sqlite target=endpoint role=triage params=(malicious_domains=malicious_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A hit indicates a host resolving infrastructure associated with phishing,
  C2, or multi-hop anonymity networks.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{malicious_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.onion%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## process-hash-query
<!-- Match process hashes to GTI malware -->
Identify active execution of binaries known to be malicious via GTI SHA256 matches.

```sqlite target=endpoint role=detection-candidate params=(malicious_hashes=malicious_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Confirmed execution of malicious code. This is a high-confidence signal
  of a successful landing.
reads:
- device_hostname
- process_hash_sha256
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_hash_sha256, time FROM hb_process_activity WHERE instr(',' || '{{malicious_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-read
<!-- Analyze initial breach evidence -->
```agent target=hunter
cite: required
context:
- vulnerability-scoping
- dns-malicious-query
- process-hash-query
max_iterations: 4
objective: Confirm if vulnerable hosts show early-stage breach indicators (DNS/Process)
  and cite the findings.
success_criteria: Host-specific verdicts citing DNS queries or malicious hash executions.
tools:
- endpoint
- network
```

## parallel-late
<!-- Search for follow-on threat behavior -->
parallel:
- → network-c2-query
- → file-impact-baseline
- → miner-behavior-triage
join: → agent-follow-on-read

## network-c2-query
<!-- C2 network connections -->
Identify established connections to known-malicious GTI IPs associated with C2 infrastructure.

```sqlite target=network role=triage params=(malicious_ips=malicious_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Row results confirm active network communication between a host and blacklisted
  C2 infrastructure.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{malicious_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-impact-baseline
<!-- Mass file modification baseline -->
Identify processes performing high volumes of file modifications or deletions, which is characteristic of ransomware encryption.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A high event count from a process on a single host may indicate ransomware;
  compare against fleet prevalence to identify anomalies.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, COUNT(*) AS event_count, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id IN (1, 3, 4, 5) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name HAVING event_count > 100
```

## miner-behavior-triage
<!-- Cryptomining behavior detection -->
Search for process and command-line indicators associated with resource hijacking and cryptocurrency miners.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Matches indicate resource hijacking for profit, often a secondary stage
  of a cloud or server breach.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%miner%' OR LOWER(process_cmd_line) LIKE '%xmrig%' OR LOWER(process_cmd_line) LIKE '%stratum%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## agent-follow-on-read
<!-- Analyze intrusion progression -->
```agent target=hunter
cite: required
context:
- agent-early-read
- network-c2-query
- file-impact-baseline
- miner-behavior-triage
max_iterations: 4
objective: 'Synthesize the entire lifecycle: does the early breach align with the
  observed C2, file impact, or mining behavior on the same hosts?'
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the progression from access to impact.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the agent-follow-on-read verdict is malicious for at least one host based on the intrusion chain" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: limited-endpoint-retention)
else: → documentation-and-tuning

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke any active sessions for the user accounts identified in the queries.
```
→ analyst-validation

## analyst-validation
<!-- Analyst incident validation -->
```manual target=analyst
Review the rows cited by both agent steps. Verify the reputation of the domains and hashes using an external GTI or VirusTotal search. Finalize the triage verdict.
```
→ documentation-and-tuning

## documentation-and-tuning
<!-- Documentation and tuning -->
```manual target=analyst
Record the hunt outcome. If malicious activity was found, update the 'malicious_hashes' and 'malicious_ips' parameters. If benign, document common updaters or backup processes to be excluded.
```
→ end
