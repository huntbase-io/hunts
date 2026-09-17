---
analysis: A simple detection rule might fire on connections to the 10 IPs in the report.
  This hunt goes further by baselining the entire fleet's DNS behavior to find unknown
  D2IP malware, using the absence of a correlation (Network without DNS) as the primary
  lead.
blind_spots:
- id: missing-network-logs
  question: Can we differentiate between DNS-resolved and direct-IP connections using
    a single table?
  requires: hb_network_connection with dst_endpoint_hostname
  risk: Without a reliable hostname field across all providers, we cannot programmatically
    distinguish between a connection to an IP that was resolved via DNS and one that
    was hard-coded, necessitating the more complex cross-surface correlation used
    here.
  stage: direct-to-ip-communication
- id: short-dns-retention
  question: Was a DNS query made before the lookback window?
  requires: 30+ day retention for hb_dns_activity
  risk: Malware that resolves a domain once and persists for weeks may appear as D2IP
    if the original query has rotated out of the logs while the connection remains
    established.
  stage: direct-to-ip-communication
coverage:
- stage: direct-to-ip-communication
  status: covered
  steps:
  - connections-to-known-c2
  - potential-d2ip-prevalence
  - dns-activity-summary
  - triage-agent
- reason: Belongs to the second hunt in this series, focusing on hb_process_activity
    and hb_file_activity.
  stage: malware-execution-stating
  status: out_of_scope
- reason: Belongs to another part of the 'Almost Half of Malware Samples Communicate
    Direct to IP' series.
  stage: obfuscated-http-exfiltration
  status: out_of_scope
- reason: Belongs to another part of the 'Almost Half of Malware Samples Communicate
    Direct to IP' series.
  stage: credential-form-collection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Direct-to-IP (D2IP) bypasses the majority of modern DNS-based defenses
    (sinkholing, filtering, and DNS monitoring). This hunt provides visibility into
    a behavior used by nearly half of all malware, ensuring that network security
    isn't solely dependent on 'well-behaved' software that uses DNS.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Malware is communicating with external C2 infrastructure by connecting
  directly to hard-coded IP addresses, evidenced by outbound network connections that
  lack corresponding DNS resolution activity or occur in processes that are DNS-silent.
labels:
- hunt
- attack.t1095
- attack.t1071.001
name: DNS Bypass and Direct IP Discovery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-04'
      ref: default
    type: number
  target_ips:
    default:
    - 154.92.19.71
    - 178.16.54.109
    - 87.120.107.33
    - 194.76.227.94
    - 2.26.98.67
    - 62.60.179.230
    - 91.92.243.29
    - 103.245.236.146
    - 178.16.54.31
    - 206.189.229.43
    description: Malicious destination IPs identified in the Unit 42 report.
    from:
      kind: article
      observed: '2026-08-04'
      ref: unit42-d2ip-research
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize servers and IoT-adjacent devices (MIPS/ARM/embedded)
  where legacy or specialized malware like Boatnet/Mozi is more likely to reside.
  Limit initial lookback to 14 days to keep DNS activity summaries manageable.
references:
- name: "Unit 42 \u2014 Almost Half of Malware Samples Communicate Direct to IP"
  url: https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/
related:
- hunt: malware-execution-stating
  reason: This hunt focuses on the network transport, not the initial execution or
    staging of the binary.
  relation: out-of-scope-alternative
- hunt: obfuscated-http-exfiltration
  reason: Data exfiltration patterns (like the backslash-GET protocol) are handled
    by a subsequent hunt in the series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malware Execution and Staging
    observables:
    - st.exe
    - cc43cdbe8eb9874f55fffbe23b560b673eb9f31fb9a953926bba29464fd2dd07
    - 01a96eeafb72042b3f69afd21b4c9155dbfe7f97ab3dca392972ad531a075ac2
    - 9639f7ebc6a6d69d7bf5b8bc869e7783a1406088f192868624ad8919e9bfd1d4
    - bf24277400cc453d530e4277d3bd24e96c5e409adef6970518bdc59205aa0241
    - e310476c41ae4f6e3c4ed9bb88303ee6e5e1455bd7afe51cf48965ea7599e6e5
    - e3513922666c202c1ae5c06eea277ba10477868d6d89ce2819f4f8ff9070bc85
    - e5715e6611ef6bcb233f5d2098510dab3db408abbb728b00e1821bb255829373
    slug: malware-execution-stating
    tactic: execution
    techniques:
    - T1204.002
  - name: Direct-to-IP C2 Communication
    observables:
    - 154.92.19.71:39989
    - wss://154.92.19.71
    - 178.16.54.109
    - 87.120.107.33
    - 194.76.227.94
    - 2.26.98.67
    - 62.60.179.230
    - 91.92.243.29
    - 103.245.236.146
    - 178.16.54.31
    - 206.189.229.43
    - No preceding DNS query for destination IP
    slug: direct-to-ip-communication
    tactic: command-and-control
    techniques:
    - T1095
    - T1071.001
  - name: Obfuscated HTTP Exfiltration
    observables:
    - \GET method (backslash-GET)
    - GET /churl
    - GET /fsave
    - GET /new.php
    - GET /sex/k/n.txt
    - Wget/1.13.4
    - Encoded payload length 250-666 characters
    - /hiddenbin/
    slug: obfuscated-http-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1071.001
  - name: In-Browser Proxy Collection
    observables:
    - Mirroring authenticated session pages
    - Exfiltration of plaintext passwords from form fields
    - Tracking identifiers (pcid/clid)
    slug: credential-form-collection
    tactic: collection
    techniques:
    - T1185
    - T1119
  summary: Approximately 45% of malware samples bypass DNS-based security by connecting
    directly to hard-coded IP addresses for C2 and exfiltration. This behavior is
    seen across ransomware droppers like Phorpiex, the SectopRAT browser-proxy, and
    IoT botnets like Mozi, often utilizing non-standard protocols like obfuscated
    backslash-GET requests.
series:
  index: 1
  slug: almost-half-of-malware-samples-communicate-direct-to-ip
  title: Almost Half of Malware Samples Communicate Direct to IP
  total: 3
severity: high
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
tlp: clear
type: investigation
---


# DNS Bypass and Direct IP Discovery

According to Unit 42 research, nearly half of malware samples bypass DNS-based security by connecting directly to IP addresses (D2IP). This hunt identifies such behavior by first scoping to known malicious IPs from the report and then identifying 'DNS-silent' processes—those that establish outbound connections to external IPs without a prior DNS query. We use prevalence to filter out noise from common system updaters and use an agent to correlate network activity with the absence of DNS queries on a per-process basis. This version incorporates reviewer feedback regarding hostname field reliability and noise reduction.

## connections-to-known-c2
<!-- Connections to Known C2 IPs -->
Scope the hunt by identifying any hosts communicating with the specific IP addresses highlighted in the research.

```sqlite target=network role=scoping params=(target_ips=target_ips, lookback_days=lookback_days)
~~~yaml
expected: A row indicates a direct hit on an IOC. Silence means none of the specific
  IPs from this report are currently active in the telemetry window.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE instr(',' || '{{target_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## parallel-check
<!-- Assess DNS Silence and Prevalence -->
parallel:
- → potential-d2ip-prevalence
- → dns-activity-summary
join: → triage-agent

## potential-d2ip-prevalence
<!-- Rare Outbound Connections Excluding Web Traffic -->
Identify processes connecting to external IPs that bypass standard web ports, filtering for rarity to avoid high-volume background noise. Note: Standard socket telemetry often lacks hostnames, so we rely on cross-surface correlation in the triage step.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare process/IP pairs that appear to bypass standard DNS resolution. High
  host counts likely indicate legitimate global services or updaters.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_name) AS proc, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND dst_endpoint_port NOT IN (80, 443) AND (dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.16.%' AND dst_endpoint_ip NOT LIKE '127.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY proc, dst_endpoint_ip HAVING host_count <= 3 ORDER BY host_count ASC, connection_count DESC
```

## dns-activity-summary
<!-- DNS Activity Summary per Process -->
Establish which processes are typically responsible for DNS traffic, allowing the agent to identify 'DNS-silent' processes using case-insensitive correlation.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A map of process DNS behavior. Processes found in the network step but missing
  here are confirmed as 'DNS-silent'.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, LOWER(process_name) AS proc, COUNT(DISTINCT query_hostname) AS unique_domains_queried, COUNT(*) AS total_queries FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, proc
```

## triage-agent
<!-- Correlate D2IP and DNS Silence -->
```agent target=hunter
cite: required
context:
- connections-to-known-c2
- potential-d2ip-prevalence
- dns-activity-summary
max_iterations: 5
objective: Identify suspicious processes connecting to external IPs without performing
  DNS queries. Prioritize rare processes from 'potential-d2ip-prevalence' that are
  absent from 'dns-activity-summary'. Account for the 'short-dns-retention' blind
  spot; if a process has long-lived or persistent connections but no recent DNS activity,
  consider that the resolution may have occurred before the telemetry window began.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  process/host pair, citing evidence from both the network and DNS surfaces.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route on Verdict -->
if~: "The triage verdict is malicious for one or more hosts connecting to known IOCs or showing strong D2IP patterns." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-network-logs)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified device_hostname(s) using the EDR containment capability. Proceed to analyst review for forensic collection.
```
→ analyst-review

## analyst-review
<!-- Forensic Review and Triage -->
```manual target=analyst
1. Review process binaries for the suspicious processes.
2. Check for existence of hard-coded IP strings (Strings/Ghidra).
3. Verify if the process is a known legitimate browser or system tool.
4. Close as false positive if the activity is sanctioned.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record the time window and hosts examined. Confirm no matches to the report's D2IP IOCs were found.
```
→ end
