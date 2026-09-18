---
analysis: A standard rule alerts on a single IP lead. This hunt pivots between the
  absence of DNS resolution and protocol-level anomalies (\GET), stack-counting them
  across the fleet to find the rare, malicious needle.
blind_spots:
- id: no-agent-on-legacy-iot
  question: whether legacy ICS or IoT devices without agents are infected
  requires: Endpoint telemetry from legacy architectures (m68k, older ARM)
  risk: Boatnet specifically targets architectures like m68k which typically lack
    modern EDR/osquery coverage.
  stage: iot-p2p-botnet-propagation
- id: encrypted-c2-payloads
  question: whether the \GET protocol is present in encrypted sessions
  requires: hb_http_activity with decrypted content or proxy inspection
  risk: Malware using custom TLS stacks or pinned certificates may bypass endpoint-based
    HTTP logging.
  stage: obfuscated-exfiltration-protocol
coverage:
- stage: dns-bypass-c2-initialization
  status: covered
  steps:
  - indicator-lead
  - dns-bypass-behavior
  - d2ip-stack-counting
- stage: staged-payload-delivery
  status: covered
  steps:
  - protocol-anomalies
- stage: obfuscated-exfiltration-protocol
  status: covered
  steps:
  - protocol-anomalies
- stage: browser-mirroring-and-theft
  status: covered
  steps:
  - protocol-anomalies
- stage: iot-p2p-botnet-propagation
  status: covered
  steps:
  - indicator-lead
  - dns-bypass-behavior
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Almost 45% of C2 malware uses D2IP to bypass DNS-based security.
    This hunt validates that these 'invisible' connections are not present or identifies
    them where hostname context is missing.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are bypassing DNS-based security controls by using hard-coded
  IP addresses for command-and-control and staged payload delivery.
labels:
- hunt
- attack.t1071.001
- attack.t1105
- attack.t1041
- attack.t1132.001
- attack.t1056.001
- attack.t1090
- attack.t1573.002
name: Direct-to-IP C2 and DNS-Bypass Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_ips:
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
    description: C2 IPs from the article.
    from:
      kind: article
      observed: '2026-08-04'
      ref: unit42-d2ip
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt.
    type: list[host]
  suspicious_paths:
    default:
    - /churl
    - /fsave
    - /new.php
    - /hiddenbin/
    - /st.exe
    - /sex/k/n.txt
    - /1
    - /2
    description: Suspicious URI paths from the article.
    from:
      kind: article
      observed: '2026-08-04'
      ref: unit42-d2ip
    type: list[string]
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
rationale: The hunt targets endpoints with downloader tools (wget, curl) as a proxy
  for susceptibility to the researched malware. Initial runs should target Linux/IoT
  assets if known, then expand fleet-wide.
references:
- name: "Unit 42 \u2014 Almost Half of Malware Samples Communicate Direct to IP"
  url: https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/
related:
- hunt: unusual-outbound-http-methods
  reason: Focuses on malformed HTTP methods broadly rather than just the DNS-bypass
    context.
  relation: sibling
scenario:
  stages:
  - name: Direct-to-IP C2 Connection
    observables:
    - 154.92.19.71:39989
    - 87.120.107.33
    - 194.76.227.94
    - 62.60.179.230
    - 91.92.243.29
    - 103.245.236.146
    - wss://154.92.19.71:39989
    slug: dns-bypass-c2-initialization
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Staged Payload Retrieval
    observables:
    - 178.16.54.109/st.exe
    - /1
    - /2
    - /sex/k/n.txt
    - /new.php
    - st.exe
    - /hiddenbin/
    slug: staged-payload-delivery
    tactic: execution
    techniques:
    - T1105
  - name: Obfuscated HTTP Exfiltration
    observables:
    - \GET
    - cc43cdbe8eb9874f55fffbe23b560b673eb9f31fb9a953926bba29464fd2dd07
    slug: obfuscated-exfiltration-protocol
    tactic: exfiltration
    techniques:
    - T1041
    - T1132.001
  - name: SectopRAT Browser Proxying
    observables:
    - /churl
    - /fsave
    - pcid
    - clid
    slug: browser-mirroring-and-theft
    tactic: credential-access
    techniques:
    - T1056.001
    - T1090
  - name: Mozi/Boatnet P2P Propagation
    observables:
    - Wget/1.13.4
    - 2.26.98.67
    slug: iot-p2p-botnet-propagation
    tactic: execution
    techniques:
    - T1573.002
  summary: Various malware families like Phorpiex, Mozi, and SectopRAT bypass DNS-based
    security by connecting directly to hard-coded IP addresses (D2IP). These campaigns
    utilize non-standard HTTP methods like backslash-GET, real-time browser mirroring
    via custom endpoints, and P2P mesh architectures to maintain command-and-control
    and exfiltrate data.
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


# Direct-to-IP C2 and DNS-Bypass Activity

Recent research shows that nearly half of malware families now utilize 'Direct-to-IP' (D2IP) communications. This allows malware to establish C2 connections without triggering DNS-based detections, sinkholes, or hostname-based anomaly alerts. This hunt focuses on identifying outbound connections to public IP addresses where no DNS resolution was recorded, corroborating this with protocol-level anomalies like malformed HTTP methods (\GET) and URI paths specific to Phorpiex, SectopRAT, and Mozi botnets.

## scope-to-downloader-hosts
<!-- Scope to hosts with common downloaders -->
Focus the hunt on systems containing utilities frequently used by D2IP malware for retrieval.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts with downloader software. Silence means no inventory is available,
  so the hunt should run unscoped.
reads:
- device_hostname
- package_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE package_name IN ('wget', 'curl', 'python3', 'python') AND asset_scope = 'endpoint'
```

## indicator-lead
<!-- Direct connections to known C2 IPs -->
Identify any host communicating with the specific IP indicators named in the research.

```sqlite target=network role=enrichment params=(malicious_ips=malicious_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Network connections to the IOC list. Silence indicates the infrastructure
  has rotated.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{malicious_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-analysis
<!-- Analyze behavior and protocol anomalies -->
parallel:
- → dns-bypass-behavior
- → protocol-anomalies
- → d2ip-stack-counting
join: → triage-agent

## dns-bypass-behavior
<!-- Behaviourial DNS-bypass connections -->
Identify processes connecting to the internet where the hostname is either absent or matches the IP exactly.

```sqlite target=network role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound D2IP traffic. Rare processes are suspicious.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- dst_endpoint_hostname
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (dst_endpoint_hostname IS NULL OR dst_endpoint_hostname = dst_endpoint_ip) AND direction = 'outbound' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## protocol-anomalies
<!-- Protocol-level artifacts and URI paths -->
Corroborate D2IP activity with malformed HTTP methods (\\GET) and specific paths associated with the researched botnets.

```sqlite target=web role=enrichment params=(suspicious_paths=suspicious_paths, lookback_days=lookback_days)
~~~yaml
expected: Hits on malformed HTTP methods or specific URI paths. Silence means no protocol-level
  evidence was captured.
reads:
- device_hostname
- dst_endpoint_ip
- url_full
- http_method
- user_agent
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, url_full, http_method, user_agent, time FROM hb_http_activity WHERE (http_method LIKE '%GET%' AND http_method LIKE '%\\\\%') OR instr(',' || '{{suspicious_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR user_agent = 'Wget/1.13.4' AND time >= datetime('now', '-{{lookback_days}} days')
```

## d2ip-stack-counting
<!-- Rare D2IP process-destination pairs -->
Stack-count D2IP connections to find rare combinations that are not common across the fleet.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare D2IP pairs. Legitimate software like NTP or CDNs might show up but
  should be fleet-wide.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_ip
  rare_below: 3
reads:
- process_name
- dst_endpoint_ip
- device_hostname
- dst_endpoint_hostname
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_hostname IS NULL OR dst_endpoint_hostname = dst_endpoint_ip) AND direction = 'outbound' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_ip HAVING hosts <= 3 ORDER BY hosts, connections
```

## triage-agent
<!-- Triage DNS-bypass evidence -->
```agent target=hunter
cite: required
context:
- indicator-lead
- dns-bypass-behavior
- protocol-anomalies
- d2ip-stack-counting
max_iterations: 4
objective: Determine if D2IP activity on any host is malicious by correlating connection
  leads, rare process baselines, and malformed HTTP artifacts.
success_criteria: A verdict of malicious | suspicious | benign citing specific processes
  and IPs.
tools:
- endpoint
- network
- web
```

## verdict-decision
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-agent-on-legacy-iot)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and begin forensic collection of the identified processes.
```
→ analyst-review

## analyst-review
<!-- Analyst review and tuning -->
```manual target=analyst
Review the cited rows. Confirm whether the D2IP process is an expected utility. Record findings and tune the hunt for future runs.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Summarize findings, note the efficacy of the D2IP behavior query, and document any newly discovered C2 infrastructure.
```
→ end
