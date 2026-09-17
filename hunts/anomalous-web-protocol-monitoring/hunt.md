---
analysis: A single detection rule would likely focus only on the backslash-GET method.
  This hunt is superior because it correlates the HTTP behavior with fleet-wide prevalence
  and cross-references it with DNS telemetry to identify the specific 'Direct-to-IP'
  signature that marks stealthy C2 channels.
blind_spots:
- id: proxy-visibility-gap
  question: Are malicious HTTP patterns visible inside encrypted (HTTPS) sessions?
  remediation: Deploy endpoint-based HTTP interception or TLS break-and-inspect on
    the network edge.
  requires: TLS Decryption at the proxy/edge
  risk: Malware using HTTPS will hide the method (backslash-GET) and URL path from
    hb_http_activity unless the proxy is actively decrypting traffic.
  stage: obfuscated-http-exfiltration
- id: dns-cache-retention
  question: Can we confirm a connection had NO DNS precursor if the resolution happened
    before the lookback window?
  remediation: Ensure DNS log retention matches or exceeds the hunt lookback window.
  requires: hb_dns_activity (live cache vs log events)
  risk: A host may have resolved a domain days earlier; if the DNS log retention is
    shorter than the lookback, a legitimate connection may falsely appear as D2IP.
coverage:
- stage: obfuscated-http-exfiltration
  status: covered
  steps:
  - malicious-http-patterns
  - rare-http-context
  - triage-anomalies
- reason: 'This is the primary focus of the first hunt in this series (Hunt 1: Direct-to-IP
    Signal).'
  stage: direct-to-ip-communication
  status: out_of_scope
- reason: Focuses on the browser behavior and SectopRAT mechanics, which is the focus
    of Hunt 3.
  stage: credential-form-collection
  status: out_of_scope
- reason: Execution artifacts (file/process) are handled by traditional EDR rules
    and Hunt 2's secondary objectives.
  stage: malware-execution-stating
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Almost half of malware samples use direct-to-IP communication to
    bypass DNS-based filters. Detecting the specific exfiltration protocols (like
    SectopRAT's browser proxying or Phorpiex's URI patterns) provides high-fidelity
    detection of active compromise that traditional DNS security cannot see.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using non-standard HTTP methods like backslash-GET or
  hard-coded URI paths (e.g., /churl, /fsave) to exfiltrate data while bypassing DNS-based
  security controls through direct-to-IP communication.
labels:
- hunt
- attack.t1041
- attack.t1071.001
name: Anomalous Web Protocol Monitoring
parameters:
  c2_ips:
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
    description: Known malicious destination IPs from the Unit 42 report.
    from:
      kind: article
      observed: '2024-05-20'
      ref: unit42-d2ip
    type: list[ip]
  legacy_user_agents:
    default:
    - Wget/1.13.4
    description: Older User-Agents used by IoT botnets like Boatnet to target unpatched
      hardware.
    from:
      kind: article
      observed: '2024-05-20'
      ref: unit42-d2ip
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-designer
    type: number
  malicious_paths:
    default:
    - /churl
    - /fsave
    - /new.php
    - /sex/k/n.txt
    - /hiddenbin/st.exe
    - /hiddenbin/
    description: Malicious URI paths identified in SectopRAT, Phorpiex, and Boatnet
      samples.
    from:
      kind: article
      observed: '2024-05-20'
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on all endpoints with outbound HTTP activity. Priority
  should be given to segments containing IoT devices (MIPS/ARM architectures) or high-value
  workstations that may be targeted for browser-proxy exfiltration (SectopRAT).
references:
- name: "Unit 42 \u2014 Almost Half of Malware Samples Communicate Direct to IP"
  url: https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/
related:
- hunt: direct-to-ip-communication-analysis
  reason: This hunt focuses on protocol-level HTTP anomalies; general IP-based direct-to-IP
    hunting is handled in a separate volume.
  relation: out-of-scope-alternative
- hunt: dns-bypass-direct-ip-discovery
  relation: follows
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
  index: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Anomalous Web Protocol Monitoring

This hunt targets specific web protocol anomalies identified by Unit 42 research. It focuses on the use of obfuscated HTTP methods and specific exfiltration paths used by malware families like SectopRAT and Phorpiex. Because these threats often bypass DNS resolution entirely, the hunt corroborates HTTP activity against DNS telemetry to identify 'Direct-to-IP' (D2IP) connections that lack a corresponding domain resolution, a strong indicator of hard-coded C2 infrastructure.

## malicious-http-patterns
<!-- Malicious HTTP Methods and Paths -->
Identify outbound HTTP traffic using the backslash-GET method, known exfiltration paths, or legacy botnet User-Agents.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, malicious_paths=malicious_paths, legacy_user_agents=legacy_user_agents, c2_ips=c2_ips)
~~~yaml
expected: Specific hits on non-standard verbs or paths used for credential exfiltration
  and payload delivery. Absence of rows suggests these specific indicators were not
  observed.
reads:
- device_hostname
- dst_endpoint_ip
- http_method
- src_endpoint_ip
- time
- url_full
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT time, device_hostname, src_endpoint_ip, dst_endpoint_ip, http_method, url_path, user_agent, url_full FROM hb_http_activity WHERE (LOWER(http_method) = '\get' OR instr(',' || '{{malicious_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR instr(',' || '{{legacy_user_agents}}' || ',', ',' || user_agent || ',') > 0 OR instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate Prevalence and DNS Context -->
parallel:
- → rare-http-context
- → dns-resolution-history
join: → triage-anomalies

## rare-http-context
<!-- Rare HTTP Method and Path Combinations -->
Stack-count HTTP method and path pairs to find unique or highly localized activity that may represent a custom C2.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Unique HTTP method/path combinations appearing on very few hosts, identifying
  potential custom exfiltration protocols.
prevalence:
  by: device_hostname
  key:
  - http_method
  - url_path
  rare_below: 3
reads:
- device_hostname
- http_method
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT http_method, url_path, user_agent, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as request_count FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY http_method, url_path, user_agent HAVING host_count <= 3 ORDER BY host_count ASC
```

## dns-resolution-history
<!-- DNS Resolution History for Destinations -->
Gather DNS telemetry to verify if destination IPs in earlier steps were ever resolved via DNS by the same host.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A list of DNS resolutions. The triage agent will check if hit destination
  IPs from Query 1 or 2 appear in these answers; an absence of match confirms a Direct-to-IP
  (D2IP) connection.
reads:
- answers
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, answers, time FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days')
```

## triage-anomalies
<!-- Triage Web Protocol Anomalies -->
```agent target=hunter
cite: required
context:
- malicious-http-patterns
- rare-http-context
- dns-resolution-history
max_iterations: 4
objective: Determine if any host is communicating with hard-coded C2 infrastructure
  using anomalous HTTP protocols without DNS resolution.
success_criteria: A host-by-host analysis citing specific HTTP requests and confirming
  the D2IP status.
tools:
- endpoint
- web
```

## evaluate-risk
<!-- Evaluate Risk -->
if~: "the triage verdict is malicious for at least one host based on backslash-GET or exfiltration paths without DNS precursors" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: proxy-visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect all process and network artifacts associated with the flagged HTTP destination IP.
```
→ analyst-review

## analyst-review
<!-- Analyst Case Review -->
```manual target=analyst
Review the flagged HTTP activity. Confirm if the request bodies match the encoded exfiltration patterns described by Unit 42. Extract destination IPs and update the edge firewall blocklists.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the hunt results. If no malicious web patterns were found, summarize the extent of the fleet visibility for web protocol anomalies.
```
→ end
