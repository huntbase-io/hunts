---
analysis: "While a detection rule can flag the User-Agent, this hunt pivots to host-level\
  \ internal loopback connections and stack-counts source IPs to differentiate UTA0533\
  \ activity from legitimate SMA Connect Agent traffic\u2014a correlation difficult\
  \ for single-surface detection rules."
blind_spots:
- id: no-loopback-telemetry
  question: Can we see connections between the web server and the internal management
    ports on the same host?
  requires: Host-level network telemetry (e.g., osquery) for the 127.0.0.1 interface.
  risk: Without host-level network logs, we can only see the external HTTP request
    and not the internal fulfillment of the tunnel, missing the confirmation of successful
    access.
  stage: c2-websocket-tunneling
- id: http-query-logging
  question: Was the specific bmID bypass parameter used?
  requires: Logging of the url_query field in hb_http_activity.
  risk: If the appliance or a reverse proxy strips the query string before logging,
    we lose the specific indicator of the bypass, relying only on status 101 and the
    User-Agent.
  stage: initial-access-proxy-bypass
coverage:
- stage: initial-access-proxy-bypass
  status: covered
  steps:
  - detect-http-proxy-bypass
  - baseline-agent-source-ips
- stage: c2-websocket-tunneling
  status: covered
  steps:
  - detect-internal-tunnel-connections
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: execution-privesc-code-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: persistence-custom-webshell
  status: out_of_scope
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: collection-network-sniffing
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SonicWall SMA appliances are critical gatekeepers. An unauthenticated
    0-day bypass allows attackers to reach highly sensitive management services and
    potentially move laterally into the internal environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting a zero-day proxy bypass on SonicWall SMA appliances
  to tunnel WebSocket traffic to internal management services, bypassing authentication
  protocols.
labels:
- hunt
- attack.t1190
- attack.t1572
- attack.t1090.003
name: SonicWall SMA Proxy Bypass and Tunneling
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  sma_models:
    default:
    - '6210'
    - '7210'
    - 8200v
    description: Affected SonicWall SMA 1000 series models.
    type: list[string]
  target_ports:
    default:
    - '1050'
    - '1051'
    - '8188'
    description: Localhost services often targeted by the tunnel (CouchDB, EPMD, Control
      Service).
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Restrict searching to high-value VPN gateways and appliances. If direct
  inventory is unavailable, apply the queries to any Linux-based web gateways in the
  edge DMZ.
references:
- name: "Volexity \u2014 Proxying to Compromise: SonicWall SMA 0-day Exploitation"
  url: https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
related:
- hunt: sonicwall-sma-code-injection-webshells
  reason: This hunt identifies the bypass and tunnel; the follow-up hunt focuses on
    the post-authentication command injection (CVE-2026-15410) and custom webshell
    persistence.
  relation: follows
scenario:
  stages:
  - name: Unauthenticated Proxy Bypass
    observables:
    - GET /wsproxy
    - 'User-Agent: SMA Connect Agent'
    - bmID=-3389
    - HTTP 101 status code
    slug: initial-access-proxy-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: WebSocket Tunneling to Local Services
    observables:
    - Connections to localhost (127.0.0.1) on ports 1050, 1051, 8188
    - Binary WebSocket protocol usage
    slug: c2-websocket-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  - name: Exploitation for Privilege Escalation
    observables:
    - CVE-2026-15410
    - Execution of /usr/local/bin/remove_hotfix with shell script arguments
    - Creation of /tmp/1234.sh
    - python3 /usr/lib/python3.11/site-packages/deploy_new.py
    slug: execution-privesc-code-injection
    tactic: execution
    techniques:
    - T1190
  - name: Webshell Persistence
    observables:
    - POST /__api__/login
    - POST /__api__/logout
    - Modified nginx configuration for URI rewriting
    slug: persistence-custom-webshell
    tactic: persistence
    techniques:
    - T1505.003
  - name: Credential and Traffic Collection
    observables:
    - nohup tcpdump -i any port 389
    - Output file in /var/tmp/
    - Memory scraping for session cookies and credentials
    slug: collection-network-sniffing
    tactic: collection
    techniques:
    - T1555
  summary: The UTA0533 threat actor exploited zero-day vulnerabilities in SonicWall
    SMA 1000 series appliances to gain initial access via a proxy bypass and WebSocket
    tunneling. Once inside, the actor achieved root-level code execution to deploy
    custom Python malware and web shells, ultimately capturing internal network traffic
    and scraping credentials from memory.
series:
  index: 1
  slug: proxying-to-compromise-sonicwall-sma-0-day-exploitation
  title: 'Proxying to Compromise: SonicWall SMA 0-day Exploitation'
  total: 2
severity: critical
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


# SonicWall SMA Proxy Bypass and Tunneling

In July 2026, a series of zero-day exploits were discovered affecting SonicWall SMA 1000 series appliances (models 6210, 7210, and 8200v). This hunt specifically targets the 'initial-access-proxy-bypass' and 'c2-websocket-tunneling' stages identified in the research. The attacker uses a specific User-Agent ('SMA Connect Agent') and a crafted URL query parameter to bypass authentication on the '/wsproxy' endpoint, establishing a persistent WebSocket tunnel.

Once the tunnel is established, the adversary connects to local-only management services such as CouchDB (port 1050), EPMD (port 1051), and the SMA Control Service (port 8188). This hunt correlates anomalous HTTP status 101 (Switching Protocols) events with internal network connections originating from the appliance's web server processes to identify successful exploitation.

## find-sma-software
<!-- Identify SonicWall SMA Software -->
Identify hosts running software packages related to SonicWall or SMA to narrow the scope of the investigation.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts running SonicWall SMA software components. This defines the primary
  search space.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%sonicwall%' OR LOWER(package_name) LIKE '%sma%'
```

## parallel-telemetry-checks
<!-- Parallel Telemetry Corroboration -->
parallel:
- → find-sma-by-model
- → detect-http-proxy-bypass
- → detect-internal-tunnel-connections
- → baseline-agent-source-ips
join: → triage-exploitation

## find-sma-by-model
<!-- Filter by Affected Hardware Models -->
Specifically identify appliances matching the affected hardware models named in the research.

```sqlite target=endpoint role=scoping params=(sma_models=sma_models)
~~~yaml
expected: Hosts matching the vulnerable model strings (6210, 7210, 8200v).
reads:
- hostname
- hardware_model
- device_uid
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT hostname, hardware_model, device_uid FROM hb_devices WHERE instr(',' || '{{sma_models}}' || ',', ',' || hardware_model || ',') > 0
```

## detect-http-proxy-bypass
<!-- Detect HTTP Proxy Bypass -->
Search for successful WebSocket protocol upgrades on the /wsproxy endpoint using the characteristic SMA Connect Agent string.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Status 101 on /wsproxy with the SMA agent indicates a potential 0-day bypass
  attempt. These results are high-fidelity leads.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- url_query
- user_agent
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, url_query, user_agent, status_code, time FROM hb_http_activity WHERE url_path = '/wsproxy' AND user_agent = 'SMA Connect Agent' AND status_code = 101 AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-internal-tunnel-connections
<!-- Detect Internal Management Tunneling -->
Identify loopback connections from web server processes to internal management ports, which indicates tunnel usage.

```sqlite target=network role=triage params=(lookback_days=lookback_days, target_ports=target_ports)
~~~yaml
expected: Connections from 'httpd' or 'nginx' to ports 1050, 1051, or 8188 locally.
  This confirms the tunnel is being utilized to reach backend services.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE dst_endpoint_ip = '127.0.0.1' AND (instr(',' || '{{target_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND (LOWER(process_name) = 'httpd' OR LOWER(process_name) = 'nginx') AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-agent-source-ips
<!-- Baseline SMA Agent Source IPs -->
Count source IPs using the SMA agent string to identify rare sources that deviate from normal fleet usage.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Source IPs seen on few hosts but making many requests. Legitimate users
  typically use a consistent set of IPs; rare ones may represent attackers.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- device_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS request_count FROM hb_http_activity WHERE user_agent = 'SMA Connect Agent' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING host_count <= 3 ORDER BY request_count DESC
```

## triage-exploitation
<!-- Triage SMA Exploitation -->
```agent target=hunter
cite: required
context:
- find-sma-by-model
- detect-http-proxy-bypass
- detect-internal-tunnel-connections
- baseline-agent-source-ips
max_iterations: 5
objective: Confirm if a vulnerable model appliance (find-sma-by-model) successfully
  switched protocols on /wsproxy (detect-http-proxy-bypass) and immediately established
  local connections to management ports (detect-internal-tunnel-connections).
success_criteria: A verdict of Malicious/Suspicious/Benign per host citing specific
  timestamps and ports.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is Malicious for at least one SonicWall SMA host." (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-loopback-telemetry)
else: → close-out

## isolate-appliance
<!-- Isolate Affected Appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the VPN appliance from the internal network and revoke all management credentials. Initiate Incident Response protocols.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the correlated HTTP and network rows. Check for the 'bmID=-3389' string in url_query if available. Confirm if the source IPs are known VPN users or external attackers.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the negative findings and verify the health of the appliances.
```
→ end
