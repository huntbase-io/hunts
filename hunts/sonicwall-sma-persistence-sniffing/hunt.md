---
analysis: This hunt uses a 30-day baseline for POST traffic to identify novel attacker-controlled
  URIs, which a static rule cannot do without high false positives. It also correlates
  disparate signals (file tampering in Python dirs and anomalous tcpdump usage) to
  surface the UTA0533 tradecraft.
blind_spots:
- id: black-box-appliances
  question: Can we see process and file events directly on the appliance?
  requires: EDR/osquery on the VPN appliance
  risk: If the appliance does not support an agent, we rely on secondary evidence
    (HTTP logs) which may not show the specific file dropped.
  stage: webshell-persistence
- id: websocket-opacity
  question: Are we seeing the content of the wsproxy WebSocket tunnel?
  requires: hb_http_activity with websocket frame inspection
  risk: UTA0533 uses WebSockets to tunnel traffic; standard HTTP logs only show the
    101 Switching Protocols event, not the tunneled commands.
  stage: network-traffic-sniffing
coverage:
- stage: webshell-persistence
  status: covered
  steps:
  - detect-webshell-traffic
  - detect-backdoor-files
- stage: network-traffic-sniffing
  status: covered
  steps:
  - detect-sniffing-processes
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: pre-auth-wsproxy-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: internal-service-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''Proxying to Compromise: SonicWall SMA
    0-day Exploitation'' series.'
  stage: root-command-injection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SonicWall SMA appliances are critical ingress points. A successful
    compromise allows a threat actor to sniff internal traffic (LDAP/RDP) and move
    laterally. Confirming the absence of persistent backdoors and collection tools
    is vital for network integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence on a VPN gateway via a Python-based
  backdoor and is performing internal network collection by sniffing LDAP traffic.
labels:
- hunt
- attack.t1505.003
- attack.t1133
- attack.t1572
name: SonicWall SMA Persistence and Sniffing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-17'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to restrict the hunt to.
    from:
      kind: manual
      observed: '2026-07-17'
      ref: inventory
    type: list[host]
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
rationale: The hunt should target all systems identified as SonicWall SMA appliances.
  Using both hb_software_inventory (agent-based) and hb_exposed_assets (scanner-based)
  ensures maximum coverage of both physical and virtual instances.
references:
- name: "Volexity \u2014 Proxying to Compromise: SonicWall SMA 0-day Exploitation"
  url: https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
related:
- hunt: sonicwall-initial-exploitation-chain
  reason: This hunt focuses on post-compromise activity (persistence and collection),
    whereas the initial 0-day exploitation chain (wsproxy/CouchDB) is a separate hypothesis.
  relation: out-of-scope-alternative
- hunt: sonicwall-sma-0day-exploitation
  relation: follows
scenario:
  stages:
  - name: Pre-authentication /wsproxy Bypass
    observables:
    - GET /wsproxy?bmID=-3389
    - 'User-Agent: SMA Connect Agent'
    - HTTP 101 Switching Protocols
    - bmID starting with -3389
    slug: pre-auth-wsproxy-bypass
    tactic: initial-access
    techniques:
    - T1190
    - T1090.003
  - name: Internal Service Tunneling
    observables:
    - Connection to 127.0.0.1:1050
    - Connection to 127.0.0.1:8188
    - Erlang Port Mapper Daemon (EPMD) access
    - CouchDB admin:admin default credentials
    slug: internal-service-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: Privilege Escalation via Code Injection
    observables:
    - CVE-2026-15410
    - /usr/local/bin/remove_hotfix
    - ../../../../../tmp/1234.sh
    - running hotfix removal for:../../../../../tmp/1234.sh
    slug: root-command-injection
    tactic: execution
    techniques:
    - T1190
  - name: Persistence via Python Backdoor
    observables:
    - /usr/lib/python3.11/site-packages/deploy_new.py
    - POST /__api__/login
    - POST /__api__/logout
    - nginx configuration modifications
    slug: webshell-persistence
    tactic: persistence
    techniques:
    - T1505.003
    - T1133
  - name: Internal Traffic Capture
    observables:
    - nohup tcpdump -i any
    - port 389
    - /var/tmp/
    - traffic destined for internal directory servers
    slug: network-traffic-sniffing
    tactic: collection
    techniques:
    - T1572
  summary: Threat actor UTA0533 compromised SonicWall SMA 1000 series appliances using
    a zero-day exploit chain involving an authentication bypass via the /wsproxy endpoint
    to tunnel into internal services. This access enabled the exploitation of CouchDB
    and a command injection vulnerability (CVE-2026-15410) to achieve root code execution,
    followed by the installation of a Python backdoor and network traffic sniffing.
series:
  index: 2
  slug: proxying-to-compromise-sonicwall-sma-0-day-exploitation
  title: 'Proxying to Compromise: SonicWall SMA 0-day Exploitation'
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# SonicWall SMA Persistence and Sniffing

This hunt targets the post-exploitation behavior of UTA0533 on SonicWall SMA 1000 series appliances. It identifies unauthorized modifications to system-level Python directories and binary paths that should remain immutable, as well as the execution of network capture tools which are anomalous on security appliances. It also baselines POST traffic to detect new, rare URI endpoints that indicate a webshell or backdoor interface has been established.

## scope-inventory
<!-- Identify VPN Gateways in Inventory -->
Locate known SonicWall SMA appliances within the managed software inventory.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames. Silence means no appliances were found in the software
  inventory, requiring the exposed-asset scoping step.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(vendor_name) LIKE '%sonicwall%' OR LOWER(package_name) LIKE '%sma%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## scope-exposed
<!-- Identify Exposed SonicWall Assets -->
Supplement inventory with internet-exposed SonicWall instances that may not have an agent installed.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: Domains or IPs identified as SonicWall products by external scanners.
reads:
- discovered_at
- domain_or_ip
- product
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT domain_or_ip, product, discovered_at FROM hb_exposed_assets WHERE LOWER(product) LIKE '%sonicwall%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || domain_or_ip || ',') > 0)
```

## parallel-compromise-checks
<!-- Perform Behavioral and Persistence Checks -->
parallel:
- → detect-webshell-traffic
- → detect-backdoor-files
- → detect-sniffing-processes
join: → triage-agent

## detect-webshell-traffic
<!-- New POST Traffic Baseline -->
Find URIs receiving POST requests that are first seen in the lookback window, relative to a 30-day baseline.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: 30d
expected: A rare URL path first receiving POST traffic recently. UTA0533 used paths
  like /__api__/login.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- device_hostname
- http_method
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, MIN(time) AS first_seen, COUNT(*) AS hits FROM hb_http_activity WHERE http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-30 days') GROUP BY device_hostname, url_path HAVING first_seen >= datetime('now', '-{{lookback_days}} days')
```

## detect-backdoor-files
<!-- Immutable Path Tampering -->
Detect file creations or updates in sensitive system directories that should be static on a VPN appliance.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: New files in site-packages or modifications to nginx configs. Genuine updates
  are rare outside of official hotfixes.
reads:
- activity_id
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE activity_id IN (1, 3) AND (LOWER(file_path) LIKE '%/python%/site-packages/%' OR LOWER(file_path) LIKE '%/usr/bin/%' OR LOWER(file_path) LIKE '%/usr/sbin/%' OR LOWER(file_path) LIKE '%/etc/nginx/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-sniffing-processes
<!-- Anomalous Packet Capture Execution -->
Identify the use of packet capture tools which are often used by attackers to harvest credentials from network traffic.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: tcpdump or tshark running, particularly with 'nohup' or writing to /var/tmp/.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%tcpdump%' OR LOWER(process_name) LIKE '%tshark%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Synthesize Compromise Indicators -->
```agent target=hunter
cite: required
context:
- scope-inventory
- scope-exposed
- detect-webshell-traffic
- detect-backdoor-files
- detect-sniffing-processes
max_iterations: 5
objective: Determine if any SonicWall appliance shows signs of persistence (unauthorized
  files or HTTP endpoints) coupled with collection (network sniffing).
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  anomalous URIs, files, or command lines.
tools:
- endpoint
- web
```

## route-decision
<!-- Decision on Compromise -->
if~: "the triage verdict is malicious for at least one host showing both sniffing activity and unauthorized URI interaction" (confidence: high, judge=hunter)
then: → isolate-action
indeterminate: → manual-task
unavailable: → manual-task (blind_spot: black-box-appliances)
else: → close-out-task

## isolate-action
<!-- Isolate Compromised Gateway -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified SonicWall appliance from the network. Revoke any administrator credentials used to manage the device.
```
→ manual-task

## manual-task
<!-- Analyst Investigation -->
```manual target=analyst
Review the identified rare POST URIs and process executions. Compare against known maintenance schedules or legitimate administrative troubleshooting. If confirmed malicious, escalate to full Incident Response.
```
→ end

## close-out-task
<!-- Hunt Completion -->
```manual target=analyst
Log the negative results for persistence and sniffing on the SonicWall fleet for this period. Ensure future Hotfixes are reflected in the inventory baseline.
```
→ end
