---
analysis: A single rule may fire on an interpreter spawning from a browser, but this
  hunt correlates that event with a rare network connection on proxy-associated ports
  using prevalence to filter out noise, providing context a static rule cannot.
blind_spots:
- id: no-process-to-network-correlation
  question: Which process initiated the rare connection?
  requires: Process-enriched network logs (e.g. Sysmon) on all endpoints
  risk: On hosts where network logs lack a process ID, the agent cannot definitively
    link the interpreter to the proxy traffic, resulting in an unavailable verdict.
  stage: c2-multi-hop-proxy
- id: encrypted-internal-traffic
  question: What commands were sent inside the proxy tunnel?
  requires: TLS inspection or JA3 fingerprinting
  risk: We can observe the proxy connection but not the actual C2 commands, making
    it difficult to assess the extent of the intrusion without host forensics.
  stage: c2-multi-hop-proxy
coverage:
- stage: initial-access-phishing
  status: covered
  steps:
  - phishing-interpreters
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - rare-proxy-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Phishing is the primary entry point for modern attacks, and multi-hop
    proxies are the standard for hiding adversary infrastructure. A negative result
    across the estate provides high confidence that these specific vectors are not
    being exploited.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access through a phishing lure and is
  communicating with a multi-hop proxy or ORB network to disguise command-and-control
  traffic.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Phishing and Multi-hop Proxy Detection
parameters:
  interpreters:
    default:
    - powershell.exe
    - pwsh.exe
    - cmd.exe
    - wscript.exe
    - cscript.exe
    description: Executables used to run malicious code after a phishing hit.
    from:
      kind: manual
      observed: '2026-08-03'
      ref: threat-intel
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-03'
      ref: threat-lead
    type: number
  parent_apps:
    default:
    - outlook.exe
    - winmail.exe
    - chrome.exe
    - msedge.exe
    - firefox.exe
    description: Common mail clients and browsers that serve as phishing vectors.
    from:
      kind: manual
      observed: '2026-08-03'
      ref: threat-intel
    type: list[string]
  proxy_ports:
    default:
    - '9001'
    - '9050'
    - '9150'
    - '1080'
    - '8080'
    description: Ports commonly used by Tor nodes and SOCKS proxies.
    from:
      kind: manual
      observed: '2026-08-03'
      ref: threat-intel
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty for the entire estate.
    from:
      kind: manual
      observed: '2026-08-03'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on user-facing workstations rather than backend servers. Prioritize
  hosts where browsers and mail clients are actively used.
references:
- name: "Elastic Security \u2014 SOC case management and detection rule history"
  url: https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history
- name: "MITRE ATT&CK \u2014 Multi-hop Proxy"
  url: https://attack.mitre.org/techniques/T1090/003/
related:
- hunt: dns-tunneling-detection
  reason: This hunt focuses on established proxy protocols on specific ports; DNS
    tunneling requires different logic over hb_dns_activity.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing Delivery
    observables:
    - Malicious links in HTTP requests
    - Creation of executable or script files from email clients
    - Suspicious child processes spawned by web browsers or mail applications
    - Navigation to known credential harvesting or malware delivery domains
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-hop Proxy C2
    observables:
    - Network connections to known Tor exit nodes
    - DNS queries for .onion domains
    - Traffic to virtual private servers (VPS) or IoT device ranges associated with
      ORB networks
    - Chained proxy communication patterns across multiple external IP addresses
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves an adversary gaining initial access through phishing
    messages containing malicious links or attachments. Once access is established,
    the attacker utilizes multi-hop proxy techniques, including Tor or operational
    relay box (ORB) networks, to obfuscate command-and-control traffic and hinder
    origin identification.
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


# Phishing and Multi-hop Proxy Detection

This hunt identifies the transition from initial access to obfuscated command-and-control by correlating suspicious process spawns from productivity applications with rare outbound network connections on common proxy ports. It targets the pattern where a user opens a malicious attachment or link that launches an interpreter, which then initiates a multi-hop connection to an external relay box or Tor node. The hunt fans out across process and network telemetry to verify if a single host shows both the delivery phase and the communication phase of an intrusion.

## workstation-scoping
<!-- Scope to workstations with productivity apps -->
Identify hosts in the estate that have common phishing vectors installed.

```sqlite target=endpoint role=scoping params=(parent_apps=parent_apps)
~~~yaml
expected: A list of hostnames. Silence suggests no managed productivity apps from
  the list are present on the surveyed hosts.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE instr(',' || '{{parent_apps}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## hunt-parallel
<!-- Correlate execution and network traffic -->
parallel:
- → phishing-interpreters
- → rare-proxy-connections
join: → triage-findings

## phishing-interpreters
<!-- Interpreters spawned by productivity apps -->
Detect suspicious child processes launched directly from mail clients or browsers.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, parent_apps=parent_apps, interpreters=interpreters, lookback_days=lookback_days)
~~~yaml
expected: Rows showing an interpreter being launched from a browser or email app.
  Silence means no such parent-child relationship was logged in this window.
reads:
- device_hostname
- process_name
- parent_process_name
- process_cmd_line
- time
- activity_id
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id = 1 AND instr(',' || '{{parent_apps}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-proxy-connections
<!-- Rare outbound proxy connections -->
Identify connections on known proxy ports that are rare across the fleet.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, proxy_ports=proxy_ports, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A connection to a proxy port involving a small number of hosts. Silence
  suggests no such connections or that the activity is fleet-wide.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, MIN(time) AS first_seen, COUNT(*) AS connections FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND state_kind = 'log' AND instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name HAVING COUNT(DISTINCT device_hostname) <= 5
```

## triage-findings
<!-- Evaluate phishing and proxy correlation -->
```agent target=hunter
cite: required
context:
- phishing-interpreters
- rare-proxy-connections
max_iterations: 3
objective: Determine whether the phishing leads and rare proxy connections together
  indicate a malicious intrusion on any single host.
success_criteria: A verdict of malicious | suspicious | benign for every host found
  in the queries.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensics-task
unavailable: → forensics-task (blind_spot: no-process-to-network-correlation)
else: → forensics-task

## isolate-endpoint
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate the identified interpreter process.
```
→ forensics-task

## forensics-task
<!-- Perform forensic review -->
```manual target=analyst
Review the process command lines for encoded strings and inspect the user's email for the original phishing lure.
```
→ close-out-task

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document any new C2 IPs or domains and determine if the scoping parameters need refinement.
```
→ end
