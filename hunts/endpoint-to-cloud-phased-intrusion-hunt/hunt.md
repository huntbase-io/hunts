---
analysis: A single detection rule may fire on a proxy domain, but it cannot weigh
  whether that domain is linked to an anomalous cloud login from the same host's internal
  IP. This phased hunt uses two layers of agentic triage to correlate identity, network,
  and process evidence.
blind_spots:
- id: proxy-payload-encryption
  owner: Network Security
  question: what commands were sent over the proxy connection
  remediation: Implement TLS interception for administrative egress traffic.
  requires: TLS decryption at the gateway
  risk: We identify the connection to the proxy but cannot see the adversary's intent
    or the stage-two payload content.
  stage: multi-hop-proxy-c2
- id: macos-file-visibility
  owner: IT Operations
  question: what local files were modified by the forensic process on macOS
  remediation: Enable full file system monitoring for macOS agents.
  requires: hb_file_activity for macOS
  risk: The absence of macOS file telemetry prevents the hunt from confirming local
    data staging or credential harvesting on non-Windows endpoints.
  stage: endpoint-alert-forensics
coverage:
- stage: endpoint-alert-forensics
  status: covered
  steps:
  - anomalous-process-forensics
- stage: lateral-movement-discovery
  status: covered
  steps:
  - network-lateral-and-proxy-check
- stage: cloud-identity-pivot
  status: covered
  steps:
  - cloud-auth-check
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - dns-proxy-c2-check
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries bypass perimeter controls using ORB networks and multi-hop
    proxies. This phased hunt correlates identity pivots and network obfuscation back
    to an endpoint beachhead, a cross-surface task that static rules cannot achieve.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary establishes a beachhead on an endpoint, moves laterally to
  obtain administrative access, and pivots to cloud services while maintaining C2
  via a multi-hop proxy.
labels:
- hunt
- attack.t1204
- attack.t1021
- attack.t1078
- attack.t1090.003
name: Endpoint-to-Cloud Phased Intrusion Hunt
parameters:
  admin_ports:
    default:
    - '22'
    - '445'
    - '3389'
    - '5985'
    - '5986'
    description: Ports commonly used for administrative lateral movement.
    from:
      kind: manual
      observed: '2025-02-18'
      ref: standard-admin-ports
    type: list[string]
  c2_domains:
    default:
    - tokens.input
    - tokens.output
    description: Suspected proxy or ORB domains observed in multi-hop campaigns.
    from:
      kind: article
      observed: '2026-07-24'
      ref: elastic-security-labs
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2025-02-18'
      ref: default-retention
    type: number
  proxy_ports:
    default:
    - '9001'
    - '9030'
    - '1080'
    - '8080'
    description: Egress ports associated with Tor relays and common proxy services.
    from:
      kind: manual
      observed: '2025-02-18'
      ref: threat-intelligence
    type: list[string]
  scope_hosts:
    default: []
    description: Focus on these hostnames; leave empty for a fleet-wide hunt.
    from:
      kind: manual
      observed: '2025-02-18'
      ref: analyst-input
    type: list[host]
  suspected_src_ips:
    default: []
    description: Filter cloud sign-ins by these source IPs; usually filled by the
      analyst from the early triage agent results.
    from:
      kind: manual
      observed: '2025-02-18'
      ref: agent-output-pivot
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value Windows and macOS assets in administrative zones first.
  Expand to all developer endpoints if proxy activity is detected.
references:
- name: "Inside Elastic InfoSec's agentic SOC: When to inline your agent's skills\
    \ for a 5\xD7 cost reduction"
  url: https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture
related:
- hunt: tor-egress-monitoring-hunt
  reason: This hunt focuses on the internal path to the proxy, whereas the Tor hunt
    focuses strictly on egress to public exit nodes.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Windows and macOS Endpoint Intrusion
    observables:
    - Windows endpoint alert
    - macOS forensic artifacts
    - process ancestry tracing
    slug: endpoint-alert-forensics
    tactic: execution
    techniques:
    - T1204
  - name: Lateral Movement Identification
    observables:
    - lateral movement indicators
    slug: lateral-movement-discovery
    tactic: lateral-movement
    techniques:
    - T1021
  - name: Identity and Cloud Pivot
    observables:
    - Okta investigation logs
    - AWS CloudTrail events
    slug: cloud-identity-pivot
    tactic: credential-access
    techniques:
    - T1078
  - name: Multi-hop Proxy Command and Control
    observables:
    - multi-hop proxy traffic
    - Tor onion routing
    - operational relay box (ORB) networks
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An intrusion campaign identified through endpoint alerts on Windows and
    macOS systems, revealing lateral movement and identity pivots involving Okta and
    AWS resources. The attackers employ multi-hop proxies and onion routing to mask
    their command-and-control communications.
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


# Endpoint-to-Cloud Phased Intrusion Hunt

This hunt implements a cost-efficient specialized agent workflow to identify long-chain intrusions. It begins by scoping the host environment and identifying early forensic anomalies and lateral movement. A second phase investigates follow-on identity pivots and command-and-control obfuscation through multi-hop proxies and ORB networks. By phasing the hunt, the agentic triage focuses only on high-confidence leads that connect host compromise to cloud exposure.

## scope-active-hosts
<!-- Establish Active Host Scope -->
Find the recently active host fleet to provide a target list for forensic and network analysis.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of active hosts within the lookback window. Silence means the scope
  filter excludes all reporting hosts.
reads:
- hostname
- device_uid
- platform
- os_version
- last_seen
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname, device_uid, platform, os_version, last_seen FROM hb_devices WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0)
```

## early-investigation
<!-- Parallel Beachhead and Lateral Check -->
parallel:
- → anomalous-process-forensics
- → network-lateral-and-proxy-check
join: → early-triage-agent

## anomalous-process-forensics
<!-- Detect Anomalous Process Execution -->
Find processes running from temporary paths or in-memory.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process with no file on disk or a binary executing from a user-writable
  path. Silence suggests an absence of simple fileless execution.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- parent_process_name
- on_disk
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, parent_process_name, on_disk, user_name, time FROM hb_process_activity WHERE (on_disk = 0 OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\users\public\%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## network-lateral-and-proxy-check
<!-- Admin and Proxy Egress Stack Counting -->
Stack outbound connections by port to find rare administrative or proxy egress.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, admin_ports=admin_ports, proxy_ports=proxy_ports)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound connections on administrative or proxy ports. Rarity identifies
  single-host outliers amidst normal network traffic.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
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
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{admin_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 OR instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, process_name HAVING hosts <= 3
```

## early-triage-agent
<!-- Early Intrusion Triage -->
```agent target=hunter
cite: required
context:
- anomalous-process-forensics
- network-lateral-and-proxy-check
max_iterations: 4
objective: Analyze the anomalous process results and lateral movement patterns to
  decide if a host is currently a beachhead. Explicitly extract and output the source
  IP addresses of hosts with suspicious activity to filter the next phase.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  process and network rows.
tools:
- endpoint
- identity
- network
```

## follow-on-pivot-investigation
<!-- Follow-on Identity and C2 Investigation -->
parallel:
- → cloud-auth-check
- → dns-proxy-c2-check
join: → full-chain-analysis-agent

## cloud-auth-check
<!-- Cloud Identity Success from Beachheads -->
Filter sign-in events by the IP addresses identified in the early-triage-agent step.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, suspected_src_ips=suspected_src_ips)
~~~yaml
expected: Successful authentications correlated with suspected compromised source
  IPs. Silence means no cloud logins were recorded for the identified hosts.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, auth_protocol, time FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{suspected_src_ips}}' = '' OR instr(',' || '{{suspected_src_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0)
```

## dns-proxy-c2-check
<!-- Proxy and ORB Domain Lookups -->
Detect DNS resolutions to known proxy domains or Tor gateways.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
expected: Any lookup to an ORB domain or Tor gateway.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname, process_name
```

## full-chain-analysis-agent
<!-- Full Chain Synthesis Agent -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- cloud-auth-check
- dns-proxy-c2-check
max_iterations: 6
objective: Review the early-triage-agent verdict and combine it with cloud-auth-check
  and dns-proxy-c2-check results to confirm a high-confidence intrusion.
success_criteria: A definitive verdict of malicious for hosts that show both a beachhead
  signature and follow-on pivots.
tools:
- endpoint
- identity
- network
```

## final-routing-decision
<!-- Routing Decision for Intrusion Chain -->
if~: "the full-chain-analysis-agent confirms a malicious host linked to cloud pivots or multi-hop proxy C2" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-incident-review
unavailable: → analyst-incident-review (blind_spot: proxy-payload-encryption)
else: → close-out-negative

## isolate-compromised-host
<!-- Isolate Compromised Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified by the triage agent as the beachhead.
```
→ analyst-incident-review

## analyst-incident-review
<!-- Analyst Intrusion Verification -->
```manual target=analyst
Verify the agent's synthesis. Confirm that the cloud sign-ins originated from the suspicious host and correlate the proxy DNS queries with the observed process ancestry. Record findings for IR.
```
→ end

## close-out-negative
<!-- Hunt Closure -->
```manual target=analyst
Document that no full intrusion chain was identified for the scoped hosts. Schedule a follow-on hunt if suspicious but incomplete signals were found.
```
→ end
