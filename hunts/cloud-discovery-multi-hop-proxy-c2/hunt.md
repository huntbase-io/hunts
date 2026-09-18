---
analysis: 'While rules exist for static indicators like ''tor'', this hunt looks for
  behavioral signals: sustained outbound data on proxy-specific ports and correlates
  them with cloud authentication pivots that a single rule cannot join.'
blind_spots:
- id: cloud-logging-gap
  question: What specific cloud resources were enumerated after authentication?
  requires: AWS CloudTrail data events (e.g. S3 list, IAM policy read)
  risk: hb_auth_signin only captures the sign-in; the actual 'discovery' (enumerating
    resources) occurs in control-plane logs not visible on these surfaces.
  stage: cloud-infrastructure-discovery
- id: network-encryption-blindness
  question: Is the content of the outbound traffic malicious or just encrypted noise?
  requires: TLS inspection or proxy-level logging
  risk: We identify proxy ports and volume, but cannot see the tunneled payload, allowing
    custom C2 to remain undetected if it uses common ports like 443.
  stage: multi-hop-proxy-c2
coverage:
- stage: cloud-infrastructure-discovery
  status: covered
  steps:
  - scoping-aws-instances
  - cloud-auth-anomalies
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - proxy-process-networking
  - rare-proxy-dns
- reason: "Belongs to another part of the \"Inside Elastic InfoSec's agentic SOC:\
    \ When to inline your agent's skills for a 5\xD7 cost reduction\" series."
  stage: endpoint-forensics-and-execution
  status: out_of_scope
- reason: "Belongs to another part of the \"Inside Elastic InfoSec's agentic SOC:\
    \ When to inline your agent's skills for a 5\xD7 cost reduction\" series."
  stage: lateral-movement-indicators
  status: out_of_scope
- reason: "Belongs to another part of the \"Inside Elastic InfoSec's agentic SOC:\
    \ When to inline your agent's skills for a 5\xD7 cost reduction\" series."
  stage: identity-provider-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromised cloud assets are frequently used as operational relay
    boxes (ORBs). Detecting this behavior protects both the cloud environment from
    resource discovery and the wider internet from being scanned by your infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised cloud instances to perform resource
  discovery while masking their command-and-control traffic through multi-hop proxies
  and long-lived outbound tunnels.
labels:
- hunt
- attack.t1090.003
- attack.t1087
- attack.t1580
name: Cloud Discovery and Multi-hop Proxy C2
parameters:
  c2_domains:
    default:
    - tokens.input
    - tokens.output
    description: C2 domains extracted from the agentic SOC research.
    from:
      kind: article
      observed: '2026-07-24'
      ref: elastic-security-labs-agentic-soc
    type: list[domain]
  lookback_days:
    default: '14'
    description: Number of days of history to examine.
    type: number
  proxy_ips:
    default: []
    description: IP addresses identified in proxy networking steps to pivot into authentication
      logs.
    from:
      kind: article
      observed: '2026-07-24'
      ref: https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture
    type: list[ip]
  proxy_ports:
    default:
    - '9001'
    - '9050'
    - '9150'
    - '1080'
    - '8080'
    description: Common ports for Tor, SOCKS, and other multi-hop proxy tunnels.
    type: list[string]
  scope_hosts:
    default: []
    description: Hostnames of the AWS instances to focus on; if empty, the whole estate
      is searched.
    type: list[host]
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
rationale: Target public-facing AWS instances first, as they are most likely to be
  used as ingress/egress points for multi-hop proxies.
references:
- name: "Inside Elastic InfoSec's agentic SOC: When to inline your agent's skills\
    \ for a 5\xD7 cost reduction"
  url: https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture
related:
- hunt: endpoint-forensics-and-execution
  reason: This hunt focuses on network and cloud-plane signals; host-based execution
    of proxy binaries is handled separately.
  relation: out-of-scope-alternative
- hunt: cross-plane-breach-endpoint-identity
  relation: follows
scenario:
  stages:
  - name: Endpoint Execution and Forensics
    observables:
    - process ancestry
    - Windows endpoint alerts
    - macOS forensics data
    slug: endpoint-forensics-and-execution
    tactic: execution
    techniques:
    - T1059
  - name: Lateral Movement Discovery
    observables:
    - lateral movement indicators
    slug: lateral-movement-indicators
    tactic: lateral-movement
    techniques:
    - T1021
  - name: Identity Provider Triage
    observables:
    - Okta sign-in anomalies
    - unauthorized session access
    slug: identity-provider-exploitation
    tactic: credential-access
    techniques:
    - T1078
  - name: Cloud Resource Discovery
    observables:
    - AWS CloudTrail logs
    - EC2 instance modifications
    slug: cloud-infrastructure-discovery
    tactic: discovery
    techniques:
    - T1087
    - T1580
  - name: Multi-hop Proxy C2
    observables:
    - Tor onion addresses
    - multi-hop proxy traffic
    - ngrok tunnel connections
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves initial compromise on Windows and macOS endpoints,
    followed by lateral movement and the subsequent exploitation of Okta identity
    and AWS cloud environments. Threat actors utilize multi-hop proxies and the Tor
    network for command and control to obfuscate their activities.
series:
  index: 2
  slug: inside-elastic-infosec-s-agentic-soc-when-to-inline-your-agent-s-skills-for-a-5-cost-reduction
  title: "Inside Elastic InfoSec's agentic SOC: When to inline your agent's skills\
    \ for a 5\xD7 cost reduction"
  total: 2
severity: medium
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


# Cloud Discovery and Multi-hop Proxy C2

This hunt identifies cloud infrastructure being repurposed as proxy nodes for command-and-control. It begins by identifying active AWS EC2 instances and then searches for behavioral network signals—specifically high-volume, long-lived outbound connections on common proxy ports—emanating from those scoped hosts. Finally, it correlates these network anomalies with AWS authentication events to identify potential cloud control-plane discovery or enumeration.

## scoping-aws-instances
<!-- Identify active AWS cloud instances -->
Identify the running AWS infrastructure that could be leveraged for proxying or discovery.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames and IPs associated with active AWS instances. Silence
  suggests no AWS-managed devices are reporting.
reads:
- hostname
- ip_address
- device_uid
- cloud_account_uid
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, ip_address, device_uid, cloud_account_uid FROM hb_devices WHERE provider = 'aws' AND lifecycle_state = 'running' AND time >= datetime('now', '-1 day')
```

## proxy-behavior-parallel
<!-- Hunt for proxy and C2 indicators -->
parallel:
- → proxy-process-networking
- → rare-proxy-dns
join: → cloud-auth-anomalies

## proxy-process-networking
<!-- Behavioral analysis of long-lived proxy connections -->
Identify instances showing sustained outbound traffic on common proxy ports, indicating a tunnel or relay node.

```sqlite target=network role=detection-candidate params=(proxy_ports=proxy_ports, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: High-volume outbound connections to ports 9001/9050 etc. from scoped AWS
  instances. Rare counts suggest non-standard behavior.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- traffic_bytes
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, SUM(traffic_bytes) as total_bytes, COUNT(*) as flow_count FROM hb_network_connection WHERE (instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING total_bytes > 5000000 ORDER BY total_bytes DESC
```

## rare-proxy-dns
<!-- Stack-count rare C2 and proxy DNS resolutions -->
Identify hosts resolving known C2 domains or onion-routing domains that are rare in the environment.

```sqlite target=endpoint role=baseline params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS resolutions for onion domains or the report's C2 domains occurring on
  3 or fewer hosts.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 4
reads:
- query_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%' OR query_hostname LIKE '%.hiddenservice.net%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## cloud-auth-anomalies
<!-- Correlated cloud authentication anomalies -->
Corroborate network proxy signals by searching for AWS authentication attempts originating from the suspected proxy IPs.

```sqlite target=identity role=enrichment params=(proxy_ips=proxy_ips, lookback_days=lookback_days)
~~~yaml
expected: AWS authentication events (failed or successful) where the source IP matches
  an IP showing behavioral proxy signals.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, status, time FROM hb_auth_signin WHERE provider = 'aws' AND ('{{proxy_ips}}' = '' OR instr(',' || '{{proxy_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-agent
<!-- Triage cloud proxy and discovery -->
```agent target=hunter
cite: required
context:
- proxy-process-networking
- rare-proxy-dns
- cloud-auth-anomalies
max_iterations: 5
objective: Determine if any AWS instance identified in the scoping step exhibits both
  sustained outbound proxy-port traffic and suspicious cloud authentication patterns.
success_criteria: A verdict of malicious | suspicious | benign per host with evidence
  of port-based proxying and AWS discovery.
tools:
- endpoint
- identity
- network
```

## verdict-decision
<!-- Route on triage result -->
if~: "the triage verdict is malicious for an AWS instance showing proxy behavior and cloud auth anomalies" (confidence: high, judge=hunter)
then: → isolate-instance
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-logging-gap)
else: → close-out

## isolate-instance
<!-- Isolate AWS instance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified EC2 instance and revoke the AWS credentials associated with the anomalous authentication events.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the high-volume network flows and AWS auth logs. Confirm if the proxy was established for developer utility or malicious C2 masking.
```
→ end

## close-out
<!-- Close hunt -->
```manual target=analyst
Record the absence of malicious proxy behavior. Note any benign proxy ports for future exclusion.
```
→ end
