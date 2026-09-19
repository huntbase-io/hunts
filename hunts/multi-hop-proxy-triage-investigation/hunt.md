---
analysis: 'This hunt applies the agentic Soc triage methodology: it doesn''t just
  alert on a domain, it gathers auth history, rare process parents, and cloud metadata
  to provide the narrative required for automated triage.'
blind_spots:
- id: limited-endpoint-visibility
  owner: Endpoint Security
  question: Does the tunneling binary exist on hosts not currently reporting telemetry?
  remediation: Audit agent health across the VPC.
  requires: Complete endpoint coverage (hb_process_activity)
  risk: A tunnel could be established on an unmanaged host and used as a jump box.
- id: ip-only-tunneling
  owner: Network Engineering
  question: Are there active tunnels to IPs that bypassed DNS?
  remediation: Implement flow log analysis for high-entropy outbound connections.
  requires: hb_network_connection with destination reputation
  risk: Direct IP connections for Tor entry nodes skip the DNS scoping step entirely.
  stage: multi-hop-proxy-dns-activity
coverage:
- stage: execution-via-noisy-processes
  status: covered
  steps:
  - rare-process-lineage
- stage: authentication-history-review
  status: covered
  steps:
  - recent-auth-history
- stage: multi-hop-proxy-dns-activity
  status: covered
  steps:
  - proxy-dns-scoping
- stage: multi-hop-proxy-network-connection
  status: covered
  steps:
  - proxy-network-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Multi-hop proxies are the primary method for persistent C2 obfuscation.
    Detecting them through behavioral DNS and process ancestry is critical for cloud
    hygiene.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies or tunneling software (like Tor
  or Ngrok) to obfuscate command-and-control traffic, often originating from a recently
  compromised user session or a developer environment.
labels:
- hunt
- attack.t1090.003
- attack.t1078
- attack.t1059.001
name: Multi-hop Proxy Triage and Investigation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for baseline and behavior.
    type: number
  noisy_processes:
    default:
    - bash
    - sh
    - zsh
    - cmd.exe
    - powershell.exe
    - code.exe
    - pycharm
    - git
    - gcc
    - make
    - docker
    - systemd
    - svchost.exe
    description: Noisy processes to filter out of initial ancestry analysis.
    from:
      kind: article
      observed: '2026-07-27'
      ref: elastic-security-labs
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to focus on; leave empty to use the results of the
      DNS scoping step.
    type: list[host]
  tunnel_domains:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - tunnel.sa.ngrok.com
    - hiddenservice.net
    - onion.ca
    - onion.cab
    - onion.casa
    - onion.city
    - onion.direct
    description: Known tunnel and proxy domains from research.
    from:
      kind: article
      observed: '2026-07-27'
      ref: elastic-security-labs
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: We focus on hosts resolving known proxy domains or exhibiting DNS tunneling
  patterns. This scope is then used to pivot into external authentication and process
  lineages. Special attention is given to cloud instances (AWS) where multi-hop proxies
  indicate C2.
references:
- name: 'Inside Elastic InfoSec''s agentic SOC: How we cut AI agent LLM calls by 60%'
  url: https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale
related:
- hunt: unauthorized-vpn-usage
  reason: Commercial VPNs use similar obfuscation but different process signatures.
  relation: sibling
scenario:
  stages:
  - name: Execution via Noisy Processes
    observables:
    - shells
    - IDEs
    - system daemons
    - build tools
    - Ancestry traces on high-event processes
    slug: execution-via-noisy-processes
    tactic: execution
    techniques:
    - T1059.001
  - name: Authentication History Review
    observables:
    - login history
    - Last 24 hours of authentication events
    slug: authentication-history-review
    tactic: credential-access
    techniques:
    - T1078
  - name: Multi-hop Proxy DNS Activity
    observables:
    - .onion
    - .hiddenservice.net
    - .onion.ca
    - .onion.cab
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    slug: multi-hop-proxy-dns-activity
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Multi-hop Proxy Network Connection
    observables:
    - TCP connections to Ngrok tunnel endpoints
    - Outbound traffic to Tor relay nodes
    slug: multi-hop-proxy-network-connection
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves adversaries utilizing multi-hop proxies and tunneling
    services to obfuscate command-and-control traffic, often preceded by the execution
    of shell commands or developer tools. Detection and triage focus on analyzing
    process ancestry for noisy shells, reviewing authentication history for anomalous
    logins, and identifying network/DNS activity related to proxy infrastructure.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  aws:
    category: siem
    huntbase:
      product: aws
    name: aws
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


# Multi-hop Proxy Triage and Investigation

This hunt identifies potential multi-hop proxy usage by combining network, DNS, and authentication telemetry. It mirrors the triage methodology used by AI agents at Elastic, which involves identifying suspicious proxy-related DNS lookups, reviewing the last 24 hours of authentication history on affected hosts (focusing on external source IPs), and analyzing process ancestry while filtering out high-frequency 'noise' processes. By stacking rare processes on hosts with tunnel-related activity, we can isolate the point of compromise or unauthorized tool usage.

## proxy-dns-scoping
<!-- Identify hosts querying proxy domains -->
Find hosts that have recently resolved known tunneling domains or exhibit patterns of DNS tunneling (high-frequency CNAME/TXT).

```sqlite target=endpoint role=scoping params=(tunnel_domains=tunnel_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence indicates no traffic to these specific domains
  or unusual DNS lengths in the window.
reads:
- device_hostname
- query_hostname
- query_type
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE (instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%' OR (query_type IN ('TXT', 'CNAME') AND length(query_hostname) > 64)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-streams
<!-- Parallel Triage Streams -->
parallel:
- → recent-auth-history
- → rare-process-lineage
- → cloud-instance-context
- → proxy-network-connections
join: → agent-triage

## recent-auth-history
<!-- Review authentication history (External IPs) -->
Identify successful logons from non-RFC1918 IPs that occurred shortly before the proxy activity.

```sqlite target=identity role=enrichment params=(scope_hosts=scope_hosts)
~~~yaml
expected: Logon events from external sources. These indicate the entry point for the
  session establishing the proxy.
reads:
- activity_name
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_name AS device_hostname, actor_user_name, src_endpoint_ip, activity_name, auth_protocol, time FROM hb_auth_signin WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND status_id = 1 AND NOT (src_endpoint_ip LIKE '10.%' OR src_endpoint_ip LIKE '192.168.%' OR src_endpoint_ip LIKE '172.1[6-9].%' OR src_endpoint_ip LIKE '172.2[0-9].%' OR src_endpoint_ip LIKE '172.3[0-1].%' OR src_endpoint_ip LIKE '127.%' OR src_endpoint_ip LIKE '169.254.%') AND time >= datetime('now', '-1 days') ORDER BY time DESC
```

## rare-process-lineage
<!-- Rare processes and ancestry -->
Find rare binaries while filtering noise, including parent context to distinguish developer use from exploits.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, noisy_processes=noisy_processes, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries (ngrok, tor, cobalt strike) and their parents (e.g., w3wp.exe
  indicating a web exploit vs bash for a developer).
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- parent_process_cmd_line
- parent_process_name
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_path, process_name, process_cmd_line, parent_process_name, parent_process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND NOT (instr(',' || '{{noisy_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4, 5 HAVING host_count <= 3 ORDER BY host_count ASC
```

## cloud-instance-context
<!-- Cloud instance metadata -->
Filter EC2 metadata to the affected hosts to identify sensitive or public-facing infrastructure roles.

```sqlite target=aws role=enrichment params=(scope_hosts=scope_hosts)
~~~yaml
expected: Metadata about specific AWS instances being investigated.
reads:
- architecture
- arn
- iam_instance_profile_arn
- image_id
- instance_id
- instance_state
silence: not_evidence_of_absence
source: aws_ec2_instance
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT instance_id, arn, instance_state, architecture, image_id, iam_instance_profile_arn FROM aws_ec2_instance WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || instance_id || ',') > 0)
```

## proxy-network-connections
<!-- Outbound proxy network traffic -->
Identify network connections to common multi-hop proxy or Tor ports from the scoped hosts.

```sqlite target=network role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct TCP connections to known proxy infrastructure, providing evidence
  of the tunnel itself.
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
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (dst_endpoint_port IN (9001, 9030, 443) AND direction = 'outbound') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Evaluate proxy and tunneling activity -->
```agent target=hunter
cite: required
context:
- proxy-dns-scoping
- recent-auth-history
- rare-process-lineage
- cloud-instance-context
- proxy-network-connections
max_iterations: 5
objective: Review DNS hits, rare processes (noting parents), outbound connections,
  and authentication history per host to determine if the multi-hop proxy usage is
  malicious (C2), suspicious (unauthorized tool), or benign (developer testing).
success_criteria: A host-by-host verdict (malicious | suspicious | benign) citing
  specific process paths, parent relationships, and external authentication anomalies.
tools:
- aws
- endpoint
- identity
- network
```

## verdict-routing
<!-- Route on verdict -->
if~: "The triage verdict is malicious or suspicious for at least one host, citing a rare tunneling process or unexplained external logon." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-endpoint-visibility)
else: → close-out

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host to prevent further exfiltration. Revoke sessions for users with anomalous external logons.
```
→ analyst-review

## analyst-review
<!-- Manual investigation and validation -->
```manual target=analyst
Review the agent's findings. Check if the 'rare process' is a known internal tool. Contact the user regarding the external logon activity.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Document the negative result. Update tunnel domain lists if false positives are found.
```
→ end
