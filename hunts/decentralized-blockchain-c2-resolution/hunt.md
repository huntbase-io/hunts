---
analysis: A static rule for blockchain domains triggers too many false positives from
  developer activity. This hunt uses multi-surface correlation (DNS -> HTTP -> Network)
  and a temporal constraint to isolate the automated resolution-to-beaconing sequence.
blind_spots:
- id: incomplete-rpc-telemetry
  question: Which specific JSON-RPC methods (eth_call, getSignaturesForAddress) were
    called?
  requires: hb_http_activity with full JSON-RPC body capture
  risk: Without the POST body, we cannot distinguish between a legitimate node status
    check and a specific coordinate retrieval call.
  stage: c2-blockchain-dead-drop-resolution
- id: tls-encrypted-rpc-payloads
  question: Is the content of the RPC call an encrypted C2 URL?
  requires: TLS inspection at the gateway or endpoint
  risk: HTTPS to standard providers like Infura masks the malicious payload from traditional
    NIDS/DPI.
  stage: c2-blockchain-dead-drop-resolution
coverage:
- stage: c2-blockchain-dead-drop-resolution
  status: covered
  steps:
  - dns-to-blockchain-rpc
  - http-rpc-post-activity
- stage: c2-primary-beaconing
  status: covered
  steps:
  - rare-outbound-beacons
- reason: Belongs to another part of the 'The challenge of defending against bulletproof
    dead drops on public blockchains' series.
  stage: initial-access-exploit
  status: out_of_scope
- reason: Belongs to another part of the 'The challenge of defending against bulletproof
    dead drops on public blockchains' series.
  stage: execution-overlord-rat
  status: out_of_scope
- reason: Belongs to another part of the 'The challenge of defending against bulletproof
    dead drops on public blockchains' series.
  stage: impact-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Blockchain dead-drops remove the single point of failure (DNS/Hosting)
    that defenders traditionally rely on for takedowns. A negative result confirms
    this resilient channel is not currently active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using public blockchain ledgers as dead-drop resolvers
  for C2 configuration, identified by outbound RPC calls to node providers followed
  by rare network beaconing to resolved endpoints.
labels:
- hunt
- attack.t1090.004
- attack.t1102.001
- command and control
- execution
- impact
- initial access
name: Decentralized Blockchain C2 Resolution
parameters:
  lookback_days:
    default: '14'
    description: History in days to examine for RPC activity and subsequent beaconing.
    type: number
  rpc_providers:
    default:
    - infura.io
    - quicnode.pro
    - tatum.io
    - mainnet.solana.com
    - api.mainnet-beta.solana.com
    - ethereum.publicnode.com
    description: Public blockchain RPC and node provider domains used as dead drops.
    from:
      kind: article
      observed: '2026-11-18'
      ref: https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/
    type: list[domain]
  scope_hosts:
    default: []
    description: Paste the hostnames identified in the lead query here to focus the
      subsequent analysis.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all hosts interacting with public blockchain RPC providers.
  Widen the search if initial results are concentrated in developer or research departments
  where such traffic is baseline.
references:
- name: The challenge of defending against bulletproof dead drops on public blockchains
  url: https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/
related:
- hunt: initial-access-via-web-exploitation
  reason: This hunt focuses on the C2 resilience phase; initial entry into the environment
    via vulnerability exploitation is a separate hypothesis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Public-Facing Application
    observables:
    - anomalous web server errors
    - unexpected inbound traffic to public-facing web applications
    slug: initial-access-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Overlord RAT Execution
    observables:
    - Overlord RAT binary
    - in-memory decryption of C2 configurations
    - lightweight decrypter process activity
    slug: execution-overlord-rat
    tactic: execution
  - name: Blockchain RPC Dead-Drop Resolution
    observables:
    - outbound JSON-RPC queries to Infura (infura.io)
    - outbound JSON-RPC queries to QuickNode (quicnode.pro)
    - outbound JSON-RPC queries to Tatum (tatum.io)
    - 'JSON-RPC methods: eth_call, getTransaction, getSignaturesForAddress'
    - base-encoded data in HTTP POST request bodies
    - DNS resolution for public blockchain node providers
    slug: c2-blockchain-dead-drop-resolution
    tactic: command-and-control
    techniques:
    - T1090.004
  - name: C2 Infrastructure Beaconing
    observables:
    - outbound connections to dynamically resolved C2 IP addresses
    - beaconing traffic to previously unknown domains
    slug: c2-primary-beaconing
    tactic: command-and-control
  - name: Data Encrypted for Impact
    observables:
    - rapid file modification and encryption
    - ransomware notes on system drives
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: The threat actor UAT-12643 utilizes the Overlord RAT to retrieve encrypted
    command-and-control configurations from public blockchains including Bitcoin,
    Ethereum, and Solana. By using JSON-RPC queries to public node providers like
    Infura and QuickNode, the malware resolves its C2 infrastructure through immutable
    ledger data such as Solana Memo transactions or Ethereum smart contracts.
series:
  index: 1
  slug: the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains
  title: The challenge of defending against bulletproof dead drops on public blockchains
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


# Decentralized Blockchain C2 Resolution

This hunt identifies attempts to resolve command-and-control infrastructure using Web3 nodes. It looks for DNS and HTTP traffic directed at public blockchain RPC providers that correlate with rare outbound network connections. By abusing immutable ledgers like Solana and Ethereum, attackers bypass traditional domain sinkholing. The hunt baselines typical developer RPC usage and highlights hosts that reach out to the blockchain and then initiate unique outbound sessions, often targeting non-standard ports within a narrow temporal window.

## dns-to-blockchain-rpc
<!-- DNS lookups to blockchain RPC nodes -->
Identify hosts and processes resolving known blockchain RPC provider domains as a lead for potential dead-drop resolution.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, rpc_providers=rpc_providers)
~~~yaml
expected: Hosts and specific processes resolving blockchain domains. Legitimate developer
  activity will show high volume across multiple distinct providers; malicious resolution
  is typically low volume and tied to unusual processes.
reads:
- device_hostname
- pid
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, pid, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_lookup FROM hb_dns_activity WHERE (instr(',' || '{{rpc_providers}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, pid, query_hostname
```

## corroborate-activity
<!-- Corroborate RPC traffic and beaconing -->
parallel:
- → http-rpc-post-activity
- → rare-outbound-beacons
join: → triage-rpc-behavior

## http-rpc-post-activity
<!-- HTTP POST activity to RPC endpoints -->
Focus on the HTTP POST requests that carry JSON-RPC payloads, which are required for querying specific blockchain data like transactions or logs.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, rpc_providers=rpc_providers, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to RPC providers from the scoping hosts. Analysts should look
  for unusual User-Agents or paths that do not match standard browser or developer
  tool patterns.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{rpc_providers}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-beacons
<!-- Rare outbound connections from RPC hosts -->
Identify non-standard outbound connections occurring on hosts that have also performed blockchain RPC lookups, prioritizing non-standard ports.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A connection to a rare external IP address on a non-standard port. Correlation
  is strongest when this connection follows an RPC lookup by the same host.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- direction
- disposition
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND disposition = 'Allowed' AND (dst_endpoint_port NOT IN (80, 443, 53)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port, process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-rpc-behavior
<!-- Evaluate blockchain-to-C2 sequence -->
```agent target=hunter
cite: required
context:
- dns-to-blockchain-rpc
- http-rpc-post-activity
- rare-outbound-beacons
max_iterations: 6
objective: Determine if a host is resolving C2 coordinates via blockchain. Specifically
  look for rare outbound network connections that occur shortly after (within 5-10
  minutes) the identified RPC activity on the same host. Evaluate if the processes
  involved in both steps are consistent or related.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  specific correlated RPC and beaconing rows.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "The triage-rpc-behavior verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-rpc-telemetry)
else: → close-out

## isolate-infected-host
<!-- Isolate host and capture memory -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture a full memory dump before rebooting or shutting down to preserve in-memory decrypters and the resolved C2 coordinates.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the process tree for the processes identified in the RPC lookups and outbound connections. Inspect any available HTTP payload data for Base64 or hex-encoded C2 strings. Validate if the activity matches the Overlord RAT's Solana-based dead-drop pattern.
```
→ close-out

## close-out
<!-- Hunt closure and tuning -->
```manual target=analyst
Document all confirmed malicious hosts and the resolved C2 IP addresses. If legitimate developer workstations were flagged, record their hostnames and typical RPC patterns for inclusion in the scope_hosts exclusion list for future runs.
```
→ end
