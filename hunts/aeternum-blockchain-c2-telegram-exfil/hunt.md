---
analysis: "A simple detection rule for Telegram or Polygon RPC use is too noisy for\
  \ production. This hunt works by finding the intersection of multiple weak signals:\
  \ DNS to specific nodes, POST requests, custom User-Agents, clean tool cover files\
  \ (putty.exe), and the load of a specific malicious module\u2014all attributed back\
  \ to the initiating process via network connection context."
blind_spots:
- id: no-http-body-visibility
  owner: Network Engineering
  question: Does the HTTP POST request contain the smart contract method 0xb68d1809?
  remediation: Deploy TLS inspection for public RPC endpoints to log HTTP request
    bodies.
  requires: TLS inspection on network edges
  risk: Legitimate use of the Polygon blockchain (wallets, development) will generate
    POST requests to the same endpoints, potentially creating false positives if the
    POST body is not visible.
  stage: blockchain-c2-polling
- id: github-obfuscation
  owner: SOC Manager
  question: Is the payload from GitHub encrypted or renamed?
  remediation: Monitor for any binary downloads from raw.githubusercontent.com originating
    from user-profile paths.
  requires: hb_http_activity responses
  risk: If the attacker changes the filename (e.g. from DotNetZip.dll to a random
    name), the file and module-based detection will fail.
  stage: github-payload-download
coverage:
- stage: blockchain-c2-polling
  status: covered
  steps:
  - scoping-dns-resolutions
  - blockchain-rpc-http-activity
  - network-connection-attribution
- stage: github-payload-download
  status: covered
  steps:
  - payload-process-activity
  - payload-module-activity
- stage: telegram-recon-exfiltration
  status: covered
  steps:
  - telegram-exfiltration-http
  - network-connection-attribution
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: initial-execution-unpacking
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: persistence-startup-link
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: secondary-malware-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Aeternum leverages decentralized blockchain infrastructure to make
    C2 takedowns impossible. A negative result confirms that the fleet is not communicating
    with these resilient C2 nodes using the known smart-contract polling protocol.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging decentralized blockchain RPC endpoints for
  C2 command retrieval and using the Telegram API with a custom User-Agent for reconnaissance
  exfiltration.
labels:
- hunt
- attack.t1102
- attack.t1102.002
- attack.t1105
- attack.t1041
- attack.t1082
name: Aeternum Blockchain C2 and Telegram Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-10'
      ref: standard-retention
    type: number
  rpc_domains:
    default:
    - polygon-mumbai-bor-rpc.publicnode.com
    description: Known Polygon RPC endpoints used for C2 polling.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum
    type: list[domain]
  scope_hosts:
    default: []
    description: Output of the scoping step; paste hostnames here to focus subsequent
      behavior queries.
    from:
      kind: manual
      ref: analyst-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on the DNS step first; paste the resulting hostnames into the 'scope_hosts'
  parameter before running the behavior queries to ensure proper programmatic flow.
references:
- name: "The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based C2 Operations"
  url: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
related:
- hunt: aeternum-loader-persistence
  reason: This hunt identifies the network-plane C2; a separate hunt examines the
    AppData persistence and Startup folder shortcuts.
  relation: follows
- hunt: aeternum-endpoint-execution-persistence
  relation: follows
scenario:
  stages:
  - name: Self-Unpacking and Core Execution
    observables:
    - Build.exe
    - wmiframework.exe
    - ZrvEsJQzWQ.exe
    - STAAAAAS.exe
    slug: initial-execution-unpacking
    tactic: execution
    techniques:
    - T1027.002
    - T1140
  - name: Persistence via Startup Shortcut
    observables:
    - AppData\Local
    - Wmi_Framework_APIKEY_wmsnet_*.lnk
    - Startup directory
    slug: persistence-startup-link
    tactic: persistence
    techniques:
    - T1547.001
  - name: Blockchain-Based C2 Retrieval
    observables:
    - polygon-mumbai-bor-rpc.publicnode.com
    - '0xb68d1809'
    - JSON-RPC over HTTP POST
    slug: blockchain-c2-polling
    tactic: command-and-control
    techniques:
    - T1102
  - name: Payload Retrieval from GitHub
    observables:
    - github.com
    - DotNetZip.dll
    - putty.exe
    slug: github-payload-download
    tactic: command-and-control
    techniques:
    - T1105
  - name: Reconnaissance and Telegram Exfiltration
    observables:
    - api.telegram.org
    - screenshot.png
    - SystemInfo Bot/2.0
    - 'chat_id: -4991861036'
    - /sendDocument
    slug: telegram-recon-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1102.002
    - T1082
  - name: Deployment of Secondary Payloads
    observables:
    - XBinderOutput_protected.exe
    - XWorm
    - XMRig
    slug: secondary-malware-deployment
    tactic: impact
    techniques:
    - T1496
    - T1489
  summary: Aeternum is a C++ botnet loader that uses the Polygon blockchain for decentralized
    command-and-control, retrieving encrypted instructions via smart contracts. The
    malware establishes persistence through startup shortcuts, downloads secondary
    payloads from GitHub, and exfiltrates system metadata and screenshots using the
    Telegram API.
series:
  index: 2
  slug: the-permanent-threat-analyzing-aeternum-s-blockchain-based-c2-operations-and-communications
  title: "The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based C2 Operations\
    \ and Communications"
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Aeternum Blockchain C2 and Telegram Exfiltration

This hunt identifies the network-plane activities of the Aeternum botnet. It focuses on identifying hosts communicating with Polygon blockchain RPC nodes via JSON-RPC POST requests to retrieve smart-contract based commands, as well as subsequent exfiltration to Telegram. It correlates these signals with the specific initiating processes and the presence of secondary payloads like DotNetZip.dll and putty.exe, providing the context necessary to distinguish botnet activity from legitimate blockchain or Telegram use.

## scoping-dns-resolutions
<!-- DNS lookups to C2 infrastructure -->
Identify hosts resolving known blockchain RPC nodes or Telegram API endpoints to establish a candidate pool for behavior analysis.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, rpc_domains=rpc_domains)
~~~yaml
expected: A list of hostnames and the specific infrastructure they are querying. This
  list should be used to populate the 'scope_hosts' parameter for the following steps.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_lookup FROM hb_dns_activity WHERE (instr(',' || '{{rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) = 'api.telegram.org') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## parallel-behavior-gathering
<!-- Gather cross-surface behavioral evidence -->
parallel:
- → blockchain-rpc-http-activity
- → telegram-exfiltration-http
- → payload-process-activity
- → payload-module-activity
- → network-connection-attribution
join: → triage-agent

## blockchain-rpc-http-activity
<!-- Blockchain RPC HTTP POST activity -->
Identify HTTP POST requests to Polygon RPC nodes, characteristic of smart-contract command polling.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, rpc_domains=rpc_domains, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to RPC nodes. These will be linked to processes by the agent
  using the src/dst IP and timestamp.
reads:
- device_hostname
- dst_endpoint_ip
- http_method
- src_endpoint_ip
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, src_endpoint_ip, dst_endpoint_ip, time FROM hb_http_activity WHERE instr(',' || '{{rpc_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## telegram-exfiltration-http
<!-- Telegram API exfiltration activity -->
Identify Telegram API interactions with the Aeternum-specific 'SystemInfo Bot' User-Agent and file-upload paths.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Exfiltration traffic to Telegram. The agent will use the IP and time to
  identify the initiating process.
reads:
- device_hostname
- dst_endpoint_ip
- src_endpoint_ip
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, src_endpoint_ip, dst_endpoint_ip, time FROM hb_http_activity WHERE LOWER(url_hostname) = 'api.telegram.org' AND (LOWER(user_agent) LIKE '%systeminfo bot%' OR LOWER(url_path) LIKE '%/senddocument%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## payload-process-activity
<!-- Execution of payload components -->
Detect the launch of putty.exe, which is downloaded as a legitimate cover or test file during the infection.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of putty.exe on the same hosts exhibiting the network signals.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%putty.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## payload-module-activity
<!-- Loading of malicious DLLs -->
Identify the load of DotNetZip.dll, the malicious component that performs exfiltration.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: DotNetZip.dll being loaded, typically into a process performing the exfiltration
  seen in earlier steps.
reads:
- device_hostname
- module_name
- module_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, module_name, module_path, process_name, time FROM hb_module_activity WHERE LOWER(module_name) = 'dotnetzip.dll' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-connection-attribution
<!-- Attributing network activity to processes -->
Extract the process_name and process_path for connections to C2 infrastructure to corroborate with the HTTP activity.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, rpc_domains=rpc_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Specific processes associated with the blockchain and Telegram connections.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_ip, process_name, process_path, time FROM hb_network_connection WHERE (instr(',' || '{{rpc_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR LOWER(dst_endpoint_hostname) = 'api.telegram.org') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze Aeternum evidence -->
```agent target=hunter
cite: required
context:
- scoping-dns-resolutions
- blockchain-rpc-http-activity
- telegram-exfiltration-http
- payload-process-activity
- payload-module-activity
- network-connection-attribution
max_iterations: 5
objective: Join the HTTP activity with the network connections to identify the process
  responsible for blockchain C2 and Telegram exfiltration. Verify if putty.exe or
  DotNetZip.dll are present on the same hosts. Provide a verdict per host.
success_criteria: A per-host assessment of malicious, suspicious, or benign, specifically
  naming the binary responsible for the C2 traffic.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route on botnet confirmation -->
if~: "the triage verdict is malicious for at least one host and identifies the initiating process" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-body-visibility)
else: → close-out

## isolate-infected-host
<!-- Isolate host and collect memory -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and perform a memory capture to attempt recovery of the smart-contract command payloads before the process is killed.
```
→ analyst-review

## analyst-review
<!-- Analyst validation and IR -->
```manual target=analyst
Review the correlated evidence. Confirm if the process identified by the agent matches the profile of 'Build.exe' (C++ binary in AppData). Initiate full IR if exfiltration to Telegram is confirmed.
```
→ end

## close-out
<!-- Close out and tune -->
```manual target=analyst
Document the findings. If blockchain traffic was identified but not confirmed as Aeternum (e.g. valid developer activity), update the rpc_domains whitelist if appropriate.
```
→ end
