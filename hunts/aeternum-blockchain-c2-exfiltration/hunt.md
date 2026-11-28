---
analysis: A standard detection rule might alert on any Telegram connection; this hunt
  specifically correlates the sequence of a rare blockchain RPC lookup followed by
  a unique Telegram User-Agent and the loading of specific botnet modules, reducing
  the false positives associated with legitimate development activity.
blind_spots:
- id: no-http-body-visibility
  question: whether the JSON-RPC POST request contains the Aeternum-specific method
    0xb68d1809
  requires: hb_http_activity with request_body
  risk: An analyst can see traffic to a public RPC node but cannot confirm it is malicious
    without seeing the getDomain() method in the body.
  stage: blockchain-c2-communication
- id: tls-encrypted-exfil
  question: the exact content of the exfiltrated ZIP or PNG file
  requires: TLS inspection for api.telegram.org
  risk: While the User-Agent is visible, the actual data leaving the estate is hidden
    by Telegram's encryption.
  stage: data-exfiltration-via-telegram
coverage:
- stage: blockchain-c2-communication
  status: covered
  steps:
  - dns-lead-to-decentralized-infra
- stage: payload-download-and-loading
  status: covered
  steps:
  - recon-and-module-artifacts
- stage: data-exfiltration-via-telegram
  status: covered
  steps:
  - telegram-http-exfiltration
  - recon-and-module-artifacts
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: aeternum-initial-execution
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: persistence-via-startup-folder
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: auxiliary-binary-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Blockchain-based C2 infrastructure is immutable and cannot be taken
    down by traditional law enforcement domain seizures. Hunting for the unique communication
    signature of Aeternum is the only durable way to find this threat as it rotates
    its smart contract addresses.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using public blockchain RPC endpoints to retrieve C2 instructions
  and the Telegram Bot API to exfiltrate system reconnaissance data, evading traditional
  domain-based filtering.
labels:
- hunt
- attack.t1102.001
- attack.t1071.001
- attack.t1105
- attack.t1567.002
- attack.t1041
name: Aeternum Decentralized C2 and Telegram Exfiltration
parameters:
  exfil_domains:
    default:
    - api.telegram.org
    - github.com
    description: Domains used for exfiltration and payload acquisition.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-c2
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rpc_endpoints:
    default:
    - polygon-mumbai-bor-rpc.publicnode.com
    description: Blockchain RPC endpoints used for decentralized C2.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-c2
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to filter on, typically identified in the initial DNS lead
      step.
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
rationale: Focus on the general endpoint estate, prioritizing systems with developers
  or administrators who might legitimately use blockchain RPCs, to distinguish them
  from infected workstations.
references:
- name: "Unit 42 \u2014 The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based\
    \ C2 Operations"
  url: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
related:
- hunt: aeternum-initial-infection
  reason: This hunt focuses on the C2 and exfiltration lifecycle; the initial execution
    and unpacking are handled in the sibling hunt.
  relation: out-of-scope-alternative
- hunt: aeternum-loader-persistence-execution
  relation: follows
scenario:
  stages:
  - name: Aeternum Loader Execution
    observables:
    - Build.exe
    - UPX-packed binary
    slug: aeternum-initial-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Persistence via Startup Folder
    observables:
    - AppData\Local
    - Wmi_Framework_APIKEY_wmsnet_*.lnk
    slug: persistence-via-startup-folder
    tactic: persistence
    techniques:
    - T1547.001
  - name: Auxiliary Binary Execution
    observables:
    - wmiframework.exe
    - ZrvEsJQzWQ.exe
    - STAAAAAS.exe
    slug: auxiliary-binary-execution
    tactic: execution
    techniques:
    - T1106
  - name: Blockchain-based C2 Communication
    observables:
    - polygon-mumbai-bor-rpc.publicnode.com
    - '0xb68d1809'
    - getDomain()
    slug: blockchain-c2-communication
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1071.001
  - name: Payload Download from GitHub
    observables:
    - github.com
    - DotNetZip.dll
    - putty.exe
    slug: payload-download-and-loading
    tactic: command-and-control
    techniques:
    - T1105
  - name: Data Exfiltration via Telegram API
    observables:
    - api.telegram.org
    - SystemInfo Bot/2.0
    - screenshot.png
    - /sendDocument
    slug: data-exfiltration-via-telegram
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1041
  summary: Aeternum is a C++ botnet loader that leverages the Polygon blockchain's
    smart contracts for decentralized command-and-control infrastructure. The loader
    establishes persistence via the Windows Startup folder and retrieves instructions
    through Polygon RPC endpoints before downloading secondary payloads from GitHub
    and exfiltrating system data via the Telegram API.
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


# Aeternum Decentralized C2 and Telegram Exfiltration

This hunt targets the network-centric lifecycle of the Aeternum botnet. It first identifies hosts communicating with decentralized blockchain infrastructure (Polygon) and social media APIs (Telegram). It then correlates these connections with specific behavioural markers, such as the SystemInfo Bot User-Agent and the loading of the DotNetZip.dll module. By fanning out across DNS, HTTP, and module telemetry, the hunt identifies the full scope of a blockchain-coordinated intrusion.

## dns-lead-to-decentralized-infra
<!-- DNS lookups to blockchain and exfil domains -->
Identify hosts communicating with decentralized RPC nodes or the Telegram API to establish a lead list.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rpc_endpoints=rpc_endpoints, exfil_domains=exfil_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts contacting Polygon or Telegram. Common developer activity
  may appear; prevalence will help filter noise in later steps.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE (instr(',' || '{{rpc_endpoints}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookup_count DESC
```

## corroborate-activity
<!-- Corroborate on network and module surfaces -->
parallel:
- → telegram-http-exfiltration
- → recon-and-module-artifacts
join: → triage-aeternum-evidence

## telegram-http-exfiltration
<!-- Telegram API exfiltration traffic -->
Find the specific HTTP User-Agent and URI paths used by the Aeternum exfiltration module, restricted to the lead host list.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to /sendDocument with the SystemInfo Bot User-Agent from lead
  hosts. This is a high-confidence indicator of the exfiltration phase.
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
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE (LOWER(user_agent) LIKE 'systeminfo bot%' OR LOWER(url_path) LIKE '%/senddocument%') AND LOWER(url_hostname) = 'api.telegram.org' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## recon-and-module-artifacts
<!-- Malicious module and reconnaissance artifacts -->
Identify the loading of the botnet downloader module and the creation of exfiltration files on lead hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The loading of dotnetzip.dll or the creation of screenshot.png specifically
  on hosts identified as having blockchain or Telegram network activity.
reads:
- device_hostname
- module_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, module_name AS artifact, process_name, time, 'module_load' AS type FROM hb_module_activity WHERE LOWER(module_name) = 'dotnetzip.dll' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') UNION ALL SELECT device_hostname, file_name AS artifact, process_name, time, 'file_creation' AS type FROM hb_file_activity WHERE LOWER(file_name) = 'screenshot.png' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-aeternum-evidence
<!-- Triage Aeternum evidence -->
```agent target=hunter
cite: required
context:
- dns-lead-to-decentralized-infra
- telegram-http-exfiltration
- recon-and-module-artifacts
max_iterations: 6
objective: Determine if any host has successfully retrieved commands via Polygon RPC
  and exfiltrated data via Telegram, citing the User-Agent, module loading, and screenshot
  creation.
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the presence of the full chain.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict identifies hosts with confirmed Aeternum exfiltration markers such as the SystemInfo Bot User-Agent or DotNetZip module load" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-http-body-visibility)
else: → close-out-hunt

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture any running processes communicating with api.telegram.org.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Examine the process trees for hosts contacting Polygon RPC endpoints. Look for C++ compiled binaries that do not belong to legitimate blockchain development tools.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Log the number of hosts identified. If Aeternum was confirmed, ensure the HTTP User-Agent and screenshot file name patterns are added to the detection backlog.
```
→ end
