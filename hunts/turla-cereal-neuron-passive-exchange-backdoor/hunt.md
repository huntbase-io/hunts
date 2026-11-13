---
analysis: Simple URI matching is brittle and easily bypassed by path rotation. This
  hunt combines indicator matching with a behavioral baseline of source IPs accessing
  Exchange namespaces, requiring an analyst to weigh source rarity against requested
  paths.
blind_spots:
- id: visibility-gap-encrypted-http
  question: Can we see the URI path if the traffic is encrypted and the EDR does not
    hook the web server process?
  requires: Endpoint-level HTTP inspection or SSL termination logs
  risk: If the environment only provides network flow logs, the hunt cannot identify
    specific URI paths and must rely solely on source IP outliers.
  stage: passive-web-backdoor
- id: uri-rotation
  question: What if the adversary changes the hardcoded URI paths to different legitimate-looking
    endpoints?
  requires: Threat research updates
  risk: Exact URI matching will fail, leaving the prevalence baseline as the only
    signal for identifying the intrusion.
  stage: passive-web-backdoor
coverage:
- stage: passive-web-backdoor
  status: covered
  steps:
  - check-cereal-uris
  - baseline-source-ips
  - triage-web-evidence
- reason: Handled by the execution-focused hunt in this series.
  stage: dotnet-stealth-execution
  status: out_of_scope
- reason: "Belongs to another part of the 'Exchange for breakfast: Turla\u2019s Cereal\
    \ tricks are not for kids' series."
  stage: offline-command-processing
  status: out_of_scope
- reason: "Belongs to another part of the 'Exchange for breakfast: Turla\u2019s Cereal\
    \ tricks are not for kids' series."
  stage: mail-pipeline-hijacking
  status: out_of_scope
- reason: "Belongs to another part of the 'Exchange for breakfast: Turla\u2019s Cereal\
    \ tricks are not for kids' series."
  stage: espionage-data-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Turla's CerealNeuron uses a passive listening mechanism that bypasses
    traditional outbound beaconing detection. Negative results across the Exchange
    estate are required to ensure espionage tools are not co-opting the organization's
    infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has installed a passive .NET backdoor on a Microsoft Exchange
  server that intercepts commands via specific URI paths within standard Exchange
  web services.
labels:
- hunt
- attack.t1071.001
- attack.t1572
- collection
- command and control
- execution
- persistence
name: Turla CerealNeuron Passive Exchange Backdoor
parameters:
  cereal_paths:
    default:
    - /owa/sdds/
    - /autodiscover/proxyservice/
    - /microsoft-server-activesync/integrated/api/
    description: Legitimate-looking URIs reported for passive command reception.
    from:
      kind: article
      observed: '2026-11-10'
      ref: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for web requests.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified as Exchange servers from the scoping step; leave
      empty to scan the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Internet-facing Microsoft Exchange servers. Use the scoping query
  to narrow the estate, then refine with the scope_hosts parameter if specific servers
  are suspected.
references:
- name: "ESET Research \u2014 Exchange for breakfast: Turla\u2019s Cereal tricks are\
    \ not for kids"
  url: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
related:
- hunt: cereal-dotnet-stealth-execution
  reason: This hunt identifies the C2 ingress; a separate hunt addresses the sophisticated
    .NET execution techniques used once commands are received.
  relation: out-of-scope-alternative
- hunt: turla-cereal-exchange-transport-hijack
  relation: follows
scenario:
  stages:
  - name: Sophisticated .NET Execution
    observables:
    - unmanaged entry points
    - native image cache abuse
    - nested .NET assemblies
    - suspicious DLLs loaded by legitimate Windows processes
    slug: dotnet-stealth-execution
    tactic: execution
    techniques:
    - T1047
  - name: Passive Web Service Backdoor
    observables:
    - https://*:443/owa/sdds/
    - HTTPS://*:443/AUTODISCOVER/PROXYSERVICE/
    - HTTPS://*:443/MICROSOFT-SERVER-ACTIVESYNC/INTEGRATED/API/
    - CerealNeuron
    slug: passive-web-backdoor
    tactic: command-and-control
    techniques:
    - T1071
    - T1572
  - name: File-based Command Interface
    observables:
    - encrypted command files on disk
    - CerealHermit
    slug: offline-command-processing
    tactic: command-and-control
    techniques:
    - T1071
  - name: Exchange Transport Hijack
    observables:
    - EdgeTransport.exe
    - injection into EdgeTransport.exe
    - memory hijacking of transport agents
    - VTable Fixups
    - CerealBox
    slug: mail-pipeline-hijacking
    tactic: persistence
    techniques:
    - T1574
  - name: Email Collection and Staging
    observables:
    - compressed and encrypted files on disk
    - .doc attachments
    - .docx attachments
    - .pdf attachments
    slug: espionage-data-staging
    tactic: collection
    techniques:
    - T1041
  summary: The Turla-linked Cereal campaign targets government Exchange servers, utilizing
    a modular .NET toolset that operates without external C&C infrastructure by co-opting
    the victim server as a passive listener. The toolset intercepts mail by injecting
    into the EdgeTransport.exe process to hijack transport agents and uses specialized
    .NET tradecraft, such as native image cache abuse, to maintain stealthy execution.
series:
  index: 2
  slug: exchange-for-breakfast-turla-s-cereal-tricks-are-not-for-kids
  title: "Exchange for breakfast: Turla\u2019s Cereal tricks are not for kids"
  total: 2
severity: critical
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


# Turla CerealNeuron Passive Exchange Backdoor

This hunt targets CerealNeuron, a component of Turla's Cereal toolset. Unlike traditional implants that beacon out, CerealNeuron acts as a passive listener within IIS on a compromised Exchange server. It monitors incoming web requests for specific encrypted payloads directed at sub-paths in /owa/, /autodiscover/, or /activesync/ namespaces. The hunt identifies Exchange assets, searches for hits against known malicious URIs, and baselines external source traffic to find anomalous access patterns that may indicate rotated command paths where standard indicators have changed.

## identify-exchange-hosts
<!-- Identify Exchange Server Assets -->
Identify the hosts running Microsoft Exchange Server to provide a narrow scope for application-layer traffic analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames hosting Exchange services. Silence means no managed
  hosts are running Exchange Server according to inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%exchange server%'
```

## parallel-web-checks
<!-- Parallel Web Traffic Investigation -->
parallel:
- → check-cereal-uris
- → baseline-source-ips
join: → triage-web-evidence

## check-cereal-uris
<!-- Match Known CerealNeuron Paths -->
Match URI paths reported as C2 endpoints for the passive backdoor exactly.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, cereal_paths=cereal_paths, lookback_days=lookback_days)
~~~yaml
expected: Direct matches indicate an external entity requested a path used for C2.
  Silence confirms these specific paths were not observed.
reads:
- device_hostname
- url_path
- src_endpoint_ip
- user_agent
- status_code
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, user_agent, status_code, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{cereal_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-source-ips
<!-- Baseline Rare Source Access -->
Stack-count source IPs accessing Exchange namespaces to find operators maintaining a consistent source profile on non-standard paths.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outlier IPs or User Agents targeting only one or two servers. Legitimate
  remote access typically spans a broader set of hosts or correlates with known user
  populations.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  - user_agent
  rare_below: 3
reads:
- src_endpoint_ip
- user_agent
- url_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT src_endpoint_ip, user_agent, url_path, COUNT(*) AS req_count, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(url_path) LIKE '/owa/%' OR LOWER(url_path) LIKE '/autodiscover/%' OR LOWER(url_path) LIKE '/microsoft-server-activesync/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, user_agent, url_path HAVING host_count <= 2 ORDER BY host_count ASC, req_count DESC
```

## triage-web-evidence
<!-- Triage Web Traffic Evidence -->
```agent target=hunter
cite: required
context:
- check-cereal-uris
- baseline-source-ips
max_iterations: 4
objective: Determine if any Exchange server shows patterns of passive command reception,
  specifically hits on known Turla URIs or rare, single-host access to sensitive namespaces.
success_criteria: A per-host verdict citing specific rows, source IPs, and requested
  URIs.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage-web-evidence verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → forensic-verification
unavailable: → forensic-verification (blind_spot: visibility-gap-encrypted-http)
else: → close-hunt

## isolate-server
<!-- Isolate Compromised Exchange Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised Exchange server from the network. Do not reboot the server before capturing a memory dump, as the backdoor runs in volatile memory.
```
→ forensic-verification

## forensic-verification
<!-- Forensic Verification -->
```manual target=analyst
Acquire a memory dump of w3wp.exe. Search for suspicious .NET assemblies with unmanaged entry points. Inspect the file system for encrypted files under the Exchange installation directory that may indicate the presence of CerealHermit.
```
→ close-hunt

## close-hunt
<!-- Hunt Close-out -->
```manual target=analyst
Record all suspicious source IPs and URIs. Update the organization's baseline for remote access to Exchange services. If hits were found, escalate to full incident response.
```
→ end
