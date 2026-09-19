---
analysis: A simple detection rule for tool filenames is easily evaded by renaming
  the binary. This hunt correlates software presence, rare User-Agents, and specific
  API abuse patterns (internal versioning) across three surfaces (process, DNS, and
  HTTP) to detect the behavior.
blind_spots:
- id: missing-cloud-logs
  owner: Cloud Infrastructure Team
  question: What exact directory objects (users, groups) were accessed and what was
    the server's full response?
  remediation: Enable 'AzureADGraphActivityLogs' in Entra ID Diagnostic Settings and
    route to the security data platform.
  requires: AzureADGraphActivityLogs enabled in Diagnostic Settings
  risk: Without platform-side logs, we rely on endpoint telemetry which can miss the
    server-side outcome and the full scope of data exfiltration.
  stage: legacy-api-enumeration
- id: http-encryption-blind-spot
  owner: Security Engineering
  question: Are url_query parameters (like api-version) visible in the telemetry?
  remediation: Ensure proxy or EDR solutions are configured to log full request URIs
    for cloud infrastructure domains.
  requires: Proxy HTTPS inspection for graph.windows.net
  risk: If the traffic is encrypted and not inspected at the network boundary, the
    internal-api-version signal will be missing, leaving only domain-level DNS/network
    telemetry.
  stage: legacy-api-enumeration
coverage:
- stage: offensive-tool-execution
  status: covered
  steps:
  - scoping-installed-tools
  - execution-of-discovery-tools
- stage: legacy-api-enumeration
  status: covered
  steps:
  - http-internal-api-usage
  - dns-graph-resolutions
  - rare-user-agents-to-graph
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The legacy AAD Graph API remains a primary blind spot and a preferred
    target for bulk directory enumeration. Closing this visibility gap is essential
    to detecting reconnaissance that precedes lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using offensive tools like ROADrecon or AADInternals to
  perform bulk directory enumeration against the legacy Azure AD Graph API (graph.windows.net),
  specifically abusing the 1.61-internal API version to extract sensitive directory
  details.
labels:
- hunt
- attack.t1059.001
- attack.t1190
name: Entra ID Enumeration via Legacy Graph API
parameters:
  internal_api_version:
    default: 1.61-internal
    description: The specific internal API version used by ROADrecon to pull sensitive
      data.
    from:
      kind: article
      observed: '2026-06-19'
      ref: elastic-security-labs
    type: string
  legacy_graph_domain:
    default: graph.windows.net
    description: The legacy AAD Graph endpoint targeted by offensive tools.
    from:
      kind: article
      observed: '2026-06-19'
      ref: elastic-security-labs
    type: domain
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-19'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: A list of hostnames to focus the investigation on; leave empty for
      the entire estate.
    from:
      kind: manual
      observed: '2026-06-19'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and developer workstations; focus on hosts where directory
  tools like ROADrecon are found in the software inventory.
references:
- name: "Elastic Security Labs \u2014 Azure AD Graph Activity Logs: Ingestion and\
    \ threat detection"
  url: https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection
related:
- hunt: microsoft-graph-bulk-enumeration
  reason: Targets the modern graph.microsoft.com surface which requires different
    API permissions and monitoring.
  relation: sibling
scenario:
  stages:
  - name: Offensive Tool Execution
    observables:
    - pip install roadrecon
    - roadrecon gather
    - roadrecon auth --device-code
    - AADInternals PowerShell cmdlets
    - Python aiohttp User-Agent
    - Microsoft.OData.Client
    slug: offensive-tool-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Legacy Graph API Enumeration
    observables:
    - graph.windows.net
    - api-version=1.61-internal
    - api-version=1.6
    - 'url.path: /users'
    - 'url.path: /groups'
    - 'url.path: /servicePrincipals'
    - 'url.path: /applications'
    - 'url.path: /tenantDetails'
    - strongAuthenticationDetail
    - 'User-Agent: Microsoft.OData.Client'
    - 'User-Agent: Microsoft Azure Graph Client Library'
    - 'User-Agent: Microsoft ADO.NET Data Services'
    - HTTP 4xx status code surges
    slug: legacy-api-enumeration
    tactic: initial-access
    techniques:
    - T1190
  summary: Adversaries utilize offensive toolkits like ROADrecon and AADInternals
    to perform bulk enumeration of Entra ID directory objects by abusing the legacy
    and often unmonitored Azure AD Graph API (graph.windows.net). This activity exploits
    a visibility gap in legacy logging and leverages internal API versions, such as
    1.61-internal, to extract sensitive authentication data that is more restricted
    in modern Microsoft Graph endpoints.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Entra ID Enumeration via Legacy Graph API

This hunt identifies the gap between endpoint tool execution and legacy cloud API abuse. It begins by scoping hosts where directory enumeration tools are installed or executing, then correlates that with high-volume network activity targeting 'graph.windows.net'. It specifically looks for the '1.61-internal' API version—a known indicator of offensive directory walkers—and stack-counts User-Agents to identify rare scripting libraries or custom headers typical of offensive tooling.

## scoping-installed-tools
<!-- Scope hosts with directory tools installed -->
Identify endpoints where ROADrecon or AADInternals are present in the software inventory as a scoping precursor.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with these packages. Silence does not prove absence if tools
  are run as portable scripts.
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
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (instr(LOWER(package_name), 'roadrecon') > 0 OR instr(LOWER(package_name), 'aadinternals') > 0)
```

## execution-of-discovery-tools
<!-- Execution of directory discovery tools -->
Detect the actual execution of enumeration tools via command line keywords.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process execution events with tool-specific strings. Renamed tools will
  be missed by this step but caught by network prevalence.
reads:
- device_hostname
- user_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(LOWER(process_cmd_line), 'roadrecon') > 0 OR instr(LOWER(process_cmd_line), 'aadinternals') > 0 OR instr(LOWER(process_cmd_line), 'get-aadint') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-network-evidence
<!-- Parallel network and behavior analysis -->
parallel:
- → http-internal-api-usage
- → dns-graph-resolutions
- → rare-user-agents-to-graph
join: → triage-agent

## http-internal-api-usage
<!-- Usage of internal Graph API versions -->
Detect HTTP requests targeting the legacy Graph domain using the internal version string.

```sqlite target=web role=triage params=(lookback_days=lookback_days, legacy_graph_domain=legacy_graph_domain, internal_api_version=internal_api_version, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests targeting directory collections with offensive API versioning.
  Silence is evidence of absence if proxy inspection is active.
reads:
- device_hostname
- src_endpoint_ip
- http_method
- url_path
- url_query
- user_agent
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, http_method, url_path, url_query, user_agent, time FROM hb_http_activity WHERE url_hostname = '{{legacy_graph_domain}}' AND (instr(LOWER(url_query), '{{internal_api_version}}') > 0 OR instr(LOWER(url_query), 'api-version=1.6') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-graph-resolutions
<!-- DNS resolutions for legacy Graph -->
Identify which processes are resolving the legacy domain to corroborate activity from scripting interpreters.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, legacy_graph_domain=legacy_graph_domain, scope_hosts=scope_hosts)
~~~yaml
expected: Resolution events originating from python.exe, powershell.exe, or unknown
  binaries.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE query_hostname = '{{legacy_graph_domain}}' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## rare-user-agents-to-graph
<!-- Rare User-Agents against legacy Graph -->
Stack-count User-Agents to identify rare scripting libraries or custom offensive tool headers.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, legacy_graph_domain=legacy_graph_domain, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: User-Agents like 'aiohttp', 'python-requests', or empty strings that stand
  out from first-party Microsoft clients.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 2
reads:
- user_agent
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_agent, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS requests, MIN(time) AS first_seen FROM hb_http_activity WHERE url_hostname = '{{legacy_graph_domain}}' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent HAVING hosts <= 2
```

## triage-agent
<!-- Triage directory enumeration -->
```agent target=hunter
cite: required
context:
- scoping-installed-tools
- execution-of-discovery-tools
- http-internal-api-usage
- dns-graph-resolutions
- rare-user-agents-to-graph
max_iterations: 5
objective: Determine if any host is successfully using offensive tools to perform
  unauthorized directory enumeration against the legacy Entra ID Graph API.
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows.
tools:
- endpoint
- web
```

## decision-route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for legacy directory enumeration on at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-cloud-logs)
else: → close-out

## contain-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and revoke all Entra ID sessions for the involved users.
```
→ analyst-review

## analyst-review
<!-- Forensic review of Graph activity -->
```manual target=analyst
Review the cited rows. If Entra ID logs are available, check 'AzureADGraphActivityLogs' for exfiltrated data.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the findings and whether to schedule as a recurring hunt.
```
→ end
