---
analysis: A simple detection rule might trigger on any metadata access, but this hunt
  correlates the presence of vulnerable AI software with specific unauthenticated
  HTTP paths and applies a baseline to ignore frequent internal scanners.
blind_spots:
- id: http-payload-visibility
  question: What Python code was submitted to the validate or build endpoints?
  requires: TLS decryption at the proxy or application-level logging of HTTP request
    bodies
  risk: An analyst can see that the endpoint was called but cannot distinguish between
    a legitimate workflow build and a malicious RCE payload without the body content.
  stage: initial-access-langflow-exploit
- id: metadata-response-status
  question: Was the metadata request successful and were credentials actually exfiltrated?
  requires: Cloud provider instance audit logs or IMDSv2 configuration state
  risk: A request to 169.254.169.254 might be blocked by IMDSv2 or local firewall
    rules, but hb_http_activity may only show the attempt.
  stage: lateral-movement-cloud-metadata
coverage:
- stage: initial-access-langflow-exploit
  status: covered
  steps:
  - identify-langflow-installations
  - detect-suspicious-api-calls
- stage: lateral-movement-cloud-metadata
  status: covered
  steps:
  - detect-metadata-access
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Langflow, MongoDB,
    and More'' series.'
  stage: execution-python-rce
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Langflow, MongoDB,
    and More'' series.'
  stage: credential-access-secrets-theft
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Langflow, MongoDB,
    and More'' series.'
  stage: persistence-database-modification
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Langflow RCEs are unauthenticated and offer immediate access to the
    compute context. Given the frequent use of Langflow in cloud-native AI pipelines,
    these hosts often have powerful identity tokens that can be used to move laterally
    into the cloud control plane.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting unauthenticated remote code execution vulnerabilities
  in Langflow AI endpoints and subsequently querying the cloud metadata service to
  harvest identity tokens for lateral movement.
labels:
- hunt
- attack.t1190
- attack.t1552.005
- credential access
- execution
- initial access
- lateral movement
- persistence
name: Langflow RCE and Cloud Metadata Discovery
parameters:
  lookback_days:
    default: '14'
    description: Days of historical HTTP activity to examine.
    type: number
  metadata_ip:
    default: 169.254.169.254
    description: The common cloud metadata service IP address.
    type: ip
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; leave empty to scan the
      full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin by searching the software inventory for Langflow. If the inventory
  is stale, run the HTTP queries across all application server subnets.
references:
- name: "Rapid7 \u2014 Metasploit Wrap Up: Langflow, MongoDB, and More"
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more
related:
- hunt: langflow-post-exploitation-python-behavior
  reason: This hunt focuses on the network-level initial access and discovery; the
    internal execution of Python and child processes is handled in a separate execution-focused
    hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Langflow Endpoints
    observables:
    - /api/v1/build/
    - /api/v1/validate
    - eval_custom_component_code
    slug: initial-access-langflow-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Python Remote Code Execution
    observables:
    - Python child processes spawning shells
    - langflow process executing arbitrary Python strings
    - Meterpreter python payload execution
    slug: execution-python-rce
    tactic: execution
    techniques:
    - T1059.006
  - name: Credential and Secret Access
    observables:
    - Accessing Langflow database files
    - Reading application secrets from database tables
    - Retrieval of SSO email addresses and phone numbers
    slug: credential-access-secrets-theft
    tactic: credential-access
    techniques:
    - T1552.001
    - T1555
  - name: Cloud Metadata Service Abuse
    observables:
    - HTTP requests to 169.254.169.254
    - Abuse of cloud metadata endpoints for tenant lateral movement
    slug: lateral-movement-cloud-metadata
    tactic: lateral-movement
    techniques:
    - T1552.005
  - name: Persistence via Database Modification
    observables:
    - Modification of tool_code in the Langflow database
    - SQL updates to public flows to re-execute attacker code
    slug: persistence-database-modification
    tactic: persistence
    techniques:
    - T1505.003
  summary: This article describes multiple Metasploit modules targeting vulnerabilities
    in Langflow and OpenCTI, providing unauthenticated remote code execution capabilities.
    In Langflow environments, successful exploitation allows attackers to execute
    arbitrary Python code, access application secrets, pivot to cloud metadata services,
    and maintain persistence by injecting malicious code into the application's database.
series:
  index: 1
  slug: metasploit-wrap-up-langflow-mongodb-and-more
  title: 'Metasploit Wrap Up: Langflow, MongoDB, and More'
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


# Langflow RCE and Cloud Metadata Discovery

This hunt identifies Langflow installations within the estate and monitors for exploitation attempts against the build and validate API endpoints. It correlates these suspicious HTTP requests with outbound traffic to the cloud metadata service (169.254.169.254), a common post-exploitation step used to pivot from a compromised container or instance into the cloud control plane. The hunt uses a stack-counting baseline to isolate rare external actors hitting these sensitive AI orchestration paths.

## identify-langflow-installations
<!-- Identify Langflow Installations -->
Locate hosts running Langflow to establish the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts and their Langflow versions. Silence means the product is
  not recorded in the package inventory.
reads:
- device_hostname
- install_path
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%langflow%'
```

## fan-out-telemetry
<!-- Fan-out Telemetry -->
parallel:
- → detect-suspicious-api-calls
- → detect-metadata-access
- → baseline-external-traffic
join: → triage-langflow-intrusion

## detect-suspicious-api-calls
<!-- Detect Suspicious API Calls -->
Find HTTP requests to the Langflow endpoints targeted by the Metasploit modules.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Requests to sensitive build or validate endpoints. Frequent 200 OK responses
  from unusual source IPs indicate potential successful exploitation.
reads:
- device_hostname
- src_endpoint_ip
- status_code
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, status_code, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/api/v1/build%' OR LOWER(url_path) LIKE '%/api/v1/validate%' OR LOWER(url_path) LIKE '%eval_custom_component_code%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-metadata-access
<!-- Detect Metadata Access -->
Identify attempts to reach the cloud metadata service from the same hosts.

```sqlite target=web role=enrichment params=(metadata_ip=metadata_ip, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound HTTP requests to the metadata service. This is anomalous for standard
  AI workflow builder operations and suggests credential theft.
reads:
- device_hostname
- dst_endpoint_ip
- src_endpoint_ip
- time
- url_full
- url_hostname
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, user_agent, time FROM hb_http_activity WHERE (url_hostname = '{{metadata_ip}}' OR dst_endpoint_ip = '{{metadata_ip}}') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-external-traffic
<!-- Baseline External Traffic -->
Stack-count source IPs to isolate rare external actors hitting Langflow endpoints.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of source IPs hitting Langflow on 3 or fewer hosts. High-volume,
  fleet-wide traffic usually indicates internal health checks or automated scanners.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/api/v1/build%' OR LOWER(url_path) LIKE '%/api/v1/validate%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-langflow-intrusion
<!-- Triage Langflow Intrusion -->
```agent target=hunter
cite: required
context:
- identify-langflow-installations
- detect-suspicious-api-calls
- detect-metadata-access
- baseline-external-traffic
max_iterations: 5
objective: Determine if any Langflow host is being actively exploited and whether
  the actor is attempting to steal cloud credentials through the metadata service.
success_criteria: A per-host verdict citing rows from both the API and metadata queries.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage-langflow-intrusion verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: http-payload-visibility)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised Langflow endpoint from the network and revoke any cloud session tokens associated with its instance identity.
```
→ analyst-remediation

## analyst-remediation
<!-- Analyst Remediation -->
```manual target=analyst
Review the full HTTP transaction logs if available. Check the cloud provider audit logs for unusual API calls using the identity of the isolated instance. Rotate any credentials stored in Langflow's environment variables.
```
→ close-out

## close-out
<!-- Close-out -->
```manual target=analyst
Document the number of Langflow instances identified and the status of their patches. Record any successful exploitation chains for future detection tuning.
```
→ end
