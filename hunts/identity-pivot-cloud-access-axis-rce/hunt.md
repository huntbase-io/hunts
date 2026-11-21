---
analysis: A static detection rule might catch 'GetNPUsers.py', but this hunt uses
  stack-counting to identify rare enumeration scripts on vulnerable servers and then
  pivots into cloud API activity to correlate that activity with sensitive data access.
  This context allows an analyst to distinguish between a developer testing a script
  and an active intruder exfiltrating data.
blind_spots:
- id: cloud-api-visibility-gap
  owner: Cloud Architecture Team
  question: Which specific data records were exfiltrated from the warehouse?
  remediation: Enable high-verbosity audit logging for all production data warehouses
    and stream to the central log repository.
  requires: Audit logging for specific data warehouse providers (Snowflake/BigQuery)
    integrated with hb_cloud_api_activity
  risk: While we see the API calls, the exact content of the queries or the rows returned
    might not be visible if the provider does not supply detailed payload logs to
    the management plane.
  stage: exfiltration-cloud-warehouse-access
- id: impacket-renaming
  owner: Endpoint Security Admin
  question: Did the attacker rename the Impacket tools to bypass name-based detection?
  remediation: Enable file hash auditing for all Python script executions on application
    servers.
  requires: hb_process_activity with on-disk binary verification
  risk: If the attacker renames 'GetNPUsers.py' to a legitimate script name, the baseline
    step relies solely on command-line pattern matching, which can be bypassed if
    the script is run through a custom interpreter.
  stage: lateral-movement-identity-pivot
coverage:
- stage: lateral-movement-identity-pivot
  status: covered
  steps:
  - rare-identity-enumeration-tools
- stage: exfiltration-cloud-warehouse-access
  status: covered
  steps:
  - suspicious-cloud-warehouse-access
- reason: Belongs to another part of the 'Rapid7 Detected Exploitation of CVE-2026-90436
    against Atlassian Confluence Data Center, N-able N-central also Exploited' series.
  stage: initial-access-axis-soap-rce
  status: out_of_scope
- reason: Belongs to another part of the 'Rapid7 Detected Exploitation of CVE-2026-90436
    against Atlassian Confluence Data Center, N-able N-central also Exploited' series.
  stage: execution-automated-shell-c2
  status: out_of_scope
- reason: Belongs to another part of the 'Rapid7 Detected Exploitation of CVE-2026-90436
    against Atlassian Confluence Data Center, N-able N-central also Exploited' series.
  stage: discovery-credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The exploitation of CVE-2026-90436 provides an immediate foothold
    that leads to identity theft and high-value data exfiltration. Because attackers
    are known to pivot from application servers to cloud resources using service accounts,
    a negative result across both endpoint and cloud surfaces is required to confirm
    that the intrusion has not progressed to the data exfiltration stage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has pivoted from a compromised application server to internal
  identity services for AS-REP roasting and accessed cloud data warehouses using stolen
  service account credentials.
labels:
- hunt
- attack.t1087.002
- attack.t1558.004
- attack.t1537
- attack.t1078.004
- discovery
- execution
- exfiltration
- initial access
- lateral movement
name: Identity Pivot and Cloud Resource Access following Axis RCE
parameters:
  attacker_ips:
    default:
    - 192.238.253.176
    - 5.133.47.243
    - 163.182.68.109
    - 104.13.106.166
    - 157.20.241.16
    - 139.99.69.109
    - 79.76.51.56
    description: Observed attacker IP addresses associated with the intrusion.
    from:
      kind: article
      observed: '2026-11-17'
      ref: Rapid7 CVE-2026-90436
    type: list[ip]
  impacket_strings:
    default:
    - GetNPUsers.py
    - GetADUsers.py
    - secretsdump.py
    - psexec.py
    - GetUserSPNs.py
    description: Impacket tool filenames used for identity enumeration.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: 'Optional: Specific hosts identified as vulnerable in the scoping
      step.'
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Begin by identifying all hosts specifically detected as vulnerable to CVE-2026-90436.
  Focus the hunt on these hosts and any service accounts they use for database or
  cloud integration.
references:
- name: "Rapid7 \u2014 Detected Exploitation of CVE-2026-90436 against Atlassian Confluence"
  url: https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited
related:
- hunt: confluence-axis-rce-initial-execution
  reason: This hunt focuses on the lateral movement and exfiltration that follows
    the initial RCE on the application server.
  relation: follows
- hunt: axis-rce-confluence-credential-harvesting
  relation: follows
scenario:
  stages:
  - name: Unauthenticated Axis SOAP RCE
    observables:
    - POST /plugins/servlet/soap-axis1/confluenceservice-v2
    - HTTP 500 Internal Server Error
    - CVE-2026-90436
    slug: initial-access-axis-soap-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: Automated shell execution and tunneling
    observables:
    - confluence service account
    - Java process launching bash and curl
    - hex-encoded shell commands
    - trycloudflare.com
    - free.pinggy.net
    - webhook.site
    - wpefh-192-238-253-176.free.pinggy.net
    - sequential task IDs
    - labeled delimiters in command output
    slug: execution-automated-shell-c2
    tactic: execution
    techniques:
    - T1059.004
    - T1105
    - T1572
  - name: Confluence data and credential harvesting
    observables:
    - /var/atlassian/application-data/confluence/attachments/v4/
    - MySQL authentication using Confluence credentials
    - parsing Office documents for credentials
    - Luhn checks for payment card numbers
    - searching for 'VPN', 'token', 'encryption keys'
    slug: discovery-credential-harvesting
    tactic: discovery
    techniques:
    - T1083
    - T1552.001
    - T1213
  - name: Identity service enumeration and AS-REP roasting
    observables:
    - Atlassian Crowd API queries
    - Impacket GetNPUsers.py against Domain Controller
    - AS-REP roasting
    slug: lateral-movement-identity-pivot
    tactic: lateral-movement
    techniques:
    - T1087.002
    - T1558.004
  - name: Cloud data warehouse and M365 access
    observables:
    - Production cloud data warehouse queries
    - M365 sign-in via legacy authentication
    - IP 192.238.253.176
    slug: exfiltration-cloud-warehouse-access
    tactic: exfiltration
    techniques:
    - T1537
    - T1078.004
  summary: Attackers exploit a critical unauthenticated RCE in Apache Axis (CVE-2026-90436)
    affecting Atlassian Confluence and N-able N-central to gain initial footprints.
    Using AI-assisted automation, they harvest credentials from local databases and
    file attachments before pivoting to internal identity services and production
    cloud environments.
series:
  index: 2
  slug: rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n
  title: Rapid7 Detected Exploitation of CVE-2026-90436 against Atlassian Confluence
    Data Center, N-able N-central also Exploited
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
tlp: clear
type: investigation
---


# Identity Pivot and Cloud Resource Access following Axis RCE

After gaining an initial foothold on Atlassian Confluence or N-able N-central servers, attackers are known to perform identity service enumeration using Impacket and then access cloud data warehouses using acquired integration credentials. This hunt identifies these pivots by finding rare enumeration tools on vulnerable hosts and corroborating them with anomalous cloud API calls and sign-ins from known attacker infrastructure. An agent weighs the endpoint and cloud telemetry together to determine if an intrusion has progressed to the data exfiltration stage.

## vulnerable-product-inventory
<!-- Identify vulnerable Confluence and N-central hosts -->
Identify hosts where the specific vulnerability CVE-2026-90436 has been detected to focus the investigation on the most likely targets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts specifically flagged with CVE-2026-90436. Zero rows means
  no scanner has identified the vulnerability yet.
reads:
- device_uid
- title
- severity
- first_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_uid, title, severity, first_seen FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-90436' OR title LIKE '%Axis 1.x%'
```

## parallel-pivot-detection
<!-- Search for identity pivots and cloud exfiltration -->
parallel:
- → rare-identity-enumeration-tools
- → suspicious-cloud-warehouse-access
join: → agent-triage

## rare-identity-enumeration-tools
<!-- Rare identity enumeration tools -->
Identify the use of Impacket or other identity enumeration tools; the actor uses these to find targets for lateral movement.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, impacket_strings=impacket_strings, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare command lines containing Impacket script names, particularly when running
  under a Python interpreter on the application servers.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_name
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT LOWER(process_name) AS proc, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{impacket_strings}}' || ',', ',' || LOWER(process_cmd_line) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%impacket%' OR LOWER(process_cmd_line) LIKE '%getnpusers%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY proc, process_cmd_line HAVING hosts < 5 ORDER BY hosts ASC
```

## suspicious-cloud-warehouse-access
<!-- Suspicious cloud warehouse access -->
Filter for data-access and exfiltration-related calls to cloud warehouses originating from attacker infrastructure or service accounts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, attacker_ips=attacker_ips)
~~~yaml
expected: Data access operations targeting cloud warehouses from reported attacker
  IPs or integration accounts that do not typically use these operations from the
  internet.
reads:
- time
- actor_user_name
- src_endpoint_ip
- api_operation
- api_service_name
- resource_name
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT time, actor_user_name, src_endpoint_ip, api_operation, api_service_name, resource_name FROM hb_cloud_api_activity WHERE (instr(',' || '{{attacker_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR LOWER(actor_user_name) LIKE '%integration%' OR LOWER(actor_user_name) LIKE '%service%') AND (LOWER(api_operation) LIKE '%select%' OR LOWER(api_operation) LIKE '%export%' OR LOWER(api_operation) LIKE '%getobject%' OR LOWER(api_operation) LIKE '%copyobject%') AND (LOWER(api_service_name) LIKE '%snowflake%' OR LOWER(api_service_name) LIKE '%bigquery%' OR LOWER(api_service_name) LIKE '%s3%') AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## agent-triage
<!-- Triage identity and cloud evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-product-inventory
- rare-identity-enumeration-tools
- suspicious-cloud-warehouse-access
max_iterations: 5
objective: Determine whether the rare processes on vulnerable hosts and the cloud
  API calls from integration accounts or attacker IPs indicate a successful breach
  and data exfiltration.
success_criteria: A per-host and per-user verdict of malicious | suspicious | benign,
  citing specific rows for the pivot and the cloud access.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage verdict is malicious for at least one host or service account" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: cloud-api-visibility-gap)
else: → analyst-manual-review

## isolate-and-revoke
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised server, revoke all active sessions for the identified service account, and rotate its credentials immediately.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the cited rows from both endpoint and cloud surfaces. Verify if other service accounts used by the vulnerable server have also been compromised.
```
→ data-impact-assessment

## data-impact-assessment
<!-- Data impact assessment -->
```manual target=analyst
Coordinate with the data engineering team to review native audit logs for the impacted data warehouse (Snowflake/BigQuery) and identify the specific tables and rows accessed by the compromised credential.
```
→ end
