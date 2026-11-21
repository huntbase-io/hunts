---
analysis: A single detection rule may catch the Java-to-bash execution, but this hunt
  correlates the initial HTTP exploit attempt, the use of tunneling services, and
  rare access to the attachment store, providing the full context of a credential
  harvesting campaign.
blind_spots:
- id: no-access-log-detail
  question: whether the specific vulnerable Axis endpoint was targeted and returned
    a 500 error
  requires: hb_http_activity with response status code
  risk: Missing the primary indicator of the initial exploit, leading to a false negative
    for the gated hunt.
  stage: initial-access-axis-soap-rce
- id: limited-retention
  question: whether the automated shell activity occurred outside the current telemetry
    window
  requires: 30 days of hb_process_activity retention
  risk: An intrusion that occurred several weeks ago might be missed if process logs
    rotate too quickly.
  stage: execution-automated-shell-c2
- id: no-agent-coverage
  question: whether an unmonitored server is currently compromised
  requires: an endpoint agent on every server
  risk: An unmanaged Confluence instance provides an invisible foothold for the attacker.
coverage:
- stage: initial-access-axis-soap-rce
  status: covered
  steps:
  - soap-exploit-leads
- stage: execution-automated-shell-c2
  status: covered
  steps:
  - java-shell-execution
  - tunnel-dns-activity
- stage: discovery-credential-harvesting
  status: covered
  steps:
  - attachment-access-prevalence
- reason: Belongs to another part of the 'Rapid7 Detected Exploitation of CVE-2026-90436
    against Atlassian Confluence Data Center, N-able N-central also Exploited' series.
  stage: lateral-movement-identity-pivot
  status: out_of_scope
- reason: Belongs to another part of the 'Rapid7 Detected Exploitation of CVE-2026-90436
    against Atlassian Confluence Data Center, N-able N-central also Exploited' series.
  stage: exfiltration-cloud-warehouse-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of CVE-2026-90436 allows unauthenticated RCE on Confluence
    servers, making it a critical threat to intellectual property and internal credentials.
    Identifying post-exploit harvesting behavior provides high assurance that the
    organization is not compromised.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary exploits the Apache Axis SOAP vulnerability (CVE-2026-90436)
  in Atlassian Confluence to execute shell commands and harvest credentials from the
  attachment store.
labels:
- hunt
- attack.t1190
- attack.t1059.004
- attack.t1105
- attack.t1572
- attack.t1083
- attack.t1552.001
- attack.t1213
- discovery
- execution
- exfiltration
- initial access
- lateral movement
name: Axis RCE and Confluence Credential Harvesting
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified as potential exploit targets from the lead query;
      paste these back in to refine the fan-out queries.
    type: list[host]
  tunnel_domains:
    default:
    - webhook.site
    description: Base domains for tunneling and exfiltration services identified in
      the report.
    from:
      kind: article
      observed: '2026-11-16'
      ref: Rapid7
    type: list[domain]
  vulnerable_uris:
    default:
    - /plugins/servlet/soap-axis1/confluenceservice-v2
    description: The vulnerable Apache Axis SOAP endpoint in Confluence.
    from:
      kind: article
      observed: '2026-11-16'
      ref: Rapid7
    type: list[string]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed Atlassian Confluence Data Center servers. The
  lead query is highly effective if HTTP access logs are retained; if not, proceed
  directly to the process execution step using the whole estate.
references:
- name: "Rapid7 \u2014 ETR: Rapid7 Detected Exploitation of CVE-2026-90436 against\
    \ Atlassian Confluence Data Center"
  url: https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited
related:
- hunt: lateral-movement-identity-pivot
  reason: This hunt focuses on the initial Confluence foothold and local harvesting;
    the subsequent identity pivot to cloud resources belongs in a follow-on identity
    hunt.
  relation: out-of-scope-alternative
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
  index: 1
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Axis RCE and Confluence Credential Harvesting

The adversary exploits a critical remote code execution vulnerability in Apache Axis. This hunt identifies the attack using a gated flow. The hunt first searches for HTTP 500 errors on the Axis SOAP endpoint. If potential exploit traffic is found, the hunt fans out to identify anomalous child processes spawned by the Java application, rare access to the Confluence attachment directory, and connections to known tunneling services. This approach allows an analyst to confirm the initial exploit, the execution of automated shells, and the subsequent harvesting of sensitive documents.

## soap-exploit-leads
<!-- Lead: SOAP exploit requests -->
Identify potential Axis exploitation by finding HTTP POST requests to the SOAP endpoint that resulted in an Internal Server Error (500), matching the behavior observed in successful compromises.

```sqlite target=web role=scoping params=(lookback_days=lookback_days, vulnerable_uris=vulnerable_uris)
~~~yaml
expected: Rows naming hosts that received suspicious POST requests to the Axis endpoint.
  Silence suggests no active targeting of the SOAP API in the window.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- status_code
- time
- http_method
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, status_code, time FROM hb_http_activity WHERE instr(',' || '{{vulnerable_uris}}' || ',', ',' || LOWER(url_path) || ',') > 0 AND status_code = 500 AND http_method = 'POST' AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate lead -->
```agent target=hunter
cite: required
context:
- soap-exploit-leads
max_iterations: 3
objective: Determine if the observed SOAP requests indicate a confirmed exploit attempt
  by analyzing source IP and request patterns.
success_criteria: A verdict of malicious or suspicious for at least one host, citing
  specific rows.
tools:
- endpoint
- web
```

## gate-on-lead
<!-- Gate on lead -->
if~: "the evaluate-lead verdict identifies at least one host with suspicious SOAP exploit attempts" (confidence: high, judge=hunter)
then: → corroborate-activity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-access-log-detail)
else: → close-out

## corroborate-activity
<!-- Corroborate activity -->
parallel:
- → java-shell-execution
- → attachment-access-prevalence
- → tunnel-dns-activity
join: → triage-intrusion

## java-shell-execution
<!-- Java shell execution -->
Identify Confluence's Java process spawning bash or network utilities, which indicates successful remote code execution from the Axis exploit.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A shell or curl process running under the confluence service account with
  a Java parent. This is a high-confidence indicator of exploitation.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(parent_process_name) LIKE '%java%' AND (LOWER(process_name) LIKE '%bash%' OR LOWER(process_name) LIKE '%sh%' OR LOWER(process_name) LIKE '%curl%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## attachment-access-prevalence
<!-- Attachment access prevalence -->
Identify rare processes accessing the Confluence attachment directory, revealing the automated data harvesting observed in the report.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes interacting with the attachment store. Normal web server
  activity should appear across the fleet; attacker scripts will be rare.
prevalence:
  by: device_hostname
  key:
  - proc
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, LOWER(process_name) AS proc, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE file_path LIKE '%/attachments/v4/%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY proc HAVING hosts <= 3
```

## tunnel-dns-activity
<!-- Tunnel DNS activity -->
Look for DNS resolutions of Pinggy, Cloudflare Tunnels, and Webhook.site, which attackers use to receive shell commands and exfiltrate harvested data.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, tunnel_domains=tunnel_domains)
~~~yaml
expected: Hosts resolving tunnel provider subdomains. This corroborates C2 activity
  following a successful exploit.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups FROM hb_dns_activity WHERE (instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.trycloudflare.com' OR LOWER(query_hostname) LIKE '%.pinggy.net') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## triage-intrusion
<!-- Triage intrusion -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- java-shell-execution
- attachment-access-prevalence
- tunnel-dns-activity
max_iterations: 6
objective: Determine if the evidence across HTTP, process, file, and DNS surfaces
  confirms a successful breach and data harvesting on the Confluence server.
success_criteria: A final verdict of malicious, suspicious, or benign per host, citing
  evidence from all four surfaces.
tools:
- endpoint
- web
```

## route-on-triage
<!-- Route on triage -->
if~: "the triage-intrusion verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-retention)
else: → close-out

## isolate-server
<!-- Isolate server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and preserve all logs for forensic analysis. Collect copies of any scripts found in the Confluence temporary directories.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited SOAP requests and shell execution logs. Verify the contents of the attachment directory to identify which specific sensitive documents were accessed by the attacker's scripts.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the search parameters and the absence of identified indicators. Re-verify that the Remote XML-RPC & SOAP API is disabled on Confluence instances where possible.
```
→ end
