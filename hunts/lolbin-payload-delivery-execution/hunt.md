---
analysis: A simple detection rule might fire on 'certutil -urlcache'. This hunt pivots
  from that lead into DNS lookups and script block content (hb_script_activity) to
  see if the downloaded file was actually executed, providing a full investigation
  chain for the analyst.
blind_spots:
- id: incomplete-telemetry
  question: Are all web-facing assets currently reporting process and script activity?
  requires: endpoint-visibility
  risk: A host without EDR coverage could be the initial beachhead and would not show
    up in the behavior steps.
- id: http-payload-visibility
  question: What was the exact exploit payload delivered to the application?
  requires: hb_http_activity with full request bodies
  risk: We can see the request metadata but not the binary content or script injected
    during the exploit phase.
  stage: initial-access-application-exploit
coverage:
- stage: initial-access-application-exploit
  status: covered
  steps:
  - scoping-web-assets
  - inbound-http-signals
- stage: defense-evasion-certutil-download
  status: covered
  steps:
  - certutil-proxy-execution
  - dns-c2-lookup
- stage: execution-powershell-payload
  status: covered
  steps:
  - rare-powershell-scripts
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: LOLBin usage for payload staging is a high-confidence indicator of
    evasion-conscious actors; finding these before they achieve lateral movement is
    critical to preventing impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using certutil.exe to download a malicious payload from
  a known C2 domain and executing it via PowerShell to evade signature-based detection.
labels:
- hunt
- attack.t1059.001
- attack.t1190
- attack.t1218
name: LOLBin-based Payload Delivery and Execution
parameters:
  c2_domains:
    default:
    - attack.the
    description: C2 domains identified in research or logs.
    from:
      kind: article
      observed: '2026-09-08'
      ref: "Elastic Security Labs \u2014 Why 2026 is the Year to Upgrade to an Agentic\
        \ AI SOC"
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Target specific hosts found in the scoping step; leave empty for
      fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the scoping step on internet-facing servers (Apache, Nginx, IIS)
  as they are the primary targets for T1190. If specific asset groups are known to
  be 'high value', include them in the scope_hosts parameter.
references:
- name: "Elastic Security Labs \u2014 Why 2026 is the Year to Upgrade to an Agentic\
    \ AI SOC"
  url: https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc
related:
- hunt: lateral-movement-via-wmi
  reason: If execution is confirmed on the beachhead, the next step is typically lateral
    movement using similar LOLBins or WMI.
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Application
    observables:
    - Incoming HTTP requests to web services
    - Vulnerability findings on internet-facing assets
    slug: initial-access-application-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Proxy Execution via Certutil
    observables:
    - certutil.exe
    - certutil.exe -urlcache -split -f
    - 'domain: attack.the'
    - base64-encoded payload downloads
    slug: defense-evasion-certutil-download
    tactic: defense-evasion
    techniques:
    - T1218
  - name: PowerShell Script Execution
    observables:
    - powershell.exe
    - Script block execution
    - base64-encoded command lines
    slug: execution-powershell-payload
    tactic: execution
    techniques:
    - T1059.001
  summary: This campaign involves the exploitation of public-facing applications to
    deliver a base64-encoded payload via the legitimate certutil.exe utility. Once
    the payload is staged, the adversary utilizes PowerShell to execute malicious
    logic, blending into normal system activity through the use of Living off the
    Land Binaries (LOLBins).
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# LOLBin-based Payload Delivery and Execution

This hunt targets a common LOLBin-based attack chain: exploitation of a web application followed by proxy execution via certutil.exe for staging and PowerShell for the final payload. We look for abnormal certutil download flags, rare PowerShell script blocks containing obfuscation or base64, and corroborating DNS and HTTP telemetry to identify the initial entry point and C2 activity.

## scoping-web-assets
<!-- Identify internet-facing web assets -->
Identify hosts running common web services that may be susceptible to exploitation (T1190).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts acting as web servers. Silence means no such software is
  indexed, suggesting this hunt should be run on a broader scope.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE package_name IN ('apache2', 'nginx', 'httpd', 'microsoft-iis', 'tomcat', 'websphere') OR LOWER(package_name) LIKE '%web%'
```

## certutil-proxy-execution
<!-- Certutil download and proxy execution -->
Detect certutil.exe being used with download flags, even if the binary has been renamed (T1218).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process executions showing certutil contacting remote domains or using the
  split/urlcache flags. These are high-confidence indicators of staging.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_original_file_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\certutil.exe' OR LOWER(process_original_file_name) = 'certutil.exe') AND (process_cmd_line LIKE '%-urlcache%' OR process_cmd_line LIKE '%-split%' OR process_cmd_line LIKE '%-f%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## corroborate-activity
<!-- Corroborate on network and execution surfaces -->
parallel:
- → dns-c2-lookup
- → rare-powershell-scripts
- → inbound-http-signals
join: → triage-verdict

## dns-c2-lookup
<!-- DNS lookups to target domains -->
Verify if the hosts that ran certutil also performed lookups for known C2 domains (T1218).

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A direct match of the provided C2 domain on the endpoint. Silence means
  the domain might have rotated, but behavior queries still matter.
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-powershell-scripts
<!-- Rare PowerShell execution patterns -->
Identify unique PowerShell scripts containing base64 or obfuscation that stand out across the fleet (T1059.001).

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unusual PowerShell script blocks seen on very few hosts. Common management
  scripts will be filtered out by the HAVING clause.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 3
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT script_content, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_script_activity WHERE script_type = 'PowerShell' AND (LOWER(script_content) LIKE '%frombase64string%' OR LOWER(script_content) LIKE '%-enc%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY script_content HAVING hosts <= 3
```

## inbound-http-signals
<!-- Suspicious inbound HTTP exploit attempts -->
Identify potential initial access attempts through web application exploitation (T1190).

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests showing common exploit strings (SQLi, cmd injection) on paths
  associated with the web assets identified in scoping.
reads:
- device_hostname
- src_endpoint_ip
- status_code
- time
- url_path
- url_query
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, url_query, status_code, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%.php%' OR LOWER(url_path) LIKE '%.jsp%' OR LOWER(url_path) LIKE '%.asp%') AND (LOWER(url_query) LIKE '%select%' OR LOWER(url_query) LIKE '%union%' OR LOWER(url_query) LIKE '%cmd%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-verdict
<!-- Triage automated LOLBin investigation -->
```agent target=hunter
cite: required
context:
- certutil-proxy-execution
- dns-c2-lookup
- rare-powershell-scripts
- inbound-http-signals
max_iterations: 4
objective: Determine if the Certutil download, DNS resolution, and PowerShell execution
  constitute a single coordinated attack chain on any host.
success_criteria: A verdict of malicious | suspicious | benign for every host showing
  activity, citing row IDs.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host showing the full certutil and powershell chain" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: incomplete-telemetry)
else: → close-as-benign

## isolate-infected-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate the identified malicious processes, and collect the staged payload from the paths identified in the triage context.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the telemetry from the triage step. If malicious, ensure the host is isolated and proceed with root cause analysis of the web application vulnerability.
```
→ end

## close-as-benign
<!-- Close out benign findings -->
```manual target=analyst
If the activity was identified as legitimate maintenance or testing, record the process paths and command lines for future exclusion in tuning.
```
→ end
