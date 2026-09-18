---
analysis: A simple detection rule may alert on shell spawns from web processes. This
  hunt adds context by correlating vulnerability inventory, baselining unusual child
  processes for the specific SharePoint service, and focusing on the specific BCS
  endpoints involved in this exploit chain.
blind_spots:
- id: no-process-visibility
  question: Did w3wp.exe spawn a shell on hosts without endpoint coverage?
  requires: hb_process_activity from an endpoint agent
  risk: An intrusion could go undetected if the server is only monitored at the network
    level.
  stage: sharepoint-shell-execution
- id: http-body-blindness
  question: Does the HTTP POST request contain the malicious .NET gadget chain?
  requires: WAF or Proxy logs with full body capture
  risk: Metadata (URL/Method) only shows interaction with the BCS endpoint, not the
    content of the exploit payload.
  stage: rce-via-dotnet-instantiation
coverage:
- stage: vulnerability-inventory
  status: covered
  steps:
  - vulnerable-inventory
- stage: unauthenticated-web-exploitation
  status: covered
  steps:
  - bcs-web-activity
- blind_spot: http-body-blindness
  reason: hb_http_activity does not record POST bodies where .NET gadget chains are
    delivered.
  stage: rce-via-dotnet-instantiation
  status: not_visible
- stage: sharepoint-shell-execution
  status: covered
  steps:
  - sharepoint-shell-spawns
  - rare-sharepoint-children
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This unauthenticated RCE chain against a ubiquitous platform is critical
    and has been added to the CISA KEV catalog. Verifying absence of exploitation
    on vulnerable assets is a high-priority business requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is chaining an authentication bypass with a .NET gadget chain
  to execute shell commands on a SharePoint server via the Business Connectivity Services
  endpoint.
labels:
- hunt
- attack.t1190
- attack.t1059.003
name: SharePoint Unauthenticated Remote Code Execution
parameters:
  cve_ids:
    default:
    - CVE-2026-55040
    - CVE-2026-63520
    description: Target CVE identifiers for SharePoint.
    from:
      kind: article
      observed: '2026-08-11'
      ref: Rapid7
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-11'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    from:
      kind: manual
      observed: '2026-08-11'
      ref: analyst-defined
    type: list[host]
  sharepoint_parents:
    default:
    - w3wp.exe
    - owstimer.exe
    description: Common SharePoint service and worker processes.
    from:
      kind: manual
      observed: '2026-08-11'
      ref: standard-sharepoint-procs
    type: list[string]
  shell_names:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - wsl.exe
    description: Common shell interpreters launched after RCE.
    from:
      kind: manual
      observed: '2026-08-11'
      ref: common-shells
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed SharePoint servers. Start with hosts identified
  by vulnerability findings for CVE-2026-55040 or CVE-2026-63520.
references:
- name: "Rapid7 \u2014 CVE-2026-63520: Microsoft SharePoint Remote Code Execution"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed/
related:
- hunt: sharepoint-unusual-service-account-behavior
  reason: If RCE is confirmed, a follow-up hunt for the SharePoint service account's
    subsequent lateral movement and data access is necessary.
  relation: follows
scenario:
  stages:
  - name: Vulnerability Inventory
    observables:
    - CVE-2026-55040
    - CVE-2026-63520
    - SharePoint Server Subscription Edition version < 16.0.19725.20522
    - SharePoint Server 2019 version < 16.0.10417.20198
    - SharePoint Server 2016 version < 16.0.5565.1001
    slug: vulnerability-inventory
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthenticated Web Exploitation
    observables:
    - HTTP POST requests to SharePoint Business Connectivity Services endpoints
    - Unauthenticated access to restricted SharePoint web paths
    - Inbound traffic to SharePoint web ports (80, 443)
    slug: unauthenticated-web-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: RCE via .NET Instantiation
    observables:
    - Custom .NET gadget chains in HTTP request bodies
    - Business Connectivity Services processing malicious .NET types
    slug: rce-via-dotnet-instantiation
    tactic: execution
    techniques:
    - T1190
  - name: SharePoint Shell Execution
    observables:
    - cmd.exe spawned by SharePoint service account
    - powershell.exe spawned by SharePoint service account
    - w3wp.exe spawning command-line interpreters
    slug: sharepoint-shell-execution
    tactic: execution
    techniques:
    - T1059.003
  summary: An unauthenticated remote code execution chain against Microsoft SharePoint
    leverages an authentication bypass (CVE-2026-55040) to reach a secondary vulnerability
    in Business Connectivity Services (CVE-2026-63520). Attackers exploit an unsafe
    .NET type instantiation issue to execute arbitrary OS commands with the privileges
    of the SharePoint service account.
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


# SharePoint Unauthenticated Remote Code Execution

This hunt identifies exploitation of CVE-2026-63520 and CVE-2026-55040. It starts by scoping the estate for vulnerable SharePoint instances and then monitors for the critical indicator of SharePoint worker processes (w3wp.exe) or the Timer service spawning command-line interpreters. It uses a parallel workstream to baseline rare child processes and monitor for specific HTTP POST activity directed at the Business Connectivity Services (BCS) endpoints, which are the primary vector for this chain.

## vulnerable-inventory
<!-- Identify Vulnerable SharePoint Hosts -->
Identify hosts in the environment reported as vulnerable to the SharePoint RCE chain to prioritize investigations.

```sqlite target=endpoint role=scoping params=(cve_ids=cve_ids)
~~~yaml
expected: Rows containing specific CVE IDs and associated device identifiers. Silence
  indicates no known vulnerable hosts are currently reporting this telemetry.
reads:
- cve_uid
- device_uid
- first_seen
- last_seen
- severity
- status
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_uid, cve_uid, severity, title, first_seen, last_seen FROM hb_vulnerability_finding WHERE instr(',' || '{{cve_ids}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed'
```

## monitor-activity
<!-- Monitor Behavior and Context -->
parallel:
- → sharepoint-shell-spawns
- → rare-sharepoint-children
- → bcs-web-activity
join: → triage-evidence

## sharepoint-shell-spawns
<!-- SharePoint Processes Spawning Shells -->
Detect a SharePoint worker or timer process launching a command-line interpreter, the direct outcome of RCE.

```sqlite target=endpoint role=detection-candidate params=(sharepoint_parents=sharepoint_parents, shell_names=shell_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A SharePoint process spawning a shell is highly unusual and suggests successful
  RCE.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line FROM hb_process_activity WHERE (instr(',' || '{{sharepoint_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-sharepoint-children
<!-- Baseline Rare SharePoint Child Processes -->
Identify unusual binaries executed by SharePoint that are not standard shells, surfacing anomalies via prevalence.

```sqlite target=endpoint role=baseline params=(sharepoint_parents=sharepoint_parents, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary launched by SharePoint appearing on only one or two hosts. This
  captures custom payloads or renamed tools.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) AS proc, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{sharepoint_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING host_count <= 2 ORDER BY host_count ASC
```

## bcs-web-activity
<!-- BCS Endpoint HTTP POST Activity -->
Confirm HTTP interaction with Business Connectivity Services, where the RCE payload is delivered via .NET gadget chains.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: POST requests to BCS-related endpoints. Successful POSTs (200 OK) followed
  by shell activity are strong indicators of exploitation.
reads:
- device_hostname
- http_method
- src_endpoint_ip
- status_code
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, http_method, user_agent, status_code, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%_vti_bin/business%' OR LOWER(url_path) LIKE '%businessdatametadata%') AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage Triage Results -->
```agent target=hunter
cite: required
context:
- vulnerable-inventory
- sharepoint-shell-spawns
- rare-sharepoint-children
- bcs-web-activity
max_iterations: 5
objective: Determine if the SharePoint shell commands resulted from unauthenticated
  RCE via CVE-2026-63520.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  process and HTTP rows.
tools:
- endpoint
- web
```

## verdict-decision
<!-- Route Based on Verdict -->
if~: "the triage verdict is malicious for at least one host exhibiting shells from SharePoint processes" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## isolate-server
<!-- Isolate Affected SharePoint Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the SharePoint server from the network and investigate the service account permissions.
```
→ analyst-review

## analyst-review
<!-- Analyst Investigation -->
```manual target=analyst
Review the shell command history and w3wp.exe activity. Check web logs for anomalous POST payloads and source IPs from the BCS activity step.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record the time window and scope. If any suspicious but non-malicious activity was found (e.g., admin usage of PowerShell via w3wp), document it for future tuning.
```
→ end
