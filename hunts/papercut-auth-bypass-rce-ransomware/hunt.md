---
analysis: A static rule for shells spawned by PaperCut is easily bypassed by different
  interpreters. This hunt correlates the specific HTTP bypass patterns with evasion
  (log tampering) and organizational impact (mass encryption), providing the necessary
  context for emergency response.
blind_spots:
- id: http-tls-visibility
  question: whether the URI bypass attempts were visible in network traffic
  requires: TLS decryption or server-side HTTP logs
  risk: If PaperCut uses HTTPS and we lack decryption, hb_http_activity will not show
    the url_query substrings used for the bypass.
  stage: initial-access-tapestry-auth-bypass
- id: nashorn-in-memory-execution
  question: whether the malicious JavaScript execution occurred within the Java process
  requires: JVM-level instrumentation
  risk: We only see the aftermath (the spawned shell). The initial Nashorn execution
    inside the PaperCut process is invisible to process activity logs.
  stage: remote-code-execution-nashorn
coverage:
- stage: initial-access-tapestry-auth-bypass
  status: covered
  steps:
  - tapestry-auth-bypass-requests
- stage: remote-code-execution-nashorn
  status: covered
  steps:
  - papercut-shell-execution
- stage: defense-evasion-log-tampering
  status: covered
  steps:
  - papercut-log-tampering
- stage: data-encryption-ransomware
  status: covered
  steps:
  - ransomware-file-impact
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: configuration-tampering-db-lookup
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: PaperCut is a high-value target for ransomware groups due to its
    widespread use and common internet exposure. A negative result confirms that the
    zero-day exploit chain has not been successfully used in the current lookback
    window.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has exploited the PaperCut NG/MF authentication bypass vulnerabilities
  to reconfigure external database lookups and execute arbitrary code, leading to
  log tampering or ransomware deployment.
labels:
- hunt
- attack.t1190
- attack.t1486
- attack.t1203
- attack.t1562.001
name: PaperCut NG/MF Auth Bypass to RCE and Ransomware
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for exploitation and post-compromise activity.
    type: number
  scope_hosts:
    default: []
    description: Target specific hostnames if PaperCut servers are already known.
    type: list[host]
  shell_names:
    default:
    - cmd.exe
    - sh
    - powershell.exe
    - pwsh.exe
    - bash
    - zsh
    description: Common shell interpreters used for post-exploitation execution across
      all platforms.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing PaperCut servers identified in the inventory.
  If the HTTP surface is empty, focus on behavioral process execution signs (PaperCut
  processes spawning shells) as the bypass may be encrypted.
references:
- name: "Rapid7 \u2014 PaperCut NG/MF Critical Zero-Day Exploited in the Wild"
  url: https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild
related:
- hunt: configuration-tampering-db-lookup
  reason: Direct monitoring of PaperCut configuration database files or registry keys
    is a separate forensic task not covered by this behavioral hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Apache Tapestry Authentication Bypass
    observables:
    - POST /app?service=direct/1/Error/ConfigEditor/quickFindForm
    - POST /app?service=direct/1/Error/ConfigEditor/$Form
    - POST /app?service=direct/1/Error/UserList/$QuickFind.$Form
    - POST /app?service=direct/1/Exception/ConfigEditor/
    - POST /app?service=direct/1/Home/ConfigEditor/
    slug: initial-access-tapestry-auth-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Database Lookup Configuration
    observables:
    - Modification of user-lookup.db-driver
    - Modification of user-lookup.db-url
    - Modification of user-lookup.id-to-username-sql
    - Modification of user-lookup.enabled
    - 'JDBC string: jdbc:no:x'
    slug: configuration-tampering-db-lookup
    tactic: persistence
    techniques:
    - T1190
  - name: Remote Code Execution via Nashorn Engine
    observables:
    - pc-app.exe spawning cmd.exe
    - pc-app.exe spawning /bin/sh
    - Nashorn JavaScript-backed database trigger execution
    - Apache Derby foreignViews feature activation
    - H2 JDBC URL with INIT statement
    slug: remote-code-execution-nashorn
    tactic: execution
    techniques:
    - T1203
  - name: Application Log Tampering
    observables:
    - Deletion of PaperCut server.log
    - Truncation of PaperCut server.log
    slug: defense-evasion-log-tampering
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Data Encrypted for Impact
    observables:
    - Mass file encryption by pc-app.exe or its children
    slug: data-encryption-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Attackers exploit a critical authentication bypass in PaperCut NG/MF to
    manipulate internal configuration settings, enabling remote code execution via
    unsafe JDBC class loading and the Nashorn JavaScript engine. This exploit chain,
    comprising CVE-2026-81578 and CVE-2026-82078, is frequently used by ransomware
    operators to gain initial access and encrypt server data.
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


# PaperCut NG/MF Auth Bypass to RCE and Ransomware

This hunt investigates the zero-day exploit chain affecting PaperCut NG and PaperCut MF (CVE-2026-81578 and CVE-2026-82078). The hunt follows a phased flow: first scoping PaperCut application servers, then detecting initial access via specific HTTP bypass URIs and subsequent shell execution from the PaperCut process across Windows, Linux, and macOS platforms. Finally, it identifies follow-on impact including application log tampering and high-volume file modification characteristic of ransomware activity.

## scope-papercut-servers
<!-- Scope PaperCut application servers -->
Locate the hosts running PaperCut to focus the behavioral search.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts with PaperCut NG or MF installed. Silence means PaperCut is not indexed
  on any monitored host.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%papercut%'
```

## early-stage-investigation
<!-- Initial access and execution investigation -->
parallel:
- → tapestry-auth-bypass-requests
- → papercut-shell-execution
join: → agent-triage-early

## tapestry-auth-bypass-requests
<!-- Detect Apache Tapestry auth bypass attempts -->
Search for HTTP POST requests targeting administrative components via public bypass pages and specific configuration identifiers.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A request to /app with query parameters referencing ConfigEditor or UserList
  via the Error, Exception, or Home pages including targeted database configuration
  strings. This is a high-fidelity exploit indicator.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- url_query
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, url_query, time FROM hb_http_activity WHERE url_path = '/app' AND http_method = 'POST' AND LOWER(url_query) LIKE '%service=direct%' AND (LOWER(url_query) LIKE '%configeditor%' OR LOWER(url_query) LIKE '%userlist%') AND (LOWER(url_query) LIKE '%error%' OR LOWER(url_query) LIKE '%exception%' OR LOWER(url_query) LIKE '%home%') AND (LOWER(url_query) LIKE '%user-lookup.db%' OR LOWER(url_query) LIKE '%user-lookup.id%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## papercut-shell-execution
<!-- Detect PaperCut spawning shells -->
Identify instances where a PaperCut application server process spawns a command shell to detect how attackers use the vulnerability for code execution.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, shell_names=shell_names)
~~~yaml
expected: A command interpreter running with a PaperCut process as its parent across
  Windows, Linux, or macOS. This strongly suggests remote code execution.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%pc-app%' AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-early
<!-- Triage initial access and execution -->
```agent target=hunter
cite: required
context:
- tapestry-auth-bypass-requests
- papercut-shell-execution
max_iterations: 3
objective: Determine if any host shows both the authentication bypass HTTP requests
  and subsequent shell execution from the PaperCut process.
success_criteria: A list of hosts with confirmed shell execution following HTTP bypass
  attempts.
tools:
- endpoint
- web
```

## impact-investigation
<!-- Impact and evasion investigation -->
parallel:
- → papercut-log-tampering
- → ransomware-file-impact
join: → agent-triage-follow-on

## papercut-log-tampering
<!-- Detect PaperCut server log tampering -->
Identify when the server.log is updated or deleted, indicating defense evasion.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: An update or deletion of server.log. Silence may mean no tampering occurred,
  or the agent missed the event before the file was removed.
reads:
- device_hostname
- process_name
- file_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_name, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'server.log' AND activity_id IN (3, 4) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransomware-file-impact
<!-- Detect high-volume file activity by PaperCut -->
Find signs of mass file encryption or modification initiated by PaperCut processes or their children to determine the final stage of the attack.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A PaperCut process modifying more than 100 distinct files on a single host.
  This is a behavioral outlier for a print server.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 2
reads:
- device_hostname
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) AS affected_files, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(process_name) LIKE '%pc-app%' OR LOWER(parent_process_name) LIKE '%pc-app%') AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING affected_files > 100
```

## agent-triage-follow-on
<!-- Triage breach impact -->
```agent target=hunter
cite: required
context:
- agent-triage-early
- papercut-log-tampering
- ransomware-file-impact
max_iterations: 4
objective: Analyze the full attack chain from initial HTTP bypass to process execution
  and the final file-system impact, using the context from the earlier triage step.
success_criteria: A detailed per-host report citing the specific URIs, spawned shells,
  and the follow-on file impact.
tools:
- endpoint
- web
```

## route-on-impact
<!-- Route on impact verdict -->
if~: "The agent-triage-follow-on verdict confirms a complete attack chain from initial HTTP bypass to process execution and subsequent file-system impact." (confidence: high, judge=hunter)
then: → isolate-compromised-server
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: http-tls-visibility)
else: → analyst-forensic-review

## isolate-compromised-server
<!-- Isolate compromised server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised PaperCut server from the network immediately using the EDR containment action.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the shell commands spawned by the PaperCut process and identify any malicious JDBC URLs configured in the application. Document the impact of the mass file modifications.
```
→ patch-and-remediate

## patch-and-remediate
<!-- Patch and remediate -->
```manual target=analyst
Apply the third emergency patch version released by PaperCut and restrict the administrative interface to known internal IP ranges only.
```
→ end
