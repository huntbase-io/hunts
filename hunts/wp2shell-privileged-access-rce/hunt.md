---
analysis: A simple rule might catch 'PHP spawning bash', but this hunt performs a
  multi-surface correlation between vulnerable version discovery, administrative login
  patterns, plugins directory file integrity, and rare child process baselining that
  a static rule cannot replicate.
blind_spots:
- id: visibility-gap-telemetry
  question: Whether shells were spawned on hosts where the agent is absent.
  requires: Endpoint telemetry (hb_process_activity) on WordPress hosts.
  risk: A host without an EDR or osquery agent is invisible to process and file integrity
    queries, leaving only network logs which may be encrypted.
  stage: malicious-plugin-execution
- id: encrypted-paths
  question: The specific URL paths accessed on the server.
  requires: HTTPS decryption or server access logs.
  risk: If hb_http_activity is sourced from a network-level proxy without TLS inspection,
    URI paths like /wp-admin/ will be hidden, preventing correlation with login activity.
  stage: unauthorized-admin-access
coverage:
- stage: unauthorized-admin-access
  status: covered
  steps:
  - admin-login-http
- stage: malicious-plugin-execution
  status: covered
  steps:
  - php-spawning-shells
  - rare-web-server-children
  - plugin-directory-writes
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: rest-api-batch-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: sql-injection-author-bypass
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: wp2shell (CVE-2026-63030) is a critical, unauthenticated RCE chain
    actively exploited in the wild (CISA KEV). Patching the core does not remove accounts
    or plugins created during a prior compromise; this hunt is the only way to verify
    the remediation of the payload itself.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has used the wp2shell exploit chain to create an unauthorized
  administrator account, deploy a malicious plugin, and execute system commands from
  the web server process.
labels:
- hunt
- attack.t1078
- attack.t1190
- attack.t1021.001
- attack.t1059.003
name: 'wp2shell: Privileged Access and Code Execution'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-22'
      ref: default
    type: number
  shell_paths:
    default:
    - /bin/sh
    - /bin/bash
    - /usr/bin/bash
    - c:\windows\system32\cmd.exe
    - c:\windows\system32\windowspowershell\v1.0\powershell.exe
    - /usr/bin/python
    - /usr/bin/perl
    - /usr/bin/nc
    - /usr/bin/curl
    - /usr/bin/wget
    description: Full paths to common shell and utility binaries used by web shells.
    from:
      kind: manual
      observed: '2026-07-22'
      ref: common-attack-tools
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets WordPress servers running vulnerable versions (6.9.0-6.9.4
  and 7.0.0-7.0.1). High-value assets like public-facing web servers should be the
  primary focus.
references:
- name: "Rapid7 \u2014 wp2shell: critical RCE in WordPress core"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/
related:
- hunt: wp2shell-initial-exploitation
  reason: This hunt focuses on the post-exploitation RCE; initial REST API batch exploitation
    is handled by a sibling hunt focusing on HTTP request desynchronization patterns.
  relation: out-of-scope-alternative
- hunt: wordpress-core-wp2shell-web-exploitation
  relation: follows
scenario:
  stages:
  - name: REST API Batch Route Confusion
    observables:
    - /wp-json/batch/v1
    - ?rest_route=/batch/v1
    slug: rest-api-batch-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: SQL Injection via author__not_in
    observables:
    - author__not_in parameter containing SQL keywords
    - UNION SELECT statements in HTTP request body
    slug: sql-injection-author-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized Administrator Login
    observables:
    - Login to /wp-login.php or /wp-admin/
    - Creation of new administrator user account
    slug: unauthorized-admin-access
    tactic: initial-access
    techniques:
    - T1078
  - name: Malicious Plugin RCE
    observables:
    - POST /wp-admin/plugin-install.php
    - Creation of .php files in /wp-content/plugins/
    - PHP process spawning shell commands like sh, bash, or cmd.exe
    slug: malicious-plugin-execution
    tactic: execution
    techniques:
    - T1078
    - T1021.001
  summary: Attackers exploit a logic flaw in the WordPress REST API batch processor
    (CVE-2026-63030) to trigger route confusion, enabling a SQL injection (CVE-2026-60137)
    via the author__not_in parameter. Successful exploitation allows for unauthenticated
    creation of administrator accounts, which are subsequently used to log in and
    upload malicious plugins for full remote code execution.
series:
  index: 2
  slug: wp2shell-critical-rce-in-wordpress-core
  title: 'wp2shell: critical RCE in WordPress core'
  total: 2
severity: critical
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


# wp2shell: Privileged Access and Code Execution

Following the initial exploitation of CVE-2026-63030 and CVE-2026-60137, an attacker gains privileged access to the WordPress dashboard. This hunt identifies the 'payload' phase: the creation of new administrator sessions, the upload of malicious PHP code disguised as plugins, and the subsequent execution of system shells or utilities. By correlating software inventory for vulnerable WordPress versions with anomalous file writes to the plugins directory and rare child processes spawned by PHP/Nginx/Apache, the hunt provides high-fidelity evidence of host compromise. It specifically looks for the desynchronization of the REST API handler that allows unauthenticated attackers to operate as administrators.

## vulnerable-wordpress-inventory
<!-- Identify vulnerable WordPress versions -->
Scope the hunt to hosts running WordPress versions 6.9.x (<6.9.5) or 7.0.x (<7.0.2) based on the vulnerability report.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running vulnerable WordPress core. Silence is evidence of
  absence if inventory is complete.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) = 'wordpress' AND ((package_version LIKE '6.9.%' AND package_version < '6.9.5') OR (package_version LIKE '7.0.%' AND package_version < '7.0.2'))
```

## php-spawning-shells
<!-- Web server processes spawning shell utilities -->
Detect the final stage of the RCE where the PHP process or web server launches an interactive shell or downloader utility.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, shell_paths=shell_paths)
~~~yaml
expected: Actionable evidence of system command execution by the web application.
  Any hit is high-fidelity.
reads:
- device_hostname
- process_path
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_path, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%php%' OR LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%apache%') AND (instr(',' || '{{shell_paths}}' || ',', ',' || LOWER(process_path) || ',') > 0 OR LOWER(process_path) LIKE '%/sh' OR LOWER(process_path) LIKE '%/bash' OR LOWER(process_path) LIKE '%/cmd.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with file and HTTP activity -->
parallel:
- → rare-web-server-children
- → plugin-directory-writes
- → admin-login-http
join: → triage-compromise

## rare-web-server-children
<!-- Rare child processes of web servers -->
Identify anomalous binaries launched by the web server that may have been renamed or aren't in standard lists.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries (like 'nc' or custom wrappers) running only on one or two
  hosts in the fleet.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  - process_name
  rare_below: 3
reads:
- parent_process_name
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT parent_process_name, process_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%php%' OR LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%apache%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY parent_process_name, process_name HAVING hosts <= 2 ORDER BY hosts ASC
```

## plugin-directory-writes
<!-- Unexpected PHP file writes in plugin directories -->
Monitor the creation or modification of PHP files in sensitive WordPress directories, which is the primary persistence mechanism.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: PHP file creation/overwrite by the web server process rather than an authorized
  update tool.
reads:
- device_hostname
- file_path
- file_name
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, file_name, process_name, activity_id, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/wp-content/plugins/%.php' OR LOWER(file_path) LIKE '%\\wp-content\\plugins\\%.php') AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days')
```

## admin-login-http
<!-- Aggregated administrative logins -->
Identify successful logins to wp-login.php or /wp-admin/ paths to correlate with the timing of file and process activity.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Login events from unexpected IPs occurring just before the deployment of
  a new plugin or execution of shells.
reads:
- device_hostname
- url_path
- src_endpoint_ip
- status_code
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, status_code, user_agent, COUNT(*) as request_count, MIN(time) as first_request, MAX(time) as last_request FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%wp-login.php%' OR LOWER(url_path) LIKE '%/wp-admin/%') AND status_code = 200 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path, src_endpoint_ip, status_code, user_agent
```

## triage-compromise
<!-- Verify the exploit chain -->
```agent target=hunter
cite: required
context:
- vulnerable-wordpress-inventory
- php-spawning-shells
- rare-web-server-children
- plugin-directory-writes
- admin-login-http
max_iterations: 6
objective: Identify hosts where a vulnerable version was present and we see the sequence
  of administrative access, plugin creation, and anomalous shell execution.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing specific
  timestamps and file paths.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route based on compromise verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: visibility-gap-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised WordPress server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Before remediation, collect the malicious plugin files (.php) and the full process tree for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Forensic validation and close-out -->
```manual target=analyst
Review the cited rows from the triage agent. Confirm that the administrative session correlates with the plugin upload and subsequent process activity. Check for RDP or SSH lateral movement originating from the WordPress host.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
No indicators of privileged access or code execution were found on the identified vulnerable assets. Record any findings related to general site hygiene.
```
→ end
