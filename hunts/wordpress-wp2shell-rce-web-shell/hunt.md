---
analysis: This hunt goes beyond a single rule by correlating the structural SQLi marker
  in web logs with a fleet-wide baseline of shell execution to highlight anomalous
  compromise behavior over legitimate maintenance.
blind_spots:
- id: missing-source-installs
  question: Are there WordPress installations not managed by system package managers?
  remediation: Augment inventory with a hunt that searches for wp-config.php across
    the fleet.
  requires: hb_software_inventory via file-system scanning
  risk: WordPress is often installed via zip or git; hb_software_inventory frequently
    misses applications not managed by deb/rpm.
  stage: initial-access-batch-route-confusion
- id: http-post-inspection
  question: Was the SQLi parameter author__not_in passed in the POST body?
  remediation: Ingest WAF or API Gateway logs that capture request bodies.
  requires: hb_http_activity with body_content or WAF logs
  risk: If the attacker passes parameters inside a JSON body rather than the query
    string, hb_http_activity will show the request but not the indicator.
  stage: initial-access-batch-route-confusion
- id: incomplete-linux-telemetry
  question: Are all web servers reporting process and file events?
  remediation: Cross-reference asset management lists with enrolled agent lists.
  requires: Endpoint agent on all WordPress hosts
  risk: Without an agent, the only evidence is the HTTP request; we cannot confirm
    if a shell was actually spawned.
coverage:
- stage: initial-access-batch-route-confusion
  status: covered
  steps:
  - vulnerable-wordpress-inventory
  - wp-json-batch-activity
- stage: persistence-plugin-webshell-drop
  status: covered
  steps:
  - wp-content-php-drops
- stage: execution-web-server-shell-spawn
  status: covered
  steps:
  - rare-web-server-shell-children
- stage: discovery-reconnaissance-commands
  status: covered
  steps:
  - rare-web-server-shell-children
- reason: The Icex0 self-cleanup script is stopped by the Payload Execution by Web
    Server rule when it tries to run rm.
  stage: defense-evasion-self-cleanup
  status: existing_rule
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: wp2shell is a critical, pre-authentication RCE chain. A negative
    result provides assurance against broad exposure, and early identification of
    shell execution allows for containment before lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited the WordPress batch route confusion vulnerability
  (CVE-2026-63030) to achieve pre-authentication RCE, resulting in PHP file drops
  and shell execution by web server processes.
labels:
- hunt
- attack.t1190
- attack.t1505.003
- attack.t1059
- attack.t1070
name: WordPress wp2shell Pre-Auth RCE and Web Shell Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts to narrow the search; if empty, the entire estate is checked.
    type: list[host]
  vulnerable_versions:
    default:
    - 6.9.0
    - 6.9.1
    - 6.9.2
    - 6.9.3
    - 6.9.4
    - 7.0.0
    - 7.0.1
    description: Affected WordPress versions vulnerable to the full RCE chain.
    from:
      kind: article
      observed: '2026-07-23'
      ref: Elastic Labs wp2shell advisory
    type: list[string]
  web_server_parents:
    default:
    - apache2
    - httpd
    - php-fpm
    - php-cgi
    - php-fcgi
    - php-cgi.cagefs
    - nginx
    description: Web server and PHP runtime process names to monitor.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing Linux hosts. If hb_software_inventory results
  are low, widen the hunt to all hosts running the processes in the web_server_parents
  parameter.
references:
- name: "Elastic Security Labs \u2014 wp2shell WordPress RCE detection"
  url: https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend
related:
- hunt: sql-injection-generic-web-application
  reason: The author__not_in primitive is a specific SQL injection that fits into
    a broader class of web application security hunts.
  relation: sibling
scenario:
  stages:
  - name: WordPress REST API Route Confusion
    observables:
    - 'url_path: /wp-json/batch/v1'
    - 'url_query: ?rest_route=/batch/v1'
    - 'url_query: author__not_in'
    - 'user_agent: wp2shell'
    - CVE-2026-63030
    - CVE-2026-60137
    slug: initial-access-batch-route-confusion
    tactic: initial-access
    techniques:
    - T1190
  - name: Webshell or Malicious Plugin Installation
    observables:
    - 'file_path: */wp-content/plugins/wp2shell_*'
    - 'file_path: */wp-content/uploads/wp2shell_*.zip'
    - 'file_path: */wp-content/temp-write-test-*'
    - 'file_path: /tmp/php*'
    - 'file_path: */wp-content/cache/*.php'
    slug: persistence-plugin-webshell-drop
    tactic: persistence
    techniques:
    - T1505.003
  - name: Web Server Payload Execution
    observables:
    - 'parent_process_name: apache2'
    - 'parent_process_name: httpd'
    - 'parent_process_name: php-fpm'
    - 'parent_process_name: php-cgi'
    - 'parent_process_name: php-cgi.cagefs'
    - 'process_name: dash'
    - 'process_name: sh'
    - 'process_name: bash'
    slug: execution-web-server-shell-spawn
    tactic: execution
    techniques:
    - T1059
  - name: Post-Exploitation Discovery
    observables:
    - 'process_cmd_line: id'
    - 'process_cmd_line: whoami'
    - 'process_cmd_line: hostname'
    - 'process_cmd_line: uname'
    - 'process_cmd_line: cat /etc/passwd'
    - 'process_cmd_line: find / -perm -u=s -type f'
    slug: discovery-reconnaissance-commands
    tactic: discovery
    techniques:
    - T1059
  - name: Automated Exploit Cleanup
    observables:
    - 'process_cmd_line: rm -rf */wp-content/plugins/wp2shell_*'
    - 'process_cmd_line: cd / && rm -rf "$d"'
    slug: defense-evasion-self-cleanup
    tactic: defense-evasion
    techniques:
    - T1070
  summary: The wp2shell attack exploits a route confusion vulnerability in the WordPress
    REST batch API to achieve pre-authentication remote code execution. Attackers
    use SQL injection to escalate privileges or drop a webshell, subsequently spawning
    a shell from the web server process to execute discovery and reconnaissance commands.
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


# WordPress wp2shell Pre-Auth RCE and Web Shell Execution

This hunt targets the end-to-end exploit chain of wp2shell. It begins by scoping vulnerable WordPress installations, then simultaneously examines web logs for the structural SQL injection primitive (author__not_in), endpoint file activity for suspicious PHP drops in plugin/upload directories, and behavioral process evidence of web servers spawning rare shell processes. This multi-surface approach ensures detection even if attackers use custom plugin names or self-cleaning payloads.

## vulnerable-wordpress-inventory
<!-- Identify Vulnerable WordPress Installations -->
Identify hosts running WordPress versions vulnerable to the pre-auth RCE chain to focus the hunt.

```sqlite target=endpoint role=scoping params=(vulnerable_versions=vulnerable_versions)
~~~yaml
expected: A list of hosts running vulnerable WordPress versions. Silence suggests
  the estate is patched or inventory is not captured by package managers.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%wordpress%') AND (instr(',' || '{{vulnerable_versions}}' || ',', ',' || package_version || ',') > 0) AND asset_scope = 'endpoint'
```

## corroborate-activity
<!-- Corroborate Multi-Surface Evidence -->
parallel:
- → wp-json-batch-activity
- → rare-web-server-shell-children
- → wp-content-php-drops
join: → triage-wp2shell

## wp-json-batch-activity
<!-- WP REST API Batch Activity -->
Identify HTTP requests targeting the vulnerable batch endpoint with the fundamental author__not_in SQL injection parameter.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests targeting the batch endpoint with SQL injection parameters.
  Silence may occur if the payload was passed in the POST body.
reads:
- device_hostname
- url_path
- url_query
- user_agent
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, url_query, user_agent, src_endpoint_ip, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (url_path LIKE '%/wp-json/batch/v1%' OR url_query LIKE '%rest_route=/batch/v1%') AND (url_query LIKE '%author__not_in%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-web-server-shell-children
<!-- Rare Shell Spawn from Web Servers -->
Identify instances where a web server process spawned a shell, baselined against the fleet to highlight anomalous behavior.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, web_server_parents=web_server_parents)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A shell process running under a web server parent that is rare across the
  fleet. High fidelity indicator of payload execution.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  - process_name
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT parent_process_name, process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_name) IN ('sh', 'dash', 'bash', 'zsh') OR process_cmd_line LIKE '%sh -c%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY parent_process_name, process_name, process_cmd_line HAVING hosts <= 3 ORDER BY hosts, runs
```

## wp-content-php-drops
<!-- Suspicious PHP drops in WordPress Directories -->
Detect generalized PHP file creation by web server processes in plugin, upload, or cache directories.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, web_server_parents=web_server_parents)
~~~yaml
expected: Creation of PHP files in sensitive WordPress directories by the web server
  process itself. Evidence of persistence.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (LOWER(file_path) LIKE '%.php') AND (LOWER(file_path) LIKE '%/wp-content/plugins/%' OR LOWER(file_path) LIKE '%/wp-content/uploads/%' OR LOWER(file_path) LIKE '%/wp-content/cache/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-wp2shell
<!-- Triage wp2shell Chain Evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-wordpress-inventory
- wp-json-batch-activity
- rare-web-server-shell-children
- wp-content-php-drops
max_iterations: 5
objective: Determine if a host has been successfully compromised via the wp2shell
  RCE chain. Cite the specific HTTP author__not_in request, the resulting rare shell
  process from the web server, and any PHP artifacts created in /wp-content/.
success_criteria: A per-host verdict of malicious, suspicious, or benign with supporting
  row citations.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route Based on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-linux-telemetry)
else: → analyst-close-out

## isolate-host
<!-- Isolate Compromised Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR. Collect the /wp-content/plugins/ directory and the full command-line history of the web server process before forensic imaging.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the cited author__not_in HTTP hits. Verify if the shell processes spawned by the web server (sh, dash) match known legitimate automation or maintenance scripts.
```
→ end

## analyst-close-out
<!-- Close-out and Summary -->
```manual target=analyst
Document how many vulnerable WordPress instances were identified and confirm if shell execution was absent on all of them. Prioritize patching.
```
→ end
