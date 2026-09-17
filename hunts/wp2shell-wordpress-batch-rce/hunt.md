---
analysis: A single rule might flag 'apache2 spawning dash', but this hunt pivots between
  the software inventory (vulnerability), the HTTP access pattern (exploit), and the
  file system staging (persistence) to build a high-confidence picture of a successful
  wp2shell hit, rather than just generic suspicious activity.
blind_spots:
- id: http-logging-blindspot
  owner: Network Engineering
  question: Was the batch request payload malicious?
  remediation: Enable verbose logging on the REST API endpoints or ensure WAF logs
    are ingested.
  requires: hb_http_activity with decrypted payloads or specific query parameter logging
  risk: If the web server or proxy does not log the full URL query or POST body (where
    the SQLi parameter resides), the hunt may miss the initial exploit attempt.
  stage: initial-access-batch-api-exploitation
- id: short-lived-plugins
  owner: Endpoint Security
  question: Were plugins dropped and immediately deleted?
  remediation: Deploy EDR with real-time file event monitoring to capture the creation/deletion
    cycle.
  requires: hb_file_activity with real-time streaming
  risk: The Icex0 PoC performs self-cleanup. If the lookback window is too long or
    the file activity is only captured via snapshots, the plugin drop may be missed.
  stage: persistence-malicious-plugin-staging
coverage:
- stage: initial-access-batch-api-exploitation
  status: covered
  steps:
  - vulnerable-wordpress-inventory
  - batch-api-exploitation-traffic
- stage: persistence-malicious-plugin-staging
  status: covered
  steps:
  - web-server-plugin-drops
  - write-test-probes
- reason: Belongs to the follow-on hunt focusing on command execution.
  stage: execution-web-server-shell-spawn
  status: out_of_scope
- reason: Belongs to the follow-on hunt focusing on discovery and recon commands.
  stage: post-exploitation-discovery
  status: out_of_scope
- reason: Handled by behavioral analysis in the execution hunt.
  stage: defense-evasion-automated-cleanup
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The wp2shell exploit chain allows pre-authentication RCE on a wide
    range of WordPress versions. Given the speed of PoC availability and observed
    scanning, verifying the absence of staging activity is critical for business continuity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting the WordPress REST API batch route confusion
  (CVE-2026-63030) to achieve SQL injection and deploy a malicious plugin for persistence.
labels:
- hunt
- attack.t1190
- attack.t1505.003
- attack.t1059
name: wp2shell WordPress Batch RCE Exploitation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-23'
      ref: hunt-designer
    type: number
  poc_user_agents:
    default:
    - wp2shell
    description: User agents observed in public PoC tooling.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: list[string]
  vulnerable_wp_versions:
    default:
    - 6.9.0
    - 6.9.1
    - 6.9.2
    - 6.9.3
    - 6.9.4
    - 7.0.0
    - 7.0.1
    description: WordPress versions vulnerable to the full RCE chain.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing WordPress servers. Widen scope to all WordPress
  instances if any 'wp2shell' user-agent or 'batch/v1' SQLi strings are found on the
  edge.
references:
- name: "Elastic Security Labs \u2014 wp2shell hits WordPress"
  url: https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend
related:
- hunt: wordpress-shell-spawn-behavior
  reason: This hunt focuses on the drop; the next hunt focuses on the execution phase
    (shell spawn from web server).
  relation: follows
scenario:
  stages:
  - name: Exploitation of WordPress Batch API
    observables:
    - POST /?rest_route=/batch/v1
    - POST /wp-json/batch/v1
    - 'User-Agent: wp2shell'
    - author__not_in SQL injection parameter
    - CVE-2026-63030
    - CVE-2026-60137
    slug: initial-access-batch-api-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Plugin Deployment
    observables:
    - temp-write-test-* files in wp-content/
    - wp-content/uploads/wp2shell_<hex>.zip
    - /tmp/php* temporary upload files
    - wp-content/plugins/wp2shell_<hex>/wp2shell_<hex>.php
    - wp-content/upgrade/wp2shell_<hex>/
    slug: persistence-malicious-plugin-staging
    tactic: persistence
    techniques:
    - T1505.003
  - name: Web Server Payload Execution
    observables:
    - apache2 spawning /usr/bin/dash
    - httpd spawning /bin/sh
    - php-fpm spawning shell processes
    - process.working_directory matches wp-content/plugins/wp2shell_*
    slug: execution-web-server-shell-spawn
    tactic: execution
    techniques:
    - T1059.004
  - name: Post-Exploitation System Discovery
    observables:
    - sh -c -- id; whoami; hostname
    - uname -a
    - cat /etc/passwd
    - find / -perm -u=s -type f
    slug: post-exploitation-discovery
    tactic: discovery
    techniques:
    - T1059
  - name: Automated Plugin Cleanup
    observables:
    - sh -c -- d=$(pwd); case "$d" in */wp-content/plugins/*) cd / && rm -rf "$d";;
      esac
    - Deletion of wp2shell_<hex> plugin directories
    slug: defense-evasion-automated-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: The wp2shell campaign exploits a pre-authentication route confusion and
    SQL injection vulnerability in WordPress Core's REST batch endpoint to achieve
    remote code execution. Attackers use this access to stage malicious plugins or
    web shells, execute discovery commands via the web server process, and perform
    automated cleanup to evade detection.
series:
  index: 1
  slug: wp2shell-hits-wordpress-detecting-pre-auth-rce-from-plugin-drop-to-command-execution
  title: 'wp2shell hits WordPress: detecting pre-auth RCE from plugin drop to command
    execution'
  total: 2
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


# wp2shell WordPress Batch RCE Exploitation

This hunt identifies the early stages of the wp2shell attack chain. It first scopes the estate to WordPress instances vulnerable to CVE-2026-63030 and CVE-2026-60137. It then looks for the specific 'route confusion' HTTP traffic targeting the batch API and correlates this with file system events where the web server process (e.g., apache2, php-fpm) writes unexpected PHP files or PoC-specific 'temp-write-test' probes into the WordPress plugin directory.

## vulnerable-wordpress-inventory
<!-- Scope vulnerable WordPress instances -->
Identify hosts running versions of WordPress affected by the pre-auth RCE chain.

```sqlite target=endpoint role=scoping params=(vulnerable_wp_versions=vulnerable_wp_versions)
~~~yaml
expected: A list of hosts currently running unpatched WordPress. Silence indicates
  no known vulnerable versions are installed.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname, package_version FROM hb_software_inventory WHERE LOWER(package_name) = 'wordpress' AND instr(',' || '{{vulnerable_wp_versions}}' || ',', ',' || package_version || ',') > 0
```

## batch-api-exploitation-traffic
<!-- Search for Batch API exploitation attempts -->
Find HTTP requests targeting the REST batch endpoint with SQL injection parameters or known PoC user agents.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, poc_user_agents=poc_user_agents)
~~~yaml
expected: Specific HTTP hits showing the 'batch' route and either the SQLi parameter
  or the PoC user agent. Evidence of the initial access attempt.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, user_agent, time FROM hb_http_activity WHERE (instr(LOWER(url_full), 'batch/v1') > 0 OR instr(LOWER(url_full), 'rest_route=/batch/v1') > 0) AND (instr(LOWER(url_full), 'author__not_in') > 0 OR instr(',' || '{{poc_user_agents}}' || ',', ',' || LOWER(user_agent) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with File Activity -->
parallel:
- → web-server-plugin-drops
- → write-test-probes
join: → triage-wp2shell

## web-server-plugin-drops
<!-- Web server process writing PHP to plugin directories -->
Detect the actual drop of the malicious plugin code by identifying PHP file creation events from web server processes.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: A web server process creating a new PHP file in a plugin directory. While
  plugin updates are normal, this provides the 'what' to the exploitation's 'how'.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(process_name) LIKE '%apache%' OR LOWER(process_name) LIKE '%httpd%' OR LOWER(process_name) LIKE '%php-fpm%' OR LOWER(process_name) LIKE '%nginx%') AND LOWER(file_path) LIKE '%/wp-content/plugins/%' AND LOWER(file_name) LIKE '%.php' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## write-test-probes
<!-- Stack count PoC write-test probes -->
Identify the rare 'temp-write-test' files used by the Icex0 PoC to check directory permissions.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare file names matching the PoC's staging behavior across the fleet.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- file_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT file_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_name) LIKE 'temp-write-test-%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name HAVING host_count <= 3
```

## triage-wp2shell
<!-- Correlate HTTP Exploitation with File Drops -->
```agent target=hunter
cite: required
context:
- vulnerable-wordpress-inventory
- batch-api-exploitation-traffic
- web-server-plugin-drops
- write-test-probes
max_iterations: 4
objective: Determine if any host shows a complete chain from vulnerable software to
  pre-auth batch API exploitation followed by suspicious file activity in the WordPress
  content directories.
success_criteria: A verdict of malicious | suspicious | benign per host, with a timeline
  of events.
tools:
- endpoint
- web
```

## verdict-decision
<!-- Route on verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: http-logging-blindspot)
else: → close-out

## isolate-host
<!-- Isolate affected WordPress server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture the recently created PHP files in the wp-content/plugins/ directory for forensic analysis.
```
→ analyst-triage

## analyst-triage
<!-- Analyst forensic review -->
```manual target=analyst
Review the HTTP logs for SQL injection payloads in the batch API calls. Inspect the 'plugins' directory for any PHP files with random hex suffixes (e.g., wp2shell_6a5566a6.php). Verify if any shells were spawned (next hunt in series).
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Log that the estate was scanned for wp2shell staging activity and no high-confidence indicators were found.
```
→ end
