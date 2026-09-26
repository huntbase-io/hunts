---
analysis: A single rule might alert on any batch API request, but this hunt provides
  the context of vulnerable inventory, stack-counts the source IPs to find rare traffic,
  and correlates it with follow-on plugin file modifications to confirm compromise.
blind_spots:
- id: http-body-blind-spot
  question: the content of the POST body sent to the batch API
  requires: hb_http_activity with request body visibility
  risk: Without body visibility, we cannot distinguish between a legitimate recursive
    batch call and one containing a SQL injection payload.
  stage: wp-batch-api-sqli-exploit
- id: wordpress-db-audit-gap
  question: whether an administrator account was created directly in the database
  requires: WordPress application-level database audit logging
  risk: The desynchronization exploit allows the creation of accounts via internal
    logic that may not trigger a standard OS-level authentication or file event until
    the attacker later logs in.
  stage: account-persistence-creation
coverage:
- stage: wordpress-vulnerability-exposure
  status: covered
  steps:
  - identify-vulnerable-wordpress
- stage: wp-batch-api-sqli-exploit
  status: covered
  steps:
  - rare-batch-api-activity
- blind_spot: wordpress-db-audit-gap
  reason: Requires application-level database logs to see account creation; partially
    inferred from follow-on activity.
  stage: account-persistence-creation
  status: not_visible
- stage: plugin-webshell-deployment
  status: covered
  steps:
  - new-plugin-php-files
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: host-rce-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: post-exploit-rdp-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: WordPress core RCE vulnerabilities (wp2shell) are actively exploited
    in the wild. Ensuring all instances are patched and haven't been compromised is
    a critical priority for public-facing assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthenticated attacker executes code on an internet-facing WordPress
  server by exploiting a logic flaw in the REST API batch endpoint to perform SQL
  injection and upload a malicious plugin.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1090.003
name: WordPress Core REST API RCE (wp2shell)
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified as running vulnerable WordPress versions;
      if empty, the hunt runs across the full estate.
    type: list[host]
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
rationale: Start with servers that host public-facing websites. Use the first step's
  findings to populate the scope_hosts parameter for the subsequent behavioral queries.
references:
- name: "Rapid7 \u2014 wp2shell: critical RCE in WordPress core"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/
related:
- hunt: host-rce-execution
  reason: Host-level command execution following a successful webshell upload is covered
    by a separate post-exploit hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Vulnerable WordPress Core Detection
    observables:
    - WordPress version 6.9.0-6.9.4
    - WordPress version 7.0.0-7.0.1
    - CVE-2026-63030
    - CVE-2026-60137
    slug: wordpress-vulnerability-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: REST API Batch Endpoint SQLi
    observables:
    - POST /wp-json/batch/v1
    - POST ?rest_route=/batch/v1
    - author__not_in parameter with UNION SELECT payloads
    - Traffic from Tor or proxy exit nodes
    slug: wp-batch-api-sqli-exploit
    tactic: initial-access
    techniques:
    - T1190
    - T1090.003
  - name: Unauthorized Administrator Creation
    observables:
    - New administrator user creation via internal WordPress logic
    - Unexpected login to /wp-admin/ or /wp-login.php
    slug: account-persistence-creation
    tactic: persistence
    techniques:
    - T1078
  - name: Malicious Plugin Persistence
    observables:
    - Upload of .zip plugin files to /wp-admin/plugin-install.php
    - New .php files created in wp-content/plugins/
    slug: plugin-webshell-deployment
    tactic: persistence
    techniques:
    - T1078
  - name: Remote Code Execution via Web Server
    observables:
    - Web server (php-fpm, apache, nginx) spawning sh, bash, or cmd.exe
    - Execution of whoami, id, or net commands from web directory
    slug: host-rce-execution
    tactic: execution
    techniques:
    - T1190
  - name: Lateral Movement via RDP
    observables:
    - Inbound RDP connections on port 3389
    - Authentication to RDP using credentials created during the WordPress exploit
    slug: post-exploit-rdp-access
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: An unauthenticated attacker exploits a logic flaw in the WordPress REST
    API batch processor (CVE-2026-63030) combined with a SQL injection vulnerability
    (CVE-2026-60137) to bypass authentication. This exploit chain allows for the creation
    of unauthorized administrator accounts, which are subsequently used to upload
    malicious plugins for full remote code execution and lateral movement.
series:
  index: 1
  slug: wp2shell-critical-rce-in-wordpress-core
  title: 'wp2shell: critical RCE in WordPress core'
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


# WordPress Core REST API RCE (wp2shell)

This hunt identifies WordPress installations exposed to CVE-2026-63030 and CVE-2026-60137. It examines the estate for vulnerable core versions and then hunts for the desynchronization exploit against the batch API. By correlating rare source IP behavior with the subsequent creation of PHP files in the plugins directory, the hunt distinguishes legitimate administrative updates from unauthorized webshell deployment. The flow is designed to assess exposure and confirmed compromise without assuming every batch request is malicious.

## identify-vulnerable-wordpress
<!-- Identify vulnerable WordPress versions -->
Scope the hunt to hosts running WordPress versions affected by CVE-2026-63030.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts and their current WordPress version. Silence means no vulnerable
  instances were found in the inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) = 'wordpress' AND (package_version LIKE '6.9%' OR package_version LIKE '7.0%') AND package_version NOT IN ('6.9.5', '7.0.2')
```

## rare-batch-api-activity
<!-- Rare batch API interaction -->
Stack-count source IPs hitting the vulnerable batch endpoint to find anomalous activity.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare source IPs hitting the batch endpoint indicate potential exploitation.
  Baseline traffic is typically automated or administrative.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- device_hostname
- url_path
- url_query
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, device_hostname, url_path, url_query, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(url_path) LIKE '%/wp-json/batch/v1%' OR LOWER(url_query) LIKE '%batch/v1%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname, url_path, url_query HAVING request_count < 100 ORDER BY request_count ASC
```

## new-plugin-php-files
<!-- New PHP files in plugins directory -->
Identify the creation of PHP files within the WordPress plugins folder, which follows a successful exploit.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of PHP files by the web server process (e.g., apache2, php-fpm)
  rather than a package manager or admin user is suspicious.
reads:
- device_hostname
- file_path
- file_name
- process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND LOWER(file_path) LIKE '%/wp-content/plugins/%.php' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## weigh-exposure-risk
<!-- Weigh exposure and signs of compromise -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-wordpress
- rare-batch-api-activity
- new-plugin-php-files
max_iterations: 4
objective: Determine if any host running a vulnerable version of WordPress shows patterns
  of batch API desynchronization followed by plugin file creation.
success_criteria: A detailed assessment citing the timing of HTTP requests and file
  modifications per host.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on risk level -->
if~: "the triage verdict is compromised for at least one host" (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: http-body-blind-spot)
else: → close-out

## remediation-review
<!-- Remediation and upgrade review -->
```manual target=analyst
For hosts marked as compromised, verify the presence of new administrator accounts in the WordPress database and inspect the content of PHP files identified in the plugins directory. Ensure all instances are upgraded to WordPress 6.9.5 or 7.0.2.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the vulnerable WordPress instances found during scoping and confirm if any showed suspicious activity. Close the hunt if no signs of compromise were identified.
```
→ end
