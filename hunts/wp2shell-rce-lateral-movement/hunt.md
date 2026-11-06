---
analysis: A standard rule alerts on sh spawning from a web server; this hunt adds
  critical context by scoping specifically to vulnerable WordPress versions and using
  stack-counting to differentiate malicious one-offs from routine maintenance scripts.
blind_spots:
- id: missing-endpoint-telemetry
  question: Are there vulnerable WordPress hosts without an endpoint agent?
  requires: hb_process_activity from an endpoint agent
  risk: A host without an agent will appear in software inventory but will not report
    the shell activity that confirms a compromise.
  stage: host-rce-execution
- id: restricted-auth-logs
  question: Was lateral movement performed via a protocol not captured in normalized
    auth logs?
  requires: SSH and RDP sign-in details in hb_auth_signin
  risk: If an attacker moves laterally via a proprietary protocol or one not integrated
    into the auth surface, it will be missed here.
  stage: post-exploit-rdp-access
coverage:
- stage: host-rce-execution
  status: covered
  steps:
  - rare-web-server-children
- stage: post-exploit-rdp-access
  status: covered
  steps:
  - rdp-ssh-auth-on-exposed-hosts
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: wordpress-vulnerability-exposure
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: wp-batch-api-sqli-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: account-persistence-creation
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell: critical RCE in WordPress core''
    series.'
  stage: plugin-webshell-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: wp2shell is a critical unauthenticated RCE in a ubiquitous CMS. Identifying
    successful exploitation before lateral movement can contain the blast radius of
    a public-facing compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited the WordPress wp2shell vulnerability to gain
  shell access and is now attempting to move laterally within the network via RDP
  or SSH using credentials compromised from the web server.
labels:
- hunt
- attack.t1190
- attack.t1021.001
- attack.t1021.004
- attack.t1078
- attack.t1090.003
name: 'wp2shell: Endpoint RCE and Lateral Movement'
parameters:
  discovery_cmds:
    default:
    - whoami
    - id
    - net
    - ip
    - uname
    description: Discovery binaries often run immediately after gaining a shell.
    from:
      kind: article
      observed: '2026-07-22'
      ref: rapid7-wp2shell
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-22'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search; defaults to all hosts
      if empty.
    from:
      kind: manual
      observed: '2026-07-22'
      ref: analyst-scoping
    type: list[host]
  shell_binaries:
    default:
    - sh
    - bash
    - cmd.exe
    - powershell.exe
    description: Standard shell interpreters used in RCE.
    from:
      kind: manual
      observed: '2026-07-22'
      ref: standard-shells
    type: list[string]
  web_server_binaries:
    default:
    - php-fpm
    - apache2
    - httpd
    - nginx
    - php
    description: Common web server or PHP processor executable names.
    from:
      kind: article
      observed: '2026-07-22'
      ref: rapid7-wp2shell
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
rationale: Focus on internet-facing servers identified in hb_software_inventory. Widen
  to internal staging servers if external hits are found.
references:
- name: "Rapid7 \u2014 wp2shell: critical RCE in WordPress core"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/
related:
- hunt: wp-batch-api-sqli-exploit
  reason: Targets the HTTP-level exploitation of the batch API logic flaw.
  relation: out-of-scope-alternative
- hunt: account-persistence-creation
  reason: Targets the database or identity-level creation of the administrative user.
  relation: out-of-scope-alternative
- hunt: wordpress-core-rest-api-rce-wp2shell
  relation: follows
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
  index: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# wp2shell: Endpoint RCE and Lateral Movement

This hunt targets the post-exploitation host-level impact of the wp2shell critical RCE chain (CVE-2026-63030 and CVE-2026-60137). We first identify vulnerable WordPress installations across the estate. We then look for anomalous child processes, specifically shells and system discovery tools, spawned by web server processes. Finally, we correlate these findings with subsequent RDP or SSH authentication events on those same hosts to identify lateral movement attempts. The hunt uses stack-counting to isolate rare attacker behavior from routine administrative activity on public-facing servers.

## scope-vulnerable-wordpress
<!-- Identify vulnerable WordPress hosts -->
Scope the estate to hosts running WordPress versions affected by the SQLi and RCE vulnerabilities.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running vulnerable WordPress versions (6.8.x < 6.8.6, 6.9.x
  < 6.9.5, or 7.0.x < 7.0.2). Silence means no vulnerable packages were found.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_version FROM hb_software_inventory WHERE LOWER(package_name) = 'wordpress' AND ((package_version LIKE '6.8.%' AND package_version < '6.8.6') OR (package_version LIKE '6.9.%' AND package_version < '6.9.5') OR (package_version LIKE '7.0.%' AND package_version < '7.0.2'))
```

## rare-web-server-children
<!-- Rare shells from web server processes -->
Identify instances where a web server spawned a shell or discovery tool that is rare across the fleet, indicative of RCE.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, web_server_binaries=web_server_binaries, shell_binaries=shell_binaries, discovery_cmds=discovery_cmds, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One-off or rare shell executions from web server parents on vulnerable hosts.
  Silence suggests no active execution was observed in this window.
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
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(parent_process_name) LIKE '%/php-fpm' OR LOWER(parent_process_name) LIKE '%/nginx' OR LOWER(parent_process_name) LIKE '%/httpd' OR LOWER(parent_process_name) LIKE '%/apache2' OR instr(',' || '{{web_server_binaries}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\powershell.exe' OR instr(',' || '{{shell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{discovery_cmds}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, parent_process_name, process_name, process_cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## rdp-ssh-auth-on-exposed-hosts
<!-- RDP and SSH authentication on vulnerable hosts -->
Identify potential lateral movement by searching for successful RDP or SSH sign-ins to the vulnerable WordPress hosts.

```sqlite target=identity role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Successful RDP or SSH sign-ins to the targeted hosts. Silence does not rule
  out lateral movement via other protocols.
reads:
- dst_endpoint_name
- actor_user_name
- auth_protocol
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, actor_user_name, auth_protocol, src_endpoint_ip, time FROM hb_auth_signin WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0)) AND (LOWER(auth_protocol) LIKE '%rdp%' OR LOWER(auth_protocol) LIKE '%ssh%' OR LOWER(auth_protocol) LIKE '%negotiate%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Evaluate exposure and post-exploit behavior -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-wordpress
- rare-web-server-children
- rdp-ssh-auth-on-exposed-hosts
max_iterations: 4
objective: Identify hosts that are both vulnerable to wp2shell and show signs of RCE
  or subsequent lateral movement via RDP/SSH.
success_criteria: A per-host verdict (malicious | suspicious | benign) citing command
  lines and RDP/SSH source IPs.
tools:
- endpoint
- identity
```

## route-results
<!-- Route on verdict -->
if~: "the agent triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → task-remediation-review
indeterminate: → task-remediation-review
unavailable: → task-remediation-review (blind_spot: missing-endpoint-telemetry)
else: → task-close-out

## task-remediation-review
<!-- Remediation and incident response -->
```manual target=analyst
For hosts with malicious child process activity, initiate incident response. For those identified only as vulnerable, ensure WordPress is updated to 6.8.6, 6.9.5, or 7.0.2 immediately.
```
→ task-close-out

## task-close-out
<!-- Close out hunt -->
```manual target=analyst
Record the hosts reviewed and confirm that remediation or patching is completed for all vulnerable instances.
```
→ end
