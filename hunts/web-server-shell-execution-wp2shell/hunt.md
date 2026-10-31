---
analysis: A simple detection rule may fire on any shell from a web server; this hunt
  adds the behavioral context of stack-counting rare commands and correlating with
  automated cleanup actions across two telemetry surfaces to confirm an actual intrusion.
blind_spots:
- id: insufficient-process-telemetry
  question: whether the web server spawned the shell with an exploit payload
  requires: hb_process_activity with parent command line information
  risk: If parent command line data is missing, distinguishing legitimate server restarts
    from RCE spawns becomes difficult.
  stage: shell-spawn-from-web-server
- id: insufficient-file-telemetry
  question: whether the attacker cleaned up the plugin files
  requires: hb_file_activity recording activity_id 4 (deletion)
  risk: If file deletion logging is disabled for the web root, the post-exploitation
    cleanup phase remains invisible.
  stage: automated-self-cleanup
coverage:
- stage: shell-spawn-from-web-server
  status: covered
  steps:
  - detect-web-shell-spawn
  - evaluate-lead
- stage: post-exploitation-discovery
  status: covered
  steps:
  - rare-shell-commands
- stage: automated-self-cleanup
  status: covered
  steps:
  - cleanup-file-events
- reason: 'Belongs to another part of the ''wp2shell hits WordPress: detecting pre-auth
    RCE from plugin drop to command execution'' series.'
  stage: exploit-wordpress-batch-api
  status: out_of_scope
- reason: 'Belongs to another part of the ''wp2shell hits WordPress: detecting pre-auth
    RCE from plugin drop to command execution'' series.'
  stage: malicious-plugin-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The wp2shell exploit chain allows pre-authentication RCE on millions
    of WordPress instances. Detecting the host-side behavior is the primary way to
    find compromised hosts where network scanning might be obfuscated.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has exploited a WordPress vulnerability to spawn a shell from
  a web server process and is currently performing system discovery or cleaning up
  traces of the wp2shell plugin.
labels:
- hunt
- attack.t1059
- attack.t1059.004
- attack.t1505.003
- attack.t1082
- attack.t1033
- attack.t1070.004
name: Web Server Shell Execution and wp2shell Post-Exploitation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-23'
      ref: hunt-standard
    type: number
  shell_children:
    default:
    - sh
    - bash
    - dash
    - zsh
    - ksh
    - fish
    description: Common shell process names spawned during exploitation.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: list[string]
  web_server_parents:
    default:
    - apache2
    - httpd
    - php-fpm
    - php-cgi
    - nginx
    - php-fcgi
    - lsphp
    - sw-engine-fpm
    description: Common web server and PHP runtime process names to monitor as parents.
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
rationale: Focus on the Linux fleet hosting public-facing WordPress instances. Identify
  web server processes first, then look for shell transitions.
references:
- name: "elastic-security-labs \u2014 wp2shell hits WordPress"
  url: https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend
related:
- hunt: malicious-plugin-staging-wordpress
  reason: This hunt focuses on the execution phase; a sibling hunt should examine
    the Zip and PHP file staging anomalies.
  relation: out-of-scope-alternative
- hunt: wordpress-rest-api-exploitation-plugin-staging
  relation: follows
scenario:
  stages:
  - name: Exploitation of WordPress REST batch API
    observables:
    - POST /?rest_route=/batch/v1
    - POST /wp-json/batch/v1
    - 'User-Agent: wp2shell'
    - CVE-2026-63030
    - CVE-2026-60137
    slug: exploit-wordpress-batch-api
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious plugin staging on disk
    observables:
    - wp-content/plugins/wp2shell_*
    - wp-content/uploads/wp2shell_*.zip
    - temp-write-test-*
    - wp-content/upgrade/wp2shell_*/
    - wp-content/plugins/wp2shell_*.php
    slug: malicious-plugin-staging
    tactic: persistence
    techniques:
    - T1505.003
  - name: Shell execution by web server process
    observables:
    - apache2 spawning dash
    - httpd spawning sh
    - php-fpm spawning bash
    - sh -c -- id; whoami; hostname
    slug: shell-spawn-from-web-server
    tactic: execution
    techniques:
    - T1059
  - name: System and privilege reconnaissance
    observables:
    - uname
    - cat /etc/passwd
    - find / -perm -u=s -type f
    slug: post-exploitation-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1033
  - name: Indicator removal and cleanup
    observables:
    - rm -rf wp-content/plugins/wp2shell_*
    - deletion of staged zip files under wp-content/uploads/
    slug: automated-self-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: Attackers leverage a pre-authentication RCE vulnerability in the WordPress
    REST batch API (CVE-2026-63030) to stage malicious plugins or web shells on vulnerable
    servers. Once established, the web server process is used to execute system shells
    for reconnaissance and automated artifact cleanup.
series:
  index: 2
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Web Server Shell Execution and wp2shell Post-Exploitation

This hunt focuses on the host-side behavior of the wp2shell RCE chain (CVE-2026-63030). It targets the specific transition where a web server or PHP runtime spawns a command shell, followed by reconnaissance and automated cleanup. By using a gated flow, the hunt first identifies suspicious parent-child process pairs before fanning out to search for rare discovery commands and specific file deletion patterns that indicate a successful compromise.

## detect-web-shell-spawn
<!-- Web server shell spawns -->
Identify instances where a web server or PHP runtime process is the direct parent of a command shell, indicating potential RCE.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, web_server_parents=web_server_parents, shell_children=shell_children)
~~~yaml
expected: Rows showing a web server parent (e.g., apache2) spawning a shell (e.g.,
  dash) as a low-privileged user (e.g., www-data). Silence suggests no such direct
  process spawns occurred.
reads:
- device_hostname
- parent_process_cmd_line
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, parent_process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE 'php-fpm%') AND instr(',' || '{{shell_children}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate shell spawn leads -->
```agent target=hunter
cite: required
context:
- detect-web-shell-spawn
max_iterations: 3
objective: Determine if any of the shell spawns identified in detect-web-shell-spawn
  are suspicious for RCE post-exploitation.
success_criteria: A clear assessment citing suspicious process lineages and command
  lines.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on lead suspicion -->
if~: "the evaluate-lead verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-process-telemetry)
else: → close-out

## parallel-investigation
<!-- Corroborate discovery and cleanup -->
parallel:
- → rare-shell-commands
- → cleanup-file-events
join: → final-triage

## rare-shell-commands
<!-- Rare reconnaissance commands -->
Find rare system and privilege discovery commands executed by the identified shells.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, web_server_parents=web_server_parents, shell_children=shell_children)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rarely seen commands like 'find / -perm -u=s' or 'cat /etc/passwd' occurring
  on a small number of hosts. Silence means no such commands were recorded for the
  suspicious processes.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR instr(',' || '{{shell_children}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%id%' OR LOWER(process_cmd_line) LIKE '%whoami%' OR LOWER(process_cmd_line) LIKE '%hostname%' OR LOWER(process_cmd_line) LIKE '%uname%' OR LOWER(process_cmd_line) LIKE '%/etc/passwd%' OR LOWER(process_cmd_line) LIKE '%-perm%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_cmd_line) HAVING host_count < 3 ORDER BY host_count ASC
```

## cleanup-file-events
<!-- Cleanup file deletions -->
Detect the removal of wp2shell plugin artifacts or staged zip files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Deletions of files under the WordPress plugin or upload directories matching
  the wp2shell pattern. Silence suggests the attacker's automated cleanup did not
  trigger or was not captured.
reads:
- activity_id
- activity_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, activity_name, time FROM hb_file_activity WHERE activity_id = 4 AND (LOWER(file_path) LIKE '%/wp-content/plugins/wp2shell_%' OR LOWER(file_path) LIKE '%/wp-content/uploads/wp2shell_%.zip') AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final triage of compromise -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- rare-shell-commands
- cleanup-file-events
max_iterations: 5
objective: Weigh the initial lead with the corroborating evidence of rare discovery
  and file deletions to confirm active wp2shell exploitation.
success_criteria: A detailed timeline and verdict for each host in scope.
tools:
- endpoint
```

## route-final
<!-- Route on final verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-file-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not restart the web server until memory forensics or binary preservation has been completed.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from final-triage. Identify the specific WordPress plugin used for staging and check for any additional webshells dropped under wp-content/cache/ or wp-content/uploads/.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts and time windows examined. Log that no suspicious web server shells or wp2shell artifacts were found. Verify that patches for CVE-2026-63030 are being applied.
```
→ end
