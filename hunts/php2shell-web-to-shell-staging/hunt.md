---
analysis: While static rules catch common shells, this hunt adds context by stack-counting
  rare children across the fleet and correlating vulnerability finding data with staging
  tools, distinguishing true compromises from administrative noise.
blind_spots:
- id: no-agent-coverage
  question: Are there web servers in the estate that are not enrolled in endpoint
    monitoring?
  requires: Complete endpoint agent coverage on all web-facing assets.
  risk: A host without an agent provides no process telemetry, making it a complete
    blind spot for behavioral execution hunting.
  stage: execution-web-worker-shell
- id: memory-only-exploitation
  question: Did the attacker execute malicious code entirely within the PHP worker
    process memory without spawning a child?
  requires: PHP engine-level tracing or APM instrumentation.
  risk: Sophisticated exploits staying within the process address space are invisible
    to process-launch telemetry.
  stage: initial-access-php-rce
coverage:
- stage: initial-access-php-rce
  status: covered
  steps:
  - vulnerable-php-assets
- stage: execution-web-worker-shell
  status: covered
  steps:
  - web-worker-shell
  - rare-web-children
- stage: discovery-system-enumeration
  status: covered
  steps:
  - follow-on-staging
- stage: execution-payload-staging
  status: covered
  steps:
  - follow-on-staging
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: c2-reverse-shell-primitives
  status: out_of_scope
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: credential-access-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: persistence-webshell-and-system
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: PHP core RCE flaws represent a massive cross-platform exposure; confirming
    the absence of the convergent 'web-to-shell' execution pattern across the estate
    is a high-value negative result for the business.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting PHP core RCE vulnerabilities (CVE-2026-109618/19)
  to force web server processes to spawn shells or interpreters, which then perform
  system discovery and payload staging.
labels:
- hunt
- attack.t1059
- attack.t1190
- attack.t1505.003
- attack.t1087
- attack.t1082
- attack.t1105
- command and control
- credential access
- discovery
- execution
- initial access
- persistence
name: 'PHP2Shell: Web-to-Shell Staging'
parameters:
  cve_ids:
    default:
    - CVE-2026-109618
    - CVE-2026-109619
    description: The PHP core RCE identifiers.
    from:
      kind: article
      observed: '2026-10-21'
      ref: https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty to hunt
      across the entire estate.
    type: list[host]
  shell_names:
    default:
    - bash
    - dash
    - sh
    - zsh
    - ksh
    description: Standard Unix shells used for post-exploitation.
    type: list[string]
  staging_tools:
    default:
    - curl
    - wget
    - python
    - python3
    - perl
    - ruby
    - node
    - php
    - id
    - whoami
    - uname
    - hostname
    description: Interpreters, downloaders, and discovery tools used for staging.
    type: list[string]
  web_server_parents:
    default:
    - apache2
    - httpd
    - nginx
    - php-cgi
    description: Common PHP-driving web server process names.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing assets running common PHP platforms like WordPress,
  Magento, or custom web applications. Priority should be given to servers running
  mod_php or PHP-FPM without container isolation.
references:
- name: "Elastic Security Labs \u2014 php2shell: Assessing Elastic detection coverage\
    \ relevant to CVE-2026-109618 and CVE-2026-109619"
  url: https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
related:
- hunt: php2shell-persistence-and-c2
  reason: This hunt focuses on the beachhead; a follow-on hunt is required for reverse
    shells and persistence mechanisms.
  relation: follows
scenario:
  stages:
  - name: PHP core RCE exploitation
    observables:
    - CVE-2026-109618
    - CVE-2026-109619
    - unauthenticated HTTP request targeting PHP worker (php-fpm, mod_php, php-cgi)
    slug: initial-access-php-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: Web worker spawning shell
    observables:
    - parent_process_name in ('apache2', 'httpd', 'nginx', 'php-cgi', 'php-fpm', 'lsphp')
    - process_name in ('bash', 'dash', 'sh', 'zsh', 'ksh')
    - process_args in ('-c', '-cl', '-lc')
    slug: execution-web-worker-shell
    tactic: execution
    techniques:
    - T1059
  - name: System and identity enumeration
    observables:
    - id
    - whoami
    - uname -a
    - hostname
    - cat /etc/os-release
    - sudo -l
    - find / -perm -u=s -type f
    - getcap -r /
    - reading /etc/passwd
    - reading /etc/shadow
    slug: discovery-system-enumeration
    tactic: discovery
    techniques:
    - T1087
    - T1082
  - name: Payload staging and interpreter pivot
    observables:
    - python3 -c
    - perl -e
    - ruby -e
    - node -e
    - php -r
    - curl -O
    - wget -O
    - echo <b64> | base64 -d | sh
    - openssl enc -d
    - xxd -r
    slug: execution-payload-staging
    tactic: execution
    techniques:
    - T1059
    - T1105
  - name: Reverse shell communication
    observables:
    - /dev/tcp/
    - mkfifo
    - nc
    - socat
    - pty.spawn
    - fsockopen
    slug: c2-reverse-shell-primitives
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Credential and identity harvesting
    observables:
    - reading .env files
    - reading ~/.aws/credentials
    - accessing /var/run/secrets/kubernetes.io/
    - HTTP request to 169.254.169.254 (IMDS)
    slug: credential-access-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
    - T1552.005
  - name: Webshell and system persistence
    observables:
    - writing .php or .phtml to web root
    - avatar.php.jpg (polyglot/double extension)
    - adding cron entries
    - creating systemd units
    - modifying ~/.ssh/authorized_keys
    slug: persistence-webshell-and-system
    tactic: persistence
    techniques:
    - T1505.003
    - T1133
    - T1053.003
  summary: Unauthenticated remote code execution vulnerabilities in PHP core (CVE-2026-109618
    and CVE-2026-109619) allow attackers to gain code execution in the context of
    web worker processes. Post-exploitation involves web servers spawning shells for
    system discovery, staging second-stage payloads via interpreters, and establishing
    persistence through webshells or system configuration.
series:
  index: 1
  slug: php2shell-assessing-elastic-detection-coverage-relevant-to-cve-2026-109618-and-cve-2026-109619
  title: 'php2shell: Assessing Elastic detection coverage relevant to CVE-2026-109618
    and CVE-2026-109619'
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


# PHP2Shell: Web-to-Shell Staging

This hunt targets the convergent post-exploitation footprint of PHP core vulnerabilities, where unauthenticated requests trigger a PHP worker to execute arbitrary code. The hunt begins by identifying vulnerable assets and then uses a phased approach to detect the transition from web server processes (like php-fpm or nginx) to shells and language interpreters. By stack-counting unusual parent-child relationships and corroborating them with discovery commands and staging tools, the hunt identifies active compromises where traditional static rules might be bypassed.

## vulnerable-php-assets
<!-- Identify vulnerable PHP assets -->
Locate hosts with active vulnerability findings for the PHP2Shell CVEs to focus the hunt.

```sqlite target=endpoint role=scoping params=(cve_ids=cve_ids)
~~~yaml
expected: Rows identify specific device UIDs and resources that are unpatched for
  the target CVEs. Silence suggests a lower exposure, but is not evidence of absence
  if scans are not current.
reads:
- resource_uid
- device_uid
- cve_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT resource_uid, device_uid, cve_uid, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{cve_ids}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed'
```

## early-execution-parallel
<!-- Early execution analysis -->
parallel:
- → web-worker-shell
- → rare-web-children
join: → agent-triage-early

## web-worker-shell
<!-- Web workers spawning shells -->
Detect the most direct indicator of RCE: a web worker process spawning a shell.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, web_server_parents=web_server_parents, shell_names=shell_names, lookback_days=lookback_days)
~~~yaml
expected: A shell running as a child of a web server. Benign hits include maintenance
  scripts or scheduled backups.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE 'php-fpm%' OR LOWER(parent_process_name) LIKE 'lsphp%') AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-web-children
<!-- Rare web server children -->
Stack-count children of web processes to identify rare pivots across the fleet that behavior rules might miss.

```sqlite target=endpoint role=baseline params=(web_server_parents=web_server_parents, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One or two hosts where a web process spawns an unusual child. Silence means
  the web tier behaves uniformly across the fleet.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
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
verified_at: '2026-10-22'
~~~
SELECT LOWER(parent_process_name) AS parent, LOWER(process_name) AS child, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{web_server_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE 'php-fpm%' OR LOWER(parent_process_name) LIKE 'lsphp%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING hosts <= 2
```

## agent-triage-early
<!-- Triage early execution -->
```agent target=hunter
cite: required
context:
- vulnerable-php-assets
- web-worker-shell
- rare-web-children
max_iterations: 4
objective: Identify hosts where the transition from a web process to a child (shell
  or rare binary) is suspicious, citing specific rows and process command lines.
success_criteria: A list of hosts and processes that warrant follow-on hunting for
  staging behavior.
tools:
- endpoint
```

## follow-on-staging
<!-- Follow-on discovery and staging -->
Search for follow-on actions (enumeration and downloading) on the hosts identified in the early triage.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, staging_tools=staging_tools, lookback_days=lookback_days)
~~~yaml
expected: Discovery commands like whoami or downloaders like curl running on the same
  hosts that showed suspicious early execution.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{staging_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%/etc/os-release%' OR LOWER(process_cmd_line) LIKE '%/etc/shadow%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-verdict
<!-- Correlate end-to-end execution -->
```agent target=hunter
cite: required
context:
- agent-triage-early
- follow-on-staging
max_iterations: 4
objective: Determine if the suspicious initial execution and subsequent staging activity
  on a host indicate a successful PHP RCE compromise. Prioritize hosts where both
  stages are present.
success_criteria: A final verdict of malicious | suspicious | benign for each examined
  host, citing the complete process chain.
tools:
- endpoint
```

## decision-route
<!-- Route on final verdict -->
if~: "the verdict of agent-final-verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → action-isolate
indeterminate: → task-manual-review
unavailable: → task-manual-review (blind_spot: no-agent-coverage)
else: → task-manual-review

## action-isolate
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve memory for forensic analysis to identify the specific PHP script that was targeted.
```
→ task-manual-review

## task-manual-review
<!-- Manual forensic review -->
```manual target=analyst
Review the hb_process_activity and hb_linux_audit logs for the isolated host. Cross-reference the shell launch time with hb_http_activity to find the unauthenticated request that triggered the RCE.
```
→ task-remediation

## task-remediation
<!-- Patch and remediate -->
```manual target=analyst
Update PHP to versions 8.5.12, 8.4.27, 8.3.36, or 8.2.35 across all identified assets.
```
→ end
