---
analysis: A single rule for 'bash from apache' exists but is often disabled for noise;
  this hunt uses prevalence and multi-surface correlation (process + file) to identify
  rare credential access that a standing rule cannot baseline effectively.
blind_spots:
- id: no-linux-endpoint-telemetry
  question: Are all web server nodes enrolled in process and file monitoring?
  requires: Endpoint agent on all Linux web nodes
  risk: A host without an agent provides no telemetry for process spawns or file reads,
    making RCE outcome invisible.
  stage: c2-reverse-shell-primitives
- id: fileless-php-execution
  question: Can we see PHP execution that uses eval() without spawning a shell?
  requires: PHP interpreter-level auditing
  risk: In-memory only execution bypasses process and file surfaces; detection relies
    on networking or script-block logging which may be incomplete.
  stage: c2-reverse-shell-primitives
coverage:
- stage: c2-reverse-shell-primitives
  status: covered
  steps:
  - web-worker-reverse-shells
- stage: credential-access-harvesting
  status: covered
  steps:
  - web-worker-credential-access
- stage: persistence-webshell-and-system
  status: covered
  steps:
  - web-worker-credential-access
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: initial-access-php-rce
  status: out_of_scope
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: execution-web-worker-shell
  status: out_of_scope
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: discovery-system-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''php2shell: Assessing Elastic detection
    coverage relevant to CVE-2026-109618 and CVE-2026-109619'' series.'
  stage: execution-payload-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: PHP core vulnerabilities are critical (9.2) and unauthenticated.
    Proactively hunting for post-exploitation behavior ensures that even if initial
    RCE occurred, the attacker did not gain persistent control or harvest sensitive
    credentials.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has exploited a PHP core vulnerability (CVE-2026-109618/109619)
  and is using the web worker context to harvest credentials or establish persistence
  via reverse shells and web shells.
labels:
- hunt
- attack.t1190
- attack.t1552.001
- attack.t1552.005
- attack.t1071.001
- attack.t1505.003
- attack.t1053.003
- command and control
- credential access
- discovery
- execution
- initial access
- persistence
name: Post-RCE Persistence and Credential Theft
parameters:
  credential_paths:
    default:
    - /.env
    - /.aws/credentials
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - /etc/shadow
    description: Sensitive file paths commonly targeted for harvesting.
    from:
      kind: article
      observed: '2024-10-21'
      ref: php2shell
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-21'
      ref: standard-retention
    type: number
  reverse_shell_tools:
    default:
    - nc
    - socat
    - ncat
    - netcat
    - mkfifo
    description: Binary names often used to establish interactive shells.
    from:
      kind: article
      observed: '2024-10-21'
      ref: php2shell
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on.
    from:
      kind: manual
      observed: '2024-10-21'
      ref: analyst-scoping
    type: list[host]
  web_worker_names:
    default:
    - php-fpm
    - apache2
    - httpd
    - nginx
    - lsphp
    - php-cgi
    description: Process names of common web workers and PHP runtimes.
    from:
      kind: article
      observed: '2024-10-21'
      ref: php2shell
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
rationale: Prioritize Linux servers running external-facing PHP applications. If the
  software inventory is outdated, run the hunt unscoped to capture all web workers.
references:
- name: 'php2shell: Assessing Elastic detection coverage relevant to CVE-2026-109618
    and CVE-2026-109619'
  url: https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection
related:
- hunt: initial-access-php-rce
  reason: This hunt focuses on post-exploitation outcomes; initial HTTP-level exploitation
    is a separate analysis of web logs.
  relation: out-of-scope-alternative
- hunt: php2shell-web-to-shell-staging
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
  index: 2
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


# Post-RCE Persistence and Credential Theft

This hunt targets the post-exploitation objectives of the php2shell vulnerabilities. It specifically examines web worker processes (php-fpm, apache2, nginx) for convergent malicious behavior: accessing cloud credentials, environment files, or instance metadata, and spawning interactive shell primitives like netcat or socat. The hunt uses a parallel fan-out to analyze file activity and process execution across multiple surfaces, identifying rare or unauthorized actions originating from the web stack.

## identify-php-assets
<!-- Identify PHP-capable assets -->
Scope the hunt to hosts running PHP or major web server packages.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that likely have a web stack capable of being exploited
  by PHP RCE. Silence suggests the estate has no indexed PHP/web software.
reads:
- package_name
- device_hostname
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%php%' OR LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%nginx%') AND asset_scope = 'endpoint'
```

## correlate-post-rce
<!-- Correlate post-RCE activity -->
parallel:
- → web-worker-credential-access
- → web-worker-reverse-shells
join: → triage-worker-behavior

## web-worker-credential-access
<!-- Web worker access to credentials and persistence -->
Identify web workers reading credential files or writing new PHP/phtml files.

```sqlite target=endpoint role=baseline params=(web_worker_names=web_worker_names, credential_paths=credential_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A web worker process accessing sensitive files or creating new PHP scripts
  on a small subset of hosts. Normal application behavior should be widespread and
  excluded by the prevalence check.
prevalence:
  by: device_hostname
  key:
  - process_name
  - file_path
  rare_below: 5
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, file_path, activity_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (instr(',' || '{{web_worker_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{web_worker_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (instr(',' || '{{credential_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR (activity_id = 1 AND (LOWER(file_path) LIKE '%.php' OR LOWER(file_path) LIKE '%.phtml' OR LOWER(file_path) LIKE '%avatar.php.jpg'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path, activity_name HAVING host_count <= 5
```

## web-worker-reverse-shells
<!-- Web worker spawning shells and network tools -->
Identify web workers spawning shell primitives or redirection tools used for interactive access.

```sqlite target=endpoint role=triage params=(web_worker_names=web_worker_names, reverse_shell_tools=reverse_shell_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A web worker spawning netcat, socat, or shell primitives. This is a high-confidence
  signal of post-exploitation command-and-control.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{web_worker_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR instr(',' || '{{web_worker_names}}' || ',', ',' || LOWER(actor_process_name) || ',') > 0) AND (instr(',' || '{{reverse_shell_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR process_cmd_line LIKE '%/dev/tcp/%' OR process_cmd_line LIKE '%pty.spawn%' OR process_cmd_line LIKE '%fsockopen%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-worker-behavior
<!-- Triage worker behavior -->
```agent target=hunter
cite: required
context:
- web-worker-credential-access
- web-worker-reverse-shells
max_iterations: 4
objective: Determine if the rare file access and process execution patterns indicate
  a compromised web node.
success_criteria: A detailed verdict per host citing rows that show unauthorized transitions
  from web requests to system-level access.
tools:
- endpoint
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host involving credential theft or reverse shells" (confidence: high, judge=hunter)
then: → isolate-affected-host
indeterminate: → manual-forensic-review
unavailable: → manual-forensic-review (blind_spot: no-linux-endpoint-telemetry)
else: → close-out-php-hunt

## isolate-affected-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any cloud credentials found in the agent context, and collect memory/web-root artifacts.
```
→ manual-forensic-review

## manual-forensic-review
<!-- Manual forensic review -->
```manual target=analyst
Review the cited rows. Verify if the web worker access to .env or AWS credentials is part of a standard application deployment. Check the timing of file writes against known RCE disclosure windows.
```
→ close-out-php-hunt

## close-out-php-hunt
<!-- Close out PHP hunt -->
```manual target=analyst
Document the hosts examined. If no malicious activity was found, record this as evidence of absence for the php2shell scenario.
```
→ end
