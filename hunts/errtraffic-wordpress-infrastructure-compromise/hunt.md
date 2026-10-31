---
analysis: A rule might catch specific PowerShell payloads, but this hunt correlates
  successful web-based logins with the subsequent creation of a rare PHP file in sensitive
  WordPress directories using a fleet-wide prevalence baseline.
blind_spots:
- id: incomplete-file-telemetry
  question: Did the backdoor installation occur during a high-volume file modification
    window?
  requires: hb_file_activity on Linux hosting servers
  risk: Some Linux servers sample file activity or ignore modifications in core WordPress
    directories, potentially missing a small PHP script injection.
  stage: persistence-php-backdoors
- id: http-logging-depth
  question: Was the login successful based on internal application logic?
  requires: hb_http_activity with full response body
  risk: If the web proxy only logs status codes, it may miss successful logins handled
    via 200 OK responses with internal error messages, leading to false negatives.
  stage: initial-access-wordpress-credentials
coverage:
- stage: initial-access-wordpress-credentials
  status: covered
  steps:
  - wp-login-activity
- stage: persistence-php-backdoors
  status: covered
  steps:
  - rare-php-file-changes
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: execution-malicious-js-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: c2-etherhiding-resolution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: execution-clickfix-powershell
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: credential-access-infostealer-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromised WordPress infrastructure is the engine for ErrTraffic
    malware distribution. Finding these backdoors early prevents the deployment of
    ClickFix lures and subsequent infostealer infections.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a WordPress server using harvested credentials
  and installed a PHP backdoor or malicious plugin to facilitate the delivery of ErrTraffic
  ClickFix lures.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1505.003
name: 'ErrTraffic: WordPress Infrastructure and Backdoor Maintenance'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to hunt across the entire
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target systems identified as WordPress servers by hb_software_inventory
  first. If inventory is missing, broaden scope to all web servers with active PHP
  processes.
references:
- name: 'Unveiling ErrTraffic: inside a growing ClickFix malware distribution framework'
  url: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: errtraffic-malicious-js-injection
  reason: This hunt finds the infrastructure; the next hunt identifies the malicious
    scripts being served to visitors.
  relation: follows
scenario:
  stages:
  - name: WordPress Credential Abuse
    observables:
    - Harvested WordPress credentials used for unauthorized logins
    slug: initial-access-wordpress-credentials
    tactic: initial-access
    techniques:
    - T1190
    - T1078
  - name: PHP Backdoor Installation
    observables:
    - Malicious PHP backdoors on WordPress servers
    - Malicious WordPress plugin facilitating framework deployment
    slug: persistence-php-backdoors
    tactic: persistence
    techniques:
    - T1505.003
  - name: JavaScript Framework Injection
    observables:
    - Injected scripts referencing /cf.js
    - Injected scripts referencing /api/css.js
    - DNS-prefetch for llc-image-ico.click
    - Base64-encoded and XOR-obfuscated JavaScript
    slug: execution-malicious-js-injection
    tactic: execution
    techniques:
    - T1059.007
  - name: Blockchain-based C2 Resolution
    observables:
    - Polygon blockchain wallet 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
    - Quicknode RPC endpoint connections
    - C2 domains with .beer, .cfd, .club, .click, .cyou, .lat, .sbs, .shop, and .xyz
      TLDs
    - RC4 encrypted C2 traffic to /api/index.php
    slug: c2-etherhiding-resolution
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1071
    - T1090.003
  - name: User-Driven PowerShell Execution
    observables:
    - PowerShell command lines provided via ClickFix lures (fake BSOD, CAPTCHA)
    - API calls to /api/index.php?a=ctx&os=windows
    - Clipboard interaction to store malicious commands
    slug: execution-clickfix-powershell
    tactic: execution
    techniques:
    - T1059.001
    - T1204.002
  - name: Infostealer Credential Theft
    observables:
    - Vidar, Stealc, Remus, and Salat infostealer payloads
    - Access to browser password storage and clipboard contents
    slug: credential-access-infostealer-impact
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  summary: ErrTraffic is a Malware-as-a-Service framework that compromises WordPress
    sites to inject malicious JavaScript and deploy the ClickFix lure. It utilizes
    EtherHiding via Polygon smart contracts as a dead-drop resolver for its C2 infrastructure,
    eventually tricking users into executing PowerShell commands that deliver infostealers
    like Vidar and Stealc.
series:
  index: 1
  slug: unveiling-errtraffic-a-growing-clickfix-malware-distribution-framework
  title: 'Unveiling ErrTraffic: a growing ClickFix malware distribution framework'
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


# ErrTraffic: WordPress Infrastructure and Backdoor Maintenance

This hunt focuses on the initial access and persistence phases of the ErrTraffic framework. It identifies servers running WordPress, looks for successful administrative authentications via HTTP POST traffic to login pages, and correlates these with rare file system modifications in sensitive WordPress directories like plugins and themes. The goal is to detect the PHP backdoors used to manage malicious JavaScript injections and ClickFix lures as described in the Sekoia ErrTraffic research.

## identify-wordpress-servers
<!-- Identify WordPress Servers -->
Find every host in the inventory running WordPress software to narrow the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames acting as WordPress servers. Silence indicates no WordPress
  installations were detected by the inventory provider.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%wordpress%'
```

## parallel-evidence-gathering
<!-- Parallel Evidence Gathering -->
parallel:
- → wp-login-activity
- → rare-php-file-changes
join: → triage-wordpress-compromise

## wp-login-activity
<!-- Successful WordPress Web Logins -->
Identify successful logins to WordPress via HTTP POST traffic, which may represent the use of harvested credentials.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful POST requests to wp-login.php. A 302 status often indicates a
  successful redirect to the dashboard.
reads:
- device_hostname
- url_path
- http_method
- status_code
- src_endpoint_ip
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, user_agent, time FROM hb_http_activity WHERE LOWER(url_path) LIKE '%wp-login.php%' AND http_method = 'POST' AND status_code IN (200, 302) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-php-file-changes
<!-- Rare PHP File Modifications -->
Stack-count PHP file changes in sensitive WordPress directories to find rare backdoors or malicious plugins.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare PHP file modifications in core WordPress directories. Legitimate updates
  usually touch many hosts; localized changes are suspicious.
prevalence:
  by: device_hostname
  key:
  - file_path
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT file_path, file_name, GROUP_CONCAT(DISTINCT device_hostname) AS hosts, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%wp-content/plugins%' OR LOWER(file_path) LIKE '%wp-content/themes%' OR LOWER(file_path) LIKE '%wp-includes%') AND LOWER(file_name) LIKE '%.php' AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path, file_name HAVING host_count <= 3
```

## triage-wordpress-compromise
<!-- Triage WordPress Compromise -->
```agent target=hunter
cite: required
context:
- identify-wordpress-servers
- wp-login-activity
- rare-php-file-changes
max_iterations: 4
objective: Determine if the observed web logins and rare file modifications indicate
  an unauthorized WordPress account takeover and subsequent PHP backdoor installation.
success_criteria: The agent identifies hosts where a successful admin login was followed
  by a rare PHP file modification in a sensitive WordPress directory.
tools:
- endpoint
- web
```

## route-compromise
<!-- Route on Compromise Verdict -->
if~: "the triage verdict is malicious or highly suspicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → manual-file-review
unavailable: → manual-file-review (blind_spot: incomplete-file-telemetry)
else: → close-out

## contain-host
<!-- Isolate WordPress Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and reset WordPress administrative credentials. Capture the suspicious PHP files for forensic analysis.
```
→ manual-file-review

## manual-file-review
<!-- Manual File and Backdoor Review -->
```manual target=analyst
Inspect the content of the suspicious PHP files identified in 'rare-php-file-changes'. Look for XOR-obfuscated JavaScript, shell execution commands, or code that matches the ErrTraffic v3 patterns.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Document the compromised hosts, the discovered PHP backdoors, and the associated WordPress accounts. Recommend updates to file monitoring policies for web servers.
```
→ end
