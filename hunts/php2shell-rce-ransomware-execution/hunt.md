---
analysis: This hunt correlates the presence of unpatched software, network-level exploit
  attempts, and behavioral encryption patterns to identify a complete intrusion chain
  that a single detection rule would miss.
blind_spots:
- id: no-file-telemetry
  question: whether encryption is occurring on hosts where file logging is suppressed
    for high-volume processes
  requires: hb_file_activity with bulk modification logging
  risk: Massive encryption activity might not emit sufficient rows to be identified
    by a count-based baseline.
  stage: impact-data-encryption
- id: http-visibility
  question: whether the exploit attempt is visible in HTTPS traffic
  requires: hb_http_activity with SSL decryption
  risk: Exploits delivered over encrypted channels will not be visible in raw HTTP
    logs without decryption.
  stage: initial-access-php2shell-rce
coverage:
- stage: vulnerability-identification-eol-php
  status: covered
  steps:
  - scope-vulnerable-php
- stage: initial-access-php2shell-rce
  status: covered
  steps:
  - http-exploit-requests
  - php-child-interpreters
- stage: execution-payload-deployment
  status: covered
  steps:
  - malicious-payloads
- stage: impact-data-encryption
  status: covered
  steps:
  - bulk-file-encryption
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The php2shell vulnerability represents a critical RCE threat to PHP-based
    web applications, and its exploitation for ransomware by INC and The Gentlemen
    affiliates has severe operational impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited the php2shell unauthenticated RCE vulnerability
  on a host running an end-of-life PHP version to deploy ransomware and encrypt local
  data.
labels:
- hunt
- attack.t1190
- attack.t1486
- attack.t1059.003
- attack.t1082
- discovery
- execution
- impact
- initial access
name: PHP2Shell RCE and Ransomware Execution
parameters:
  interpreter_names:
    default:
    - cmd.exe
    - powershell.exe
    - sh
    - bash
    - python
    - curl
    - wget
    description: Common shell and utility binaries launched by web servers after exploitation.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: Common tradecraft
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  payload_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 7fc50b69b56bfdfa9fc0a3e088ff13904587d6336a51e9edcc7919cba83d4e3f
    - 985c3972712218c62d2418b41056dba5fe883ca5104d8ec12041f8611db344f9
    - d921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1
    description: SHA256 hashes of payloads from the Talos report.
    from:
      kind: article
      observed: '2026-10-22'
      ref: https://blog.talosintelligence.com/i-had-plans-for-that-second/
    type: list[hash]
  payload_names:
    default:
    - sample.exe
    - cca616647db9370c88998ae25da6997f.exe
    - 485055033bcddfde56325c0d2feea4f2.exe
    - d921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1.exe
    description: Filenames associated with malicious activity.
    from:
      kind: article
      observed: '2026-10-22'
      ref: https://blog.talosintelligence.com/i-had-plans-for-that-second/
    type: list[path]
  scope_hosts:
    default: []
    description: Hosts identified as running vulnerable PHP; if empty, the whole estate
      is searched.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/i-had-plans-for-that-second/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-exposed servers in the DMZ. Use the scoping step to
  identify hosts where the software inventory confirms PHP 8.1 or older.
references:
- name: "Cisco Talos \u2014 I had plans for that second"
  url: https://blog.talosintelligence.com/i-had-plans-for-that-second/
related:
- hunt: generic-php-webshell-behavior
  reason: Adversaries may use the same PHP2Shell exploit to drop generic webshells
    without proceeding to ransomware.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Identification of Vulnerable PHP Environments
    observables:
    - PHP versions 5.4 through 8.1
    - End of Life (EOL) PHP branches
    - WordPress, Drupal, Magento, Shopware, WooCommerce
    slug: vulnerability-identification-eol-php
    tactic: discovery
    techniques:
    - T1082
  - name: PHP2Shell Remote Code Execution
    observables:
    - Simple HTTP request
    - php2shell
    - Targeting WordPress, Drupal, or Magento installations
    slug: initial-access-php2shell-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Payload Execution
    observables:
    - sample.exe
    - cca616647db9370c88998ae25da6997f.exe
    - 485055033bcddfde56325c0d2feea4f2.exe
    - d921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1.exe
    - Win.Tool.Kmsauto
    - Win.Worm.Zard
    slug: execution-payload-deployment
    tactic: execution
    techniques:
    - T1059.003
  - name: Ransomware Encryption
    observables:
    - INC Ransomware encryptor builds
    - The Gentlemen ransomware encryptor builds
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Attackers exploit 'php2shell' unauthenticated RCE vulnerabilities in PHP
    versions 5.4 through 8.1 via crafted HTTP requests to gain initial access. This
    exploitation is being leveraged by ransomware affiliates like INC and The Gentlemen
    to execute malicious payloads, including encryptors and administrative tools.
severity: critical
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


# PHP2Shell RCE and Ransomware Execution

This phased hunt identifies internet-facing hosts running vulnerable, end-of-life PHP versions (5.4 through 8.1) and investigates signs of the php2shell RCE. The first phase looks for suspicious HTTP requests and unusual child processes spawned by the PHP interpreter. The second phase follows these leads to identify the deployment of specific ransomware payloads mentioned in the Talos research and evidence of mass file encryption. The hunt concludes by routing suspicious hosts for immediate isolation and analyst review.

## scope-vulnerable-php
<!-- Identify EOL PHP environments -->
Scope the estate to hosts running PHP versions 5.4 through 8.1 which are susceptible to PHP2Shell.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts and their PHP versions. Zero rows means no vulnerable versions
  are recorded in the inventory.
reads:
- device_hostname
- install_path
- package_name
- package_version
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%php%' OR LOWER(package_name) LIKE '%wordpress%' OR LOWER(package_name) LIKE '%drupal%' OR LOWER(package_name) LIKE '%magento%' OR LOWER(package_name) LIKE '%shopware%' OR LOWER(package_name) LIKE '%woocommerce%') AND (package_version LIKE '5.%' OR package_version LIKE '6.%' OR package_version LIKE '7.%' OR package_version LIKE '8.0%' OR package_version LIKE '8.1%')
```

## parallel-early
<!-- Investigate initial access signals -->
parallel:
- → http-exploit-requests
- → php-child-interpreters
join: → early-triage

## http-exploit-requests
<!-- HTTP requests to PHP targets -->
Find HTTP requests targeting PHP endpoints or application-specific paths on the scoped hosts.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unusual HTTP requests targeting PHP scripts, potentially containing exploit
  strings.
reads:
- device_hostname
- src_endpoint_ip
- status_code
- time
- url_path
- url_query
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, url_path, url_query, src_endpoint_ip, status_code, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(url_path) LIKE '%.php%' OR LOWER(url_query) LIKE '%php2shell%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## php-child-interpreters
<!-- PHP spawning shells or interpreters -->
Identify if a PHP interpreter launched a shell or common utility, indicating code execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, interpreter_names=interpreter_names)
~~~yaml
expected: Processes like cmd.exe or sh whose parent is a PHP binary. This is highly
  indicative of successful RCE.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- process_original_file_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(parent_process_name) LIKE '%php%' AND (instr(',' || '{{interpreter_names}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{interpreter_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage
<!-- Evaluate early-stage signals -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-php
- http-exploit-requests
- php-child-interpreters
max_iterations: 3
objective: Determine if any host running EOL PHP has been targeted by an HTTP request
  that resulted in an unusual shell or utility launch.
success_criteria: A per-host verdict citing specific rows from the process and HTTP
  surfaces.
tools:
- endpoint
- web
```

## parallel-follow-on
<!-- Investigate follow-on impact -->
parallel:
- → malicious-payloads
- → bulk-file-encryption
join: → follow-on-triage

## malicious-payloads
<!-- Match known payload indicators -->
Search for the specific SHA256 hashes and executables used by INC and The Gentlemen ransomware.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, payload_hashes=payload_hashes, payload_names=payload_names)
~~~yaml
expected: Execution of a binary matching the report's hashes or names. Any hit is
  high confidence for payload deployment.
reads:
- device_hostname
- process_cmd_line
- process_hash_sha256
- process_name
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_hash_sha256, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{payload_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR instr(',' || '{{payload_names}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## bulk-file-encryption
<!-- Detection of mass file modifications -->
Identify processes performing high-volume file modifications, indicative of encryption.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A process modifying over 100 files on a single host. If that process matches
  the payload query, impact is confirmed.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) AS unique_files, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_files > 100
```

## follow-on-triage
<!-- Evaluate full intrusion chain -->
```agent target=hunter
cite: required
context:
- early-triage
- malicious-payloads
- bulk-file-encryption
max_iterations: 4
objective: Confirm if the early-stage RCE indicators on PHP hosts correlate with the
  identified ransomware payload execution and mass file modification.
success_criteria: A definitive verdict for each host showing at least two stages of
  the chain.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-telemetry)
else: → close-out

## contain-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the malicious binary for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Intrusion confirmation -->
```manual target=analyst
Review the agent's citations. Verify the PHP version on the target and the source of the HTTP request. If encryption is confirmed, initiate the ransomware recovery playbook.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record that no active intrusion was found. Note any EOL PHP hosts for immediate update to PHP 8.2+ as per the advisory.
```
→ end
