---
analysis: A static rule can find the plesk_sys_driver.php filename, but this hunt
  correlates rare configuration changes with live behavioral anomalies like web server
  process managers spawning shells, identifying AI-generated payloads that use varying
  filenames or paths to evade simple rules.
blind_spots:
- id: missing-file-telemetry
  question: Which process originally modified the PHP configuration files
  requires: hb_linux_audit or real-time FIM on /etc/php and /opt/plesk
  risk: If file activity logging is not enabled for system configuration paths, the
    initial modification by the web shell may be missed, leaving only the persistent
    state visible.
  stage: php-persistence-tampering
- id: ephemeral-webshell-execution
  question: Whether a web shell was deployed and deleted in a very short window
  requires: hb_process_activity with low latency
  risk: AI-automated agents may deploy a web shell, execute commands, and delete the
    file within seconds, making it invisible to file system snapshots.
  stage: web-shell-deployment
coverage:
- stage: web-shell-deployment
  status: covered
  steps:
  - webshell-execution-patterns
  - rare-config-modifications
- stage: php-persistence-tampering
  status: covered
  steps:
  - rare-config-modifications
- stage: credential-harvesting-sudo
  status: covered
  steps:
  - rare-config-modifications
- reason: Belongs to another part of the 'AI-Powered Espionage Campaign Targets Government
    Linux Infrastructure' series.
  stage: sysgorat-execution
  status: out_of_scope
- reason: Belongs to another part of the 'AI-Powered Espionage Campaign Targets Government
    Linux Infrastructure' series.
  stage: reverse-shell-activity
  status: out_of_scope
- reason: Belongs to another part of the 'AI-Powered Espionage Campaign Targets Government
    Linux Infrastructure' series.
  stage: c2-communication
  status: out_of_scope
- reason: Belongs to another part of the 'AI-Powered Espionage Campaign Targets Government
    Linux Infrastructure' series.
  stage: data-collection-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protects Linux web infrastructure from automated, AI-driven persistence
    that bypasses standard signatures by masquerading as legitimate administrative
    configuration changes.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence on Linux web servers using AI-generated
  PHP web shells and hijacked administrative credentials by tampering with shell profiles
  and configuration files.
labels:
- hunt
- attack.t1505.003
- attack.t1059
- attack.t1071
- attack.t1041
- collection
- command and control
- credential access
- execution
- persistence
name: Linux Persistence and Credential Hijacking
parameters:
  known_malicious_files:
    default:
    - plesk_sys_driver.php
    - search_social.php
    - Solarwinds.StatusLog.txt
    - zip_mails.sh
    description: Malicious filenames or decoy logs identified in the campaign.
    from:
      kind: article
      observed: '2026-10-15'
      ref: Unit 42 CL-UNK-1211
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the scoping step; refresh this list
      with results from identify-linux-web-servers before running detection steps.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with Linux servers running Plesk or public-facing PHP applications.
  The identify-linux-web-servers query finds these based on installed software. Use
  the resulting host list to populate scope_hosts for the detection queries.
references:
- name: "Unit 42 \u2014 AI-Powered Espionage Campaign Targets Government Linux Infrastructure"
  url: https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/
related:
- hunt: sysgorat-rat-detection
  reason: Detection of the custom Go-based SysGoRAT binary is handled in a separate
    hunt focused on binary-on-disk analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Web Shell Deployment
    observables:
    - /usr/lib/php/plesk_sys_driver.php
    - POST requests to PHP files via php-fpm parent process
    - search_social.php
    slug: web-shell-deployment
    tactic: persistence
    techniques:
    - T1505.003
  - name: PHP Configuration Tampering
    observables:
    - Modification of auto_prepend_file in /etc/php/
    - Modification of auto_prepend_file in /opt/plesk/php/
    slug: php-persistence-tampering
    tactic: persistence
    techniques:
    - T1505.003
  - name: Sudo Command Hijacking
    observables:
    - Modification of .bashrc with sudo aliases
    - Solarwinds.StatusLog.txt
    - Commands searching for SMTP or database passwords in config files
    slug: credential-harvesting-sudo
    tactic: credential-access
    techniques:
    - T1059
  - name: SysGoRAT Backdoor Execution
    observables:
    - sys-control-client
    - pip2.7
    - ea_install
    - ./semanage
    - Go-based multi-platform RAT
    slug: sysgorat-execution
    tactic: execution
    techniques:
    - T1059
  - name: In-Memory Reverse Shells
    observables:
    - mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc
    - bash -i >& /dev/tcp/
    - python3 -c "import socket,subprocess,os; s=socket.socket(...)"
    slug: reverse-shell-activity
    tactic: execution
    techniques:
    - T1059
  - name: WebSocket Command and Control
    observables:
    - wss://<addr>/ws
    - 104.194.158.65:443
    - proxy_connect command via RAT
    slug: c2-communication
    tactic: command-and-control
    techniques:
    - T1071
  - name: Mailbox and Database Collection
    observables:
    - Enumeration of /var/qmail/mailnames/
    - zip_mails.sh
    - Iteration through Maildir/cur/ directories
    slug: data-collection-exfiltration
    tactic: collection
    techniques:
    - T1041
  summary: CL-UNK-1211 is an AI-assisted campaign targeting government Linux infrastructure
    to exfiltrate mailboxes and sensitive databases. The attackers utilize custom
    Go-based backdoors (SysGoRAT), extensive web shell deployments, and creative credential
    theft such as hijacking the sudo command through .bashrc modifications.
series:
  index: 1
  slug: ai-powered-espionage-campaign-targets-government-linux-infrastructure
  title: AI-Powered Espionage Campaign Targets Government Linux Infrastructure
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


# Linux Persistence and Credential Hijacking

The adversary uses AI-assisted code to modify PHP configuration directories and .bashrc profiles, ensuring that malicious code executes whenever a web request is processed or a user elevates privileges. This hunt targets the activity of CL-UNK-1211, focusing on the specialized Linux persistence and credential theft observed in their campaign. The hunt identifies the web server estate and executes parallel checks: one to find anomalous shell execution originating from web server process managers, and another to baseline rare file modifications across critical configuration paths. The analyst evaluates the results to differentiate legitimate administrative activity from AI-automated intrusion artifacts.

## identify-linux-web-servers
<!-- Identify Linux web server estate -->
Scope the hunt to Linux hosts running PHP, Plesk, or common web server packages where these persistence techniques are viable.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames serving as web infrastructure. Use these results to
  populate the scope_hosts parameter for subsequent steps.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%php%' OR LOWER(package_name) LIKE '%plesk%' OR LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%apache%') AND asset_scope = 'endpoint'
```

## corroborate-threat-evidence
<!-- Corroborate behavior and rare persistence -->
parallel:
- → webshell-execution-patterns
- → rare-config-modifications
join: → triage-compromise

## webshell-execution-patterns
<!-- Web shell execution patterns -->
Identify the primary behavioral signature of a web shell: a web server process manager spawning an interactive shell or interpreter.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Web server child processes that are shell interpreters. User name 'www-data'
  or similar indicates web shell context; 'root' indicates successful privilege escalation.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%php-fpm%' OR LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%apache%') AND (LOWER(process_name) LIKE '%bash%' OR LOWER(process_name) LIKE '%sh%' OR LOWER(process_name) LIKE '%nc%' OR LOWER(process_name) LIKE '%python%' OR LOWER(process_name) LIKE '%perl%' OR LOWER(process_name) LIKE '%php%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-config-modifications
<!-- Rare modifications to configurations and profiles -->
Identify modifications to PHP configuration directories and shell profiles that are rare across the fleet, suggesting targeted tampering.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, known_malicious_files=known_malicious_files)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare file modifications in critical paths. The presence of deceptive names
  like Solarwinds.StatusLog.txt or plesk_sys_driver.php on specific hosts is a strong
  indicator of the CL-UNK-1211 playbook.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 5
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, actor_user_name, file_path, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/etc/php/%' OR LOWER(file_path) LIKE '%/opt/plesk/php/%' OR LOWER(file_path) LIKE '%/.bashrc' OR instr(',' || '{{known_malicious_files}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND file_path IN (SELECT file_path FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/etc/php/%' OR LOWER(file_path) LIKE '%/opt/plesk/php/%' OR LOWER(file_path) LIKE '%/.bashrc' OR instr(',' || '{{known_malicious_files}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path HAVING COUNT(DISTINCT device_hostname) <= 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage compromise indicators -->
```agent target=hunter
cite: required
context:
- webshell-execution-patterns
- rare-config-modifications
max_iterations: 4
objective: Identify persistent web shells or credential harvesting artifacts by correlating
  rare file modifications with anomalous shell execution under web server processes.
  Compare the user context of process execution against the file actors to identify
  suspicious elevation.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  relevant process and file rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on shell execution and config tampering" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-verification
unavailable: → forensic-verification (blind_spot: missing-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active sessions for administrative accounts seen in the interactive shell telemetry.
```
→ forensic-verification

## forensic-verification
<!-- Forensic verification -->
```manual target=analyst
Examine the identified .bashrc and PHP configuration files on the isolated host. Check for conversational comments or 'AI-reasoning' markers within the code. Recover the content of any deceptive log files like Solarwinds.StatusLog.txt to identify captured administrative passwords and force immediate resets for those accounts.
```
→ close-out

## close-out
<!-- Hunt closure -->
```manual target=analyst
Record the effectiveness of the prevalence check for identifying configuration tampering. Note any hosts that lacked software inventory for web services.
```
→ end
