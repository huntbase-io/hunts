---
analysis: A simple rule for 'nc' or 'bash -i' is often too noisy for developer-heavy
  Linux environments. This hunt pivots from the initial behavioral lead to verify
  C2 traffic and then stack-counts the specific data collection patterns (mailbox
  zipping) that define this intrusion cluster, using three surfaces to confirm a breach.
blind_spots:
- id: shell-visibility-gap
  question: whether the redirect pattern bash -i >& /dev/tcp/ was executed inside
    a complex script
  requires: command-line auditing or script block logging on Linux
  risk: If the bash redirect is executed via an eval or inside a pre-existing shell
    without a new process launch, the command line might not be visible in hb_process_activity.
  stage: reverse-shell-activity
- id: network-visibility-gap
  question: whether the WebSocket traffic was for SysGoRAT or a benign service
  requires: hb_http_activity with decrypted WebSocket headers
  risk: WebSocket traffic (wss://) is encrypted; hb_network_connection sees only the
    IP and port, preventing confirmation of the WebSocket protocol or URI path without
    a decrypting proxy.
  stage: c2-communication
coverage:
- stage: reverse-shell-activity
  status: covered
  steps:
  - lead-reverse-shells
- stage: c2-communication
  status: covered
  steps:
  - c2-network-hits
- stage: data-collection-exfiltration
  status: covered
  steps:
  - mailbox-access-baseline
- reason: Handled by the preceding hunt in this series.
  stage: web-shell-deployment
  status: out_of_scope
- reason: Handled by the preceding hunt in this series.
  stage: php-persistence-tampering
  status: out_of_scope
- reason: Handled by the preceding hunt in this series.
  stage: credential-harvesting-sudo
  status: out_of_scope
- reason: Handled by the preceding hunt in this series.
  stage: sysgorat-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The exfiltration of government mailboxes and databases represents
    a critical loss of sensitive data; a negative result for these collection patterns
    over the mail infrastructure is a high-value signal for national security.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using in-memory reverse shells to conduct interactive
  discovery and exfiltrate government mailboxes, likely use AI-assisted scripting
  patterns for efficiency.
labels:
- hunt
- attack.t1059
- attack.t1071
- attack.t1041
- collection
- command and control
- credential access
- execution
- persistence
name: Interactive Shells and Data Collection (CL-UNK-1211)
parameters:
  c2_ips:
    default:
    - 104.194.158.65
    description: Known C2 IP addresses from the CL-UNK-1211 report.
    from:
      kind: article
      observed: '2026-10-15'
      ref: unit42-ai-espionage-2026
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
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
rationale: Focus the hunt on Linux-based mail servers (qmail, postfix) and database
  servers, as these are the primary targets for the collection techniques described
  in the CL-UNK-1211 report.
references:
- name: "Unit 42 \u2014 AI-Powered Espionage Campaign Targets Government Linux Infrastructure"
  url: https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/
related:
- hunt: cl-unk-1211-initial-access-and-persistence
  reason: The initial web shell deployment and credential harvesting phase are handled
    in a separate hunt focused on web server persistence.
  relation: precedes
- hunt: linux-persistence-credential-hijacking
  relation: follows
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Interactive Shells and Data Collection (CL-UNK-1211)

This hunt focuses on the active intrusion phase of the CL-UNK-1211 campaign. It identifies behavioral indicators of interactive reverse shells (Netcat, Bash redirects, and Python subprocesses) which the attacker uses to enumerate and compress mailbox data for exfiltration. The hunt uses a gated flow, first identifying the characteristic shell patterns before fanning out to check for known C2 traffic and unusual mailbox access across the Linux estate.

## lead-reverse-shells
<!-- Suspicious reverse shell patterns -->
Identify the characteristic behavioral patterns of in-memory reverse shells using pipes, redirects, or scripted sockets.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows containing shell commands that redirect I/O to network sockets. Silence
  indicates no shell redirection was captured in the process logs during the window.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, user_name, process_cmd_line, time FROM hb_process_activity WHERE ((LOWER(process_cmd_line) LIKE '%mkfifo%' AND LOWER(process_cmd_line) LIKE '%nc %') OR (LOWER(process_cmd_line) LIKE '%/dev/tcp/%') OR (LOWER(process_cmd_line) LIKE '%socket.socket%' AND LOWER(process_cmd_line) LIKE '%subprocess.call%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-assessment
<!-- Assess lead validity -->
```agent target=hunter
cite: required
context:
- lead-reverse-shells
max_iterations: 3
objective: Decide if the reverse shell patterns in lead-reverse-shells require further
  investigation based on the context of the user and host.
success_criteria: A verdict of malicious | suspicious | benign for the reverse shell
  patterns found.
tools:
- endpoint
- network
```

## gate-on-lead
<!-- Gate on reverse shell activity -->
if~: "the lead-assessment verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-corroboration
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: shell-visibility-gap)
else: → close-out

## parallel-corroboration
<!-- Corroborate with network and collection logs -->
parallel:
- → c2-network-hits
- → mailbox-access-baseline
join: → final-triage

## c2-network-hits
<!-- Network connections to C2 IPs -->
Verify if the hosts with suspicious shells are communicating with the reported C2 infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Outbound connections to 104.194.158.65. Silence does not rule out infection
  if the adversary rotated IPs.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## mailbox-access-baseline
<!-- Rare mailbox access and compression -->
Stack-count directory enumeration and compression commands involving mail storage to identify data collection while filtering common administrative noise.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare command string zipping a mail directory on one or two hosts. Genuine
  backup processes should be frequent across the fleet.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/var/qmail/%' OR LOWER(process_cmd_line) LIKE '%/maildir/%' OR LOWER(process_cmd_line) LIKE '%/cur/%') AND (LOWER(process_cmd_line) LIKE '%zip %' OR LOWER(process_cmd_line) LIKE '%tar %' OR LOWER(process_cmd_line) LIKE '%find %') AND LOWER(process_name) NOT LIKE '%backup%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## final-triage
<!-- Combined evidence triage -->
```agent target=hunter
cite: required
context:
- lead-assessment
- c2-network-hits
- mailbox-access-baseline
max_iterations: 6
objective: Determine if the evidence across lead-reverse-shells, c2-network-hits,
  and mailbox-access-baseline confirms an active intrusion on the target hosts.
success_criteria: A combined verdict on whether the initial shell activity and follow-on
  collection constitute a confirmed intrusion.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on confirmed intrusion -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: network-visibility-gap)
else: → manual-review

## isolate-endpoint
<!-- Isolate confirmed host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve process memory to capture the in-memory shell scripts and the SysGoRAT binary.
```
→ manual-review

## manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the shell commands and network hits; determine if the mailbox collection represents a breach of sensitive data and notify the relevant government mailbox owners.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the findings and update the detection rule for reverse shells based on any tuning notes identified.
```
→ end
