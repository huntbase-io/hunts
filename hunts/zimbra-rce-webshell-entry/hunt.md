---
analysis: A simple rule for the ZB73570 User-Agent is easily bypassed by rotating
  headers. This hunt uses a prevalence baseline for JSP files in application webroots
  and pivots into the specific process lineage of a monitoring component (swatchdog)
  that should never spawn network tools or interactive shells.
blind_spots:
- id: no-http-telemetry
  question: Are the reconnaissance probes reaching the mail server?
  requires: hb_http_activity or web server logs
  risk: Without HTTP visibility, the lead activity is missed and the gate to deeper
    investigation remains closed.
  stage: reconnaissance-and-probing
- id: no-endpoint-telemetry
  question: Can we observe the child processes of snmptrap?
  requires: hb_process_activity on Linux mail servers
  risk: If the mail server lacks an endpoint agent, unauthenticated command execution
    occurs invisibly.
  stage: initial-access-cve-2026-73570
- id: short-file-retention
  question: Was the JSP web shell drop captured if it occurred weeks ago?
  requires: hb_file_activity retention > 14 days
  risk: Attackers often deploy shells early and then use them sparingly; short retention
    hides the persistence installation.
  stage: persistence-jsp-webshells
coverage:
- stage: reconnaissance-and-probing
  status: covered
  steps:
  - lead-probing-activity
- stage: initial-access-cve-2026-73570
  status: covered
  steps:
  - command-injection-processes
- stage: persistence-jsp-webshells
  status: covered
  steps:
  - rare-jsp-webshells
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: discovery-cluster-mapping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: privilege-escalation-pam-hook
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: host-persistence-systemd
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: credential-access-zimbra-secrets
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: lateral-movement-ssh-rsync
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: command-and-control-agent
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: exfiltration-mailbox-data
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Unauthenticated command injection on internet-facing mail servers
    provides an immediate beachhead for cluster-wide credential theft and mailbox
    exfiltration. A negative result confirms that the vulnerable SNMP notification
    path has not been exploited on the current estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting CVE-2026-73570 on internet-facing Zimbra servers
  to execute commands via the SNMP path and drop JSP web shells in the webroot for
  persistence.
labels:
- hunt
- attack.t1190
- attack.t1059.004
- attack.t1505.003
- attack.t1071.001
- attack.t1041
- command and control
- credential access
- discovery
- exfiltration
- initial access
- lateral movement
- persistence
- privilege escalation
- reconnaissance
name: Zimbra CVE-2026-73570 RCE and JSP Web Shell Entry
parameters:
  exploit_user_agent:
    default: ZB73570
    description: CVE-specific User-Agent from Microsoft telemetry.
    from:
      kind: article
      observed: '2026-09-30'
      ref: msrc-blog-cve-2026-73570
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: standard-lookback
    type: number
  oast_domains:
    default:
    - oast.fun
    - oast.online
    - dnslog.pp.ua
    - requestrepo.com
    - bypass.eu.org
    description: Callback domains observed in probing activity.
    from:
      kind: article
      observed: '2026-09-30'
      ref: msrc-blog-cve-2026-73570
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to filter investigations; analyst should paste results
      from the scoping step here.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying hosts with CVE-2026-73570 findings. If the
  vulnerability scanner is not up to date, the analyst can alternative-scope by searching
  hb_software_inventory for 'Zimbra' packages version < 10.1.20.
references:
- name: "Microsoft Security Blog \u2014 Unauthenticated command injection on internet-facing\
    \ mail servers"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/
related:
- hunt: zimbra-privilege-escalation-pam
  reason: This hunt identifies entry; a separate hunt examines the PAM-exec privilege
    escalation observed in the same campaign.
  relation: follows
- hunt: zimbra-credential-harvesting
  reason: Attackers target LDAP and MySQL secrets after establishing a web shell;
    that activity requires specialized credential-access queries.
  relation: follows
scenario:
  stages:
  - name: Pre-exploitation scanning
    observables:
    - 'User-Agent: ZB73570'
    - oast.fun
    - oast.online
    - dnslog.pp.ua
    - requestrepo.com
    - bypass.eu.org
    - 'Commands: curl, wget, ping, nslookup, id'
    slug: reconnaissance-and-probing
    tactic: reconnaissance
    techniques:
    - T1595
  - name: Zimbra SNMP command injection
    observables:
    - CVE-2026-73570
    - swatchdog
    - snmptrap
    slug: initial-access-cve-2026-73570
    tactic: initial-access
    techniques:
    - T1190
  - name: JSP web shell deployment
    observables:
    - Jetty and mailboxd application paths
    - JSP files
    - Payload reconstruction from staged fragments
    - chmod on webroot directories
    slug: persistence-jsp-webshells
    tactic: persistence
    techniques:
    - T1505.003
  - name: Zimbra cluster mapping
    observables:
    - zmprov
    - /opt/zimbra/.ssh/zimbra_identity
    slug: discovery-cluster-mapping
    tactic: discovery
    techniques:
    - T1087
    - T1083
  - name: PAM hook privilege escalation
    observables:
    - 'Symlink: zmmailboxd.out -> /etc/pam.d/sudo'
    - zmmailboxdmgr
    - zmstat-fd
    - pam_exec session hook
    - 'NOPASSWD: ALL in sudoers'
    slug: privilege-escalation-pam-hook
    tactic: privilege-escalation
    techniques:
    - T1548.003
    - T1556
  - name: Systemd service persistence
    observables:
    - /etc/systemd/system/zimlog.service
    - Timestomping to match rsync.service or sshd.service
    - systemctl enable zimlog.service
    slug: host-persistence-systemd
    tactic: persistence
    techniques:
    - T1543.002
  - name: Service credential collection
    observables:
    - zmlocalconfig -s
    - ldapsearch
    - zimbraPreAuthKey
    - zimbraAuthTokenKey
    - zimbraTwoFactorAuthSecret
    slug: credential-access-zimbra-secrets
    tactic: credential-access
    techniques:
    - T1552
    - T1555
  - name: Lateral movement across nodes
    observables:
    - ssh -o BatchMode=yes
    - rsync of payload fragments
    - 'SSH identity: /opt/zimbra/.ssh/zimbra_identity'
    slug: lateral-movement-ssh-rsync
    tactic: lateral-movement
    techniques:
    - T1021.004
  - name: Remote access agents
    observables:
    - zimdown2
    - zimclient2
    - agent2.sh
    - openssl s_client
    - 'Named pipe: /tmp/s'
    - WebSocket connections
    slug: command-and-control-agent
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1105
  - name: Mailbox exfiltration attempt
    observables:
    - zimbra-exfil/client-dump
    - Compressed archive creation
    - Transfer of collected data
    slug: exfiltration-mailbox-data
    tactic: exfiltration
    techniques:
    - T1567
    - T1041
  summary: Attackers exploit a command injection vulnerability (CVE-2026-73570) in
    Zimbra's SNMP notification path to execute commands as the zimbra user. The campaign
    involves deploying JSP web shells, escalating privileges to root via PAM hooks,
    stealing service credentials, and moving laterally across the cluster using existing
    SSH identities.
series:
  index: 1
  slug: unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570
  title: 'Unauthenticated command injection on internet-facing mail servers: tracking
    CVE-2026-73570'
  total: 3
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


# Zimbra CVE-2026-73570 RCE and JSP Web Shell Entry

This hunt targets the unauthenticated remote command injection vulnerability in the Zimbra SNMP notification path. Attackers use crafted SMTP requests to trigger the swatchdog and snmptrap execution chain. The hunt follows a gated flow: it first identifies vulnerable Zimbra hosts and checks for reconnaissance probes matching known CVE-specific User-Agents and OAST callback domains. Only if probes are detected does the hunt execute expensive process-ancestry and file-prevalence queries. An agent weighs the network probes against the host-side command execution and the presence of rare JSP files to identify a confirmed compromise.

## scoping-vulnerable-hosts
<!-- Scope Vulnerable Zimbra Hosts -->
Identify hosts currently known to have the CVE-2026-73570 finding.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that have the CVE finding. Silence indicates either a patched
  estate or a missing scanner integration.
reads:
- device_uid
- resource_uid
- title
- cve_uid
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_uid, resource_uid, title FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-73570' AND status != 'suppressed'
```

## lead-probing-activity
<!-- Identify Reconnaissance Probes -->
Find HTTP probes that use the CVE-specific User-Agent or hit OAST domains.

```sqlite target=web role=triage params=(lookback_days=lookback_days, oast_domains=oast_domains, exploit_user_agent=exploit_user_agent, scope_hosts=scope_hosts)
~~~yaml
expected: Requests from external IPs using the ZB73570 User-Agent. Silence proves
  that specific known scanners were not seen in the window.
reads:
- device_hostname
- src_endpoint_ip
- user_agent
- url_hostname
- url_full
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, src_endpoint_ip, user_agent, url_hostname, url_full, time FROM hb_http_activity WHERE (LOWER(user_agent) = LOWER('{{exploit_user_agent}}') OR instr(',' || '{{oast_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Probing Lead -->
```agent target=hunter
cite: required
context:
- lead-probing-activity
max_iterations: 3
objective: Determine if the HTTP activity in lead-probing-activity constitutes a plausible
  exploit attempt against a mail server.
success_criteria: A per-host verdict of suspicious | benign.
tools:
- endpoint
- web
```

## gate-to-deep-investigation
<!-- Gate: Proceed to Deep Investigation -->
if~: "the verdict in evaluate-lead is suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-telemetry)
else: → close-out

## parallel-investigation
<!-- Deep Investigation Fan-out -->
parallel:
- → command-injection-processes
- → rare-jsp-webshells
join: → triage-investigation

## command-injection-processes
<!-- Swatchdog Command Injection Chain -->
Find the specific process tree of swatchdog invoking snmptrap to launch shell commands.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process command lines showing the zimbra user executing network tools or
  shells via snmptrap. This is a high-confidence indicator of exploitation.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%swatchdog%' OR LOWER(process_name) LIKE '%snmptrap%') AND (LOWER(process_cmd_line) LIKE '%curl%' OR LOWER(process_cmd_line) LIKE '%wget%' OR LOWER(process_cmd_line) LIKE '%/bin/sh%' OR LOWER(process_cmd_line) LIKE '%/bin/bash%') AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-jsp-webshells
<!-- Rare JSP Web Shell Creation -->
Identify rare JSP files dropped in Zimbra application paths across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: JSP files that appear on few hosts; these are likely web shells. Benign
  JSP updates should appear on many hosts simultaneously.
prevalence:
  by: device_hostname
  key:
  - jsp_path
  rare_below: 5
reads:
- device_hostname
- file_path
- activity_id
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT LOWER(file_path) AS jsp_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 1 AND LOWER(file_path) LIKE '%.jsp' AND (LOWER(file_path) LIKE '%/opt/zimbra/jetty/webapps/%' OR LOWER(file_path) LIKE '%/opt/zimbra/mailboxd/webapps/%') AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY jsp_path HAVING host_count <= 5 ORDER BY host_count ASC
```

## triage-investigation
<!-- Triage Investigation Evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- command-injection-processes
- rare-jsp-webshells
max_iterations: 6
objective: 'Confirm if the identified hosts exhibit a complete exploit chain: from
  the ZB73570 User-Agent probe to the swatchdog/snmptrap command execution and finally
  the creation of a rare JSP web shell.'
success_criteria: A final verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage-investigation verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Compromised Mail Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture the JSP file identified in rare-jsp-webshells and check /opt/zimbra/log/ for staging fragments before remediation.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the process tree for swatchdog. Confirm if the JSP file content contains web shell commands. If malicious, verify if cluster-wide secrets (LDAP/MySQL) were accessed.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the absence of exploitation on the examined Zimbra hosts. If probes were seen but no execution occurred, consider promoting the HTTP User-Agent query to a detection rule.
```
→ end
