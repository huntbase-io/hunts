---
analysis: A simple rule might find 'zimlog.service', but this hunt uses a fleet-wide
  prevalence baseline to find rare services and correlates them with the specific,
  complex file-system pivots used during the PAM hijacking, which a single-surface
  rule cannot easily capture.
blind_spots:
- id: no-file-telemetry
  question: Was the file modification actually a symlink creation?
  requires: hb_file_activity with symlink target tracking
  risk: If the EDR only logs a 'write' or 'create' but not the symlink target, the
    specific PAM hijacking technique may appear as normal log rotation or noise.
  stage: privilege-escalation-pam-hook
- id: timestomping-blindness
  question: What was the actual creation time of the zimlog.service file?
  requires: MFT or inode birth time analysis
  risk: A successful timestomp makes the persistence mechanism look like a pre-existing,
    legitimate component, potentially misleading an analyst who filters by 'new' files.
  stage: host-persistence-systemd
coverage:
- stage: privilege-escalation-pam-hook
  status: covered
  steps:
  - pam-symlink-abuse
  - triage-escalation
- stage: host-persistence-systemd
  status: covered
  steps:
  - rare-systemd-services
  - triage-escalation
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: reconnaissance-and-probing
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: initial-access-cve-2026-73570
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: persistence-jsp-webshells
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: discovery-cluster-mapping
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
  justification: The privilege escalation to root via PAM hijacking is a critical
    stage in the Zimbra compromise that allows attackers to move from application-level
    access to full host control. Detecting this and the subsequent root persistence
    is vital for preventing long-term occupancy and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has escalated from the Zimbra service account to root by symlinking
  application logs to PAM configurations and established persistence through a rare
  systemd service.
labels:
- hunt
- attack.t1548.003
- attack.t1556
- attack.t1543.002
- attack.t1070.006
- command and control
- credential access
- discovery
- exfiltration
- initial access
- lateral movement
- persistence
- privilege escalation
- reconnaissance
name: Zimbra Privilege Escalation and Root Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Target Zimbra hostnames; leave empty to scan the entire estate.
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
rationale: Start with public-facing MTA and Mailbox nodes identified in hb_software_inventory.
  Widen the scope to all hosts if the initial queries show any suspicious PAM activity.
references:
- name: 'MSRC Blog - Unauthenticated command injection on internet-facing mail servers:
    tracking CVE-2026-73570'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/
related:
- hunt: zimbra-webshell-and-c2
  reason: This hunt focuses on host-level privilege escalation, while initial access
    via CVE-2026-73570 and JSP webshell deployment are covered in a separate hunt.
  relation: out-of-scope-alternative
- hunt: zimbra-rce-webshell-entry
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
  index: 2
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
tlp: clear
type: investigation
---


# Zimbra Privilege Escalation and Root Persistence

This hunt targets the complex post-exploitation chain observed in CVE-2026-73570. An adversary takes ownership of the sudo PAM configuration by symlinking application logs to sensitive system files. It then identifies rare systemd services created in /etc/systemd/system/, specifically focusing on services named zimlog.service or those whose timestamps have been modified to match legitimate system services like rsync or sshd. The hunt uses an agent to correlate these file and service anomalies, allowing an analyst to confirm root-level persistence.

## scope-zimbra-hosts
<!-- Identify Zimbra servers -->
Define the scope by identifying hosts that have Zimbra software installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running Zimbra. Silence indicates no Zimbra installation
  is visible in the current inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%zimbra%' OR LOWER(vendor_name) LIKE '%zimbra%')
```

## detect-behavior-parallel
<!-- Search for Escalation and Persistence -->
parallel:
- → rare-systemd-services
- → pam-symlink-abuse
join: → triage-escalation

## rare-systemd-services
<!-- Rare systemd services -->
Stack-count systemd services to find the 'zimlog.service' or other anomalies across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A service found on only one or two hosts, specifically looking for 'zimlog.service'.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_definition_path
  rare_below: 3
reads:
- job_name
- job_definition_path
- job_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT job_name, job_definition_path, job_cmd_line, COUNT(DISTINCT device_hostname) AS host_count FROM hb_scheduled_job WHERE job_definition_path LIKE '/etc/systemd/system/%' AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name, job_definition_path, job_cmd_line HAVING host_count <= 2
```

## pam-symlink-abuse
<!-- PAM and Log Symlink Abuse -->
Identify file activity where the zimbra account touches the PAM sudo configuration or its own log files abnormally.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Modifications to the PAM configuration by a non-root user (zimbra), or operations
  involving the zmmailboxd.out log file that precede sudo elevation.
reads:
- device_hostname
- file_path
- actor_user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, file_path, actor_user_name, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/etc/pam.d/sudo%' OR LOWER(file_path) LIKE '%zmmailboxd.out%') AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-escalation
<!-- Evaluate Escalation Evidence -->
```agent target=hunter
cite: required
context:
- scope-zimbra-hosts
- rare-systemd-services
- pam-symlink-abuse
max_iterations: 5
objective: Determine if the zimbra user successfully hijacked the PAM configuration
  and established root-level persistence via a systemd service. Analyze whether the
  service appears to be timestomped to match legitimate services.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows from the file activity and job tables.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-escalation verdict is malicious for at least one host involving PAM configuration modification and a rare systemd service" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-file-telemetry)
else: → close-out

## isolate-server
<!-- Isolate Compromised Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not restart services as this may trigger persistence hooks. Capture a memory image and the /etc/pam.d/ and /etc/systemd/system/ directories for forensic analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Forensic Review of Persistence -->
```manual target=analyst
Inspect the file system on isolated hosts. Verify if /opt/zimbra/log/zmmailboxd.out is a symlink to /etc/pam.d/sudo. Check the modification times of /etc/systemd/system/zimlog.service against the systemd journal to confirm timestomping.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Summarize which hosts were examined. If no activity was found, record the negative results as evidence of absence for this specific technique.
```
→ end
