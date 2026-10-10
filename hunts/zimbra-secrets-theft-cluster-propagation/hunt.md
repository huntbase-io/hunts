---
analysis: 'While a rule can alert on the zimbra user running zmlocalconfig, this hunt
  pivots from that single indicator to look for the fleet-wide consequences: lateral
  movement and data staging. By using a baseline for administrative mapping tools,
  it filters out routine maintenance that simple rules would likely miss or over-alert
  on.'
blind_spots:
- id: limited-process-visibility
  question: whether administrative commands were run on unmanaged nodes
  requires: endpoint agent presence on all nodes
  risk: Attackers can map the cluster from a single node without an agent, making
    the first stage of the attack invisible.
  stage: discovery-cluster-mapping
- id: ssh-identity-exfiltration
  question: whether the SSH identity was copied rather than executed
  requires: detailed file-read monitoring of the SSH identity path
  risk: If the attacker exfiltrates the SSH identity to an external machine to move
    laterally from outside, the local process logs will not capture the subsequent
    connections.
  stage: lateral-movement-ssh-rsync
coverage:
- stage: discovery-cluster-mapping
  status: covered
  steps:
  - discovery-and-mapping
- stage: credential-access-zimbra-secrets
  status: covered
  steps:
  - secret-collection-activity
- stage: lateral-movement-ssh-rsync
  status: covered
  steps:
  - lateral-movement-activity
- stage: command-and-control-agent
  status: covered
  steps:
  - exfiltration-and-c2-activity
- stage: exfiltration-mailbox-data
  status: covered
  steps:
  - exfiltration-and-c2-activity
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
  stage: privilege-escalation-pam-hook
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unauthenticated command injection on internet-facing
    mail servers: tracking CVE-2026-73570'' series.'
  stage: host-persistence-systemd
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The compromise of service keys on a mail server is a high-impact
    event that provides long-term, cluster-wide access; proactive hunting for the
    reuse of these keys is required to mitigate the risk of mass mailbox exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using Zimbra administrative utilities to dump service credentials
  and move laterally to peer nodes using the zimbra service account's SSH identity.
labels:
- hunt
- attack.t1087
- attack.t1083
- attack.t1552
- attack.t1555
- attack.t1021.004
- attack.t1071.001
- attack.t1567
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
name: Zimbra secrets theft and cluster propagation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of Zimbra server hostnames to narrow the search; leave empty
      to scan all hosts.
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing Zimbra nodes (MTA and Mailbox roles). Focus
  on systems where the optional zimbra-snmp package is installed, as this is the injection
  vector for the primary CVE.
references:
- name: "Microsoft Blog \u2014 Unauthenticated command injection on internet-facing\
    \ mail servers: tracking CVE-2026-73570"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/
related:
- hunt: zimbra-persistence-webshells
  reason: Persistence via JSP webshells and systemd units is handled in a separate
    hunt focused on the post-exploitation survival phase.
  relation: out-of-scope-alternative
- hunt: zimbra-privesc-pam-systemd
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
  index: 3
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


# Zimbra secrets theft and cluster propagation

After an initial breach, actors use Zimbra-specific tools like zmprov and zmlocalconfig to identify peer nodes and extract LDAP or replication passwords. This hunt targets the post-compromise stages of a Zimbra mail server intrusion. It focuses on how attackers map the cluster and harvest service credentials. The hunt follows a phased approach. First, it identifies high-risk administrative activity on Zimbra servers. Then, the agent pivots to find evidence of lateral movement via SSH identity reuse and the staging of mailbox data for exfiltration. By correlating these behaviors across the cluster, the analyst distinguishes legitimate administrative work from an active, spreading intrusion.

## identify-zimbra-hosts
<!-- Identify Zimbra servers -->
Filter the estate to hosts running Zimbra Collaboration Suite to focus behavioral hunting.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where Zimbra is installed. Silence indicates no Zimbra nodes
  were found in the current inventory.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%zimbra%'
```

## parallel-early-evidence
<!-- Search for early discovery and secret theft -->
parallel:
- → discovery-and-mapping
- → secret-collection-activity
join: → early-triage-agent

## discovery-and-mapping
<!-- Zimbra cluster mapping and reconnaissance -->
Detect the use of cluster-mapping tools like zmprov or broad LDAP searches that reveal node roles.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines that are rare across the fleet; legitimate admin scripts usually
  appear on all Zimbra nodes, whereas attacker reconnaissance is localized.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS executions, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%zmprov%' OR LOWER(process_cmd_line) LIKE '%ldapsearch%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3 ORDER BY hosts ASC
```

## secret-collection-activity
<!-- Zimbra service credential dumping -->
Identify the extraction of service-account credentials using zmlocalconfig, a prerequisite for lateral movement.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The zimbra user dumping sensitive configuration secrets. This is the primary
  indicator of credential theft intent.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%zmlocalconfig% -s%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage-agent
<!-- Triage early-stage indicators -->
```agent target=hunter
cite: required
context:
- discovery-and-mapping
- secret-collection-activity
max_iterations: 4
objective: Identify hosts where rare cluster-mapping commands or credential dumping
  occurred, distinguishing them from baseline admin activity.
success_criteria: A verdict citing specific rows that warrant follow-on hunting for
  lateral movement.
tools:
- endpoint
```

## parallel-follow-on-evidence
<!-- Hunt for follow-on movement and exfiltration -->
parallel:
- → lateral-movement-activity
- → exfiltration-and-c2-activity
join: → follow-on-triage-agent

## lateral-movement-activity
<!-- Lateral movement via SSH and rsync -->
Detect the reuse of the zimbra_identity SSH key for automated movement between nodes.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: SSH or rsync processes using the Zimbra batch-mode identity. This indicates
  propagation from a compromised node to the rest of the cluster.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/opt/zimbra/.ssh/zimbra_identity%' OR (LOWER(process_cmd_line) LIKE '%ssh %' AND LOWER(process_cmd_line) LIKE '%batchmode%') OR LOWER(process_cmd_line) LIKE '%rsync %') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exfiltration-and-c2-activity
<!-- Exfiltration staging and C2 implants -->
Identify named pipes, archive files, and known Zimbra-specific exfiltration implants.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of archives in non-standard paths or the presence of named pipes
  and implant binaries. Silence confirms the absence of these specific staging artifacts.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/tmp/s' OR LOWER(file_name) LIKE '%.tar.gz' OR LOWER(file_name) LIKE '%.zip' OR LOWER(file_name) LIKE '%zimdown2%' OR LOWER(file_name) LIKE '%zimclient2%' OR LOWER(file_name) LIKE '%zimbra-exfil%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage-agent
<!-- Correlate cluster-wide intrusion -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- lateral-movement-activity
- exfiltration-and-c2-activity
max_iterations: 6
objective: Determine if the discovery and secret theft from the first phase is logically
  connected to the lateral movement or exfiltration staging found in the second phase.
success_criteria: A final verdict of malicious | suspicious per host, citing the evidence
  chain.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-node
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review (blind_spot: limited-process-visibility)
else: → close-out-investigation

## isolate-compromised-node
<!-- Isolate Zimbra node -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised Zimbra host immediately. Rotate the SSH identity at /opt/zimbra/.ssh/zimbra_identity and change all service passwords found via zmlocalconfig across the entire cluster.
```
→ analyst-remediation-review

## analyst-remediation-review
<!-- Analyst remediation review -->
```manual target=analyst
Review Zimbra mailbox access logs for the service accounts involved. Check for large-scale archive transfers or uncharacteristic outbound network traffic to the remote C2 endpoints identified in the triage.
```
→ end

## close-out-investigation
<!-- Close out investigation -->
```manual target=analyst
Record the hunt outcome. If the activity was legitimate administration, update the prevalence thresholds to exclude the specific script or command pattern observed.
```
→ end
