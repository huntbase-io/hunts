---
analysis: While a rule might alert on any process with a '-pass' flag, this hunt correlates
  that signal with ActiveMQ server locations and RDP authentication patterns across
  a specific 14-day window, distinguishing targeted intrusion from administrative
  noise.
blind_spots:
- id: rdp-log-rotation
  question: Was there lateral movement 18 days ago that has been rotated out of logs?
  requires: Windows Event Log retention > 21 days
  risk: Standard 14-day log rotation on many endpoints would hide the actor's initial
    credential harvesting and movement.
  stage: lateral-movement-rdp
- id: transient-files
  question: Was the rdp.bat file used and then deleted on the beachhead?
  requires: hb_file_activity with delete activity
  risk: The actor deleted the batch file within six minutes; without high-frequency
    file event collection, the exact commands used to open the RDP firewall ports
    may be missing.
  stage: lateral-movement-rdp
coverage:
- stage: lateral-movement-rdp
  status: covered
  steps:
  - rdp-movement
- stage: lockbit-ransomware-deployment
  status: covered
  steps:
  - lockbit-execution
- reason: This hunt starts post-compromise at the lateral movement phase; initial
    access is covered by a sibling hunt.
  stage: activemq-rce-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Apache ActiveMQ Exploit Leads to LockBit
    Ransomware' series.
  stage: metasploit-payload-ingress
  status: out_of_scope
- reason: Belongs to another part of the 'Apache ActiveMQ Exploit Leads to LockBit
    Ransomware' series.
  stage: local-privilege-escalation
  status: out_of_scope
- reason: Belongs to another part of the 'Apache ActiveMQ Exploit Leads to LockBit
    Ransomware' series.
  stage: credential-dumping-lsass
  status: out_of_scope
- reason: Belongs to another part of the 'Apache ActiveMQ Exploit Leads to LockBit
    Ransomware' series.
  stage: internal-discovery-and-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Apache ActiveMQ Exploit Leads to LockBit
    Ransomware' series.
  stage: defense-evasion-and-log-clearing
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt addresses the critical gap between re-exploitation and
    ransomware deployment. Since the actor transitioned to ransomware in less than
    90 minutes during the second phase, a negative result provides immediate assurance
    against an active LockBit campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has transitioned from an exploited ActiveMQ server to lateral
  movement via RDP using stolen credentials, ultimately deploying LockBit ransomware
  from user-writable directories or with specific execution flags.
labels:
- hunt
- attack.t1021.001
- attack.t1021.002
- attack.t1486
- attack.t1543.003
- attack.t1078
name: Apache ActiveMQ Lateral Movement and Ransomware Impact
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified as running ActiveMQ; leave empty to search the
      entire estate.
    from:
      kind: manual
      observed: '2024-02-23'
      ref: activemq-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should begin with systems running Apache ActiveMQ. If logs from
  18 days ago are unavailable, focus on current RDP source/destination patterns involving
  those servers.
references:
- name: "The DFIR Report \u2014 Apache ActiveMQ Exploit Leads to LockBit Ransomware"
  url: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/
related:
- hunt: activemq-initial-rce-exploitation
  reason: The initial exploit of CVE-2023-46604 via malicious XML/Java Spring classes
    is handled by a separate hunt focused on web server logs and ingress.
  relation: out-of-scope-alternative
- hunt: activemq-exploitation-metasploit-staging
  relation: follows
scenario:
  stages:
  - name: Apache ActiveMQ RCE Exploitation
    observables:
    - CVE-2023-46604
    - org.springframework.context.support.ClassPathXmlApplicationContext
    - ActiveMQ server process java.exe parent
    - Java Spring bean configuration XML file download
    slug: activemq-rce-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Metasploit Payload Ingress
    observables:
    - certutil.exe -urlcache -f
    - uFSyLszKsuR.exe
    - C:\Users\\AppData\Local\Temp\uFSyLszKsuR.exe
    - 166.62.100.52
    slug: metasploit-payload-ingress
    tactic: execution
    techniques:
    - T1105
    - T1059.003
  - name: Privilege Escalation via getsystem
    observables:
    - cmd.exe /c echo kesknq > \\.\pipe\kesknq
    - Metasploit stager with SYSTEM level permissions
    - Service name kesknq
    slug: local-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1134
    - T1055
  - name: Credential Access via LSASS Dumping
    observables:
    - lsass.exe memory access
    - GrantedAccess 0x1010 (VMRead)
    - CallTrace UNKNOWN indicative of injected code
    slug: credential-dumping-lsass
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Internal Discovery and Persistence
    observables:
    - AnyDesk.exe installation
    - AnyDesk Service creation (Event ID 7045)
    - Advanced_IP_Scanner.exe
    - SMB traffic spikes (network scanning)
    slug: internal-discovery-and-persistence
    tactic: discovery
    techniques:
    - T1046
    - T1018
    - T1133
  - name: Defense Evasion and Log Clearing
    observables:
    - rdp.bat creation and deletion
    - wevtutil cl System
    - wevtutil cl Security
    - SystemSettingsAdminFlows.exe used to disable Windows Defender
    - Injected winlogon.exe creating batch files
    slug: defense-evasion-and-log-clearing
    tactic: defense-evasion
    techniques:
    - T1070.001
    - T1562.001
    - T1218
  - name: Lateral Movement via RDP and Services
    observables:
    - RDP connections using privileged service accounts
    - Remote service execution of Metasploit payloads
    - Firewall modification to allow port 3389
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1021.002
    - T1543.003
  - name: LockBit Ransomware Deployment
    observables:
    - LockBit ransomware binary execution
    - Execution with specific path and password flags
    - Execution from Downloads folder via double-click
    slug: lockbit-ransomware-deployment
    tactic: impact
    techniques:
    - T1486
  summary: A threat actor exploited an internet-facing Apache ActiveMQ server using
    CVE-2023-46604 to execute code via Java Spring bean XML files, subsequently downloading
    a Metasploit stager using CertUtil. The intrusion involved privilege escalation
    via getsystem, credential dumping from LSASS, and extensive lateral movement using
    RDP and remote services before deploying LockBit ransomware.
series:
  index: 3
  slug: apache-activemq-exploit-leads-to-lockbit-ransomware
  title: Apache ActiveMQ Exploit Leads to LockBit Ransomware
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Apache ActiveMQ Lateral Movement and Ransomware Impact

This hunt focuses on the lateral propagation and impact stages following an Apache ActiveMQ (CVE-2023-46604) compromise. The report highlights that after initial access, the actor extracts credentials to move laterally via RDP and services, eventually deploying LockBit ransomware within a narrow 90-minute window of the second intrusion.

The hunt first identifies ActiveMQ installations across the estate to scope potential beachheads. It then fanned-out queries to find RDP authentication patterns originating from these hosts and rare process executions that exhibit LockBit-specific traits, such as running from a Downloads directory or using password-protected execution flags. An agent correlates these signals to identify active propagation and impact.

## activemq-scoping
<!-- Identify Apache ActiveMQ Infrastructure -->
Find systems running Apache ActiveMQ to establish the potential starting point for lateral movement.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running ActiveMQ. Silence means the software is
  not installed via standard package managers.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%activemq%'
```

## propagation-analysis
<!-- Analyze Propagation and Impact -->
parallel:
- → rdp-movement
- → lockbit-execution
join: → triage-impact

## rdp-movement
<!-- RDP Lateral Movement from Scope -->
Detect RDP connections involving the scoped hosts to identify successful lateral movement.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Logon events identifying which users moved to which target hosts via RDP.
reads:
- time
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- auth_protocol
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT time, actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol FROM hb_auth_signin WHERE activity_id = 1 AND (LOWER(auth_protocol) LIKE '%rdp%' OR LOWER(activity_name) LIKE '%remote%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lockbit-execution
<!-- LockBit Ransomware Execution Patterns -->
Identify processes executed from user downloads or using password/path flags typical of LockBit deployment.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process execution with malicious flags or suspicious paths. Silence
  suggests no such deployment occurred.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%-pass%' OR LOWER(process_path) LIKE '%\downloads\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line, process_path HAVING host_count <= 3
```

## triage-impact
<!-- Triage TTP Correlation -->
```agent target=hunter
cite: required
context:
- activemq-scoping
- rdp-movement
- lockbit-execution
max_iterations: 5
objective: Determine if any host in the environment has been accessed via RDP following
  an ActiveMQ detection and subsequently ran a process from a downloads folder or
  with password flags.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing RDP
  source IPs and process command lines.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route on Impact Verdict -->
if~: "the triage-impact verdict is malicious for any host, identifying a link between ActiveMQ scoping and ransomware execution" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → manual-triage
unavailable: → manual-triage (blind_spot: rdp-log-rotation)
else: → close-out

## isolate-infected-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host immediately using the endpoint agent. Do not reboot the system as memory artifacts may be lost.
```
→ manual-triage

## manual-triage
<!-- Manual Analyst Review -->
```manual target=analyst
Examine the beachhead and target hosts for 'rdp.bat' or any AnyDesk installation. Review the 'lockbit-execution' process results for legitimate administrative tools using similar flags and exclude them from future runs.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the outcome of the hunt. If the LockBit execution query identified malicious binaries with high precision, promote it to a standing detection rule.
```
→ end
