---
analysis: A simple alert for Bitdefender stopping is too noisy for most environments.
  This hunt correlates the RDP source (who), the service disruption (what), and the
  rare binary execution (why) into a single analytical verdict.
blind_spots:
- id: missing-service-telemetry
  question: whether services were disabled via registry or killed directly as a process
  requires: hb_service_activity with event_code 7036
  risk: Stopping a service via process termination or registry modification (Start=4)
    might not trigger the specific SCM event used in this hunt.
  stage: defense-evasion-service-stop
- id: ephemeral-staging-paths
  question: whether the attacker used a random, non-PerfLogs path for staging
  requires: hb_process_activity process_path
  risk: Filtering on specific staging paths may miss tools run from deep user profile
    directories if not caught by the prevalence check.
  stage: lsass-credential-dumping
coverage:
- stage: rdp-lateral-access
  status: covered
  steps:
  - rdp-scoping
- stage: defense-evasion-service-stop
  status: covered
  steps:
  - bitdefender-disruption
- stage: lsass-credential-dumping
  status: covered
  steps:
  - rare-perflogs-processes
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: gost-tunneling-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: rclone-data-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: inhibit-recovery-shadow-copy-deletion
  status: out_of_scope
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: akira-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Akira affiliates consistently use RDP for lateral movement and disable
    endpoint security to proceed with credential theft. Detecting these precursor
    steps allows for containment before encryption starts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained lateral access via RDP and is disabling security
  software to perform credential dumping from staging directories like PerfLogs.
labels:
- hunt
- attack.t1021.001
- attack.t1003.001
- attack.t1562.001
- command and control
- credential access
- defense evasion
- exfiltration
- impact
- lateral movement
name: 'Akira: Remote Access and Security Software Disruption'
parameters:
  attacker_workstation:
    default: C1IFRYXI
    description: Workstation name associated with the threat actor in the Huntress
      report.
    from:
      kind: article
      observed: '2024-10-06'
      ref: Huntress Akira Mapping
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-06'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the investigation based on scoping
      results.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/mapping-akira-ransomware-attack
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin the hunt on domain controllers and servers with public-facing services.
  Use the attacker workstation name 'C1IFRYXI' as a high-fidelity starting point.
references:
- name: "Huntress \u2014 Mapping an Akira Ransomware Attack"
  url: https://www.huntress.com/blog/mapping-akira-ransomware-attack
related:
- hunt: akira-persistence-and-exfiltration
  reason: This hunt covers initial access and blinding; the next hunt in the series
    focuses on GOST tunneling and RClone exfiltration.
  relation: follows
scenario:
  stages:
  - name: RDP Lateral Access
    observables:
    - Workstation name C1IFRYXI
    - RDP connection from non-customer workstation
    slug: rdp-lateral-access
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Bitdefender Service Disablement
    observables:
    - Bitdefender Endpoint Update Service stopped
    - Bitdefender Endpoint Integration Service stopped
    - Bitdefender Endpoint Protected Service stopped
    - Bitdefender Endpoint Security Service stopped
    slug: defense-evasion-service-stop
    tactic: defense-evasion
  - name: LSASS Credential Dumping
    observables:
    - procdump.exe
    - C:\PerfLogs\procdump.exe
    - lsass.exe dump
    slug: lsass-credential-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: GOST Tunneling Persistence
    observables:
    - C:\PerfLogs\Temp\svchost.exe
    - C:\PerfLogs\Temp\config.dll
    - d00833318a04caa019c6f95dcb3598ad947d405010bfb2f3cbd04530a00bc3a4
    - 64.227.4.134
    slug: gost-tunneling-persistence
    tactic: command-and-control
    techniques:
    - T1572
    - T1041
  - name: RClone Data Exfiltration
    observables:
    - rclone.exe
    - C:\PerfLogs\rclone.exe
    slug: rclone-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Recovery Inhibition via Shadow Copy Deletion
    observables:
    - powershell.exe -Command Get-WmiObject Win32_Shadowcopy | Remove-WmiObject
    slug: inhibit-recovery-shadow-copy-deletion
    tactic: impact
    techniques:
    - T1490
    - T1047
    - T1059.001
  - name: Akira Data Encryption
    observables:
    - win.exe
    - 1f1bb322591b6d27fd2946e373d7d2efc2f4e1e66818846060d391600b600fba
    - Akira log files
    - Shellbags access to Shares folder
    slug: akira-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Akira ransomware affiliates gained access via RDP and disabled Bitdefender
    security services before using Procdump to harvest credentials. The attackers
    established persistence using the GOST tunnel tool and exfiltrated data via RClone
    before executing the Akira ransomware, which deleted volume shadow copies and
    encrypted files.
series:
  index: 1
  slug: up-a-creek-without-a-command-line-mapping-an-akira-ransomware-attack
  title: 'Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack'
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Akira: Remote Access and Security Software Disruption

This hunt identifies early-stage Akira ransomware activity by correlating inbound RDP connections with subsequent efforts to blind security tools. It specifically looks for the cessation of Bitdefender services and the execution of rare binaries from the PerfLogs directory, a known staging area for this threat actor.

By examining authentication, service activity, and process telemetry, the hunt builds a timeline of compromise from initial lateral entry to the dumping of LSASS memory. An agent evaluates the combined evidence to distinguish between administrative maintenance and a coordinated ransomware precursor.

## rdp-scoping
<!-- Inbound RDP Scoping -->
Identify hosts targeted by RDP sessions from the reported attacker workstation or other external sources.

```sqlite target=identity role=scoping params=(attacker_workstation=attacker_workstation, lookback_days=lookback_days)
~~~yaml
expected: Hosts receiving RDP connections from the specific workstation name C1IFRYXI
  or high-volume remote interactive logins.
reads:
- device_hostname
- src_endpoint_hostname
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, src_endpoint_hostname, actor_user_name, time FROM hb_auth_signin WHERE (LOWER(src_endpoint_hostname) = LOWER('{{attacker_workstation}}') OR (logon_type_id = 10 AND src_endpoint_hostname != '')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate
<!-- Corroborate Evidence -->
parallel:
- → rare-perflogs-processes
- → bitdefender-disruption
join: → triage-compromise

## rare-perflogs-processes
<!-- Rare Processes in PerfLogs -->
Find rare executables running from PerfLogs or Temp directories, which are used by Akira for staging tools like ProcDump.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary like procdump.exe or svchost.exe (masqueraded) running from C:\PerfLogs
  on a small number of hosts.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS exec_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\perflogs\\%' OR LOWER(process_path) LIKE '%\\temp\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts ASC
```

## bitdefender-disruption
<!-- Bitdefender Service Disruption -->
Identify security service disablement following RDP access.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Multiple Bitdefender services being stopped on a host shortly after an inbound
  RDP session.
reads:
- device_hostname
- service_name
- service_state
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, service_name, service_state, time FROM hb_service_activity WHERE (LOWER(service_name) LIKE '%bitdefender%') AND (LOWER(service_state) LIKE '%stop%' OR LOWER(service_state) LIKE '%disable%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage Compromise Indicators -->
```agent target=hunter
cite: required
context:
- rdp-scoping
- rare-perflogs-processes
- bitdefender-disruption
max_iterations: 3
objective: Determine if the evidence supports an active Akira intrusion where an RDP
  session was followed by the stopping of security services and the execution of staging
  tools in PerfLogs.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  RDP source, the specific services stopped, and the path of the rare binary.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host involving both service stops and rare binary execution" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-service-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot. Collect the PerfLogs directory and LSASS memory dump if found.
```
→ analyst-review

## analyst-review
<!-- Analyst Verification -->
```manual target=analyst
Review the agent verdict. Check hb_process_activity for rclone.exe or GOST-related configurations in C:\PerfLogs\Temp.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
If no activity was found, record the hosts and time window. If legitimate maintenance caused a service stop, tune the detection candidate rule.
```
→ end
