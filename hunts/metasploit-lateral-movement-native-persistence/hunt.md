---
analysis: A standard detection rule alerts on the PsExec service. This hunt correlates
  successful authentication with stack-counted process trees across the fleet to reconstruct
  the entire movement chain.
blind_spots:
- id: no-remoting-telemetry
  question: whether the initial WinRM session occurred on an unmonitored host
  requires: hb_auth_signin coverage for all internal endpoints
  risk: The adversary can bypass the lead entirely if their beachhead is on infrastructure
    not reporting to the auth surface.
  stage: remote-command-execution-and-payloads
- id: missing-process-context
  question: the exact arguments passed to the persistent binary
  requires: hb_process_activity with command line history
  risk: Without historical command lines, the triage agent may fail to distinguish
    between legitimate management tools and persistence.
  stage: persistence-via-process-creation
coverage:
- stage: remote-command-execution-and-payloads
  status: covered
  steps:
  - winrm-authentication-lead
  - native-process-persistence
- stage: lateral-movement-smb-winrm
  status: covered
  steps:
  - smb-movement-check
- stage: persistence-via-process-creation
  status: covered
  steps:
  - native-process-persistence
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Payloads and Exploits,
    and Scanners, Oh my!'' series.'
  stage: vulnerability-scanning-and-reconnaissance
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Payloads and Exploits,
    and Scanners, Oh my!'' series.'
  stage: exploit-public-facing-web-applications
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Internal movement via SMB and WinRM is a critical phase of framework-driven
    intrusions; a negative result over these protocols confirms the integrity of the
    internal network.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses Metasploit to move laterally via WinRM and SMB and maintains
  persistence through direct process creation from user-writable paths to evade shell-based
  detection.
labels:
- hunt
- attack.t1021.002
- attack.t1059.001
name: Metasploit Lateral Movement and Native Persistence
parameters:
  admin_shares:
    default:
    - \\*\ADMIN$
    - \\*\C$
    - \\*\IPC$
    description: Standard administrative shares used by Metasploit psexec modules.
    from:
      kind: article
      observed: '2026-08-28'
      ref: rapid7-wrap-up
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication and telemetry.
    from:
      kind: manual
      observed: '2026-08-28'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to focus the fan-out queries; leave empty
      to hunt across the entire estate.
    from:
      kind: manual
      observed: '2026-08-28'
      ref: analyst-scoping
    type: list[host]
  standard_parent_paths:
    default:
    - C:\Windows\System32\services.exe
    - C:\Windows\explorer.exe
    - C:\Windows\System32\cmd.exe
    - C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    description: Expected parent process paths to filter out during persistence hunting.
    from:
      kind: manual
      observed: '2026-08-28'
      ref: baseline-standard
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-payloads-exploits-scanners
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The lead query focuses on servers where management protocols are typical.
  The gated logic ensures expensive process and share queries only run if a potential
  authenticated entry point is found.
references:
- name: 'Metasploit Wrap Up: Payloads and Exploits, and Scanners, Oh my!'
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-payloads-exploits-scanners
related:
- hunt: metasploit-external-exploit-hunting
  reason: External scanning and application exploitation are handled by a sibling
    hunt focusing on the perimeter.
  relation: out-of-scope-alternative
- hunt: metasploit-2026-recon-web-exploitation
  relation: follows
scenario:
  stages:
  - name: Protocol and Application Fingerprinting
    observables:
    - opc.tcp://
    - /ccm/system/dialogs/file/usage/
    - CVE-2026-0265
    - CVE-2026-16232
    - CVE-2026-6826
    slug: vulnerability-scanning-and-reconnaissance
    tactic: initial-access
    techniques:
    - T1190
  - name: Exploitation of Web Vulnerabilities
    observables:
    - ulap.php
    - file://localhost/etc/passwd
    - X-Spip-Filtre
    - CVE-2026-3576
    - CVE-2026-59774
    - CVE-2026-9082
    - CVE-2026-66066
    slug: exploit-public-facing-web-applications
    tactic: initial-access
    techniques:
    - T1190
  - name: Authenticated Execution and Payloads
    observables:
    - PSRP-backed PowerShell session
    - MIPS64 exec payload
    - CVE-2026-19681
    - CVE-2026-21820
    - CVE-2026-56274
    slug: remote-command-execution-and-payloads
    tactic: execution
    techniques:
    - T1059.001
  - name: Lateral Movement via SMB and WinRM
    observables:
    - windows/smb/psexec aarch64
    - winrm_login with SessionType PSRP
    slug: lateral-movement-smb-winrm
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: Persistence via CreateProcess
    observables:
    - Metasploit persistence modules using create_process instead of cmd_exec
    slug: persistence-via-process-creation
    tactic: persistence
    techniques:
    - T1059.001
  summary: This Metasploit update details a range of exploit and scanner modules targeting
    vulnerabilities in web platforms (Forgejo, WordPress, Drupal, SPIP), networking
    hardware (PAN-OS, Check Point), and SCADA protocols. The framework has been enhanced
    to support remote execution via PSRP-backed PowerShell sessions, cross-platform
    SMB movement on aarch64, and improved persistence through native process creation.
series:
  index: 2
  slug: metasploit-wrap-up-payloads-and-exploits-and-scanners-oh-my
  title: 'Metasploit Wrap Up: Payloads and Exploits, and Scanners, Oh my!'
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


# Metasploit Lateral Movement and Native Persistence

The adversary moves through the internal network using authenticated remoting and installs persistence by creating processes from user-controlled directories. This hunt identifying successful WinRM and PSRP logons as an initial lead. If the hunt finds anomalous remoting activity, it fans out to examine two surfaces: administrative share access for movement and rare parent-child process relationships where binaries in writable directories run from non-standard parents. Finally, an agent correlates the findings to identify compromised hosts and the analyst suggests containment actions.

## winrm-authentication-lead
<!-- WinRM and PSRP Authentication Lead -->
Identify successful WinRM or PowerShell Remoting logons that may indicate a beachhead moving laterally.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows show users connecting to remoting services. Zero rows mean no recent
  remoting sessions were logged.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%winrm%' OR LOWER(dst_endpoint_name) LIKE '%powershell%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead-logons
<!-- Evaluate Lead Logons -->
```agent target=hunter
cite: required
context:
- winrm-authentication-lead
max_iterations: 3
objective: Determine if the WinRM/PSRP logons in winrm-authentication-lead warrant
  a detailed movement investigation by checking for anomalous source IPs or usernames.
success_criteria: A clear decision on proceeding to fan-out queries.
tools:
- endpoint
- identity
```

## gate-check
<!-- Gate Check -->
if~: "the evaluate-lead-logons agent identifies at least one logon as suspicious or requiring further investigation" (confidence: high, judge=hunter)
then: → fan-out-telemetry
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-remoting-telemetry)
else: → close-out

## fan-out-telemetry
<!-- Fan-out Telemetry -->
parallel:
- → smb-movement-check
- → native-process-persistence
join: → movement-triage

## smb-movement-check
<!-- SMB Administrative Share Movement -->
Detect SMB lateral movement through administrative shares, focusing on the scoped hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, admin_shares=admin_shares, scope_hosts=scope_hosts)
~~~yaml
expected: Access to hidden shares like ADMIN$ or C$. Presence of these rows on hosts
  that also had WinRM logons confirms movement.
reads:
- actor_user_name
- device_hostname
- share_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_smb_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, actor_user_name, share_name, src_endpoint_ip, time FROM hb_smb_activity WHERE instr(',' || '{{admin_shares}}' || ',', ',' || share_name || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## native-process-persistence
<!-- Native Process Creation Persistence -->
Identify processes in writable directories with non-standard parent hierarchies using stack-counting.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, standard_parent_paths=standard_parent_paths, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique parent-child pairs where the binary lives in a profile path. Rare
  hits in a large fleet indicate potential persistence.
prevalence:
  by: device_hostname
  key:
  - process_name
  - parent_process_name
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%/tmp/%') AND NOT instr(',' || '{{standard_parent_paths}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, parent_process_name HAVING host_count <= 3
```

## movement-triage
<!-- Movement Triage -->
```agent target=hunter
cite: required
context:
- evaluate-lead-logons
- smb-movement-check
- native-process-persistence
max_iterations: 6
objective: Weigh the initial logon lead together with SMB share activity and rare
  process hierarchies to determine if a host is compromised by Metasploit movement
  or persistence.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  rows from the queries.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the movement-triage verdict identifies at least one host as malicious or suspicious" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-context)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the hosts identified as malicious and revoke the credentials used for the suspicious remoting sessions.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited telemetry; confirm if the persistence mechanisms match expected administrative behavior and provide tuning feedback for the standard_parent_paths parameter.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Summarize the hosts examined and any evidence of absence for the lateral movement phase. Record any visibility gaps encountered.
```
→ end
