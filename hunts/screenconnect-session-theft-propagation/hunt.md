---
analysis: A single rule might flag encoded PowerShell, but this hunt connects the
  harvesting of browser cookies via SQLite to the specific network relays and the
  custom uploader binary used by the SCKit worm, providing the context required to
  confirm lateral movement rather than a simple loader alert.
blind_spots:
- id: no-process-visibility
  question: whether the SQLite command line specifically targeted the Cookies file
  requires: EDR process command-line auditing
  risk: A host with truncated command-line logs might only show 'sqlite3.exe' without
    the target path, making it harder to distinguish from legitimate use.
  stage: session-cookie-harvesting
- id: encrypted-dns
  question: whether the host used DoH to resolve attacker relays
  requires: Network-level DNS inspection or EDR DNS capture
  risk: If the attacker uses DNS-over-HTTPS, lookups for the C2 domains will not appear
    in hb_dns_activity, leaving only the process execution as a signal.
  stage: lateral-toolbox-propagation
coverage:
- stage: session-cookie-harvesting
  status: covered
  steps:
  - worm-script-execution
  - rare-binary-prevalence
- stage: lateral-toolbox-propagation
  status: covered
  steps:
  - worm-script-execution
  - attacker-dns-activity
- reason: Initial access through RMM+ vulnerabilities is handled in a separate scoping
    hunt focused on ScreenConnect server logs.
  stage: rmm-plus-extension-exploitation
  status: out_of_scope
- reason: The initial PowerShell loaders and decoders belong to the deployment hunt.
  stage: scripted-loader-execution
  status: out_of_scope
- reason: The TrapWatch persistence mechanism via Scheduled Tasks is covered by standard
    persistence hunts.
  stage: trapwatch-task-persistence
  status: out_of_scope
- reason: Registry-based persistence using the RelayTrapLiteAlert key is out of scope
    for this propagation focus.
  stage: registry-run-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The SCKit worm targets technicians to harvest session cookies and
    spread laterally through RMM tools; a negative result over the technician estate
    confirms no such session hijacking is occurring.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is harvesting technician session cookies using SQLite-based
  scripts and using them to propagate payloads through the ScreenConnect Shared Toolbox.
labels:
- hunt
- attack.t1059.001
- attack.t1539
- attack.t1021.002
- credential access
- execution
- initial access
- lateral movement
- persistence
name: ScreenConnect Session Theft and Toolbox Propagation
parameters:
  attacker_domains:
    default:
    - relaytrap.cs
    - ns.mo7sen.dev
    - newnewnew.gotdns.org
    - sc.payproofkit.com
    - soxnewwork.homedns.org
    - cdn007-digitaldownloads.com
    description: Known SCKit relay and C2 domains.
    from:
      kind: article
      observed: '2026-11-12'
      ref: huntress-sckit-worm
    type: list[domain]
  execution_hosts:
    default: []
    description: Optional list of hostnames identified in the lead step; leave empty
      to scan all.
    type: list[host]
  found_process_name:
    default: ToolboxRelayUploader.exe
    description: The specific uploader process name identified in the beachhead detection.
    type: string
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
    from: https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on technician workstations and servers running ScreenConnect client
  software. If technician hostnames are known, use the execution_hosts parameter to
  reduce noise from developers using SQLite.
references:
- name: "Huntress \u2014 SCKit Worm Installs Rogue ScreenConnect Clients and Session\
    \ Cookie Relays"
  url: https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
related:
- hunt: screenconnect-rogue-client-persistence
  reason: This hunt focuses on session theft and lateral movement; the installation
    of persistent rogue clients is a separate stage of the SCKit infection.
  relation: out-of-scope-alternative
- hunt: sckit-endpoint-hijacking-persistence
  relation: follows
scenario:
  stages:
  - name: RMM+ Extension Authentication Bypass
    observables:
    - POST requests to ScreenConnect servers with blank RMMPlus.AccessKey
    - RMM+ versions 1.0.31 and 1.0.32
    slug: rmm-plus-extension-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Scripted Loader and Payload Delivery
    observables:
    - Stage0Loader.ps1
    - Run-Lateral-Full.bat
    - sckit-loader.ps1
    - ns.mo7sen.dev/EadF.php?p=1
    - '%TEMP%\k<guid>.ps1'
    - cdn007-digitaldownloads.com
    slug: scripted-loader-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: High-Frequency Scheduled Task Persistence
    observables:
    - 'Task name: TrapWatch'
    - 'Command: TrapWatch.ps1'
    - 'Frequency: Every 10 seconds'
    - Runs as SYSTEM
    slug: trapwatch-task-persistence
    tactic: persistence
    techniques:
    - T1053.005
  - name: Registry Run Key Persistence
    observables:
    - 'Run key name: RelayTrapLiteAlert'
    - 'Command: Lite-Alert.ps1'
    - C:\ProgramData\RelayTrap
    slug: registry-run-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Technician Session Cookie Theft
    observables:
    - sqlite3.exe reading browser cookie databases
    - Panel-Lateral.ps1
    - LabConfig.ps1
    - ns.mo7sen.dev/EadF.php?p=5
    slug: session-cookie-harvesting
    tactic: credential-access
    techniques:
    - T1059.001
  - name: Shared Toolbox Lateral Propagation
    observables:
    - ToolboxRelayUploader.exe using stolen tokens
    - AddToToolbox command on ScreenConnect panels
    - sc.payproofkit.com
    - 185.99.255.28
    - 155.94.150.39
    slug: lateral-toolbox-propagation
    tactic: lateral-movement
    techniques:
    - T1059.001
  summary: Attackers exploit an authentication flaw in the third-party RMM+ extension
    for ScreenConnect to push commands to managed endpoints. The resulting SCKit worm
    establishes persistence via high-frequency scheduled tasks and registry keys,
    hijacks legitimate client connections, and steals technician session cookies to
    propagate laterally through the ScreenConnect shared toolbox.
series:
  index: 2
  slug: sckit-worm-installs-rogue-screenconnect-clients-and-session-cookie-relays-across-hundreds-of-end
  title: SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays
    Across Hundreds of Endpoints
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


# ScreenConnect Session Theft and Toolbox Propagation

This hunt identifies the harvesting of ScreenConnect session cookies from technician browsers and the subsequent use of those hijacked sessions for lateral movement. The SCKit worm automates cookie extraction using a scripted SQLite utility and then broadcasts payloads to all endpoints accessible through the technician's ScreenConnect panel using a custom uploader tool. The hunt begins by identifying the execution of core worm scripts (Panel-Lateral.ps1, LabConfig.ps1) and the specialized uploader binary. It then fan-outs to verify the mechanism of theft—specifically sqlite3.exe interacting with browser database paths—and checks for connections to identified attacker relay infrastructure from those same hosts. An agent weighs these signals to determine if a host is an active beachhead for propagation.

## worm-script-execution
<!-- SCKit worm scripts and uploader execution -->
Find the primary execution of the worm's harvesting and propagation components.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Any row indicates the worm's presence. Silence suggests the harvesting phase
  has not started or used different filenames.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%panel-lateral.ps1%' OR LOWER(process_cmd_line) LIKE '%labconfig.ps1%' OR LOWER(process_name) = 'toolboxrelayuploader.exe' OR (LOWER(process_name) = 'sqlite3.exe' AND (LOWER(process_cmd_line) LIKE '%cookies%' OR LOWER(process_cmd_line) LIKE '%login data%'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## enrichment-fan-out
<!-- Corroborate harvesting and C2 activity -->
parallel:
- → rare-binary-prevalence
- → attacker-dns-activity
join: → triage-worm-activity

## rare-binary-prevalence
<!-- Prevalence of worm-related binaries -->
Stack-count the uploader utility identified in the beachhead check to establish rarity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, found_process_name=found_process_name)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Artifacts appearing on 1-2 hosts confirm they are likely the attacker's
  toolkit rather than common software.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 5
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT LOWER(process_name) AS name, LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) = LOWER('{{found_process_name}}') OR LOWER(process_path) LIKE '%\relaytrap\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## attacker-dns-activity
<!-- DNS lookups from beachhead hosts -->
Confirm that the hosts executing worm scripts are also reaching out to known SCKit relays.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, attacker_domains=attacker_domains, execution_hosts=execution_hosts)
~~~yaml
expected: DNS queries for the specified domains from the same hosts identified as
  executing the worm. Absence means direct IP communication or domain rotation.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{attacker_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{execution_hosts}}' = '' OR instr(',' || '{{execution_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## triage-worm-activity
<!-- Weigh worm execution and network signals -->
```agent target=hunter
cite: required
context:
- worm-script-execution
- rare-binary-prevalence
- attacker-dns-activity
max_iterations: 4
objective: Determine if the identified host exhibits the full SCKit worm lifecycle,
  from cookie harvesting to propagation attempts.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  script execution and corresponding C2 traffic.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage result -->
if~: "the triage-worm-activity verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → analyst-review

## isolate-host
<!-- Isolate beachhead host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active ScreenConnect session tokens associated with users on this machine.
```
→ analyst-review

## analyst-review
<!-- Verify session hijacking -->
```manual target=analyst
Examine the browser profile paths accessed by sqlite3.exe; verify if the stolen sessions were used to push payloads to other environments by checking ScreenConnect server audit logs for Toolbox activity.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the identified binaries and domains. If new filenames or domains were found, update the hunt parameters and consider promoting the script execution query to a permanent detection rule.
```
→ end
