---
analysis: "While static rules might alert on 'Ydxhjxwf.exe', they are easily bypassed.\
  \ This hunt looks for the loader's immutable logic\u2014WMI hardware queries, specific\
  \ sandbox-evasion usernames, and stack-counted rare binaries in profile paths\u2014\
  correlating three distinct surfaces into one high-fidelity verdict."
blind_spots:
- id: missing-script-telemetry
  question: Was the exclusion or payload download performed via an obfuscated VBScript
    or JScript?
  requires: hb_script_activity for non-PowerShell interpreters
  risk: PureCrypter commonly uses PowerShell, but if a variant uses a different interpreter
    without script block logging, the Defender exclusion step will be silent.
  stage: loader-evasion-and-anti-analysis
- id: reflective-loading-blindspot
  question: Can we see the reflective loading of the stage 2 DLL or the final payload?
  requires: hb_module_activity
  risk: Since reflective loading occurs in memory, file activity will not capture
    the transition. We rely on process monitoring of the initial loader and the prevalence
    of the resulting process.
  stage: mallox-ransomware-execution
coverage:
- stage: loader-evasion-and-anti-analysis
  status: covered
  steps:
  - purecrypter-evasion-checks
  - defender-exclusion-tampering
- stage: persistence-run-key
  status: covered
  steps:
  - run-key-persistence
- stage: mallox-ransomware-execution
  status: covered
  steps:
  - rare-profile-binaries
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: sql-brute-force-access
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: sql-server-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: initial-payload-delivery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Mallox ransomware affiliates target database infrastructure to maximize
    leverage for extortion. Detecting the PureCrypter loader's heavy anti-analysis
    logic and persistence allows intervention before the destructive encryption phase
    begins.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is executing the PureCrypter loader on a compromised SQL server,
  performing heavy environment checks and establishing user-profile persistence before
  deploying the Mallox ransomware payload.
labels:
- hunt
- attack.t1497.001
- attack.t1562.001
- attack.t1129
- attack.t1547.001
- attack.t1486
- attack.t1047
name: PureCrypter evasion and Mallox ransomware execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_usernames:
    default:
    - john
    - anna
    - xxxxxxxx
    description: Usernames checked by PureCrypter as part of anti-analysis; finding
      these in activity may indicate an evasion attempt.
    from:
      kind: article
      observed: '2024-05-02'
      ref: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
    type: list[string]
  mallox_filename:
    default: Ydxhjxwf.exe
    description: The specific ransomware filename observed in the report.
    from:
      kind: article
      observed: '2024-05-02'
      ref: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
    type: string
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt (e.g., confirmed MSSQL
      servers).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value assets running SQL Server. The software inventory scoping
  step narrows the hunt to these servers, but leaving the scope_hosts parameter empty
  allows for a fleet-wide search if lateral movement is suspected.
references:
- name: Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation
  url: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
related:
- hunt: mssql-bruteforce-and-exploitation
  reason: This hunt picks up after the exploitation of the SQL server to deploy the
    loader.
  relation: follows
- hunt: mallox-mssql-exploitation-initial-delivery
  relation: follows
scenario:
  stages:
  - name: MS-SQL Brute Force
    observables:
    - Brute-force attempts against 'sa' account
    - Source IP address in AS208091 (XHost Internet Solution)
    - Approximately 320 authentication attempts per minute
    - Targeting MS-SQL port (1433)
    slug: sql-brute-force-access
    tactic: initial-access
    techniques:
    - T1110
    - T1190
  - name: MS-SQL Feature Exploitation
    observables:
    - Enabling 'TRUSTWORTHY' database parameter
    - Enabling 'clr enabled' parameter
    - Creating assembly named 'shell' (SqlShell DLL)
    - Creating stored procedure 'cmd_exec'
    - Enabling 'xp_cmdshell' configuration
    - Enabling 'Ole Automation Procedures'
    - Use of 'sp_oacreate' to create 'wscript.shell' OLE object
    - Application name 'vYMiFrYR' in SQL connection logs
    slug: sql-server-exploitation
    tactic: execution
    techniques:
    - T1059.003
  - name: PowerShell Downloader and WMIC Execution
    observables:
    - echo and redirect used to create PowerShell script
    - PowerShell script saved to C:\ProgramData
    - WMIC used to execute downloaded binary
    - Downloading multimedia-themed files (e.g., .mp4, .wav, .pdf) containing encrypted
      payloads
    slug: initial-payload-delivery
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: PureCrypter Anti-Analysis and Evasion
    observables:
    - WMI query 'select * from Win32_BIOS' to check for VMWare, Virtual, AMI, or Xen
    - WMI query 'select * from Win32_ComputerSystem' to check for Microsoft or VMWare
    - Process search for 'SbieDll.dll'
    - Monitor size check for 1440x900
    - Username check for 'john', 'anna', or 'xxxxxxxx'
    - Execution of 'ipconfig /renew' and 'ipconfig /release' for network testing
    - Patching 'EtwEventWrite' and 'AmsiScanBuffer' in memory
    - Adding Windows Defender exclusions via 'MpPreference -Exclusion'
    slug: loader-evasion-and-anti-analysis
    tactic: defense-evasion
    techniques:
    - T1497.001
    - T1562.001
    - T1129
  - name: Registry Run Key Persistence
    observables:
    - Registry key addition in 'Software\Microsoft\Windows\CurrentVersion\Run\'
    slug: persistence-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Mallox Ransomware Execution
    observables:
    - Ransomware executable named 'Ydxhjxwf.exe' in %appdata%
    - Reflective code loading of stage 2 DLL
    - Elevation of process privileges with 'SeDebugPrivilege'
    slug: mallox-ransomware-execution
    tactic: impact
    techniques:
    - T1486
  summary: An affiliate of Mallox ransomware targets internet-facing MS-SQL servers
    using brute-force attacks against the 'sa' account. Upon gaining access, the attacker
    exploits SQL features such as CLR assemblies and xp_cmdshell to deliver PureCrypter,
    a .NET loader that employs extensive anti-analysis and evasion techniques before
    executing the final Mallox ransomware payload.
series:
  index: 2
  slug: mallox-ransomware-affiliate-leverages-purecrypter-in-mssql-exploitation
  title: Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation
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


# PureCrypter evasion and Mallox ransomware execution

This hunt focuses on the behavioral indicators of the PureCrypter loader and the Mallox ransomware it drops. It identifies unique defense evasion techniques, such as WMI-based BIOS and manufacturer checks, screen size validation, and network resets. It then corroborates these with registry-based persistence in user profile Run keys and stack-counts rare binaries running from AppData. This multi-surface approach ensures visibility even if the final ransomware filenames rotate.

## scope-mssql-servers
<!-- Identify candidate SQL servers -->
Focus the hunt on hosts with Microsoft SQL Server installed, as they are the primary targets of this campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames likely hosting SQL Server. If empty, the hunt runs across
  the full estate.
reads:
- device_hostname
- package_name
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%sql%server%' OR LOWER(vendor_name) LIKE '%microsoft%') AND asset_scope = 'endpoint'
```

## parallel-telemetry-gathering
<!-- Gather multi-surface evidence -->
parallel:
- → purecrypter-evasion-checks
- → run-key-persistence
- → defender-exclusion-tampering
- → rare-profile-binaries
join: → triage-agent

## purecrypter-evasion-checks
<!-- Anti-analysis behavior and WMI checks -->
Find process execution matching the loader's environment checks (WMI for BIOS/System) and the specific usernames it exits for.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, malicious_usernames=malicious_usernames, lookback_days=lookback_days)
~~~yaml
expected: Processes querying hardware identifiers or matching a known sandbox username.
  Finding BIOS/System WMI queries paired with ipconfig resets is highly indicative.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%win32_bios%' OR LOWER(process_cmd_line) LIKE '%win32_computersystem%' OR instr(',' || '{{malicious_usernames}}' || ',', ',' || LOWER(user_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%ipconfig%renew%' OR LOWER(process_cmd_line) LIKE '%ipconfig%release%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## run-key-persistence
<!-- Persistence in user Run key -->
Identify the registry entry established by the loader to ensure survival after reboots.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A Run key pointing to a binary in a user-writable path. Normal applications
  usually install to Program Files.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(reg_target) LIKE '%software\microsoft\windows\currentversion\run%' AND (LOWER(reg_value_data) LIKE '%\appdata\local\%' OR LOWER(reg_value_data) LIKE '%\appdata\roaming\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## defender-exclusion-tampering
<!-- Windows Defender exclusion activity -->
Find the PowerShell commands used to suppress Defender alerts for the ransomware binary.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks adding the loader or payload path to MpPreference exclusions.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(script_content) LIKE '%mppreference%' AND LOWER(script_content) LIKE '%-exclusion%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-profile-binaries
<!-- Rare executables in user profile paths -->
Stack-count processes running from AppData to highlight the Mallox binary against fleet background noise.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, mallox_filename=mallox_filename, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries seen on only one or two hosts, specifically matching the reported
  Mallox filename or running from unusual AppData subdirectories.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
- process_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) as path, COUNT(DISTINCT device_hostname) as hosts, COUNT(*) as runs, MIN(time) as first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) = LOWER('{{mallox_filename}}') OR (LOWER(process_path) LIKE '%\appdata\%' AND LOWER(process_path) LIKE '%.exe')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-agent
<!-- Triaging PureCrypter and Mallox presence -->
```agent target=hunter
cite: required
context:
- purecrypter-evasion-checks
- run-key-persistence
- defender-exclusion-tampering
- rare-profile-binaries
max_iterations: 4
objective: 'Determine if any host exhibits the PureCrypter behavior chain: environment
  sensing followed by persistence and execution of a rare binary in AppData.'
success_criteria: A detailed verdict citing process paths, registry keys, and specific
  WMI queries.
tools:
- endpoint
```

## routing-decision
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host and confirms ransomware execution indicators" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-script-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR/Identity control. Collect the rare binary from the identified AppData path for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst confirmation and tuning -->
```manual target=analyst
Verify the rare process activity and check for signs of volume shadow copy deletion or mass file encryption on the identified hosts.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Log the hosts examined and confirm no PureCrypter/Mallox indicators were found. Retain the scoping results for the next monthly run.
```
→ end
