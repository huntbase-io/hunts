---
analysis: While rules exist for encoded PowerShell, this hunt pivots across four surfaces
  (software inventory, process command lines, registry stack-counts, and script block
  content) to identify a specific, multi-stage infection pattern. The use of prevalence
  stacking on registry keys allows us to find zero-day loader variants that a single
  signature-based rule would miss.
blind_spots:
- id: missing-script-logging
  question: whether the loader successfully patched AMSI or ETW in memory
  requires: PowerShell Script Block Logging (Event ID 4104)
  risk: Without script block logging, the memory-patching query (hb_script_activity)
    will return zero results even if the behavior occurred.
  stage: purecrypter-evasion-and-checks
- id: registry-log-retention
  question: which process originally wrote the Run key
  requires: hb_registry_activity with state_kind = 'log'
  risk: If only live (snapshot) registry data is available, the host_count prevalence
    still works, but we lose the process context needed to confirm the source process.
  stage: purecrypter-persistence
coverage:
- stage: staged-script-execution
  status: covered
  steps:
  - staged-script-redirection
- stage: purecrypter-evasion-and-checks
  status: covered
  steps:
  - purecrypter-evasion-tactics
  - script-memory-patching
- stage: purecrypter-persistence
  status: covered
  steps:
  - rare-persistence-run-keys
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: mssql-brute-force-access
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: sql-internal-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: mallox-ransomware-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: PureCrypter is a sophisticated loader that facilitates ransomware
    delivery (Mallox, 8220 Gang). Detecting its evasion and persistence patterns provides
    a proactive defense against high-impact ransomware infections that bypass standard
    signature-based detection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a foothold following a database compromise,
  using PowerShell redirection to stage payloads in ProgramData and executing anti-analysis
  checks before persisting via registry Run keys.
labels:
- hunt
- attack.t1059.001
- attack.t1047
- attack.t1562.001
- attack.t1497
- attack.t1547.001
name: 'Mallox Affiliate: Loader Evasion and Persistence'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioral events.
    type: number
  writable_paths:
    default:
    - \ProgramData\
    - \Users\Public\
    - \AppData\Local\Temp\
    description: Common user-writable paths where payloads are staged.
    type: list[path]
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
rationale: The hunt begins by identifying MS-SQL servers, then looks broadly across
  the estate for behavioral loader patterns. If many hits are found in staging, focus
  first on the hosts identified in the scoping step.
references:
- name: Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation
  url: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
related:
- hunt: mallox-mssql-exploitation
  reason: This hunt focuses on the loader; the initial compromise happens via MS-SQL
    exploitation, which is covered in the first hunt of this series.
  relation: precedes
- hunt: mallox-ransomware-impact
  reason: This hunt detects the loader; the eventual file encryption and impact are
    handled in the final hunt of this series.
  relation: follows
- hunt: mallox-sql-brute-force-os-breakout
  relation: follows
scenario:
  stages:
  - name: MS-SQL Administrator Brute Force
    observables:
    - 'account: sa'
    - 320 attempts per minute
    - 'source network: AS208091 (XHost Internet Solution)'
    slug: mssql-brute-force-access
    tactic: initial-access
    techniques:
    - T1110
    - T1190
  - name: SQL Shell and Command Execution
    observables:
    - 'database parameter: TRUSTWORTHY'
    - 'database parameter: clr enabled'
    - 'assembly name: shell'
    - 'stored procedure: cmd_exec'
    - 'SQL command: xp_cmdshell'
    - 'OLE object: wscript.shell'
    - 'SQL command: sp_oacreate'
    - 'client_app_name: vYMiFrYR'
    slug: sql-internal-exploitation
    tactic: execution
    techniques:
    - T1059
  - name: PowerShell and WMIC Staging
    observables:
    - 'path: C:\ProgramData\'
    - 'process: powershell.exe'
    - 'process: wmic.exe'
    - 'behavior: echo redirection to create .ps1 script'
    - 'command: WMIC to execute dropped binary'
    slug: staged-script-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: PureCrypter Anti-Analysis and Defense Evasion
    observables:
    - 'module: SbieDll.dll'
    - 'WMI query: Win32_BIOS'
    - 'WMI query: Win32_ComputerSystem'
    - 'command: ipconfig /renew'
    - 'command: ipconfig /release'
    - 'function patching: EtwEventWrite'
    - 'function patching: AmsiScanBuffer'
    - 'command: MpPreference -Exclusion'
    - 'privilege: SeDebugPrivilege'
    slug: purecrypter-evasion-and-checks
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1497
  - name: Registry Run Key Persistence
    observables:
    - 'registry key: Software\Microsoft\Windows\CurrentVersion\Run\'
    slug: purecrypter-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Mallox Ransomware Deployment
    observables:
    - 'file: Ydxhjxwf.exe'
    - 'path: %appdata%'
    - 'encryption: AES in CBC mode'
    slug: mallox-ransomware-impact
    tactic: impact
    techniques:
    - T1486
  summary: A Mallox ransomware affiliate gained access to internet-facing MS-SQL servers
    by brute-forcing the 'sa' account. Once inside, they leveraged SQL features like
    xp_cmdshell and CLR assemblies to stage a PowerShell script that deployed the
    PureCrypter loader, which ultimately executed the Mallox ransomware payload while
    attempting to evade detection through sandbox checks and security tool patching.
series:
  index: 2
  slug: mallox-ransomware-affiliate-leverages-purecrypter-in-mssql-exploitation
  title: Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation
  total: 3
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Mallox Affiliate: Loader Evasion and Persistence

This hunt focuses on the post-exploitation lifecycle of the PureCrypter loader as used by Mallox ransomware affiliates. It specifically targets the transition from SQL exploitation to full system persistence. The hunt looks for the unique 'echo' redirection method used to stage scripts in ProgramData, the environment-checking WMI queries used to detect sandboxes, and the registry modifications used to ensure the loader survives reboots. By corroborating process execution with registry and script block telemetry, we can distinguish the loader's activity from standard administrative tasks.

## scope-sql-servers
<!-- Identify SQL Server Hosts -->
Identify hosts running Microsoft SQL Server, as these are the primary targets for the initial brute-force and exploitation described in the research.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames hosting SQL Server. Silence means no SQL servers are
  enrolled, or the software inventory is not being collected.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%sql server%'
```

## parallel-loader-activities
<!-- Examine Loader Staging and Evasion -->
parallel:
- → staged-script-redirection
- → purecrypter-evasion-tactics
- → rare-persistence-run-keys
- → script-memory-patching
join: → triage-loader-behavior

## staged-script-redirection
<!-- PowerShell Staging via Echo Redirection -->
Detect the specific command-line behavior of creating a .ps1 script using 'echo' and then executing it via WMIC or PowerShell, a key staging step for this affiliate.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Processes involving CMD/PowerShell redirecting output to a script file in
  a writable path, followed by WMIC executing a binary from that same path.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ((LOWER(process_cmd_line) LIKE '%echo %' AND LOWER(process_cmd_line) LIKE '%>%.ps1%') OR (LOWER(process_name) LIKE '%wmic.exe%' AND (LOWER(process_cmd_line) LIKE '%process call create%' AND (LOWER(process_cmd_line) LIKE '%\programdata\%' OR LOWER(process_cmd_line) LIKE '%\users\public\%')))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## purecrypter-evasion-tactics
<!-- PureCrypter Anti-Analysis and Defense Evasion -->
Detect the loader's environment-checking behavior (WMI BIOS/Manufacturer queries) and its attempts to disable Defender and manipulate network settings.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: 'A cluster of events on a single host: WMI queries for VM artifacts, IP
  renew/release cycles, and PowerShell commands adding Defender exclusions.'
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%win32_bios%' OR LOWER(process_cmd_line) LIKE '%win32_computersystem%' OR LOWER(process_cmd_line) LIKE '%ipconfig /renew%' OR LOWER(process_cmd_line) LIKE '%ipconfig /release%' OR LOWER(process_cmd_line) LIKE '%mppreference -exclusion%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-persistence-run-keys
<!-- Rare Run Key Persistence in Writable Paths -->
Identify persistent registry Run keys pointing to binaries in user-writable paths, stack-counting them across the fleet to find outliers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Registry values in the Run key pointing to random or suspicious binaries
  in non-standard paths, occurring on only a few hosts.
prevalence:
  by: device_hostname
  key:
  - reg_target
  - reg_value_data
  rare_below: 3
reads:
- reg_target
- reg_value_data
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT reg_target, reg_value_data, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\currentversion\run%' AND (LOWER(reg_value_data) LIKE '%\appdata\%' OR LOWER(reg_value_data) LIKE '%\programdata\%' OR LOWER(reg_value_data) LIKE '%\users\public\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_target, reg_value_data HAVING host_count <= 3
```

## script-memory-patching
<!-- Script-Based Memory Patching (AMSI/ETW) -->
Find script content that contains strings related to memory patching (EtwEventWrite or AmsiScanBuffer), which PureCrypter uses to evade EDR and logging.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Script block fragments containing byte-patching code or function names for
  AMSI/ETW bypasses.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%etweventwrite%' OR LOWER(script_content) LIKE '%amsiscanbuffer%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-loader-behavior
<!-- Triage Loader Behavior -->
```agent target=hunter
cite: required
context:
- scope-sql-servers
- staged-script-redirection
- purecrypter-evasion-tactics
- rare-persistence-run-keys
- script-memory-patching
max_iterations: 5
objective: Determine if any host exhibits the combined behavior of staging via echo
  redirection, anti-analysis WMI queries, and rare Run key persistence.
success_criteria: Verdicts (malicious | suspicious | benign) with cited rows for each
  host.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for one or more hosts" (confidence: high, judge=hunter)
then: → isolate-and-contain
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-script-logging)
else: → close-out

## isolate-and-contain
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the binary staged in ProgramData for analysis. Remove the malicious Registry Run value.
```
→ analyst-review

## analyst-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the cited telemetry from process, registry, and script blocks. Confirm the presence of PureCrypter or similar loader. Update detection rules for the specific staging script if it uses a unique pattern.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record the hosts examined and confirm the negative result. Document any false positives from legitimate WMI administrative scripts.
```
→ end
