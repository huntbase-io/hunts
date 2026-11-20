---
analysis: A simple rule might catch sa brute force, but this hunt links those login
  failures to specific, unauthorized child processes from the SQL service. This correlation
  across two telemetry surfaces reduces the noise of automated scanners and identifies
  confirmed human-driven activity.
blind_spots:
- id: mssql-internal-logs
  question: Was the TRUSTWORTHY bit or CLR assembly enabled internally?
  remediation: Enable MSSQL Audit logging for database-level changes and ship them
    to the platform.
  requires: MSSQL internal trace/audit logs
  risk: The hunt sees the resulting process but may miss failed exploitation attempts
    or configuration changes that didn't lead to a process launch.
  stage: execution-mssql-exploitation
- id: obfuscated-script-blocks
  question: What was the intent of the PowerShell loader if it was heavily encoded?
  remediation: Ensure PowerShell Script Block Logging (ID 4104) is enabled and collected.
  requires: hb_script_activity with full block de-obfuscation
  risk: Adversaries using Base64 or complex obfuscation may hide the downloader URI
    from simple command-line inspection.
  stage: execution-mssql-exploitation
coverage:
- stage: initial-access-mssql-brute-force
  status: covered
  steps:
  - sa-account-brute-force
- stage: execution-mssql-exploitation
  status: covered
  steps:
  - sql-server-shell-spawn
  - forensic-verification
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: command-and-control-payload-download
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: defense-evasion-purecrypter-loading
  status: out_of_scope
- reason: Belongs to another part of the 'Mallox ransomware affiliate leverages PureCrypter
    in MSSQL exploitation' series.
  stage: impact-mallox-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MSSQL servers are primary targets for ransomware affiliates because
    they often store high-value data and run with administrative privileges. This
    hunt finds the intrusion at the beachhead, before encryption occurs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is brute-forcing the MSSQL sa account to enable administrative
  features and execute a PowerShell loader from the SQL process.
labels:
- hunt
- attack.t1110
- attack.t1190
- attack.t1059.001
- attack.t1047
- attack.t1486
name: Mallox Ransomware MSSQL Authentication and Service Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty for the whole estate.
    type: list[host]
  shell_paths:
    default:
    - c:\windows\system32\cmd.exe
    - c:\windows\system32\windowspowershell\v1.0\powershell.exe
    - c:\windows\system32\wbem\wmic.exe
    description: Full paths to shell interpreters used in exploitation.
    from:
      kind: article
      observed: '2024-05-02'
      ref: Sekoia Mallox
    type: list[path]
  target_accounts:
    default:
    - sa
    description: Common administrative accounts targeted in MSSQL brute force.
    from:
      kind: article
      observed: '2024-05-02'
      ref: Sekoia Mallox
    type: list[string]
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
rationale: Start with SQL servers exposed on port 1433 or those located in DMZ segments.
  If the software inventory is stale, run the behavioral queries over the whole estate.
references:
- name: "Sekoia \u2014 Mallox ransomware affiliate leverages PureCrypter in MSSQL\
    \ exploitation"
  url: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
related:
- hunt: purecrypter-loading-behavior
  reason: The loading phase of PureCrypter involves anti-analysis and memory reflection
    common to many malware families beyond Mallox.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: MSSQL Brute-force
    observables:
    - Targeting 'sa' account
    - ~320 attempts per minute
    - Inbound traffic on port 1433
    - Application name vYMiFrYR
    slug: initial-access-mssql-brute-force
    tactic: initial-access
    techniques:
    - T1110
    - T1190
  - name: MSSQL Feature Abuse
    observables:
    - Enable TRUSTWORTHY parameter on master database
    - Enable clr enabled parameter
    - Create assembly named 'shell' on msdb database
    - Enable xp_cmdshell
    - Use sp_oacreate to create wscript.shell OLE object
    - PowerShell script in C:\ProgramData
    - WMIC execution of binary
    slug: execution-mssql-exploitation
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: PureCrypter Retrieval
    observables:
    - Download of random-named files with media extensions (.mp4, .wav, .pdf)
    - 3DES encrypted data payload
    slug: command-and-control-payload-download
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: PureCrypter Evasion and Persistence
    observables:
    - Registry key Software\Microsoft\Windows\CurrentVersion\Run\
    - WMI query select * from Win32_BIOS
    - WMI query select * from Win32_ComputerSystem
    - EtwEventWrite patching
    - AmsiScanBuffer patching
    - MpPreference -Exclusion commands
    - Module load of SbieDll.dll
    - Reflective code loading of .NET library
    slug: defense-evasion-purecrypter-loading
    tactic: defense-evasion
    techniques:
    - T1059.001
    - T1047
  - name: Mallox Ransomware Encryption
    observables:
    - Ydxhjxwf.exe in %appdata%
    - AES-CBC encrypted file content
    - Ransomware file encryption activity
    slug: impact-mallox-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Mallox ransomware affiliates compromise internet-facing MS-SQL servers
    through brute-force attacks on the 'sa' account. Once inside, they abuse internal
    SQL features like CLR assemblies and OLE automation to execute PowerShell scripts
    that deploy PureCrypter, which eventually loads the Mallox ransomware in memory.
series:
  index: 1
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Mallox Ransomware MSSQL Authentication and Service Abuse

This hunt targets the initial compromise of Microsoft SQL Servers by Mallox ransomware affiliates. It identifies high-volume authentication failures against the sa account and correlates them with the activation of SQL features like xp_cmdshell or OLE automation, which results in the SQL service spawning shells to download second-stage payloads. The hunt pivots between identity logs and endpoint process activity to identify confirmed intrusions.

## identify-sql-servers
<!-- Identify active MSSQL installations -->
Find hosts where Microsoft SQL Server is installed to narrow the scope of the subsequent behavioral queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running SQL Server. Silence indicates no SQL installations
  were found in the software inventory.
reads:
- device_hostname
- package_name
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%sql server%' OR LOWER(vendor_name) LIKE '%microsoft%') AND asset_scope = 'endpoint'
```

## investigate-compromise
<!-- Investigate brute-force and execution -->
parallel:
- → sa-account-brute-force
- → sql-server-shell-spawn
join: → triage-mallox-activity

## sa-account-brute-force
<!-- Brute-force activity against SQL accounts -->
Detect high-volume login failure patterns targeting the SQL Administrator account.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, target_accounts=target_accounts)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: A host showing hundreds of failed sign-ins on the sa account. Silence proves
  no large-scale brute force occurred during the window.
prevalence:
  by: dst_endpoint_name
  key:
  - actor_user_name
  rare_below: 2
reads:
- dst_endpoint_name
- actor_user_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, actor_user_name, COUNT(*) as fail_count, MIN(time) as first_fail, MAX(time) as last_fail FROM hb_auth_signin WHERE activity_id = 5 AND instr(',' || '{{target_accounts}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) GROUP BY dst_endpoint_name, actor_user_name HAVING fail_count > 100 ORDER BY fail_count DESC
```

## sql-server-shell-spawn
<!-- SQL Server spawning shell interpreters -->
Identify instances where the SQL service process spawns a shell or WMIC, indicating successful xp_cmdshell or OLE automation abuse.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, shell_paths=shell_paths)
~~~yaml
expected: Process rows showing cmd.exe or powershell.exe as children of the MSSQL
  service. Silence proves the SQL engine did not spawn common shells on the audited
  hosts.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%sqlservr.exe%' OR LOWER(process_cmd_line) LIKE '%sqlservr%') AND instr(',' || '{{shell_paths}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-mallox-activity
<!-- Weigh brute-force and execution results -->
```agent target=hunter
cite: required
context:
- sa-account-brute-force
- sql-server-shell-spawn
max_iterations: 3
objective: Determine if the brute-force activity against the sa account resulted in
  successful execution of shells or downloaders on any SQL server.
success_criteria: A verdict of malicious for any host where shell execution temporally
  follows a period of login failures.
tools:
- endpoint
- identity
```

## is-intrusion-confirmed
<!-- Confirm intrusion on SQL host -->
if~: "the agent confirms that a high volume of login failures was followed by the SQL service spawning a shell or downloader on the same host" (confidence: high, judge=hunter)
then: → isolate-infected-server
indeterminate: → forensic-verification
unavailable: → forensic-verification (blind_spot: mssql-internal-logs)
else: → close-out

## isolate-infected-server
<!-- Isolate the compromised SQL host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately. Stop the MSSQL service and prevent local shell execution until investigation is complete.
```
→ forensic-verification

## forensic-verification
<!-- Forensic audit of SQL engine -->
```manual target=analyst
Review SQL Server logs for application name vYMiFrYR. Check the master database for TRUSTWORTHY setting changes. Look for a CLR assembly named shell in the msdb database. Search C:\ProgramData for PowerShell scripts or random-named multimedia files.
```
→ close-out

## close-out
<!-- Hunt close-out and remediation -->
```manual target=analyst
Record the results for all SQL servers in scope. If the shell-spawn query found true positives, promote it to a standing detection rule. Recommend rotating the sa password and disabling xp_cmdshell.
```
→ end
