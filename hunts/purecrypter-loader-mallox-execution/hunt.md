---
analysis: A simple detection rule would alert on a 'MpPreference' exclusion but would
  suffer from high false-positive rates from legitimate IT tasks. This hunt correlates
  that evasion lead with persistence and network patterns across three surfaces, allowing
  an analyst to verify the full attack chain.
blind_spots:
- id: no-endpoint-coverage
  question: Are we missing activity on hosts that are not enrolled in the monitoring
    platform?
  requires: EDR agent coverage on all internet-facing servers
  risk: An intruder could compromise an unmanaged server and deploy the loader without
    producing any behavioral telemetry.
- id: patching-bypasses-script-logging
  question: Did the loader successfully patch AMSI or ETW to blind PowerShell script
    logging?
  requires: Memory injection monitoring
  risk: If patching occurs, the hb_script_activity surface may fail to record the
    malicious commands, leaving only the process command-line as evidence.
  stage: defense-evasion-purecrypter-loading
- id: encrypted-payload-inspection
  question: Was the content of the media files (.mp4, .pdf) actually a malicious payload?
  requires: Network-level decryption or sandbox analysis
  risk: The hunt identifies the transfer of media files, but because they are 3DES
    encrypted, their malicious nature is only confirmed by observing the subsequent
    endpoint behavior.
  stage: command-and-control-payload-download
coverage:
- stage: command-and-control-payload-download
  status: covered
  steps:
  - media-payload-downloads
- stage: defense-evasion-purecrypter-loading
  status: covered
  steps:
  - defender-and-payload-lead
  - persistence-run-keys
- stage: impact-mallox-encryption
  status: covered
  steps:
  - defender-and-payload-lead
  - triage-loader-activity
- reason: Belongs to a separate hunt targeting SQL authentication logs.
  stage: initial-access-mssql-brute-force
  status: out_of_scope
- reason: Belongs to a separate hunt focusing on SQL server internal audit logs and
    assemblies.
  stage: execution-mssql-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: PureCrypter is an active loader used to deploy Mallox ransomware.
    Detecting its early evasion and payload retrieval stages provides a critical window
    to intervene before data encryption begins.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using PureCrypter to deliver Mallox ransomware, identified
  by Windows Defender exclusion commands followed by the retrieval of encrypted payloads
  disguised as media files and persistent Run keys in user profiles.
labels:
- hunt
- attack.t1562.001
- attack.t1059.001
- attack.t1047
- attack.t1547.001
- attack.t1105
- attack.t1486
name: PureCrypter Loader and Mallox Ransomware Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  mallox_binary_name:
    default: ydxhjxwf.exe
    description: Specific binary name observed for the Mallox ransomware payload.
    from:
      kind: article
      observed: '2024-05-02'
      ref: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
    type: string
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows servers, specifically those running Microsoft SQL Server,
  as they are the primary targets for this Mallox affiliate.
references:
- name: "Sekoia \u2014 Mallox ransomware affiliate leverages PureCrypter in MSSQL\
    \ exploitation"
  url: https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/
related:
- hunt: initial-access-mssql-brute-force
  reason: This hunt focuses on the loader behavior post-compromise, not the initial
    SQL brute-force attack.
  relation: out-of-scope-alternative
- hunt: mallox-mssql-initial-access-execution
  relation: follows
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# PureCrypter Loader and Mallox Ransomware Execution

This hunt targets the behavioral indicators of the PureCrypter loader as it prepares a host for Mallox ransomware. It identifies the use of 'Add-MpPreference' commands to blind local security, then correlates this lead with two independent signals: the creation of persistent Run keys pointing to profile-based binaries and the retrieval of encrypted stages disguised as common media files (.mp4, .wav, .pdf). An agent evaluates the combined evidence to detect active loader activity before the ransomware proceeds to full-scale file encryption.

## defender-and-payload-lead
<!-- Defender Exclusions and Ransomware Binary -->
Detects attempts to blind Windows Defender or the execution of known ransomware binaries.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, mallox_binary_name=mallox_binary_name)
~~~yaml
expected: Processes attempting to exclude paths from Windows Defender or executions
  of the specific Mallox binary. Silence suggests this specific evasion or payload
  was not seen.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%add-mppreference%' OR LOWER(process_cmd_line) LIKE '%{{mallox_binary_name}}%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-loader
<!-- Corroborate Loader Activity -->
parallel:
- → persistence-run-keys
- → media-payload-downloads
join: → triage-loader-activity

## persistence-run-keys
<!-- Registry Run-Key Persistence -->
Check for the loader's persistence mechanism in the Run key pointing at user-writable paths.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare Run-key values pointing to executables in profile directories. Legitimate
  software usually appears across more hosts.
prevalence:
  by: device_hostname
  key:
  - reg_value_data
  rare_below: 3
reads:
- activity_id
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, reg_target, reg_value_data, MIN(time) AS first_seen FROM hb_registry_activity WHERE activity_id = 2 AND LOWER(reg_target) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' AND (LOWER(reg_value_data) LIKE '%\\appdata\\%' OR LOWER(reg_value_data) LIKE '%\\users\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_value_data HAVING COUNT(DISTINCT device_hostname) < 3
```

## media-payload-downloads
<!-- Suspicious Media Payload Downloads -->
Detect the retrieval of encrypted stages disguised as common media files, a specific PureCrypter behavior.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests for media files that occur near the time of Defender exclusions
  or Run-key changes. Random filenames are high confidence indicators.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- device_hostname
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%.mp4' OR LOWER(url_path) LIKE '%.wav' OR LOWER(url_path) LIKE '%.pdf') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname HAVING COUNT(DISTINCT device_hostname) < 3
```

## triage-loader-activity
<!-- Triage Loader Activity -->
```agent target=hunter
cite: required
context:
- defender-and-payload-lead
- persistence-run-keys
- media-payload-downloads
max_iterations: 6
objective: Determine if the collective evidence on any host indicates a PureCrypter
  loader delivering Mallox ransomware. Focus on the timing of Defender exclusions
  relative to suspicious media downloads and Run-key persistence.
success_criteria: A verdict of malicious for hosts exhibiting multiple correlated
  stages, prioritizing those where a rare media download occurred shortly before or
  alongside a Defender exclusion event or a new Run-key entry.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host, citing specific Defender exclusions, rare media downloads, or the mallox binary name" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-coverage)
else: → close-out

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot, as it may trigger the persistence mechanism or final encryption stage. Collect the suspicious binary identified in the Run key for analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Tuning -->
```manual target=analyst
Review the cited rows from process, registry, and network activity. If legitimate administrative activity is identified, record the exclusion pattern for future tuning. Verify if the host was compromised via the MSSQL sa account.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Document the hosts examined, the malicious artifacts identified, and whether any remediation steps were taken. If no activity was found, record the period of negative coverage.
```
→ end
