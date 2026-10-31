---
analysis: While a rule might flag on_disk=0, this hunt correlates a script-driven
  staging phase with a rare binary sideload and follow-on injection across four telemetry
  surfaces. This phased context allows an analyst to confirm a coordinated campaign
  rather than a single administrative anomaly.
blind_spots:
- id: transient-hollowing-state
  owner: Detection Engineering
  question: whether a hollowed process ran and terminated between collection intervals
  remediation: Enable Sysmon Event ID 1 (Process Create) and Event ID 10 (Process
    Access) to monitor for CREATE_SUSPENDED patterns in real-time.
  requires: Event-based process monitoring for NtUnmapViewOfSection
  risk: A snapshot-based process check will miss hollowing if the process terminates
    before the next collection cycle; an ephemeral infostealer could steal credentials
    and exit unnoticed.
  stage: process-hollowing-servicemodelreg
- id: no-script-block-logging
  owner: IT Operations
  question: the full de-obfuscated content of the ClickFix staging script
  remediation: Enable PowerShell Script Block Logging via GPO for all Windows endpoints.
  requires: PowerShell Script Block Logging (Event ID 4104)
  risk: If obfuscation is high and script block logging is disabled, the script-activity
    query will fail to find the hex flags even if the script executes successfully.
  stage: clickfix-powershell-staging
coverage:
- stage: clickfix-powershell-staging
  status: covered
  steps:
  - detect-staging-scripts
- stage: mscoree-dll-sideloading
  status: covered
  steps:
  - detect-sideload-events
- stage: edr-disablement-byovd
  status: covered
  steps:
  - detect-byovd-files
- stage: process-hollowing-servicemodelreg
  status: covered
  steps:
  - detect-hollowed-infostealer
- reason: The infostealer execution is identified by the hollowing detection on the
    target process.
  stage: remus-infostealer-collection
  status: covered
  steps:
  - detect-hollowed-infostealer
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The ClickFix campaign abuses signed Microsoft binaries and native
    OS functionality to bypass traditional application controls; a negative result
    across the estate confirms that this specific sequence of sideloading and injection
    is not established.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed a ClickFix script to sideload a malicious library
  into a signed Microsoft binary, followed by hollowing a system process to run an
  infostealer and using a BYOVD driver to blind endpoint security.
labels:
- hunt
- attack.t1055.012
- attack.t1059.001
- attack.t1555
- attack.t1574.002
name: ClickFix DLL Sideloading and Infostealer Injection
parameters:
  creation_flags:
    default: '0x8000004'
    description: Hexadecimal flags for suspended process creation (CREATE_SUSPENDED
      | CREATE_NO_WINDOW).
    from:
      kind: article
      observed: '2026-08-28'
      ref: elastic-security-labs
    type: string
  hollowing_target:
    default:
    - servicemodelreg.exe
    description: Process names targeted for hollowing.
    from:
      kind: article
      observed: '2026-08-28'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-hunt-policy
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to narrow the hunt.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
  target_dlls:
    default:
    - mscoree.dll
    description: Commonly hijacked library names.
    from:
      kind: article
      observed: '2026-08-28'
      ref: elastic-security-labs
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows endpoints containing .NET 7.0 runtimes or Microsoft keyword
  upgrade tools. The lookback period should capture the progression from the initial
  ClickFix lure to full infostealer deployment.
references:
- name: "Elastic Security Labs \u2014 From 88 lines to 1: Detecting DLL hijacking\
    \ with Elastic Defend"
  url: https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend
related:
- hunt: credential-theft-browser-database-access
  reason: This hunt focuses on the execution chain; monitoring file access to browser
    profile paths for credential theft is a separate behavioral signal.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ClickFix PowerShell Staging
    observables:
    - powershell.exe
    - -enc
    - EncodedCommand
    slug: clickfix-powershell-staging
    tactic: execution
    techniques:
    - T1059.001
  - name: DLL Sideloading of mscoree.dll
    observables:
    - vb7to8.exe
    - mscoree.dll
    - 'dll.Ext.defense_evasions: "DLL Hijack: Masquerading"'
    slug: mscoree-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: EDR Disablement via BYOVD
    observables:
    - vulnerable driver
    - Elastic Endpoint
    slug: edr-disablement-byovd
    tactic: defense-evasion
  - name: Process Hollowing of ServiceModelReg.exe
    observables:
    - ServiceModelReg.exe
    - '0x8000004'
    - CREATE_SUSPENDED
    - CREATE_NO_WINDOW
    - ZwUnmapViewOfSection
    - NtUnmapViewOfSection
    slug: process-hollowing-servicemodelreg
    tactic: defense-evasion
    techniques:
    - T1055.012
  - name: Remus Infostealer Execution
    observables:
    - Remus
    slug: remus-infostealer-collection
    tactic: credential-access
    techniques:
    - T1555
  summary: The ClickFix campaign utilizes PowerShell to deploy a legitimate Microsoft
    utility (vb7to8.exe) along with a malicious sideloaded DLL (mscoree.dll) to achieve
    initial execution. Once active, the loader employs a vulnerable driver to disable
    EDR defenses and performs process hollowing on ServiceModelReg.exe to deploy the
    Remus infostealer.
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


# ClickFix DLL Sideloading and Infostealer Injection

This hunt identifies a multi-stage infection chain starting with PowerShell script staging and mscoree.dll search-order hijacking. It then pivots to monitor for the subsequent execution of the Remus infostealer inside a hollowed ServiceModelReg.exe process and the deployment of malicious drivers designed to disable EDR products.

The hunt follows the phased flow: first establishing the initial access and persistence leads via module loads and script block telemetry, then correlating these with evidence of active in-memory injection and defense evasion. This approach distinguishes targeted binary abuse from legitimate system administration by verifying the presence of the entire attack sequence.

## scope-targeted-software
<!-- Scope to Microsoft upgrade tool installations -->
Identify hosts that have software often targeted for sideloading to focus the search.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts containing Microsoft utilities like vb7to8.exe. Silence
  indicates the tool is not managed by standard package managers but does not prove
  its absence as a standalone binary.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%visual basic%' OR LOWER(package_name) LIKE '%upgrade tool%') AND LOWER(vendor_name) LIKE '%microsoft%'
```

## parallel-early-phase
<!-- Parallel Early Phase: Lead Detection -->
parallel:
- → detect-sideload-events
- → detect-staging-scripts
join: → agent-early-triage

## detect-sideload-events
<!-- Detect mscoree.dll sideloading -->
Find search-order hijacking where mscoree.dll is loaded from a path that is not Windows\System32.

```sqlite target=endpoint role=baseline params=(target_dlls=target_dlls, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A module load for a system library name from an unusual directory. Rare
  paths seen on few hosts are high-confidence indicators.
prevalence:
  by: device_hostname
  key:
  - module_path
  rare_below: 3
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, module_name, module_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_module_activity WHERE instr(',' || '{{target_dlls}}' || ',', ',' || LOWER(module_name) || ',') > 0 AND LOWER(module_path) NOT LIKE 'c:\windows\system32\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, module_name, module_path HAVING host_count <= 3
```

## detect-staging-scripts
<!-- Detect ClickFix staging scripts -->
Identify PowerShell execution that stages binaries and prepares for process hollowing using specific API flags.

```sqlite target=endpoint role=enrichment params=(creation_flags=creation_flags, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing the 0x8000004 flag. Silence suggests the staging
  used different obfuscation or occurred outside the lookback.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE instr(LOWER(script_content), LOWER('{{creation_flags}}')) > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Assess early phase evidence -->
```agent target=hunter
cite: required
context:
- detect-sideload-events
- detect-staging-scripts
max_iterations: 3
objective: Determine if mscoree.dll sideloading and suspended process flags in PowerShell
  indicate a coordinated ClickFix staging event on any host.
success_criteria: A verdict of malicious | suspicious | benign for every host found
  in the early queries.
tools:
- endpoint
```

## parallel-follow-on-phase
<!-- Parallel Follow-on Phase: Evasion and Impact -->
parallel:
- → detect-hollowed-infostealer
- → detect-byovd-files
join: → agent-follow-on-triage

## detect-hollowed-infostealer
<!-- Detect process hollowing in ServiceModelReg -->
Identify the infostealer running inside a hollowed ServiceModelReg.exe process by checking for missing disk images.

```sqlite target=endpoint role=detection-candidate params=(hollowing_target=hollowing_target, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows where ServiceModelReg.exe is running but the binary is missing from
  disk, a definitive sign of in-memory injection.
reads:
- device_hostname
- process_name
- process_cmd_line
- on_disk
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, on_disk, time FROM hb_process_activity WHERE instr(',' || '{{hollowing_target}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-byovd-files
<!-- Detect BYOVD driver deployment -->
Identify the driver dropped to disable endpoint security, typically placed in user-writable paths.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of driver files in non-system paths. This is unusual behavior for
  legitimate software installers.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE LOWER(file_name) LIKE '%.sys' AND (LOWER(file_path) LIKE '%\temp\%' OR LOWER(file_path) LIKE '%\users\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-follow-on-triage
<!-- Final intrusion assessment -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- detect-hollowed-infostealer
- detect-byovd-files
max_iterations: 5
objective: Review the early staging verdict alongside process hollowing and driver
  deployment to confirm a successful infostealer infection.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the full chain of evidence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The follow-on agent verdict is malicious for at least one host, indicating a confirmed injection sequence following a sideloading lead." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: transient-hollowing-state)
else: → remediation-cleanup

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect a memory dump of ServiceModelReg.exe before terminating the process.
```
→ forensic-investigation

## forensic-investigation
<!-- Forensic review -->
```manual target=analyst
Extract the malicious mscoree.dll from the execution directory and dump the memory of the ServiceModelReg.exe process. Verify if EDR services were effectively blinded on the host.
```
→ remediation-cleanup

## remediation-cleanup
<!-- Remediation and cleanup -->
```manual target=analyst
Re-image confirmed compromised hosts. Promote the detection of ServiceModelReg.exe running with on_disk=0 to a permanent detection rule.
```
→ end
