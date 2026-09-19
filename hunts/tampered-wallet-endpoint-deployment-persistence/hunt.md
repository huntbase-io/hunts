---
analysis: A single detection rule on 'msiexec /quiet' is too noisy for most environments.
  This hunt combines software inventory metadata anomalies (fake 'Apple' manufacturer),
  file path fingerprints from ZIP staging, and a fleet-wide baseline of headless window
  usage to identify the specific RAT tradecraft described in the research.
blind_spots:
- id: missing-endpoint-telemetry
  question: whether the installer ran on hosts not enrolled in telemetry
  requires: endpoint agent reporting on every host
  risk: Invisible persistence on unmanaged endpoints.
- id: reparenting-context
  question: whether Exodus.exe was reparented to explorer.exe to evade process tree
    detections
  requires: hb_process_activity with parent PID history
  risk: Malicious processes appearing as legitimate user-launched applications, bypassing
    'msiexec -> exodus' detections.
  stage: evasion-process-reparenting
- id: script-content-visibility
  question: what the specific JavaScript logic in the .js dropper was doing
  requires: hb_script_activity with content capture
  risk: Relying on file paths only; missing the actual behavior of the JS dropper
    before the MSI is called.
  stage: initial-access-script-dropper
coverage:
- stage: initial-access-script-dropper
  status: covered
  steps:
  - temp-and-install-artifacts
- stage: execution-silent-msi-install
  status: covered
  steps:
  - silent-msi-install-leads
- stage: persistence-hidden-wallet-install
  status: covered
  steps:
  - scheduled-task-persistence
  - temp-and-install-artifacts
- stage: evasion-process-reparenting
  status: covered
  steps:
  - headless-conhost-usage
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: c2-legitimate-domain-masking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt identifies a sophisticated modular RAT that uses legitimate
    crypto-wallet code to mask its presence. Given the silent installation and UI
    suppression, standard detection rules for suspicious processes may miss it; finding
    the 'INetHealth' task or rare '--headless' conhost patterns is the most reliable
    way to uncover the persistence mechanism.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed a tampered cryptocurrency wallet using a double-extension
  JS dropper or ZIP-staged file, then used a silent MSI installation and a hidden
  scheduled task to maintain a persistent, UI-less backdoor.
labels:
- hunt
- attack.t1566.001
- attack.t1036.007
- attack.t1218.007
- attack.t1547.001
- attack.t1053.005
- attack.t1134.004
- attack.t1562.001
name: Tampered Wallet Endpoint Deployment and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress
    type: number
  scope_hosts:
    default: []
    description: Limit the search to these hostnames; leave empty for whole estate.
    type: list[host]
  target_version:
    default: 24.33.4
    description: Legitimate version of Exodus targeted for tampering.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on standard user endpoints and servers where users may manage digital
  assets. The installer does not require admin privileges, so the search must cover
  user-writable paths like %TEMP% and %APPDATA%.
references:
- name: "Huntress \u2014 The Crypto Wallet That Never Opened"
  url: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
related:
- hunt: c2-legitimate-domain-masking
  reason: This hunt focuses on endpoint infection and persistence; the network-level
    behavior of masking C2 traffic behind legitimate Exodus domains is handled in
    a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: JavaScript Dropper Delivery
    observables:
    - .pdf.js
    - Update_GS_7G0N-254V38L2350.zip
    - Update_GS_7G0N-254V38L2350.js
    - search-ms:displayname=Search Results
    - \\us05.org@8080\update
    - us05.org
    - 35.212.159.20
    slug: initial-access-script-dropper
    tactic: initial-access
    techniques:
    - T1566.001
    - T1036.007
  - name: Silent MSI Installation
    observables:
    - msiexec /i "%TEMP%\jn0101.msi" /quiet /norestart
    - msiexec /i "%TEMP%\jg0384.msi" /quiet /norestart
    - jn0101.msi
    - jg0384.msi
    slug: execution-silent-msi-install
    tactic: execution
    techniques:
    - T1218.007
  - name: Persistent Invisible Installation
    observables:
    - '%APPDATA%\ExdBackupTool\'
    - Exodus.exe
    - app.asar
    - INetHealth
    - conhost.exe --headless powershell -e
    slug: persistence-hidden-wallet-install
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: UI Suppression and Reparenting
    observables:
    - explorer.exe parent of Exodus.exe
    - BrowserWindow.prototype.show = function () {};
    - app.setPath('userData', ...)
    - conhost.exe --headless
    slug: evasion-process-reparenting
    tactic: defense-evasion
    techniques:
    - T1134.004
    - T1562.001
  - name: Wallet Domain C2
    observables:
    - fiat.a.exodus.io
    - assets-gateway-clarity-api.a.exodus.io
    - 35.212.159.20
    slug: c2-legitimate-domain-masking
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: A campaign using tampered Exodus wallet installers to deliver a modular
    RAT. Victims are lured via JavaScript droppers with double extensions or ZIP archives
    that silently install a real but modified wallet which suppresses its UI to remain
    invisible while mimics legitimate network traffic to steal credentials.
series:
  index: 1
  slug: the-crypto-wallet-that-never-opened-tampered-exodus-installer-hides-a-modular-rat
  title: 'The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular
    RAT'
  total: 2
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


# Tampered Wallet Endpoint Deployment and Persistence

This hunt targets the infection chain of a modular RAT disguised as the Exodus wallet. It begins by scoping hosts with suspicious software metadata ('Background Service' by 'Apple Inc') or specific targeted versions of Exodus. It then pivots to find silent MSI installations executed from user TEMP directories, often followed by the creation of an 'INetHealth' scheduled task that uses the '--headless' conhost wrapper to run concealed PowerShell commands. The hunt also searches for specific file artifacts in user profiles, such as the '.zip.###' fingerprint left by Explorer's temporary extraction process.

## software-inventory-scoping
<!-- Scoping: Tampered software metadata -->
Find hosts where the 'Background Service' (tampered metadata) or targeted Exodus version is installed.

```sqlite target=endpoint role=scoping params=(target_version=target_version)
~~~yaml
expected: Hosts with software named 'Background Service' published by 'Apple Inc'
  (high-confidence anomaly) or the specific 24.33.4 version of Exodus.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (LOWER(package_name) = 'background service' AND LOWER(vendor_name) LIKE '%apple%') OR (LOWER(package_name) LIKE '%exodus%' AND package_version = '{{target_version}}')
```

## silent-msi-install-leads
<!-- Silent MSI execution from Temp -->
Identify potential dropper activity where msiexec installs packages from the user's temporary folder without UI interaction.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes invoking msiexec to install an MSI from a temp path quietly. High
  confidence if the filename matches a random 2-letter, 4-digit pattern (e.g. jn0101.msi).
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%msiexec.exe' AND (LOWER(process_cmd_line) LIKE '%/i%' AND (LOWER(process_cmd_line) LIKE '%/quiet%' OR LOWER(process_cmd_line) LIKE '%/qn%')) AND (LOWER(process_cmd_line) LIKE '%\temp\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Gather supporting evidence -->
parallel:
- → scheduled-task-persistence
- → headless-conhost-usage
- → temp-and-install-artifacts
join: → triage-agent

## scheduled-task-persistence
<!-- Task persistence and headless execution -->
Locate the 'INetHealth' persistence mechanism or other tasks using headless windows to hide script execution.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A scheduled job named 'INetHealth' or a job that executes conhost with the
  --headless flag. Silence suggests these specific indicators are absent.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'inethealth' OR (LOWER(job_cmd_line) LIKE '%conhost%' AND LOWER(job_cmd_line) LIKE '%--headless%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## headless-conhost-usage
<!-- Baseline of headless windows -->
Stack-count the usage of conhost --headless to find rare, suspicious commands potentially wrapping malware.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Commands using --headless seen on very few hosts. Legitimate developer tools
  will stack out; unique malicious scripts will stand out.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%--headless%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 3 ORDER BY hosts, runs
```

## temp-and-install-artifacts
<!-- Dropper and installation artifacts -->
Search for residual MSI files in TEMP, the ExdBackupTool installation path, or Explorer-staged ZIP fingerprints.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File touches in the specific APPDATA path or .zip.### temporary folders,
  confirming a user opened a ZIP dropper directly.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\temp\%.msi' OR LOWER(file_path) LIKE '%\exdbackuptool\%' OR (LOWER(file_path) LIKE '%.zip.%\%.js')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage the infection chain -->
```agent target=hunter
cite: required
context:
- software-inventory-scoping
- silent-msi-install-leads
- scheduled-task-persistence
- headless-conhost-usage
- temp-and-install-artifacts
max_iterations: 4
objective: 'Determine if the evidence supports a full infection chain: from a JS dropper
  (or ZIP staging) to a silent MSI install, ending in an INetHealth task or headless
  conhost execution.'
success_criteria: A per-host verdict of malicious, suspicious, or benign with citations
  of the specific MSI files or task names found.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on the correlation of silent MSI installs and INetHealth tasks" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Collect the MSI from %TEMP% and the app.asar file from %APPDATA%\ExdBackupTool\ for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited evidence. Pay close attention to the '.zip.###' path fragments in file activity to confirm if the dropper was opened directly from a ZIP file. Verify if the 'Exodus.exe' process is reparented to explorer.exe.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the examined hosts and findings. If the 'Background Service' metadata or 'INetHealth' task were confirmed, consider promoting these queries to permanent detection rules.
```
→ end
