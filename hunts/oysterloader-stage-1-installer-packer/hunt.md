---
analysis: A standard detection rule might fire on a rare 'putty.exe' hash, but this
  hunt pivots to the 'hammering' behavior (excessive module loads) to differentiate
  between a simple old version of PuTTY and a malicious packer designed to evade sandboxes.
  It baseline rarity against the fleet and corroborates with the file delivery path.
blind_spots:
- id: module-telemetry-gap
  question: Can we see every LdrLoadDll call if the packer loads and unloads modules
    quickly?
  requires: hb_module_activity with high frequency polling or event-based load reporting
  risk: If the agent only snapshots modules periodically, the 'hammering' behavior
    (brief load-and-discard) may be missed.
  stage: textshell-packer-obfuscation
- id: signed-installer-trust
  question: Was the MSI signed with a stolen but 'valid' certificate?
  requires: hb_file_activity with signature verification results
  risk: Legitimate-looking signatures can cause analysts to deprioritize these hits
    during triage.
  stage: initial-access-trojanized-installer
coverage:
- stage: initial-access-trojanized-installer
  status: covered
  steps:
  - affected-software-scope
  - rare-installer-prevalence
  - user-path-msi-activity
- stage: textshell-packer-obfuscation
  status: covered
  steps:
  - api-hammering-behavior
- reason: This stage is covered in the next hunt of the series (Stage 2).
  stage: in-memory-lzma-decompression
  status: out_of_scope
- reason: This stage is covered in the final hunt of the series (Stage 3/4).
  stage: downloader-c2-beaconing
  status: out_of_scope
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: final-payload-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: OysterLoader is an active multi-stage loader leading to ransomware
    (Rhysida) and high-impact stealers (Vidar). Its first stage relies on 'API hammering'
    to defeat automated sandboxes; a targeted hunt is required because standard rules
    often exclude these noisy GDI/DLL loads to avoid false positives.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are delivering trojanized installers for common IT utilities
  that execute the TextShell packer, which uses extreme API hammering (redundant DLL
  loads) and rare hashes to evade standard detection.
labels:
- hunt
- attack.t1204.002
- attack.t1027
- attack.t1497.003
- attack.t1140
name: 'OysterLoader Stage 1: Installer Execution and Packer Hammering'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for process and module activity.
    type: number
  target_software:
    default:
    - putty
    - winscp
    - google authenticator
    - googleauthenticator
    description: Software names often impersonated by OysterLoader installers.
    from:
      kind: article
      observed: '2024-06-01'
      ref: sekoia-oysterloader
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints where IT administrators or developers operate, as they
  are the primary targets for trojanized PuTTY/WinSCP installers.
references:
- name: 'OysterLoader unmasked: the multi-stage evasion loader'
  url: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
related:
- hunt: oysterloader-stage-2-memory-shellcode
  reason: This hunt detects the packer execution; the next hunt focuses on the LZMA
    decompression and in-memory shellcode (Stage 2).
  relation: follows
scenario:
  stages:
  - name: Trojanized MSI Installer
    observables:
    - MSI files impersonating PuTTy, WinSCP, Google Authenticator
    - Fake software download websites
    - Digitally signed MSI files to appear benign
    slug: initial-access-trojanized-installer
    tactic: initial-access
    techniques:
    - T1204.002
  - name: TextShell Packer Execution
    observables:
    - API hammering using irrelevant GDI calls (RevokeDragDrop, GetDC, CreateSolidBrush,
      SetMapMode)
    - IsDebuggerPresent() check leading to infinite loop 'while(1);'
    - 'Custom hashing formula for API resolution: h = (h * 0x2001 + ord(ch))'
    - Allocation of RWX memory using NtAllocateVirtualMemory
    - Data copied in 8-byte chunks to allocated memory
    slug: textshell-packer-obfuscation
    tactic: defense-evasion
    techniques:
    - T1027
    - T1497.003
    - T1140
  - name: Shellcode LZMA Decompression
    observables:
    - Custom LZMA range decoder with parameters lc=3, lp=0, pb=2
    - Relocation fixups for relative CALL (E8) and JMP (E9) opcodes
    - VirtualProtect calls to change memory regions to executable
    - Process injection behavior (on_disk = false)
    slug: in-memory-lzma-decompression
    tactic: defense-evasion
    techniques:
    - T1055
    - T1140
  - name: Downloader Intermediate Stage
    observables:
    - HTTP communication to retrieve OysterLoader core
    - Environment verification (language check, keyboard layout identification)
    - Dynamic loading of InternetOpenW
    - Custom hashing for server communication parameters
    slug: downloader-c2-beaconing
    tactic: command-and-control
    techniques:
    - T1105
    - T1090.003
  - name: Payload Deployment (Vidar/Rhysida)
    observables:
    - Deployment of Vidar infostealer for credential theft
    - Execution of Rhysida ransomware for file encryption
    - Credential harvesting from password stores
    slug: final-payload-deployment
    tactic: impact
    techniques:
    - T1486
    - T1555
  summary: OysterLoader (Broomstick) is a multi-stage C++ loader distributed via trojanized
    installers for software like PuTTy and WinSCP. It utilizes the TextShell packer,
    custom LZMA decompression, and in-memory shellcode to eventually deliver Rhysida
    ransomware or Vidar infostealers.
series:
  index: 1
  slug: oysterloader-unmasked-the-multi-stage-evasion-loader
  title: 'OysterLoader unmasked: the multi-stage evasion loader'
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


# OysterLoader Stage 1: Installer Execution and Packer Hammering

This hunt focuses on the first stage of OysterLoader (aka CleanUp/Broomstick). It targets the initial execution of trojanized MSI installers for tools like PuTTY, WinSCP, and Google Authenticator. The hunt specifically identifies the 'TextShell' packer's signature behavior: 'API hammering,' where it performs hundreds of redundant calls to legitimate Windows GDI and System DLLs to overwhelm heuristic engines and sandboxes. By combining software inventory scoping with prevalence analysis and module-load counts, we can isolate these malicious loaders from legitimate administrative activity.

## affected-software-scope
<!-- Identify hosts with targeted software -->
Identify hosts that have the targeted software installed, narrowing the hunt to potential beachheads.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with matching software. This provides the 'inventory' context;
  existence alone is not malicious, but serves as the starting scope.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%putty%' OR LOWER(package_name) LIKE '%winscp%' OR LOWER(package_name) LIKE '%authenticator%')
```

## identify-malicious-patterns
<!-- Analyze behavior and prevalence -->
parallel:
- → api-hammering-behavior
- → rare-installer-prevalence
- → user-path-msi-activity
join: → triage-packer-execution

## api-hammering-behavior
<!-- Detect API Hammering (Excessive Module Loads) -->
Find processes that load an unusually high number of distinct DLLs, a proxy for the 'hundreds of calls to legitimate DLLs' used by the TextShell packer.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process loading 60+ unique DLLs. Legitimate utilities like PuTTY usually
  load far fewer. High module counts in a short window indicate the packer's obfuscation
  attempt.
reads:
- device_hostname
- process_name
- pid
- module_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, pid, COUNT(DISTINCT module_name) as distinct_modules, MIN(time) as first_load, MAX(time) as last_load FROM hb_module_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, pid HAVING distinct_modules > 60 ORDER BY distinct_modules DESC
```

## rare-installer-prevalence
<!-- Rare software hashes for targeted products -->
Identify targeted software (PuTTY, WinSCP) with hashes that are rare across the fleet, suggesting trojanized versions.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A hash for 'putty.exe' or 'winscp.exe' seen on only one or two hosts. Standard
  enterprise software is usually consistent across the fleet; deviations suggest an
  ad-hoc download of a trojanized installer.
prevalence:
  by: device_hostname
  key:
  - process_hash_sha256
  rare_below: 3
reads:
- process_hash_sha256
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_hash_sha256, process_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%putty%' OR LOWER(process_name) LIKE '%winscp%' OR LOWER(process_name) LIKE '%authenticator%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING host_count <= 2
```

## user-path-msi-activity
<!-- MSI activity in user-writable paths -->
Find MSI or executable creation in user profiles, which is typical for browser-based delivery of trojanized installers.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Installers landing in temporary or download folders. While common, when
  correlated with high module loads and rare hashes, it confirms the 'trojanized installer'
  delivery stage.
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\downloads\%' OR LOWER(file_path) LIKE '%\appdata\local\temp\%') AND (LOWER(file_name) LIKE '%.msi' OR LOWER(file_name) LIKE '%.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-packer-execution
<!-- Triage TextShell execution -->
```agent target=hunter
cite: required
context:
- affected-software-scope
- api-hammering-behavior
- rare-installer-prevalence
- user-path-msi-activity
max_iterations: 4
objective: Decide if the combination of a rare installer hash, land in a user-writable
  path, and excessive DLL loading (60+) indicates a malicious packer.
success_criteria: A verdict of malicious or suspicious per host, citing specific PIDs
  and hashes.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for one or more hosts." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: module-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Host and Collect Artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Collect the rare binary hash identified in triage for sandbox analysis. Check for persistence in the next hunt.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the distinct module load counts and installer path. If malicious, escalate to the 'OysterLoader Stage 2' hunt to look for in-memory shellcode.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the lookback window and targeted software names that returned zero suspicious hits.
```
→ end
