---
analysis: A standard detection rule for mshta.exe or Run keys lacks the context to
  connect them to the 70+ registry modules or the ADS-hidden worm. This phased hunt
  correlates initial vulnerability status with high-volume modular writes and propagation
  indicators across the entire infection lifecycle.
blind_spots:
- id: no-endpoint-telemetry
  question: Which unmanaged hosts are vulnerable to CVE-2025-8088?
  requires: endpoint agent coverage
  risk: An unmanaged vulnerable host can act as a silent staging platform or propagation
    source.
- id: encryption-hides-payload
  question: What is the content and functionality of the individual PowerShell modules?
  requires: forensic DPAPI key extraction
  risk: While we can detect the existence of modules via registry write volume, their
    encrypted nature hides their specific functional logic from static analysis.
  stage: gammasteel-powershell-exfiltration
- id: ads-visibility
  question: Are NTFS Alternate Data Streams visible in the file sensor telemetry?
  requires: hb_file_activity that resolves NTFS streams
  risk: If the file sensor ignores or truncates stream identifiers, GammaWorm persistence
    will remain invisible to behavioral queries.
  stage: gammaworm-propagation-persistence
coverage:
- stage: gammaphish-initial-access-exploit
  status: covered
  steps:
  - vulnerable-winrar-hosts
  - mshta-startup-or-remote
- stage: gammaload-vbscript-staging
  status: covered
  steps:
  - gammaload-registry-run
- stage: gammaworm-propagation-persistence
  status: covered
  steps:
  - gammaworm-ads-lnk
- stage: gammasteel-powershell-exfiltration
  status: covered
  steps:
  - gammasteel-registry-blobs
  - intrusion-chain-agent
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Gamaredon is a high-tempo, FSB-linked actor targeting government
    infrastructure. Their modular approach using registry-resident payloads and ADS-hidden
    worms requires a multi-surface hunt to bypass standard detection layers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited a Windows WinRAR path traversal vulnerability
  to execute HTA-based loaders, subsequently deploying VBScript stagers, an ADS-resident
  worm, and a modular PowerShell stealer persisting in the registry.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1218.005
- attack.t1059.001
- attack.t1071
- attack.t1053.005
- attack.t1041
- attack.t1555
name: Gamaredon Modular Espionage Chain
parameters:
  cve_id:
    default: CVE-2025-8088
    description: WinRAR vulnerability used in the initial GammaPhish stage.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia_gamaredon_2026
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: default_retention
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hostnames; leave empty for fleet-wide
      analysis.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: analyst_input
    type: list[host]
  startup_path_pattern:
    default: '%\Microsoft\Windows\Start Menu\Programs\Startup\%'
    description: Standard startup folder path for HTA extraction.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: standard_windows_path
    type: path
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/fsbs-matryoshka-1-3-gamaredons-gifts-that-keeps-unpacking-gammaphish-and-gammaworm
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope the hunt to all Windows endpoints, prioritizing those with vulnerable
  versions of WinRAR as identified in hb_software_inventory.
references:
- name: "Sekoia \u2014 FSB\u2019s matryoshka #1/3: Inside Gamaredon Cyber Operations"
  url: https://www.sekoia.com/blog/fsbs-matryoshka-1-3-gamaredons-gifts-that-keeps-unpacking-gammaphish-and-gammaworm
related:
- hunt: gammawiper-behavioral-hunt
  reason: GammaWipe is a destructive component often used against researchers; this
    hunt focuses on the espionage and exfiltration chain.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: GammaPhish Initial Access via WinRAR Exploit
    observables:
    - Weaponised xHTML files
    - Malicious RAR archives
    - CVE-2025-8088 exploitation
    - HTA files extracted to \Microsoft\Windows\Start Menu\Programs\Startup
    - mshta.exe execution calling remote staging URLs
    slug: gammaphish-initial-access-exploit
    tactic: initial-access
    techniques:
    - T1190
    - T1566
    - T1218.005
  - name: GammaLoad VBScript Staging
    observables:
    - Cascade of VBScript loaders
    - Host fingerprinting via script
    - Dead Drop Resolvers (DDR) stored in Windows registry
    - HTTP requests for additional VBScript payloads
    slug: gammaload-vbscript-staging
    tactic: execution
    techniques:
    - T1059.001
    - T1071
  - name: GammaWorm Propagation and Persistence
    observables:
    - Obfuscated VBScript worm (LitterDrifter)
    - Malicious code hidden in NTFS Alternate Data Streams (ADS)
    - Scheduled tasks for persistence
    - Creation of LNK shortcut files on USB and network drives
    - Hiding of legitimate directories on removable media
    slug: gammaworm-propagation-persistence
    tactic: persistence
    techniques:
    - T1053.005
    - T1059.001
  - name: GammaSteel PowerShell Exfiltration
    observables:
    - Modular PowerShell stealer
    - 71 distinct modules stored as encrypted registry values
    - Encryption using Windows Data Protection API (DPAPI)
    - Real-time monitoring of local/network file modifications
    - Exfiltration to S3-compatible cloud storage
    - Fallback C2 communication for remote code execution
    slug: gammasteel-powershell-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1555
    - T1059.001
  summary: Gamaredon (FSB) 2026 espionage campaign targeting Ukrainian entities through
    a modular infection chain including GammaPhish initial access, GammaLoad staging,
    GammaWorm propagation, and GammaSteel exfiltration. The campaign leverages a critical
    WinRAR vulnerability (CVE-2025-8088) to drop payloads that persist via registry
    keys, NTFS Alternate Data Streams, and scheduled tasks.
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


# Gamaredon Modular Espionage Chain

This hunt reconstructs the multi-stage Gamaredon (UAC-0010) Matryoshka infection chain. It begins by identifying vulnerable WinRAR instances (CVE-2025-8088) and subsequent mshta.exe execution. It then pivots to find GammaLoad VBScript persistence and GammaWorm propagation via Alternate Data Streams and LNK files. Finally, the hunt identifies GammaSteel exfiltration modules by detecting high-volume encrypted registry values, which the group uses to maintain stealth and persistence across Ukrainian targets.

## vulnerable-winrar-hosts
<!-- Inventory vulnerable WinRAR instances -->
Identify hosts in the estate that are vulnerable to the WinRAR path traversal vulnerability CVE-2025-8088, establishing the initial scope.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: A list of host UIDs and resource identifiers reporting the WinRAR vulnerability.
  Silence proves the vulnerability is not currently present in the scanned inventory.
reads:
- affected_package_version
- cve_uid
- device_uid
- resource_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, resource_uid, affected_package_version, severity FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status != 'suppressed'
```

## early-stage-parallel
<!-- Parallel initial access investigation -->
parallel:
- → mshta-startup-or-remote
- → gammaload-registry-run
join: → early-stage-triage

## mshta-startup-or-remote
<!-- GammaPhish MSHTA staging -->
Identify mshta.exe executing payloads from remote URLs or the Startup directory, typical of GammaPhish staging.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, startup_path_pattern=startup_path_pattern, scope_hosts=scope_hosts)
~~~yaml
expected: Process events showing mshta.exe reaching out to staging URLs or running
  an HTA from a user startup path.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\mshta.exe' OR LOWER(process_name) = 'mshta.exe') AND (LOWER(process_cmd_line) LIKE '%http%' OR LOWER(process_cmd_line) LIKE LOWER('{{startup_path_pattern}}')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gammaload-registry-run
<!-- GammaLoad VBScript persistence -->
Search for VBScript loaders established in standard registry Run/RunOnce keys, indicating GammaLoad persistence.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry values pointing to VBScript files in autorun locations. Silence
  means no such persistence is present in the telemetry.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\\currentversion\\run%' OR LOWER(reg_target) LIKE '%\\currentversion\\runonce%') AND (LOWER(reg_value_data) LIKE '%.vbs%' OR LOWER(reg_value_data) LIKE '%wscript%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early infection stages -->
```agent target=hunter
cite: required
context:
- vulnerable-winrar-hosts
- mshta-startup-or-remote
- gammaload-registry-run
max_iterations: 4
objective: Identify if vulnerable WinRAR hosts show signs of successful HTA staging
  or VBScript loader execution.
success_criteria: A verdict for each host citing evidence of early-stage infection.
tools:
- endpoint
```

## follow-on-parallel
<!-- Investigate follow-on propagation and exfiltration -->
parallel:
- → gammaworm-ads-lnk
- → gammasteel-registry-blobs
join: → intrusion-chain-agent

## gammaworm-ads-lnk
<!-- GammaWorm ADS and LNK creation -->
Detect GammaWorm (LitterDrifter) activity by identifying the creation of Alternate Data Streams and suspicious LNK shortcut files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File paths containing colons past the drive letter (ADS) or a volume of
  new LNK files. Silence indicates no such visible propagation.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (instr(substr(file_path, 4), ':') > 0 OR LOWER(file_name) LIKE '%.lnk') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gammasteel-registry-blobs
<!-- GammaSteel modular registry storage -->
Identify GammaSteel's modular footprint by counting high volumes of values written to a single registry key path, indicative of the 70+ encrypted modules.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A registry key on a host containing more than 50 values (Gamaredon uses
  ~71). This stack-count highlights modular deployment.
prevalence:
  by: device_hostname
  key:
  - reg_key_path
  rare_below: 3
reads:
- device_hostname
- reg_key_path
- state_kind
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, reg_key_path, COUNT(*) AS module_count, MIN(time) AS first_write FROM hb_registry_activity WHERE state_kind = 'log' AND (LOWER(reg_key_path) LIKE '%software\\microsoft\\%' OR LOWER(reg_key_path) LIKE '%software\\classes\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, reg_key_path HAVING module_count > 50
```

## intrusion-chain-agent
<!-- Unified Matryoshka chain assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- gammaworm-ads-lnk
- gammasteel-registry-blobs
max_iterations: 5
objective: Determine if the evidence supports a full-chain Gamaredon compromise, building
  on the early-stage triage.
success_criteria: A detailed verdict citing the transition from initial access to
  modular stealer deployment.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on chain verdict -->
if~: "the intrusion-chain-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-endpoint-telemetry)
else: → manual-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to prevent data exfiltration and further worm propagation.
```
→ manual-review

## manual-review
<!-- Forensic review and module recovery -->
```manual target=analyst
Collect the registry hives from identified hosts to extract GammaSteel modules. Verify the content of Alternate Data Streams on the filesystem to confirm worm persistence. Review USB insertion history for possible propagation events.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Summarize the findings per host. If the high-volume registry module query provided high-fidelity results, recommend promoting it to a permanent detection rule for modular malware storage.
```
→ end
