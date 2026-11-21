---
analysis: A single rule on certutil or MpCmdRun triggers excessive noise. This hunt
  uses a gated flow to first scope to targeted host software, then correlates the
  lead with fleet-wide binary rarity and specific masquerading (like RuntimeBroker
  in AppData) to confirm the threat.
blind_spots:
- id: missing-process-telemetry
  question: whether MpCmdRun was used to download a file
  requires: hb_process_activity with command-line arguments
  risk: If command-line arguments are not logged, the download behavior of LOLBins
    is indistinguishable from routine execution.
  stage: lolbin-stager-execution
- id: missing-registry-telemetry
  question: whether the MsgEdgeUpdate run key was created
  requires: hb_registry_activity with set-value logging
  risk: Hosts without registry write event logging will hide the creation of persistence
    mechanisms.
  stage: persistence-via-masquerading
- id: msbuild-in-memory-compilation
  question: whether MSBuild compiled and executed C# directly in memory
  requires: AMSI logs or memory scan
  risk: The MSBuild downloader leaves no file on disk, making it invisible to file-based
    scanners and standard process-path monitors.
  stage: lolbin-stager-execution
coverage:
- stage: weaponized-stager-delivery
  status: covered
  steps:
  - scoping-targeted-software
  - lolbin-stager-lead
- stage: lolbin-stager-execution
  status: covered
  steps:
  - lolbin-stager-lead
  - masqueraded-binary-prevalence
- stage: persistence-via-masquerading
  status: covered
  steps:
  - persistence-registry-check
  - masqueraded-binary-prevalence
- reason: 'Belongs to another part of the ''UAT-12643: Suspected North Korea-aligned
    actor blends blockchain resilience with targeted infostealing'' series.'
  stage: collection-and-infostealing
  status: out_of_scope
- reason: 'Belongs to another part of the ''UAT-12643: Suspected North Korea-aligned
    actor blends blockchain resilience with targeted infostealing'' series.'
  stage: c2-and-cloud-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: UAT-12643 utilizes signed binaries to bypass initial application
    allowlisting. A negative result across targeted host profiles confirms the environment
    is currently free of this actor's primary stager tradecraft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using signed Windows binaries to stage payloads on hosts
  running targeted software, establishing persistence through masqueraded Edge updater
  binaries in user-writable paths.
labels:
- hunt
- attack.t1218
- attack.t1218.005
- attack.t1547.001
- attack.t1195.002
- attack.t1204.002
- collection
- command and control
- execution
- initial access
- persistence
name: UAT-12643 Stager Abuse and Registry Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-18'
      ref: hunt-standard
    type: number
  malicious_filenames:
    default:
    - RuntimeBroker.exe
    - s.exe
    - MsgEdgeUpdate.exe
    - Ovl.exe
    - Client.exe
    - Ova.exe
    - microsip-config.exe
    description: Filenames observed in the UAT-12643 staging directory and persistence
      mechanisms.
    from:
      kind: article
      observed: '2024-11-18'
      ref: talos-uat12643
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames identified in the scoping step; leave empty to
      run across the whole estate.
    from:
      kind: manual
      observed: '2024-11-18'
      ref: analyst-entry
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scoping is essential to narrow the lead query to hosts running Viber or
  MicroSIP, as UAT-12643 specifically targets these softphone/messaging environments
  with trojanized installers.
references:
- name: "Cisco Talos \u2014 UAT-12643: Suspected North Korea-aligned actor blends\
    \ blockchain resilience with targeted infostealing"
  url: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
related:
- hunt: collection-and-infostealing
  reason: This hunt focuses on initial access and persistence; the infostealing and
    clipboard hijacking behaviors are handled by a separate behavioral hunt.
  relation: out-of-scope-alternative
- hunt: c2-and-cloud-exfiltration
  reason: Network C2 via Solana transactions and exfiltration to Discord/GoFile is
    handled by a network-heavy companion hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Weaponized Stager Delivery
    observables:
    - LNK files using document icons
    - weaponized HTA files
    - MSBuild XML project files (dl.xml)
    - trojanized Viber or MicroSIP installers
    slug: weaponized-stager-delivery
    tactic: initial-access
    techniques:
    - T1204.002
    - T1195.002
  - name: LOLBin Stager Execution
    observables:
    - MpCmdRun.exe -DownloadFile
    - certutil -urlcache -f
    - mshta.exe executing JavaScript
    - msbuild.exe with C# CodeTaskFactory tasks
    - RuntimeBroker.exe (masquerading downloaded payload)
    - BITS/7.8 User-Agent string
    slug: lolbin-stager-execution
    tactic: execution
    techniques:
    - T1218
    - T1218.005
  - name: Persistence via Masquerading
    observables:
    - '%APPDATA%\MsgEdgeUpdate.exe'
    - Registry Run key 'MsgEdgeUpdate'
    - FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM attributes
    slug: persistence-via-masquerading
    tactic: persistence
    techniques:
    - T1547.001
  - name: Infostealing and Collection
    observables:
    - Good Game Python infostealer
    - clipboard polling loop every 500ms
    - mutex 'UuuRjinBZPBMIjnc'
    - screenshot PNG and webcam PNG in temporary directories
    slug: collection-and-infostealing
    tactic: collection
    techniques:
    - T1115
    - T1555
  - name: C2 and Cloud Exfiltration
    observables:
    - Solana blockchain transaction memo URLs
    - gofile.io
    - upload.gofile.io
    - Discord webhooks
    - 41.216.188.11
    - ports 5173, 5656, 5959
    - ipwhois.app
    - kora.pyc
    - platform.system
    - shutil.copy
    slug: c2-and-cloud-exfiltration
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
    - T1572
  summary: North Korea-aligned actor UAT-12643 targets European finance, crypto, and
    VoIP users using weaponized LNK, HTA, and MSBuild stagers to deliver the Overlord
    RAT and a cryptocurrency clipboard hijacker. The campaign leverages Solana blockchain
    transaction memos for C2 resilience and exfiltrates data to GoFile.io via Discord
    webhooks.
series:
  index: 1
  slug: uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infoste
  title: 'UAT-12643: Suspected North Korea-aligned actor blends blockchain resilience
    with targeted infostealing'
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


# UAT-12643 Stager Abuse and Registry Persistence

This hunt identifies the execution of Living-off-the-Land Binaries used by UAT-12643 to download and stage malware. It begins by scoping hosts with targeted messaging and VoIP software, then lead-queries for certutil, MpCmdRun, and MSBuild abuse. If suspicious stagers are found, the hunt fans out to correlate these with rare binaries in user-profile directories and the specific registry run key 'MsgEdgeUpdate'. An agent synthesizes the staging and persistence evidence to route high-confidence hits to host isolation.

## scoping-targeted-software
<!-- Scope Hosts with Targeted Software -->
Identify hosts running software lures targeted by the actor, such as Viber or MicroSIP.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. These are the primary targets for the behavioral lead
  query.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%viber%' OR LOWER(package_name) LIKE '%microsip%'
```

## lolbin-stager-lead
<!-- LOLBin Downloader Lead Query -->
Detect signed binaries performing remote downloads or executing suspicious scripts as seen in the stager phase.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing LOLBins with suspicious command arguments. Silence suggests
  no active staging using these specific methods.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE ((LOWER(process_name) LIKE '%\\mpcmdrun.exe' AND LOWER(process_cmd_line) LIKE '%-downloadfile%') OR (LOWER(process_name) LIKE '%\\certutil.exe' AND LOWER(process_cmd_line) LIKE '%-urlcache%') OR (LOWER(process_name) LIKE '%\\mshta.exe' AND (LOWER(process_cmd_line) LIKE '%.hta%' OR LOWER(process_cmd_line) LIKE '%javascript:%')) OR (LOWER(process_name) LIKE '%\\msbuild.exe' AND LOWER(process_cmd_line) LIKE '%.xml%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-agent
<!-- Evaluate Stager Lead -->
```agent target=hunter
cite: required
context:
- lolbin-stager-lead
max_iterations: 3
objective: Identify if the LOLBin was used to fetch an executable to a user-writable
  path or executed a script that could serve as a stager.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  command line and host.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Pursue Corroboration? -->
if~: "the lead-agent verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-activity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-telemetry)
else: → close-out

## corroborate-activity
<!-- Corroborate Persistence and Rarity -->
parallel:
- → masqueraded-binary-prevalence
- → persistence-registry-check
join: → final-triage

## masqueraded-binary-prevalence
<!-- Masqueraded Binary Prevalence -->
Identify rare binaries in user-writable paths or those using specific report names like RuntimeBroker.exe or MsgEdgeUpdate.exe.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, malicious_filenames=malicious_filenames)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries in suspicious locations or those exactly matching the actor's
  masquerading names.
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
verified_at: '2026-11-19'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{malicious_filenames}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR (LOWER(process_path) LIKE '%\\appdata\\%' OR LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## persistence-registry-check
<!-- Run Key Persistence Check -->
Verify if the specific 'MsgEdgeUpdate' registry key was used for persistence as reported.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A registry entry for MsgEdgeUpdate pointing at a payload. Silence suggests
  this specific persistence string was not used.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\currentversion\\run\\msgedgeupdate' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final Verdict Synthesis -->
```agent target=hunter
cite: required
context:
- lead-agent
- masqueraded-binary-prevalence
- persistence-registry-check
max_iterations: 6
objective: Determine if the LOLBin activity, the rare binary in AppData, and the MsgEdgeUpdate
  registry key represent a confirmed intrusion.
success_criteria: A malicious verdict for any host showing the full stager-to-persistence
  chain.
tools:
- endpoint
```

## final-decision
<!-- Route Final Response -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-registry-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate the suspicious RuntimeBroker.exe or MsgEdgeUpdate.exe processes in user-writable paths, and delete the MsgEdgeUpdate Run registry key.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the cited rows. Confirm if the rare binary in AppData matches the XOR-encrypted hijacker description and whether it was launched via the identified LOLBin.
```
→ end

## close-out
<!-- Close-out and Documentation -->
```manual target=analyst
Document the hosts scoped and the findings. Note any hosts that were skipped due to lack of process or registry telemetry.
```
→ end
