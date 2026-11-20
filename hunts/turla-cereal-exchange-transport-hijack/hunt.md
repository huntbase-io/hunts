---
analysis: This is a hunt because standard detection rules often fail to catch .NET
  native image cache abuse or process injection that mimics legitimate Exchange service
  behavior. By stack-counting rare unsigned modules and correlating them with local
  file markers in Exchange paths, an analyst can distinguish an active intrusion from
  legitimate administrator activity that a single rule might miss or alert on excessively.
blind_spots:
- id: module-logging-gaps
  question: whether the unsigned native image loads are observable on all Exchange
    servers
  requires: hb_module_activity with Sysmon 7 or advanced EDR telemetry
  risk: Without comprehensive module load logging, the primary indicator of Turla's
    .NET tradecraft is invisible.
  stage: dotnet-stealth-execution
- id: vtable-fixup-visibility
  question: whether VTable fixups were used to hijack legitimate transport agents
    without loading a new module
  requires: Memory forensics or deep process inspection
  risk: standard endpoint telemetry will not see the hijacking of internal structures,
    only the initial injection of the malicious module.
  stage: mail-pipeline-hijacking
coverage:
- stage: dotnet-stealth-execution
  status: covered
  steps:
  - rare-unsigned-native-images
- stage: offline-command-processing
  status: covered
  steps:
  - cereal-hermit-command-files
- stage: mail-pipeline-hijacking
  status: covered
  steps:
  - edge-transport-hijack
- stage: espionage-data-staging
  status: covered
  steps:
  - staged-espionage-data
- reason: "Belongs to another part of the 'Exchange for breakfast: Turla\u2019s Cereal\
    \ tricks are not for kids' series."
  stage: passive-web-backdoor
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Turla's Cereal toolset targets governmental and sensitive institutional
    email traffic by co-opting the victim's own infrastructure. Identifying these
    stealthy in-memory and file-based techniques is critical for defending against
    long-term, high-impact espionage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using sophisticated .NET tradecraft to hijack an Exchange
  server's mail transport pipeline in memory, using local file markers for command
  processing and staging encrypted archives of collected emails.
labels:
- hunt
- attack.t1041
- attack.t1047
- attack.t1071
- attack.t1574
- collection
- command and control
- execution
- persistence
name: 'Turla Cereal: Exchange Transport Hijack and .NET Stealth'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Specific Exchange servers to target; leave empty to hunt across the
      entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Client Access and Edge Transport roles within the Exchange infrastructure.
  Expand to mailbox servers if data staging is detected.
references:
- name: "ESET Research \u2014 Exchange for breakfast: Turla\u2019s Cereal tricks are\
    \ not for kids"
  url: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
related:
- hunt: turla-cereal-passive-web-backdoor
  reason: This hunt focuses on endpoint hijacking and email collection; the passive
    web backdoor on OWA paths is a distinct network/HTTP investigation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Sophisticated .NET Execution
    observables:
    - unmanaged entry points
    - native image cache abuse
    - nested .NET assemblies
    - suspicious DLLs loaded by legitimate Windows processes
    slug: dotnet-stealth-execution
    tactic: execution
    techniques:
    - T1047
  - name: Passive Web Service Backdoor
    observables:
    - https://*:443/owa/sdds/
    - HTTPS://*:443/AUTODISCOVER/PROXYSERVICE/
    - HTTPS://*:443/MICROSOFT-SERVER-ACTIVESYNC/INTEGRATED/API/
    - CerealNeuron
    slug: passive-web-backdoor
    tactic: command-and-control
    techniques:
    - T1071
    - T1572
  - name: File-based Command Interface
    observables:
    - encrypted command files on disk
    - CerealHermit
    slug: offline-command-processing
    tactic: command-and-control
    techniques:
    - T1071
  - name: Exchange Transport Hijack
    observables:
    - EdgeTransport.exe
    - injection into EdgeTransport.exe
    - memory hijacking of transport agents
    - VTable Fixups
    - CerealBox
    slug: mail-pipeline-hijacking
    tactic: persistence
    techniques:
    - T1574
  - name: Email Collection and Staging
    observables:
    - compressed and encrypted files on disk
    - .doc attachments
    - .docx attachments
    - .pdf attachments
    slug: espionage-data-staging
    tactic: collection
    techniques:
    - T1041
  summary: The Turla-linked Cereal campaign targets government Exchange servers, utilizing
    a modular .NET toolset that operates without external C&C infrastructure by co-opting
    the victim server as a passive listener. The toolset intercepts mail by injecting
    into the EdgeTransport.exe process to hijack transport agents and uses specialized
    .NET tradecraft, such as native image cache abuse, to maintain stealthy execution.
series:
  index: 1
  slug: exchange-for-breakfast-turla-s-cereal-tricks-are-not-for-kids
  title: "Exchange for breakfast: Turla\u2019s Cereal tricks are not for kids"
  total: 2
severity: critical
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


# Turla Cereal: Exchange Transport Hijack and .NET Stealth

This hunt targets the endpoint behavior of Turla's Cereal toolset. It identifies the early indicators of .NET stealth, such as unsigned DLLs loaded from the native image cache, and the presence of encrypted command files used by the CerealHermit variant. It then pivots to look for active exploitation: the injection of malicious modules into EdgeTransport.exe and the creation of encrypted data archives in Exchange installation paths. Because the toolset is designed to run in memory and avoid external C2 beacons by co-opting the Exchange server itself, the hunt focuses on prevalence-based detection of rare module loads and file-based staging patterns that deviate from normal Exchange activity.

## exchange-server-inventory
<!-- Identify potential Exchange servers -->
Scope the hunt to hosts running Microsoft Exchange Server or exhibiting mail transport characteristics.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames belonging to the Exchange infrastructure. Silence means
  no Exchange servers were found in the current inventory.
reads:
- package_name
- vendor_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft exchange server%' OR LOWER(vendor_name) LIKE '%microsoft%exchange%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-stealth
<!-- Hunt for early-stage stealth indicators -->
parallel:
- → rare-unsigned-native-images
- → cereal-hermit-command-files
join: → triage-early-indicators

## rare-unsigned-native-images
<!-- Rare unsigned native images -->
Stack-count unsigned DLLs loaded from the .NET Native Image cache to find rare execution markers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unsigned modules in the native image cache that appear on very few hosts.
  Legitimate Microsoft native images are signed.
prevalence:
  by: device_hostname
  key:
  - module_path
  rare_below: 3
reads:
- module_path
- device_hostname
- module_signed
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT module_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_module_activity WHERE module_signed = 'false' AND (LOWER(module_path) LIKE '%\nativeimages_%' OR LOWER(module_path) LIKE '%\assembly\nativeimages%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY module_path HAVING hosts <= 3
```

## cereal-hermit-command-files
<!-- CerealHermit command and results -->
Find encrypted command and result files on disk used by the offline variant of the Cereal backdoor.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation or modification of data files in Exchange installation directories
  that do not match known log or configuration schemas.
reads:
- device_hostname
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%microsoft\exchange server\v15%' AND (LOWER(file_name) LIKE '%.dat' OR LOWER(file_name) LIKE '%.bin') AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-early-indicators
<!-- Triage early indicators -->
```agent target=hunter
cite: required
context:
- rare-unsigned-native-images
- cereal-hermit-command-files
max_iterations: 3
objective: Determine if any host shows a combination of rare unsigned .NET native
  images and suspicious command file markers in Exchange directories.
success_criteria: A verdict of malicious | suspicious | benign per host based on the
  correlation of module and file events.
tools:
- endpoint
```

## follow-on-hijacking
<!-- Hunt for follow-on hijacking and staging -->
parallel:
- → edge-transport-hijack
- → staged-espionage-data
join: → triage-full-intrusion

## edge-transport-hijack
<!-- EdgeTransport module hijack -->
Identify injection into EdgeTransport.exe, the Exchange service that handles email flow, by finding modules loaded from non-standard paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A module load into the Exchange transport process from an unexpected path
  (e.g., ProgramData or a temp directory), indicating potential injection.
reads:
- device_hostname
- process_name
- module_path
- module_signed
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, process_name, module_path, module_signed, time FROM hb_module_activity WHERE LOWER(process_name) LIKE '%edgetransport.exe%' AND LOWER(module_path) NOT LIKE '%\microsoft\exchange server%' AND LOWER(module_path) NOT LIKE '%\windows\assembly%' AND LOWER(module_path) NOT LIKE '%\windows\microsoft.net%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## staged-espionage-data
<!-- Staged espionage data -->
Look for the compressed and encrypted files that stage collected emails before exfiltration.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of archive files in the Exchange directory, which serves as the
  staging area for Turla's email collection module.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE (LOWER(file_name) LIKE '%.zip' OR LOWER(file_name) LIKE '%.enc' OR LOWER(file_name) LIKE '%.7z') AND LOWER(file_path) LIKE '%microsoft\exchange server\v15%' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-full-intrusion
<!-- Triage full intrusion -->
```agent target=hunter
cite: required
context:
- triage-early-indicators
- edge-transport-hijack
- staged-espionage-data
max_iterations: 5
objective: Confirm if hijacking of EdgeTransport.exe and data staging are present,
  building on the initial stealth indicators.
success_criteria: A final verdict citing both the early-stage stealth indicators and
  the confirmed hijacking evidence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage-full-intrusion verdict is malicious for at least one host, indicating confirmed EdgeTransport hijack or the staging of exfiltration-ready archives." (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-forensics
unavailable: → analyst-forensics (blind_spot: module-logging-gaps)
else: → hunt-close-out

## isolate-server
<!-- Isolate Exchange server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host and initiate memory forensics to identify the in-memory hooking of transport agents.
```
→ analyst-forensics

## analyst-forensics
<!-- Analyst forensics and review -->
```manual target=analyst
Examine the Exchange installation directory for unusual data files. Review the EdgeTransport.exe memory space for injected modules. If archives are found, determine which accounts were targeted for email collection.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Record the results of the hunt. If the EdgeTransport module hijack query was successful, promote it to a standing detection rule.
```
→ end
