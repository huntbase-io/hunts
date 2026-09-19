---
analysis: This hunt goes beyond a simple rule by correlating software inventory (PuTTY
  0.83), file-system prevalence (rare .lnk files), and multi-stage process execution
  (AppData loader -> RAT/Miner) across three different telemetry surfaces. This allows
  an analyst to weigh the entire infection chain rather than relying on a single,
  potentially noisy indicator.
blind_spots:
- id: incomplete-host-coverage
  question: Which hosts in the environment are not currently enrolled in endpoint
    monitoring?
  requires: Endpoint agents on all domain-joined and roaming assets
  risk: Malware on unmanaged hosts can maintain persistence and perform exfiltration
    without triggering host-based telemetry.
- id: short-lived-processes
  question: Did the loader terminate immediately after spawning its persistent children?
  requires: Process execution stream telemetry (Sysmon or EDR-like logging)
  risk: A snapshot-based surface may miss the 'Build.exe' execution if it terminates
    before the next collection interval.
  stage: initial-execution-unpacking
coverage:
- stage: initial-execution-unpacking
  status: covered
  steps:
  - identify-putty-marker
  - appdata-binary-execution
- stage: persistence-startup-link
  status: covered
  steps:
  - rare-startup-shortcuts
- stage: secondary-malware-deployment
  status: covered
  steps:
  - impact-payload-execution
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: blockchain-c2-polling
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: github-payload-download
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: telegram-recon-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Aeternum's use of blockchain for C2 makes traditional network-based
    detection highly difficult. However, its endpoint persistence and payload deployment
    follow observable patterns (Startup shortcuts, AppData execution) that are resilient
    to C2 rotation and provide a reliable hunting target.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed Aeternum loader binaries that persist via Startup
  shortcuts and execute from user profile paths to drop secondary payloads such as
  miners or RATs.
labels:
- hunt
- attack.t1027.002
- attack.t1140
- attack.t1547.001
- attack.t1496
- attack.t1489
name: Aeternum Endpoint Execution and Persistence
parameters:
  aeternum_binaries:
    default:
    - build.exe
    - wmiframework.exe
    - zrvesjqwq.exe
    - staaaaas.exe
    - xbinderoutput_protected.exe
    description: Binary names associated with Aeternum execution and supporting frameworks.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-analysis
    type: list[string]
  aeternum_hashes:
    default:
    - 5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898
    - f2a326cff405299e4ebdfaac955c52fc7e496544eaa0921ecad4816cb3ae3a27
    description: SHA256 hashes for the Aeternum loader and secondary payloads named
      in the research.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-analysis
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt, derived from the scoping
      step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scoping begins by identifying hosts with PuTTY 0.83, a specific version
  used as an Aeternum marker during its testing and payload delivery phases. The hunt
  then narrows to hosts showing rare .lnk creations in startup folders and execution
  from AppData\Local. Analysts should use the results of the software inventory scoping
  to populate the 'scope_hosts' parameter for deeper behavioral inspection.
references:
- name: "Unit 42 \u2014 The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based\
    \ C2 Operations and Communications"
  url: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
related:
- hunt: aeternum-blockchain-c2-polling
  reason: The second hunt in the series focuses on the network layer, specifically
    the JSON-RPC requests to Polygon blockchain endpoints used by the loader.
  relation: follows
scenario:
  stages:
  - name: Self-Unpacking and Core Execution
    observables:
    - Build.exe
    - wmiframework.exe
    - ZrvEsJQzWQ.exe
    - STAAAAAS.exe
    slug: initial-execution-unpacking
    tactic: execution
    techniques:
    - T1027.002
    - T1140
  - name: Persistence via Startup Shortcut
    observables:
    - AppData\Local
    - Wmi_Framework_APIKEY_wmsnet_*.lnk
    - Startup directory
    slug: persistence-startup-link
    tactic: persistence
    techniques:
    - T1547.001
  - name: Blockchain-Based C2 Retrieval
    observables:
    - polygon-mumbai-bor-rpc.publicnode.com
    - '0xb68d1809'
    - JSON-RPC over HTTP POST
    slug: blockchain-c2-polling
    tactic: command-and-control
    techniques:
    - T1102
  - name: Payload Retrieval from GitHub
    observables:
    - github.com
    - DotNetZip.dll
    - putty.exe
    slug: github-payload-download
    tactic: command-and-control
    techniques:
    - T1105
  - name: Reconnaissance and Telegram Exfiltration
    observables:
    - api.telegram.org
    - screenshot.png
    - SystemInfo Bot/2.0
    - 'chat_id: -4991861036'
    - /sendDocument
    slug: telegram-recon-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1102.002
    - T1082
  - name: Deployment of Secondary Payloads
    observables:
    - XBinderOutput_protected.exe
    - XWorm
    - XMRig
    slug: secondary-malware-deployment
    tactic: impact
    techniques:
    - T1496
    - T1489
  summary: Aeternum is a C++ botnet loader that uses the Polygon blockchain for decentralized
    command-and-control, retrieving encrypted instructions via smart contracts. The
    malware establishes persistence through startup shortcuts, downloads secondary
    payloads from GitHub, and exfiltrates system metadata and screenshots using the
    Telegram API.
series:
  index: 1
  slug: the-permanent-threat-analyzing-aeternum-s-blockchain-based-c2-operations-and-communications
  title: "The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based C2 Operations\
    \ and Communications"
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


# Aeternum Endpoint Execution and Persistence

This hunt focuses on the endpoint footprint of the Aeternum botnet, specifically its use of self-unpacking binaries and persistence via Windows Startup shortcuts. The hunt identifies hosts with PuTTY 0.83—the clean marker for Aeternum testing—then searches for rare .lnk files and binaries running from user profile paths. This approach detects the malware's local residency independently of its decentralized blockchain-based C2 infrastructure, allowing teams to identify compromised hosts that have successfully fetched secondary payloads like XMRig or XWorm.

## identify-putty-marker
<!-- Scope hosts with PuTTY 0.83 -->
Identify hosts running the specific PuTTY version used as a downloader marker in Aeternum campaigns to narrow the search space.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that have the specific software version cited in the report.
  The analyst should use these hostnames to populate the 'scope_hosts' parameter for
  subsequent steps.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%putty%' AND package_version = '0.83'
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → rare-startup-shortcuts
- → appdata-binary-execution
- → impact-payload-execution
join: → triage-agent

## rare-startup-shortcuts
<!-- Rare LNK creation in Startup directory -->
Find rare persistence shortcuts created in the Startup folder, identifying the acting process and looking for Aeternum's naming convention.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A .lnk file with a name like Wmi_Framework_*.lnk seen on very few hosts.
  The 'process_name' identifies the loader responsible for the shortcut.
prevalence:
  by: device_hostname
  key:
  - file_name
  - process_name
  rare_below: 3
reads:
- file_name
- process_name
- file_path
- device_hostname
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT file_name, process_name, device_hostname, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%\start menu\programs\startup\%' AND LOWER(file_name) LIKE '%.lnk') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, process_name HAVING hosts <= 2 ORDER BY hosts ASC
```

## appdata-binary-execution
<!-- Aeternum execution from Local AppData -->
Detect Aeternum binaries or UPX-packed loaders executing from user-writable profile directories, which is a key behavioral marker for this loader.

```sqlite target=endpoint role=detection-candidate params=(aeternum_binaries=aeternum_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Execution of a report-named binary from the AppData directory. High-fidelity
  indicator of the loader's local residency.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\local\%' AND (instr(',' || '{{aeternum_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE 'wmi_%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## impact-payload-execution
<!-- Secondary payload arrival (RAT/Miners) -->
Identify follow-on impact binaries like XMRig or XWorm correlated by hash or name, confirming the successful exploitation chain.

```sqlite target=endpoint role=enrichment params=(aeternum_hashes=aeternum_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Presence of cryptocurrency miners or RATs on the same hosts that showed
  Aeternum loader activity, completing the hypothesis.
reads:
- device_hostname
- process_name
- process_path
- process_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_hash_sha256, time FROM hb_process_activity WHERE (instr(',' || '{{aeternum_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR LOWER(process_name) IN ('xmrig.exe', 'xworm.exe')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage Aeternum infection chain -->
```agent target=hunter
cite: required
context:
- identify-putty-marker
- rare-startup-shortcuts
- appdata-binary-execution
- impact-payload-execution
max_iterations: 4
objective: Determine if any host shows execution of named Aeternum binaries from AppData
  in conjunction with Startup shortcut persistence or the presence of secondary RAT/Miner
  payloads.
success_criteria: A verdict citing specific process paths, .lnk filenames, and corroborating
  hashes for each host.
tools:
- endpoint
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on the persistence and execution markers" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-host-coverage)
else: → close-out

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate identified malicious processes (Build.exe, XMRig, etc.), and delete the Startup folder .lnk persistence files.
```
→ analyst-review

## analyst-review
<!-- Analyst review and tuning -->
```manual target=analyst
Verify the cited activity chain. If confirmed, promote the AppData binary execution query to a permanent detection rule. Document any new hashes or C2 endpoints observed during IR.
```
→ close-out

## close-out
<!-- Close hunt -->
```manual target=analyst
Log results and schedule a re-run of this hunt in 30 days to ensure no remnants persist.
```
→ end
