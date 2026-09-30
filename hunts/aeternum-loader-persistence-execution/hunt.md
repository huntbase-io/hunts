---
analysis: A single detection rule for the shortcut name is fragile as names can change;
  this hunt uses the shortcut as a trigger to then baseline all rare binaries in the
  user's profile and check for a set of related malicious executables. This multi-surface
  correlation confirms an infection that no single signature could definitively prove.
blind_spots:
- id: missing-file-telemetry
  question: whether the shortcut was created on hosts where file event logging is
    limited or disabled
  requires: hb_file_activity with coverage for user profile Startup paths
  risk: The gated hunt may stop at the lead step for an infected host if shortcut
    creation is not captured.
  stage: persistence-via-startup-folder
- id: no-endpoint-coverage
  question: whether the botnet binaries are running on systems without a reporting
    agent
  requires: hb_process_activity from an installed agent
  risk: Persistence might exist, but the hunt will miss the active execution stage
    on unmanaged hosts.
  stage: aeternum-initial-execution
coverage:
- stage: aeternum-initial-execution
  status: covered
  steps:
  - stack-rare-appdata-binaries
- stage: persistence-via-startup-folder
  status: covered
  steps:
  - lead-startup-lnk
- stage: auxiliary-binary-execution
  status: covered
  steps:
  - check-auxiliary-binaries
- reason: Belongs to a network-based sibling hunt for RPC traffic.
  stage: blockchain-c2-communication
  status: out_of_scope
- reason: Belongs to a hunt focusing on GitHub and Telegram API traffic.
  stage: payload-download-and-loading
  status: out_of_scope
- reason: Belongs to a hunt focusing on HTTPS exfiltration patterns.
  stage: data-exfiltration-via-telegram
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Aeternum botnet's decentralized C2 on the Polygon blockchain
    makes network-based detection extremely difficult; hunting for its unique host-side
    persistence and auxiliary process patterns provides a resilient detection path
    for this permanent threat.
  methodology: model-assisted
  trigger: intel-report
hypothesis: The Aeternum loader has established persistence by creating a uniquely
  named LNK file in the user Startup directory and is executing auxiliary binaries
  from the local AppData profile.
labels:
- hunt
- attack.t1204.002
- attack.t1547.001
- attack.t1106
name: Aeternum Loader Persistence and Execution
parameters:
  auxiliary_binaries:
    default:
    - wmiframework.exe
    - zrvesjqzwq.exe
    - staaaaas.exe
    description: Supporting binaries executed by the Aeternum loader.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-c2
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to narrow the search; leave empty to hunt the whole estate.
    type: list[host]
  startup_pattern:
    default: wmi_framework_apikey_wmsnet_%.lnk
    description: SQL LIKE pattern for the Aeternum persistence shortcut name.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum-c2
    type: string
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope to Windows systems. The Aeternum loader specifically targets Windows
  endpoints and utilizes standard user profile paths for its initial footprint.
references:
- name: "Unit 42 \u2014 The Permanent Threat: Analyzing Aeternum\u2019s Blockchain-Based\
    \ C2 Operations and Communications"
  url: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
related:
- hunt: aeternum-blockchain-c2-network
  reason: This hunt focuses on endpoint footprint; network activity to Polygon RPC
    and Telegram APIs requires a separate network-centric hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Aeternum Loader Execution
    observables:
    - Build.exe
    - UPX-packed binary
    slug: aeternum-initial-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Persistence via Startup Folder
    observables:
    - AppData\Local
    - Wmi_Framework_APIKEY_wmsnet_*.lnk
    slug: persistence-via-startup-folder
    tactic: persistence
    techniques:
    - T1547.001
  - name: Auxiliary Binary Execution
    observables:
    - wmiframework.exe
    - ZrvEsJQzWQ.exe
    - STAAAAAS.exe
    slug: auxiliary-binary-execution
    tactic: execution
    techniques:
    - T1106
  - name: Blockchain-based C2 Communication
    observables:
    - polygon-mumbai-bor-rpc.publicnode.com
    - '0xb68d1809'
    - getDomain()
    slug: blockchain-c2-communication
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1071.001
  - name: Payload Download from GitHub
    observables:
    - github.com
    - DotNetZip.dll
    - putty.exe
    slug: payload-download-and-loading
    tactic: command-and-control
    techniques:
    - T1105
  - name: Data Exfiltration via Telegram API
    observables:
    - api.telegram.org
    - SystemInfo Bot/2.0
    - screenshot.png
    - /sendDocument
    slug: data-exfiltration-via-telegram
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1041
  summary: Aeternum is a C++ botnet loader that leverages the Polygon blockchain's
    smart contracts for decentralized command-and-control infrastructure. The loader
    establishes persistence via the Windows Startup folder and retrieves instructions
    through Polygon RPC endpoints before downloading secondary payloads from GitHub
    and exfiltrating system data via the Telegram API.
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Aeternum Loader Persistence and Execution

This hunt identifies the initial host-based footprint of the Aeternum botnet. It begins by scoping to Windows systems and uses a cheap lead query to find uniquely named persistence shortcuts in user Startup folders. If a shortcut is found, the hunt expands to search for specifically named auxiliary binaries and stacks rare executables running from user-writable paths to confirm the infection. The gated flow ensures expensive fleet-wide analysis only occurs when a high-confidence indicator is present.

## scope-windows-hosts
<!-- Scope Windows hosts -->
Identify Windows endpoints where the Aeternum PE loader could execute.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the Windows estate. Silence means no Windows
  software is indexed.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%windows%' OR LOWER(vendor_name) LIKE '%microsoft%'
```

## lead-startup-lnk
<!-- Lead: Startup shortcut creation -->
Find the creation of uniquely named LNK files in user Startup directories used for Aeternum persistence.

```sqlite target=endpoint role=triage params=(startup_pattern=startup_pattern, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows naming the Aeternum shortcut and the host. Silence means the specific
  persistence mechanism was not observed.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) LIKE '{{startup_pattern}}' AND (LOWER(file_path) LIKE '%\\startup\\%' OR LOWER(file_path) LIKE '%\\start menu\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-startup-lead
<!-- Evaluate startup lead -->
```agent target=hunter
cite: required
context:
- lead-startup-lnk
max_iterations: 3
objective: Decide if the file name and path in lead-startup-lnk match the Aeternum
  persistence pattern and warrant further investigation.
success_criteria: A verdict for each host citing the specific shortcut path and naming
  the creator process.
tools:
- endpoint
```

## gate-on-startup
<!-- Gate on startup lead -->
if~: "the evaluate-startup-lead verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-expansion
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-telemetry)
else: → close-out

## parallel-expansion
<!-- Expanded investigation -->
parallel:
- → check-auxiliary-binaries
- → stack-rare-appdata-binaries
join: → triage-infection-context

## check-auxiliary-binaries
<!-- Check auxiliary binaries -->
Identify execution of supporting binaries that the Aeternum loader drops and runs.

```sqlite target=endpoint role=detection-candidate params=(auxiliary_binaries=auxiliary_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows naming wmiframework.exe or other auxiliary processes on the affected
  hosts.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE instr(',' || '{{auxiliary_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## stack-rare-appdata-binaries
<!-- Stack rare AppData binaries -->
Find the primary loader (Build.exe) even if renamed by identifying rare processes in user-writable paths.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of rare executables appearing on only 1-3 hosts. Legitimate
  updaters will be filtered out by fleet-wide counts.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\appdata\\local\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts, runs
```

## triage-infection-context
<!-- Triage infection context -->
```agent target=hunter
cite: required
context:
- evaluate-startup-lead
- check-auxiliary-binaries
- stack-rare-appdata-binaries
max_iterations: 6
objective: Determine if any host shows both the Aeternum persistence shortcut and
  active execution of the loader or its auxiliary binaries.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing specific
  rows and paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-infection-context verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-coverage)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and remove the malicious shortcut from the Startup folder.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the identified process command lines and shortcut paths. Check for network traffic to Polygon RPC nodes if possible.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no Aeternum persistence or auxiliary execution was detected in the given window.
```
→ end
