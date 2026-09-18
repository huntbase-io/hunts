---
analysis: A single rule on '.lnk' files or 'AppData' binaries is too noisy. This hunt
  uses a parallel structure to correlate rarity, location, and persistence while using
  an agent to weigh the combined indicators, providing a contextual verdict that simple
  rules cannot.
blind_spots:
- id: lnk-target-visibility
  question: What binary does the startup shortcut actually point to?
  requires: forensic parsing of .lnk file contents
  risk: While we see the shortcut creation, we rely on subsequent process activity
    to infer the link's target.
  stage: initial-execution-and-persistence
- id: short-lived-processes
  question: Did transient loaders (like STAAAAAS.exe) run and exit between snapshots?
  requires: event-based process auditing (e.g. Sysmon or EDR stream)
  risk: Snapshot-based hb_process_activity may miss short-lived binaries that perform
    setup and terminate.
  stage: supporting-binary-execution
coverage:
- stage: initial-execution-and-persistence
  status: covered
  steps:
  - startup-persistence-lnk
  - rare-appdata-processes
- stage: supporting-binary-execution
  status: covered
  steps:
  - known-payload-execution
- stage: blended-threat-impact
  status: covered
  steps:
  - known-payload-execution
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: blockchain-c2-communication
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: github-payload-download
  status: out_of_scope
- reason: "Belongs to another part of the 'The Permanent Threat: Analyzing Aeternum\u2019\
    s Blockchain-Based C2 Operations and Communications' series."
  stage: telegram-data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Aeternum leverages blockchain-based C2 that is nearly impossible
    to take down; hunting for the host-level persistence and payload deployment is
    the most reliable way to identify and neutralize these nodes.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence via a startup shortcut pointing
  to a binary in a user-writable directory, which then executes multi-stage loaders
  and miners.
labels:
- hunt
- attack.t1547.001
- attack.t1204.002
- attack.t1027.002
- attack.t1059
- attack.t1496
name: 'Aeternum Botnet: Persistence and Payload Deployment'
parameters:
  known_binaries:
    default:
    - build.exe
    - wmiframework.exe
    - zrvesjqzwq.exe
    - staaaaas.exe
    - xbinderoutput_protected.exe
    description: Specific binary names associated with Aeternum loaders.
    from:
      kind: article
      observed: '2026-08-10'
      ref: unit42-aeternum
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
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
rationale: The hunt focuses on Windows endpoints. Scoping uses a broad check for Microsoft
  software to identify the estate.
references:
- name: "Unit 42: Analyzing Aeternum\u2019s Blockchain-Based C2 Operations and Communications"
  url: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
related:
- hunt: aeternum-blockchain-c2-network-analysis
  reason: This hunt focuses on host artifacts; the DNS and RPC patterns for the Polygon
    blockchain are covered in a network-centric sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Self-Unpacking and Persistence Setup
    observables:
    - Build.exe
    - Wmi_Framework_APIKEY_wmsnet_*.lnk
    - '%LOCALAPPDATA%\Local'
    - UPX-packed 32-bit PE
    slug: initial-execution-and-persistence
    tactic: persistence
    techniques:
    - T1204.002
    - T1547.001
    - T1027.002
  - name: Supporting Binary Execution
    observables:
    - wmiframework.exe
    - ZrvEsJQzWQ.exe
    - STAAAAAS.exe
    slug: supporting-binary-execution
    tactic: execution
    techniques:
    - T1059
  - name: Decentralized Blockchain C2 Discovery
    observables:
    - polygon-mumbai-bor-rpc.publicnode.com
    - '0xb68d1809'
    - JSON-RPC POST
    - getDomain()
    slug: blockchain-c2-communication
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1071.001
  - name: Payload Retrieval from GitHub
    observables:
    - github.com
    - putty.exe
    - DotNetZip.dll
    slug: github-payload-download
    tactic: command-and-control
    techniques:
    - T1105
  - name: System Info Exfiltration via Telegram
    observables:
    - api.telegram.org
    - /bot
    - /sendDocument
    - SystemInfo Bot/2.0
    - screenshot.png
    - systeminfoboundary
    slug: telegram-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1102.002
    - T1567.002
    - T1005
  - name: Blended Threat Deployment
    observables:
    - XBinderOutput_protected.exe
    - XMRig
    - XWorm
    slug: blended-threat-impact
    tactic: impact
    techniques:
    - T1496
  summary: Aeternum is a C++ botnet loader that utilizes the Polygon blockchain as
    a decentralized C2 infrastructure by querying smart contracts for encrypted instructions.
    The malware maintains persistence via Windows startup shortcuts and performs data
    exfiltration using the Telegram API, occasionally dropping additional threats
    like XWorm and XMRig miners.
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


# Aeternum Botnet: Persistence and Payload Deployment

This hunt targets the host-side lifecycle of the Aeternum botnet. It begins by scoping to Windows-based assets, then simultaneously searches for the creation of startup shortcuts and rare process executions in user-writable paths like AppData. Finally, it corroborates these behavioral signals against known loader and impact binary names (XWorm, XMRig) mentioned in research.

## identify-windows-hosts
<!-- Identify Windows Assets -->
Aeternum is a Windows-centric botnet; this step narrows the estate to hosts running Microsoft software.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to the Windows estate. Silence here means
  no Windows assets were found, which would render the rest of the hunt irrelevant.
reads:
- device_hostname
- vendor_name
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(vendor_name) LIKE '%microsoft%' OR LOWER(package_name) LIKE '%windows%')
```

## gather-evidence
<!-- Gather Evidence Parallel -->
parallel:
- → startup-persistence-lnk
- → rare-appdata-processes
- → known-payload-execution
join: → triage-agent

## startup-persistence-lnk
<!-- New Startup Shortcuts -->
Find .lnk files created in the Startup directory, a common persistence technique for the Aeternum loader.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Shortcuts created in the startup folder. Most shortcuts here are benign;
  context provided by the other steps will isolate the threat.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\programs\startup\%' AND LOWER(file_name) LIKE '%.lnk' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-appdata-processes
<!-- Rare Processes in AppData -->
Identify binaries running from user-writable AppData paths that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries running from local user profiles seen on very few hosts. Legitimate
  software (like Teams or Discord) will typically appear across many hosts.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\appdata\local\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts < 3
```

## known-payload-execution
<!-- Known Loader and Miner Execution -->
Match specific filenames and command-line patterns from the Aeternum research.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, known_binaries=known_binaries)
~~~yaml
expected: Execution of specific binaries mentioned in the report. This is high-confidence
  evidence if paired with persistence or rarity.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{known_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%xmrig%' OR LOWER(process_cmd_line) LIKE '%xworm%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage Agent -->
```agent target=hunter
cite: required
context:
- startup-persistence-lnk
- rare-appdata-processes
- known-payload-execution
max_iterations: 3
objective: Determine if any host has evidence of Aeternum infection based on startup
  persistence, rare AppData execution, and known binary indicators.
success_criteria: Verdicts citing the specific .lnk paths and process rarity.
tools:
- endpoint
```

## verdict-decision
<!-- Verdict Decision -->
if~: "the triage verdict is 'malicious' for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: short-lived-processes)
else: → manual-review

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve forensic state for binary analysis of any found AppData executables.
```
→ manual-review

## manual-review
<!-- Manual Review -->
```manual target=analyst
Review the rare AppData binaries and startup shortcuts. If malicious, initiate an incident response plan to investigate lateral movement.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Log the result. If no hits, document the negative result for the lookback period.
```
→ end
