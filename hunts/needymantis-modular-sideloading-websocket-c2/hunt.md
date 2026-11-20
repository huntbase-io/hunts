---
analysis: A single rule for WinSparkle.dll or libcurl.dll creates noise when these
  apps are legitimately updated. This hunt correlates the unusual placement (ProgramData),
  the execution context (sideloading into a legitimate app), and the external network
  signal to achieve high-fidelity detection that a rule cannot provide.
blind_spots:
- id: websocket-visibility-gap
  owner: network-team
  question: Whether the persistent TCP traffic is an authenticated WebSocket stream
  remediation: Enable WebSocket protocol logging on the perimeter proxy or firewall.
  requires: Deep packet inspection with WebSocket protocol parsing
  risk: Without protocol awareness, persistent 443 traffic might be dismissed as standard
    encrypted browser traffic or update checks.
  stage: c2-websockets-communication
- id: archive-content-visibility
  owner: endpoint-engineering
  question: What files are contained within the staged extensionless archives
  remediation: Implement sandbox detonation for extensionless archives found in ProgramData.
  requires: Decompression and decryption capability on the host
  risk: The framework stages its second and third components inside an encrypted archive
    that hb_file_activity cannot see inside.
  stage: lateral-movement-impacket-deployment
coverage:
- stage: lateral-movement-impacket-deployment
  status: covered
  steps:
  - impacket-deployment-file-writes
- stage: dll-sideloading-execution
  status: covered
  steps:
  - sideloaded-module-execution
  - module-rarity-baseline
- stage: c2-websockets-communication
  status: covered
  steps:
  - c2-dns-resolution
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: archive-extraction-and-payload-load
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: NeedyMantis is a specialized framework for long-term persistence
    used in targeted operations. Detecting the sideloading and C2 early is the only
    way to prevent follow-on modular functionality and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term access by sideloading modular components
  into legitimate processes like Poedit or Vim, using encrypted archives staged in
  unusual directories to bypass detection.
labels:
- hunt
- attack.t1574.002
- attack.t1071.001
- attack.t1021.002
- command and control
- defense evasion
- execution
- lateral movement
name: NeedyMantis Modular Sideloading and WebSocket C2
parameters:
  c2_domains:
    default:
    - corp.tripswithengine.com
    description: Identified C2 domains for NeedyMantis.
    from:
      kind: article
      observed: '2026-09-28'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt; if empty, the whole
      estate is scanned.
    type: list[host]
  target_dlls:
    default:
    - winsparkle.dll
    - libcurl.dll
    - vim64.dll
    - dbghelp.dll
    - jli.dll
    - nvml.dll
    description: Malicious DLL names used by the framework for sideloading.
    from:
      kind: article
      observed: '2026-09-28'
      ref: msrc-blog
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start the hunt by examining workstations that run Poedit, Vim, or curl,
  particularly in developer and administrative groups.
references:
- name: "MSRC Blog \u2014 NeedyMantis: Unpacking a post-compromise malware family"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/
related:
- hunt: archive-extraction-and-payload-load
  reason: This hunt focuses on the initial deployment and C2; parsing the custom archive
    format and shellcode loading is handled in the deeper forensic sequel.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Lateral movement and tool deployment
    observables:
    - Impacket toolkit usage
    - copying WinSparkle.dll from network share
    - copying libcurl.dll from network share
    - files placed in %ProgramFiles%\Poedit
    - files placed in %ProgramData%\USOShared
    - files placed in %ProgramData%\VIM
    slug: lateral-movement-impacket-deployment
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: DLL sideloading of legitimate software
    observables:
    - Poedit.exe loading WinSparkle.dll
    - curl.exe loading libcurl.dll
    - vim.exe loading vim64.dll
    - TightVNC.exe loading vim64.dll
    - nvml.dll
    - dbghelp.dll
    - jli.dll
    slug: dll-sideloading-execution
    tactic: execution
    techniques:
    - T1574.002
  - name: Encrypted archive extraction and modular loading
    observables:
    - extensionless archive files (WinSparkle, libcurl)
    - encryptbase64.ps1
    - dnsapi.dll (malicious config)
    - ws2_32.dll (malicious C2 component)
    - msvcrt140.dll (malicious loader)
    - 'mutex: <username>-<process_name> (e.g., Contoso-Poedit.exe)'
    slug: archive-extraction-and-payload-load
    tactic: defense-evasion
    techniques:
    - T1027
    - T1059.001
  - name: WebSockets Command and Control
    observables:
    - corp.tripswithengine.com
    - port 443
    - 'URL path: /library/zip/'
    - WebSockets communication protocol
    - SystemInfo export usage
    slug: c2-websockets-communication
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: China-linked threat actors use the modular NeedyMantis framework for post-compromise
    persistence in targeted sectors. The malware is deployed via lateral movement
    tools like Impacket and leverages DLL sideloading in common applications like
    Poedit and Vim to load encrypted archives containing C2 and modular components.
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


# NeedyMantis Modular Sideloading and WebSocket C2

NeedyMantis is a modular framework observed in targeted operations against government and telecommunications sectors. It relies on DLL sideloading within common software and maintains a persistent WebSocket-based connection for command and control. This hunt identifies the framework by tracing the initial file deployment via Impacket-style patterns, confirming the execution through rare module loads from non-standard paths, and identifying the low-prevalence DNS resolution of known C2 infrastructure.

## impacket-deployment-file-writes
<!-- Impacket-style Framework Deployment -->
Identify the initial placement of the sideloading DLLs and accompanying archives in ProgramData or Program Files subfolders, mimicking the lateral movement observed in the report.

```sqlite target=endpoint role=scoping params=(target_dlls=target_dlls, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A row showing a DLL like WinSparkle.dll or libcurl.dll being written to
  ProgramData. Silence indicates no obvious staging of these components was captured.
reads:
- activity_id
- actor_user_name
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE (activity_id = 1 OR activity_id = 3) AND (LOWER(file_path) LIKE '%\\programdata\\%' OR LOWER(file_path) LIKE '%\\users\\public\\%' OR LOWER(file_path) LIKE '%\\program files\\poedit\\%' OR LOWER(file_path) LIKE '%\\program files\\vim\\%') AND instr(',' || '{{target_dlls}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Correlate Sideloading and C2 -->
parallel:
- → sideloaded-module-execution
- → c2-dns-resolution
- → module-rarity-baseline
join: → triage-agent

## sideloaded-module-execution
<!-- Sideloaded Module Execution -->
Confirm that the target processes (Poedit, curl, etc.) are actually loading the masquerading DLLs from unusual paths.

```sqlite target=endpoint role=detection-candidate params=(target_dlls=target_dlls, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A legitimate process loading a DLL from a path where it does not normally
  reside. This is the core behavioral indicator of NeedyMantis.
reads:
- device_hostname
- module_name
- module_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE instr(',' || '{{target_dlls}}' || ',', ',' || LOWER(module_name) || ',') > 0 AND (LOWER(module_path) LIKE '%\\programdata\\%' OR LOWER(module_path) LIKE '%\\users\\public\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-resolution
<!-- C2 Domain Resolution -->
Match the host activity to the known NeedyMantis C2 domain to confirm the nature of the infection.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Resolution of corp.tripswithengine.com, specifically originating from a
  process involved in the sideloading branch.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## module-rarity-baseline
<!-- Module Rarity Baseline -->
Stack-count the identified modules to ensure the signal is not fleet-wide noise from a standard administrative tool.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A low host count for the specific module names identifies the targeted nature
  of the payload.
prevalence:
  by: device_hostname
  key:
  - module_name
  rare_below: 3
reads:
- device_hostname
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT LOWER(module_name) as name, COUNT(DISTINCT device_hostname) as host_count FROM hb_module_activity WHERE (LOWER(module_path) LIKE '%\\programdata\\%' OR LOWER(module_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## triage-agent
<!-- Correlate Framework Signals -->
```agent target=hunter
cite: required
context:
- impacket-deployment-file-writes
- sideloaded-module-execution
- c2-dns-resolution
- module-rarity-baseline
max_iterations: 5
objective: Determine if any host shows the correlated pattern of a WinSparkle, libcurl,
  or vim64 module load from ProgramData alongside DNS resolution to the identified
  C2 domain.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Framework Verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-payload-analysis
unavailable: → forensic-payload-analysis (blind_spot: websocket-visibility-gap)
else: → hunt-closeout

## isolate-endpoint
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the ProgramData directory for forensic collection.
```
→ forensic-payload-analysis

## forensic-payload-analysis
<!-- Forensic Payload Analysis -->
```manual target=analyst
Identify the extensionless archive matching the loader DLL name. Attempt to XOR-decode and decompress the archive to recover the second-stage loader and communications DLL. Check for the SystemInfo export.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt Close-out -->
```manual target=analyst
Record all confirmed malicious paths and the account involved in the initial file write. Determine if the module-loading detection candidate can be promoted to a rule for specific sensitive environments.
```
→ end
