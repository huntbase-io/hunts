---
analysis: A single rule might flag Slack.exe in a Temp folder, but this hunt correlates
  masqueraded execution with rare file access (gaming configuration files) and registry-based
  profiling, providing the multi-surface context required for an automated response.
blind_spots:
- id: no-process-audit
  owner: Endpoint Engineering
  question: Was a masqueraded binary executed and then deleted before the hunt ran?
  remediation: Enable Sysmon Event ID 1 with Image and OriginalFileName logging.
  requires: Complete process execution logging with full paths and PE metadata.
  risk: If the binary is gone and the process has stopped, behavioral file evidence
    might exist but the lead executable is missed.
  stage: execution-masquerading
- id: app-bound-bypass
  owner: Detection Engineering
  question: Did the stealer successfully bypass App-Bound Encryption via debugger
    injection?
  remediation: Deploy rules for Cross-Process Debugging / Debugger Attach to browsers.
  requires: Memory forensics or hardware breakpoint telemetry.
  risk: The hunt sees file access but lacks visibility into the memory-based technique
    used to decrypt the keys.
  stage: credential-access-harvesting
- id: fnv1a-obfuscation
  owner: Threat Research
  question: Which specific CIS locales or sandbox usernames did the malware check?
  remediation: Analyze samples to extract and decrypt embedded hash tables.
  requires: Binary analysis or API hooking telemetry.
  risk: Profiling checks are performed via internal hashing; we see the activity but
    not the parameters of the evasion logic.
  stage: discovery-profiling-and-evasion
coverage:
- stage: execution-masquerading
  status: covered
  steps:
  - masqueraded-processes
- stage: discovery-profiling-and-evasion
  status: covered
  steps:
  - software-enumeration
- stage: credential-access-harvesting
  status: covered
  steps:
  - rare-file-access
- stage: lateral-movement-proxy
  status: covered
  steps:
  - follow-on-modules
- stage: impact-resource-hijacking
  status: covered
  steps:
  - follow-on-modules
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: initial-access-phishing-lures
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: c2-blockchain-dead-drop
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: REVSTEALER is actively targeting corporate credentials through gaming
    and chat impersonation; early detection prevents account takeovers and the establishment
    of persistent backconnect proxies within the network.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is running REVSTEALER binaries masquerading as legitimate
  software in user-writable paths to profile the host, harvest gaming credentials,
  and deploy secondary proxy or mining modules.
labels:
- hunt
- attack.t1115
- attack.t1133
- attack.t1176
- attack.t1496
- attack.t1555
- attack.t1566
name: REVSTEALER Host Activity and Credential Theft
parameters:
  follow_on_modules:
    default:
    - softmanager.exe
    - lockapphost.exe
    - xmrig.exe
    - promanager.exe
    - winupdate.exe
    description: Secondary payloads delivered by REVSTEALER tasking.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-labs-revstealer
    type: list[string]
  gaming_files:
    default:
    - Battle.net.config
    - local.vdf
    - loginusers.vdf
    - RobloxCookies.dat
    - accounts.json
    description: Sensitive configuration and cookie files targeted for credential
      theft.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-labs-revstealer
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-retention
    type: number
  masquerade_names:
    default:
    - Slack.exe
    - qBittorrent.exe
    - SteelSeriesGG.exe
    - Blender.exe
    description: Legitimate binary names REVSTEALER is known to impersonate.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-labs-revstealer
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; leave empty to scan the
      entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying hosts where targeted chat and gaming applications
  are installed. The lookback period should be at least 14 days to capture initial
  execution through to module deployment.
references:
- name: 'REVSTEALER ramps up: analysis of up-and-coming infostealer'
  url: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer
related:
- hunt: revstealer-c2-blockchain-dead-drop
  reason: This hunt focuses on host-side behavior; the Polygon/Ethereum blockchain
    infrastructure requires distinct network-layer hunting.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: YouTube Phishing and Malicious Downloads
    observables:
    - elitecheatsx.live
    - resight-cheats.net
    - YouTube video descriptions linking to game cheats
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: Masqueraded Binary Execution
    observables:
    - Slack.exe
    - qBittorrent.exe
    - SteelSeriesGG.exe
    - Blender.exe
    - VMProtect packer
    - 6-character token verification window
    slug: execution-masquerading
    tactic: execution
  - name: Victim Profiling and Sandbox Evasion
    observables:
    - GetEnvironmentStringsW
    - OpenClipboard
    - GetClipboardData
    - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    - CIS locale check (keyboard layout/language hash)
    - Sandbox scoring (CPU count, RAM threshold, GPU/PCI vendor)
    slug: discovery-profiling-and-evasion
    tactic: discovery
    techniques:
    - T1115
    - T1555
  - name: Credential and Application Harvesting
    observables:
    - '%LOCALAPPDATA%\Battle.net\Battle.net.config'
    - '%LOCALAPPDATA%\Steam\local.vdf'
    - '%LOCALAPPDATA%\Steam\loginusers.vdf'
    - '%LOCALAPPDATA%\Roblox\LocalStorage\RobloxCookies.dat'
    - '%USERPROFILE%\.lunarclient\settings\game\accounts.json'
    - Hardware breakpoints for App-Bound Encryption bypass
    - 225 Chromium extension identifiers
    slug: credential-access-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1176
  - name: Polygon Blockchain C2 Dead Drop
    observables:
    - polygon.iwmukj.xyz
    - polygon.mnyhgxda.xyz
    - static4.livelab.one
    - Port 443
    - Polygon JSON-RPC endpoints
    - '0x7e4126ADFE6679B3613F629CD49162Fb08fc53Bd'
    - '0x0EC6a6D31b36271eBD06450EA98c84eBa8a191d5'
    - '0x49cE5712164755ed212209bc71539bBc6fCFF541'
    slug: c2-blockchain-dead-drop
    tactic: command-and-control
  - name: Reverse SOCKS5 Proxy Deployment
    observables:
    - SoftManager module
    - Encrypted WebSocket protocol for backconnect
    slug: lateral-movement-proxy
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Cryptojacking Impact
    observables:
    - LockAppHost module
    - XMRig deployment
    slug: impact-resource-hijacking
    tactic: impact
    techniques:
    - T1496
  summary: REVSTEALER is an emerging infostealer distributed through YouTube-based
    phishing lures that impersonate legitimate software and game cheats. The malware
    profiles victims using sandbox scoring and CIS locale checks before harvesting
    credentials from browsers, cryptocurrency wallets, and gaming platforms like Steam
    and Battle.net. It utilizes Polygon blockchain smart contracts as a dead-drop
    mechanism for C2 resilience and can deploy follow-on modules for cryptojacking
    and reverse proxy access.
series:
  index: 1
  slug: revstealer-ramps-up-analysis-of-up-and-coming-infostealer
  title: 'REVSTEALER ramps up: analysis of up-and-coming infostealer'
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


# REVSTEALER Host Activity and Credential Theft

REVSTEALER is an emerging infostealer that targets gaming platforms (Battle.net, Steam, Roblox) and cryptocurrency wallets. It uses masquerading and VMProtect to evade initial detection, then performs extensive system profiling including clipboard theft and environment string dumps. This hunt identifies masqueraded processes running from unusual paths, detects unauthorized access to sensitive gaming configuration files, and uncovers follow-on modules like SoftManager or XMRig. The presence of these behaviors across multiple surfaces (process, file, registry) provides high-confidence evidence of compromise.

## scope-targeted-apps
<!-- Scope to hosts with targeted applications -->
Identify hosts running software REVSTEALER is known to target (Slack, Steam, Battle.net) to prioritize the hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with relevant software installed. Used to focus subsequent
  queries.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%slack%' OR LOWER(package_name) LIKE '%steam%' OR LOWER(package_name) LIKE '%roblox%' OR LOWER(package_name) LIKE '%battle.net%'
```

## masqueraded-processes
<!-- Masqueraded binaries in user-writable paths -->
Find REVSTEALER lead processes impersonating legitimate apps like Slack but running from unusual locations.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, masquerade_names=masquerade_names)
~~~yaml
expected: A process named 'Slack.exe' or 'qBittorrent.exe' running from a user's Public
  or Temp folder.
reads:
- device_hostname
- process_name
- process_path
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{masquerade_names}}' || ',', ',' || process_name || ',') > 0 AND (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\public\%') AND LOWER(process_path) NOT LIKE '%\appdata\local\slack\%' AND LOWER(process_path) NOT LIKE '%\program files%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Gather behavioral evidence -->
parallel:
- → rare-file-access
- → software-enumeration
- → follow-on-modules
join: → triage-agent

## rare-file-access
<!-- Rare access to gaming credentials -->
Detect processes reading sensitive gaming configuration files which are the primary targets of REVSTEALER.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, gaming_files=gaming_files)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A non-game process (e.g., Slack.exe in Temp) reading Steam or Battle.net
  configuration files.
prevalence:
  by: device_hostname
  key:
  - process_name
  - file_name
  rare_below: 3
reads:
- device_hostname
- process_name
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_name, COUNT(*) as access_count, MIN(time) as first_seen FROM hb_file_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{gaming_files}}' || ',', ',' || file_name || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_name
```

## software-enumeration
<!-- Registry-based software profiling -->
Identify the stealer's profiling phase where it enumerates installed software via the Uninstall registry key.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A single process reading numerous entries in the Uninstall key in a short
  window.
reads:
- device_hostname
- process_name
- reg_target
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, reg_target, time FROM hb_registry_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND LOWER(reg_target) LIKE '%\currentversion\uninstall%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-modules
<!-- Execution of secondary REVSTEALER modules -->
Confirm the infection has reached the impact stage by detecting secondary payloads like SoftManager (Proxy) or LockAppHost (Miner).

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, follow_on_modules=follow_on_modules)
~~~yaml
expected: Execution of known REVSTEALER modules by name or PE original filename.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_original_file_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_original_file_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(',' || '{{follow_on_modules}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{follow_on_modules}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage REVSTEALER activity -->
```agent target=hunter
cite: required
context:
- masqueraded-processes
- rare-file-access
- software-enumeration
- follow-on-modules
max_iterations: 4
objective: Determine if the observed behavior (masqueraded path, gaming file access,
  registry profiling, or module execution) indicates a REVSTEALER infection.
success_criteria: A verdict per host citing the specific rows that link the lead process
  to theft or impact.
tools:
- endpoint
```

## routing-decision
<!-- Route on verdict -->
if~: "the triage verdict is malicious for any host where a masqueraded process also accessed gaming config files or follow-on modules" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review-task
unavailable: → analyst-review-task (blind_spot: no-process-audit)
else: → analyst-review-task

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Terminate the malicious process tree. Collect the binary for analysis. Initiate password resets for all services logged into on that host (Battle.net, Steam, Roblox, Slack).
```
→ analyst-review-task

## analyst-review-task
<!-- Review findings and tune -->
```manual target=analyst
Review the process path and signature for hits in masqueraded-processes. Confirm if gaming-file access corresponds to authorized software or legitimate user activity.
```
→ close-out-task

## close-out-task
<!-- Hunt close-out -->
```manual target=analyst
Document findings. If REVSTEALER was identified, promote the masqueraded-processes query to a detection rule.
```
→ end
