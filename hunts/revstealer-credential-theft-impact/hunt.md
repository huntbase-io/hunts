---
analysis: A simple rule on Polygon RPC endpoints would be too noisy for common crypto
  users. This hunt joins those network signals with rare process execution and specific
  gaming configuration file access to create a high-confidence behavioral picture.
blind_spots:
- id: abe-bypass-monitoring
  question: Was App-Bound Encryption bypassed via hardware breakpoints?
  requires: hb_module_activity with debugger-specific eventing
  risk: Traditional file access rules miss the memory-based bypass of browser security,
    allowing silent extraction of browser-bound keys.
  stage: credential-and-gaming-data-theft
- id: decrypted-c2-visibility
  question: What is the final C2 destination after smart-contract decryption?
  requires: HTTP decryption or memory analysis
  risk: The adversary rotates the final C2 server using a smart contract, meaning
    static DNS/IP lists will fail to observe the new infrastructure.
  stage: c2-polygon-dead-drop
coverage:
- stage: credential-and-gaming-data-theft
  status: covered
  steps:
  - gaming-config-theft
- stage: c2-polygon-dead-drop
  status: covered
  steps:
  - c2-dns-resolutions
- stage: follow-on-module-delivery
  status: covered
  steps:
  - follow-on-modules
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: anti-analysis-and-evasion
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: victim-profiling-and-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: REVSTEALER uses resilient blockchain infrastructure to maintain persistent
    account access for theft. A negative result confirms that session cookies for
    critical platforms have not been harvested from the enrolled estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed an infostealer to harvest credentials from gaming
  and communication platforms, utilizing blockchain-based fallback infrastructure
  to maintain C2 and deploying impact modules like miners and proxies.
labels:
- hunt
- attack.t1555
- attack.t1176
- attack.t1496
- attack.t1133
- attack.t1115
- attack.t1566
name: 'REVSTEALER: Credential Theft and Follow-on Impact'
parameters:
  c2_domains:
    default:
    - elitecheatsx.live
    - resight-cheats.net
    - polygon.iwmukj.xyz
    - polygon.mnyhgxda.xyz
    - static4.livelab.one
    description: Known primary C2 and Polygon dead-drop domains.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs
    type: list[domain]
  gaming_config_files:
    default:
    - battle.net.config
    - robloxcookies.dat
    - local.vdf
    - loginusers.vdf
    description: Filenames of gaming configuration files targeted for harvesting.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: default
    type: number
  module_names:
    default:
    - promanager.exe
    - winupdate.exe
    - softmanager.exe
    - lockapphost.exe
    - xmrig.exe
    description: Names of follow-on modules delivered via REVSTEALER tasking.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; defaults to all.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: default
    type: list[host]
  target_software:
    default:
    - slack
    - steam
    - battle.net
    - qbittorrent
    - roblox
    - blender
    - steelseries
    description: Software names associated with REVSTEALER lures or targets.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs
    type: list[string]
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations where users have gaming software installed alongside
  corporate applications like Slack. Narrow to hosts where lure software (qBittorrent,
  Blender) has been recently launched.
references:
- name: 'REVSTEALER ramps up: analysis of up-and-coming infostealer'
  url: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer
related:
- hunt: revstealer-victim-profiling
  reason: Victim profiling and CIS discovery checks are distinct behaviors covered
    in a separate profiling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering via YouTube and Trojanized Software
    observables:
    - elitecheatsx.live
    - resight-cheats.net
    - SteelSeriesGG.exe
    - slack.exe
    - qBittorrent.exe
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Evasion and Sandbox Scoring
    observables:
    - VMProtect packer
    - FNV-1a hash lookups
    - 6-character token verification window
    - indirect syscalls
    slug: anti-analysis-and-evasion
    tactic: defense-evasion
  - name: System Profiling and Information Discovery
    observables:
    - GetEnvironmentStringsW
    - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    - OpenClipboard
    - GetClipboardData
    - screenshot capture
    slug: victim-profiling-and-discovery
    tactic: discovery
    techniques:
    - T1115
  - name: Credential and Gaming Account Harvesting
    observables:
    - Chromium App-Bound Encryption bypass
    - '%LOCALAPPDATA%\Battle.net\Battle.net.config'
    - Robloxcookies.dat
    - local.vdf
    - loginusers.vdf
    - 225 Chromium extension identifiers
    slug: credential-and-gaming-data-theft
    tactic: credential-access
    techniques:
    - T1555
    - T1176
  - name: C2 Communication and Polygon Fallback
    observables:
    - polygon.iwmukj.xyz
    - polygon.mnyhgxda.xyz
    - static4.livelab.one
    - '0x7e4126ADFE6679B3613F629CD49162Fb08fc53Bd'
    - '0x0EC6a6D31b36271eBD06450EA98c84eBa8a191d5'
    slug: c2-polygon-dead-drop
    tactic: command-and-control
  - name: Resource Hijacking and Proxy Modules
    observables:
    - ProManager
    - WinUpdate
    - SoftManager
    - LockAppHost
    - XMRig
    slug: follow-on-module-delivery
    tactic: impact
    techniques:
    - T1496
    - T1133
  summary: "REVSTEALER is an emerging infostealer distributed through social engineering\
    \ and trojanized installers for software like Slack and qBittorrent, using a custom\
    \ sandbox scoring system and Polygon blockchain dead drops for C2 resilience.\
    \ The malware specifically targets gaming platforms, cryptocurrency wallets, and\
    \ browser credentials\u2014including a bypass for Chromium's App-Bound Encryption\u2014\
    and can deploy additional modules for cryptomining and proxying."
series:
  index: 2
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# REVSTEALER: Credential Theft and Follow-on Impact

This hunt targets the core stealing behavior and resilience mechanisms of REVSTEALER. It identifies hosts with targeted gaming or communication software, then correlates this with evidence of sensitive configuration file access, DNS resolutions to Polygon-based dead-drop infrastructure, and the execution of task-delivered impact modules like XMRig. An agent weighs these signals together to identify active account takeovers and resource hijacking across the fleet.

## target-software-inventory
<!-- Inventory of targeted software -->
Identify endpoints where software that REVSTEALER targets or impersonates is installed to narrow the scope of the investigation.

```sqlite target=endpoint role=scoping params=(target_software=target_software)
~~~yaml
expected: Hosts with Steam, Battle.net, Slack, or other lure software. Silence means
  no such software is indexed in the inventory.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{target_software}}' || ',', ',' || LOWER(package_name) || ',') > 0)
```

## corroborate-activity
<!-- Corroborate behavior and network signals -->
parallel:
- → gaming-config-theft
- → c2-dns-resolutions
- → follow-on-modules
join: → agent-triage

## gaming-config-theft
<!-- Sensitive gaming configuration access -->
Find processes reading the specific configuration files targeted by REVSTEALER for account takeover.

```sqlite target=endpoint role=detection-candidate params=(gaming_config_files=gaming_config_files, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes other than the legitimate game engine reading these files indicate
  potential credential theft.
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
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{gaming_config_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-resolutions
<!-- C2 and Polygon infrastructure resolutions -->
Identify DNS activity to known REVSTEALER C2 servers and Polygon smart-contract RPC endpoints.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Resolutions to the malicious domains. Silence is not proof of absence if
  new smart contracts or RPCs are in use.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-modules
<!-- Execution of follow-on impact modules -->
Identify the execution of rare modules delivered via REVSTEALER tasks to find malicious payloads like XMRig.

```sqlite target=endpoint role=baseline params=(module_names=module_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Execution of named modules on a very small subset of hosts. Higher counts
  may indicate legitimate software.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS p_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{module_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING hosts <= 3
```

## agent-triage
<!-- Triage REVSTEALER evidence -->
```agent target=hunter
cite: required
context:
- target-software-inventory
- gaming-config-theft
- c2-dns-resolutions
- follow-on-modules
max_iterations: 6
objective: Determine if any host shows overlapping evidence of sensitive configuration
  theft, C2 network patterns, and follow-on module execution.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  specific rows found.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage verdict is malicious for at least one host based on overlapping file theft and C2 activity." (confidence: high, judge=hunter)
then: → isolate-host-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: abe-bypass-monitoring)
else: → close-out

## isolate-host-and-revoke
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the endpoint agent. Force a password reset and session revocation for all potentially compromised accounts, including Steam, Battle.net, and Slack.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from file and network activity. Check the environmental variables of the malicious process for sensitive tokens. Confirm if ProManager or XMRig modules were successfully executed.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings, including any new contract addresses identified. If the gaming configuration access signal was high confidence, promote the 'gaming-config-theft' query to a standing rule.
```
→ end
