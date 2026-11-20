---
analysis: A single rule might alert on a rundll32 ordinal, but this hunt connects
  that lead to earlier social engineering scripts and follow-on persistence from RMM
  tools, providing the context an analyst needs for a confirmed intrusion verdict.
blind_spots:
- id: memory-only-stealers
  question: Are Amatera or ZigCryptoStealer active in memory?
  requires: Endpoint memory scanning or live forensic dump
  risk: Since these stealers are often memory-only after injection, standard process
    snapshots will miss them once the loading process (rundll32) exits.
  stage: credential-access-memory-stealers
- id: webdav-uri-encryption
  question: What were the specific filenames accessed on the WebDAV share?
  requires: TLS-decrypted HTTP/WebDAV logs
  risk: Encrypted WebDAV traffic prevents seeing the specific payload paths, making
    the hunt reliant on script-pasting behavior.
  stage: initial-access-social-engineering-webdav
coverage:
- stage: initial-access-social-engineering-webdav
  status: covered
  steps:
  - webdav-script-leads
- stage: execution-rundll32-ordinals
  status: covered
  steps:
  - rundll32-ordinal-prevalence
- stage: defense-evasion-edr-termination
  status: covered
  steps:
  - vulnerable-driver-hunt
- stage: persistence-netsupport-rmm
  status: covered
  steps:
  - rmm-persistence-hunt
- blind_spot: memory-only-stealers
  reason: Memory-resident stealers require memory forensics or specialized memory
    scanning not provided by standard process snapshots.
  stage: credential-access-memory-stealers
  status: not_visible
- reason: Belongs to another part of the "We've got one word for it, and it's usually
    the wrong one" series.
  stage: c2-blockchain-infrastructure
  status: out_of_scope
- reason: Belongs to another part of the "We've got one word for it, and it's usually
    the wrong one" series.
  stage: initial-access-cisco-fmc-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-10820 uses sophisticated evasion like rundll32 ordinals and BYOVD
    to bypass standard detection. A phased hunt is required to correlate early access
    leads with persistent behavioral indicators.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has infected an endpoint using a WebDAV social engineering
  chain, followed by the execution of disguised DLLs via rundll32 ordinals and the
  installation of unauthorized RMM tools for persistence.
labels:
- hunt
- attack.t1566.002
- attack.t1218.011
- attack.t1219
- attack.t1068
- attack.t1562.001
- attack.t1555
name: UAT-10820 Multi-Stage Stealer Infection Chain
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_filenames:
    default:
    - SECOH-QAD.exe
    - client32.exe
    description: Known filenames associated with NetSupport Manager and ProcPatcher.
    from:
      kind: article
      observed: '2026-09-10'
      ref: "Talos \u2014 We've got one word for it"
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to scan the entire
      Windows estate.
    type: list[host]
  vulnerable_drivers:
    default:
    - procexp.sys
    - iobitvdrv.sys
    description: Common vulnerable drivers used in BYOVD attacks to terminate EDR.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: Known BYOVD Driver Lists
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/weve-got-one-word-for-it-and-its-usually-the-wrong-one/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows workstations and servers. The hunt assumes EDR telemetry
  for script execution and process activity is enabled.
references:
- name: "Cisco Talos \u2014 We've got one word for it, and it's usually the wrong\
    \ one"
  url: https://blog.talosintelligence.com/weve-got-one-word-for-it-and-its-usually-the-wrong-one/
related:
- hunt: uat-10820-c2-blockchain-infrastructure
  reason: This hunt focuses on host-based infection markers; C2 activity via BNB Smart
    Chain and Google Visualization requires network-level analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social engineering via WebDAV and fake CAPTCHA
    observables:
    - fake CAPTCHA prompts
    - WebDAV infection chain
    - copying and pasting commands from fake verification prompts
    slug: initial-access-social-engineering-webdav
    tactic: initial-access
    techniques:
    - T1566
  - name: Rundll32 ordinal execution
    observables:
    - rundll32.exe
    - disguised DLLs
    - suspicious ordinal calls
    - tmp00055df5.dll
    slug: execution-rundll32-ordinals
    tactic: defense-evasion
    techniques:
    - T1218.011
  - name: EDR termination via BYOVD
    observables:
    - vulnerable driver
    - terminate EDR software
    slug: defense-evasion-edr-termination
    tactic: defense-evasion
    techniques:
    - T1068
    - T1562.001
  - name: Unauthorized RMM installation
    observables:
    - NetSupport Manager
    - SECOH-QAD.exe
    slug: persistence-netsupport-rmm
    tactic: persistence
    techniques:
    - T1219
  - name: In-memory credential theft
    observables:
    - Amatera stealer
    - ZigCryptoStealer
    slug: credential-access-memory-stealers
    tactic: credential-access
    techniques:
    - T1555
  - name: C2 via BNB Smart Chain
    observables:
    - BNB Smart Chain
    - bulletproof hosting
    slug: c2-blockchain-infrastructure
    tactic: command-and-control
    techniques:
    - T1071
  - name: Cisco FMC vulnerability exploitation
    observables:
    - CVE-2026-20079
    - CVE-2026-20316
    - Cisco Secure Firewall Management Center (FMC) Software
    - crafted HTTP requests
    - static user credentials
    slug: initial-access-cisco-fmc-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1133
  summary: Russian threat actor UAT-10820 targets organizations with a WebDAV-based
    infection chain that tricks users into executing malicious commands via fake CAPTCHA
    prompts. The campaign deploys the Amatera and ZigCrypto stealers, utilizing vulnerable
    drivers to terminate security software and NetSupport Manager for persistent remote
    access.
series:
  index: 1
  slug: we-ve-got-one-word-for-it-and-it-s-usually-the-wrong-one
  title: We've got one word for it, and it's usually the wrong one
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


# UAT-10820 Multi-Stage Stealer Infection Chain

This hunt identifies the multi-stage infection pattern of UAT-10820, starting with interactive scripts that mount WebDAV shares or paste base64-encoded commands. It pivots to identify rare rundll32.exe executions using ordinal calls instead of named exports, a tactic used to load the Amatera stealer. The second phase corroborates these leads by hunting for unauthorized NetSupport Manager installations in user-writable paths and the presence of vulnerable drivers used for EDR termination. The phased agent-led analysis connects early-stage access signals to persistent, high-impact indicators.

## scope-windows-endpoints
<!-- Scope Windows Workstations -->
Filter the estate to Windows endpoints where WebDAV social engineering and rundll32 ordinal execution are viable.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Windows hostnames. Silence indicates no Windows devices are reporting
  telemetry.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE LOWER(platform) = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Initial Access and Execution Search -->
parallel:
- → webdav-script-leads
- → rundll32-ordinal-prevalence
join: → early-triage-agent

## webdav-script-leads
<!-- WebDAV and Interactive Script Leads -->
Identify scripts mounting WebDAV shares or running rundll32 from user-pasted commands.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks performing remote mounts or using rundll32. Silence means
  no such interactive script blocks were logged.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(script_content) LIKE '%net use%' OR LOWER(script_content) LIKE '%dav%') AND (LOWER(script_content) LIKE '%rundll32%' OR LOWER(script_content) LIKE '%powershell%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rundll32-ordinal-prevalence
<!-- Rundll32 Ordinal Execution Baseline -->
Identify rare rundll32.exe command lines using ordinal calls instead of function names.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: 'Rare command lines where rundll32 executes an export by its ordinal number
  (e.g., #1).'
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_cmd_line
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(process_name) LIKE '%rundll32.exe' AND process_cmd_line LIKE '%,#%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts < 5 ORDER BY hosts ASC
```

## early-triage-agent
<!-- Early Stage Evidence Review -->
```agent target=hunter
cite: required
context:
- webdav-script-leads
- rundll32-ordinal-prevalence
max_iterations: 3
objective: Determine if the host shows high-confidence signs of the UAT-10820 initial
  access and execution chain.
success_criteria: A per-host verdict of suspicious or malicious based on the presence
  of WebDAV scripts and rare rundll32 ordinal calls.
tools:
- endpoint
```

## follow-on-parallel
<!-- Follow-on Persistence and Driver Search -->
parallel:
- → rmm-persistence-hunt
- → vulnerable-driver-hunt
join: → chain-analysis-agent

## rmm-persistence-hunt
<!-- Unauthorized RMM Process Activity -->
Identify unauthorized remote access tools running from user-writable directories.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, rmm_filenames=rmm_filenames, lookback_days=lookback_days)
~~~yaml
expected: Processes associated with RMM tools running from non-standard, user-writable
  locations. None means no such processes were active.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\users\public\%') AND (instr(',' || '{{rmm_filenames}}' || ',', ',' || process_name || ',') > 0 OR LOWER(process_name) LIKE '%netsupport%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## vulnerable-driver-hunt
<!-- Vulnerable Driver Loads (BYOVD) -->
Identify loads of known vulnerable drivers used to bypass endpoint security.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, vulnerable_drivers=vulnerable_drivers, lookback_days=lookback_days)
~~~yaml
expected: Loads of drivers like procexp.sys or iobitvdrv.sys that are commonly abused
  for EDR termination.
reads:
- device_hostname
- driver_path
- driver_signature_subject
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, driver_path, driver_signature_subject, time FROM hb_kernel_extension_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{vulnerable_drivers}}' || ',', ',' || LOWER(driver_path) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## chain-analysis-agent
<!-- Full Intrusion Chain Analysis -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- rmm-persistence-hunt
- vulnerable-driver-hunt
max_iterations: 4
objective: Confirm if the identified host has been compromised by the UAT-10820 chain
  by linking early-stage findings with persistence markers.
success_criteria: A per-host verdict of Malicious | Suspicious | Benign, identifying
  which stage of the infection each host is in.
tools:
- endpoint
```

## route-decision
<!-- Route on Verdict -->
if~: "the chain-analysis-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: memory-only-stealers)
else: → analyst-review

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately and collect forensic artifacts (memory and disk) for further investigation into Amatera stealer presence.
```
→ analyst-review

## analyst-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Analyze the cited rundll32 command lines and RMM activity. Review hb_auth_signin for unusual logins from isolated hosts.
```
→ close-out

## close-out
<!-- Hunt Closeout -->
```manual target=analyst
Record the results and any tuning notes (e.g., legitimate IT use of NetSupport).
```
→ end
