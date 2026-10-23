---
analysis: 'A single rule on telegra.ph resolution is too noisy. This hunt uses a phased
  approach: scoping by infrastructure, corroborating via memory-evasion indicators
  (module activity), and confirming via behavioral theft patterns (file activity).
  Only the agent''s consolidated read provides high-confidence confirmation.'
blind_spots:
- id: incomplete-telemetry
  question: whether the module stomping occurred on unmanaged hosts
  requires: endpoint agent on all devices
  risk: A host without the hb_module_activity surface cannot be assessed for DLL hollowing,
    leading to false negatives.
  stage: stealthy-loader-evasion
- id: memory-resident-evasion
  question: the presence of the final Amatera payload
  requires: memory scanning
  risk: Amatera is memory-resident; a negative result on hb_file_activity does not
    prove the absence of the stealer if it was never written to disk.
  stage: stealthy-loader-evasion
coverage:
- stage: stealthy-loader-evasion
  status: covered
  steps:
  - loader-hollowing-dbghelp
- stage: amatera-c2-resolution
  status: covered
  steps:
  - telegraph-c2-resolution
- stage: credential-and-crypto-theft
  status: covered
  steps:
  - cryptocurrency-wallet-access
- stage: secondary-payload-deployment
  status: covered
  steps:
  - secondary-payload-activity
- reason: Belongs to another part of the 'ClearFake WebDAV infection chain delivers
    Amatera stealer, ZigCryptoStealer, and NetSupport Manager' series.
  stage: clearfake-etherhiding-delivery
  status: out_of_scope
- reason: Belongs to another part of the 'ClearFake WebDAV infection chain delivers
    Amatera stealer, ZigCryptoStealer, and NetSupport Manager' series.
  stage: clickfix-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'ClearFake WebDAV infection chain delivers
    Amatera stealer, ZigCryptoStealer, and NetSupport Manager' series.
  stage: webdav-rundll32-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Amatera targets high-value cryptocurrency and identity assets. Its
    use of module stomping and dead-drop resolution makes traditional rule-based detection
    difficult. A phased hunt that correlates early infection with follow-on theft
    is necessary to confirm the full intrusion chain.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed the Amatera stealer, characterized by DLL hollowing
  of dbghelp.dll and dead-drop C2 resolution via Telegraph, and is now scanning for
  cryptocurrency wallets or deploying secondary payloads like ZigCryptoStealer.
labels:
- hunt
- attack.t1574.002
- attack.t1059.001
- attack.t1555
- attack.t1115
- attack.t1218.011
name: Amatera Stealer and Follow-on Payloads
parameters:
  c2_domains:
    default:
    - telegra.ph
    - leaguejazire.com
    - riyazinikokar.xyz
    - verification.google
    - pf.ch
    description: Domains used for dead-drop resolution and command-and-control.
    from:
      kind: article
      observed: '2026-09-08'
      ref: talos
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty to scan
      the entire estate.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: default
    type: list[host]
  secondary_payload_names:
    default:
    - client32.exe
    - secur32.dll
    description: Process and module names associated with secondary payloads.
    from:
      kind: article
      observed: '2026-09-08'
      ref: talos
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should start with endpoints communicating with telegra.ph. If
  no matches are found, broaden the scope to servers and workstations running rundll32.exe
  with unusually high module activity.
references:
- name: "Talos \u2014 ClearFake WebDAV infection chain delivers Amatera stealer, ZigCryptoStealer,\
    \ and NetSupport Manager"
  url: https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
related:
- hunt: webdav-rundll32-execution
  reason: The initial delivery mechanism (WebDAV UNC paths and rundll32 ordinals)
    is handled by a separate hunt focused on delivery.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: EtherHiding via BNB Smart Chain
    observables:
    - bsc-testnet-rpc.publicnode.com
    - '0x886d310Ac23e05EA705e24E513D19f53793832A9'
    - '0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff'
    - '0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5'
    slug: clearfake-etherhiding-delivery
    tactic: initial-access
    techniques:
    - T1059.001
  - name: ClickFix Fake CAPTCHA Overlay
    observables:
    - cjs_id cookie
    - Fake Google CAPTCHA UI
    - Run dialog clipboard paste prompt
    slug: clickfix-social-engineering
    tactic: execution
  - name: WebDAV DLL Execution
    observables:
    - rundll32.exe
    - leaguejazire.com
    - pf.ch
    - verification.google
    - 'ordinal #1'
    - WebClient service start
    slug: webdav-rundll32-execution
    tactic: execution
    techniques:
    - T1218.011
  - name: DLL Hollowing and VEH Unpacking
    observables:
    - dbghelp.dll module hollowing
    - Vectored Exception Handling (VEH)
    - LZNT1 decoding
    - WoW64 syscall stubs
    - TpAllocWork function callback
    slug: stealthy-loader-evasion
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Amatera Dead Drop C2 Resolution
    observables:
    - telegra.ph/Functions-04-03
    - 145.249.109.147
    - GETWELLV2 string
    - Auxiliary Function Driver (AFD) socket
    slug: amatera-c2-resolution
    tactic: command-and-control
  - name: Credential and Wallet Collection
    observables:
    - Browser credential store access
    - Cryptocurrency wallet directory scanning
    - Clipboard monitoring
    slug: credential-and-crypto-theft
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  - name: Secondary Payload Installation
    observables:
    - secur32.dll sideloading
    - NetSupport Manager
    - ZigCryptoStealer
    - riyazinikokar.xyz
    slug: secondary-payload-deployment
    tactic: persistence
    techniques:
    - T1574.002
    - T1059.001
  summary: The ClearFake campaign utilizes EtherHiding via BNB Smart Chain and social
    engineering through fake Google CAPTCHA overlays to trick users into executing
    malicious commands. These commands trigger a WebDAV-based DLL execution via rundll32.exe,
    deploying the Amatera stealer which subsequently installs secondary payloads like
    ZigCryptoStealer and NetSupport Manager.
series:
  index: 2
  slug: clearfake-webdav-infection-chain-delivers-amatera-stealer-zigcryptostealer-and-netsupport-manage
  title: ClearFake WebDAV infection chain delivers Amatera stealer, ZigCryptoStealer,
    and NetSupport Manager
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Amatera Stealer and Follow-on Payloads

This hunt identifies the post-infection lifecycle of the Amatera stealer, focusing on its specific evasion and persistence techniques. Amatera often employs module stomping (DLL hollowing) in dbghelp.dll to hide its memory-resident payload and resolves its C2 server via encoded strings on Telegraph pages. Once established, the stealer scans the host for browser credentials and cryptocurrency wallet directories. The hunt uses a phased approach: first scoping the estate for early infection signals, then pivoting to identify evidence of theft and the deployment of secondary payloads like NetSupport Manager or ZigCryptoStealer.

## scope-hosts-by-dns
<!-- Scope hosts by known C2 DNS traffic -->
Identify endpoints that have resolved the reported C2 or dead-drop domains to focus the search.

```sqlite target=endpoint role=scoping params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames communicating with reported infrastructure. Silence
  suggests the C2 is not currently active via these domains.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early-infection
<!-- Parallel hunt for early infection stages -->
parallel:
- → loader-hollowing-dbghelp
- → telegraph-c2-resolution
join: → agent-early-triage

## loader-hollowing-dbghelp
<!-- DLL hollowing of dbghelp.dll -->
Detect the overwriting of legitimate modules, specifically targeting dbghelp.dll in rundll32 processes.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Instances of rundll32 loading dbghelp.dll. While legitimate, their combination
  in a transient process is an indicator of module stomping.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE LOWER(module_name) = 'dbghelp.dll' AND LOWER(process_name) LIKE '%rundll32.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## telegraph-c2-resolution
<!-- Telegraph dead-drop resolution -->
Identify HTTP requests to the dead-drop pages used to resolve the C2 server IP.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to specific URIs on telegra.ph. Silence proving the dead-drop
  has not been accessed using these known paths.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE LOWER(url_hostname) = 'telegra.ph' AND (LOWER(url_path) LIKE '/functions-%' OR LOWER(url_path) LIKE '/getwell%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage the early infection -->
```agent target=hunter
cite: required
context:
- loader-hollowing-dbghelp
- telegraph-c2-resolution
max_iterations: 3
objective: Determine which hosts show early Amatera behavior, specifically the hollowing
  of dbghelp.dll or Telegraph C2 resolution.
success_criteria: A list of hosts with confirmed or suspicious loader presence.
tools:
- endpoint
- web
```

## parallel-follow-on
<!-- Hunt for theft and impact -->
parallel:
- → cryptocurrency-wallet-access
- → secondary-payload-activity
join: → agent-follow-on-triage

## cryptocurrency-wallet-access
<!-- Cryptocurrency wallet and credential access -->
Find unusual processes accessing wallet directories or browser data.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unusual processes reading wallet files. Stack-counting helps isolate theft
  from normal browser updates.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_path, COUNT(*) AS access_count, MIN(time) AS first_access FROM hb_file_activity WHERE (instr(LOWER(file_path), 'wallets') > 0 OR instr(LOWER(file_path), 'atomic') > 0 OR instr(LOWER(file_path), 'exodus') > 0 OR LOWER(file_name) = 'login data') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path HAVING access_count < 50
```

## secondary-payload-activity
<!-- ZigCrypto and NetSupport activity -->
Detect secondary tools deployed by the Amatera loader, such as NetSupport Manager or sideloaded modules.

```sqlite target=endpoint role=detection-candidate params=(secondary_payload_names=secondary_payload_names, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: NetSupport (client32.exe) or sideloaded ZigCrypto components running from
  user-writable paths. Absence suggests secondary payloads have not yet been deployed.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{secondary_payload_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{secondary_payload_names}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\users\public\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-follow-on-triage
<!-- Triage the full infection lifecycle -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- cryptocurrency-wallet-access
- secondary-payload-activity
max_iterations: 4
objective: 'Determine if any host shows the complete lifecycle of Amatera: loader
  mechanics, C2 resolution, wallet access, and secondary payload deployment.'
success_criteria: A per-host verdict citing specific rows from all behavioral surfaces.
tools:
- endpoint
- web
```

## decision-route
<!-- Route on final verdict -->
if~: "the agent-follow-on-triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified by the agent and block all traffic to 145.249.109.147.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited module activity for dbghelp.dll hollowing and verify the process tree of any wallet access events.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Summarize findings and document any observed secondary payload paths for detection engineering.
```
→ end
