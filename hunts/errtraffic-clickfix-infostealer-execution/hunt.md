---
analysis: A simple detection rule might fire on 'PowerShell with IEX', but this hunt
  combines process lineage (browser parentage), prevalence stacking of sensitive file
  access (non-browser touching Login Data across profiles), and infrastructure-specific
  DNS TLDs to differentiate from legitimate admin activity.
blind_spots:
- id: limited-endpoint-telemetry
  question: Was the script content fully captured if the block size was large or obfuscated?
  requires: hb_script_activity with high PowerShell logging levels
  risk: Incomplete script content prevents an analyst from seeing the actual download
    URL or exfiltration logic.
  stage: social-engineering-execution
- id: clipboard-monitoring-gap
  question: Can we see what was copied to the clipboard before execution?
  requires: Clipboard activity monitoring (T1115)
  risk: We only see the result of the execution, not the preceding social engineering
    'copy' action, making it harder to confirm the lure type.
  stage: social-engineering-execution
coverage:
- stage: social-engineering-execution
  status: covered
  steps:
  - powershell-lure-execution
  - script-block-deobfuscation
- stage: infostealer-payload-activity
  status: covered
  steps:
  - browser-credential-access
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: wordpress-server-compromise
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: etherhiding-c2-resolution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: clickfix-payload-delivery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ErrTraffic represents a growing 'Malware-as-a-Service' ecosystem
    specializing in high-conversion social engineering. Detecting the endpoint execution
    phase is the last line of defense against credential theft by infostealers like
    Vidar or Stealc.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used social engineering lures to trick a user into executing
  a malicious PowerShell command from the clipboard, leading to the deployment of
  an infostealer that targets browser credential stores.
labels:
- hunt
- attack.t1059.001
- attack.t1115
- attack.t1555
name: ErrTraffic ClickFix Lure and Infostealer Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_keywords:
    default:
    - invoke-webrequest
    - iex
    - downloadstring
    - bitsadmin
    - mshta
    - -enc
    - -encodedcommand
    - '-e '
    - '-en '
    - '-enco '
    description: Keywords typically found in malicious PowerShell lures executed via
      the ClickFix technique.
    type: list[string]
  suspicious_tlds:
    default:
    - .beer
    - .cfd
    - .club
    - .click
    - .cyou
    - .lat
    - .sbs
    - .shop
    - .xyz
    description: Suspicious TLDs used by ErrTraffic C2 clusters for TDS delivery.
    from:
      kind: article
      observed: '2026-06-02'
      ref: sekoia-errtraffic-2026
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets end-user workstations where browsers (Chrome, Edge, Firefox)
  are installed, as these are the primary targets for social engineering lures. The
  time window is critical as ClickFix lures are often transient.
references:
- name: "Sekoia \u2014 Unveiling ErrTraffic: a growing ClickFix malware distribution\
    \ framework"
  url: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: errtraffic-c2-infrastructure-tracking
  reason: This hunt focuses on endpoint execution; tracking the rotating smart-contract
    C2 resolution is a network/infrastructure hunt.
  relation: out-of-scope-alternative
- hunt: errtraffic-web-compromise-blockchain-resolution
  relation: follows
scenario:
  stages:
  - name: WordPress Initial Access and Persistence
    observables:
    - PHP backdoors
    - Malicious WordPress plugin
    - Exploited WordPress accounts
    - index.php
    slug: wordpress-server-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: Blockchain-based C2 Resolution
    observables:
    - Polygon blockchain smart contract 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
    - Quicknode RPC endpoints
    - EtherHiding technique
    - Base64-encoded XOR-obfuscated JS
    slug: etherhiding-c2-resolution
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: ClickFix Lure Delivery
    observables:
    - /cf.js
    - /api/css.js
    - /api/index.php
    - llc-image-ico.click
    - Domains with .beer, .cfd, .club, .click, .cyou, .lat, .sbs, .shop, or .xyz TLDs
    slug: clickfix-payload-delivery
    tactic: command-and-control
    techniques:
    - T1071
  - name: User-Driven PowerShell Execution
    observables:
    - Fake BSOD lure
    - Fake Cloudflare Turnstile CAPTCHA
    - Malicious PowerShell command copied to clipboard
    - PowerShell download commands
    slug: social-engineering-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Infostealer Credential Theft
    observables:
    - Vidar infostealer
    - Stealc infostealer
    - Remus infostealer
    - Salat infostealer
    - Access to browser password stores
    slug: infostealer-payload-activity
    tactic: credential-access
    techniques:
    - T1555
  summary: ErrTraffic is a Malware-as-a-Service framework that compromises WordPress
    sites to inject malicious JavaScript and deliver 'ClickFix' social engineering
    lures. It utilizes 'EtherHiding' by querying Polygon blockchain smart contracts
    for resilient C2 infrastructure resolution and tricks users into running PowerShell
    commands that download infostealers like Vidar and Stealc.
series:
  index: 2
  slug: unveiling-errtraffic-a-growing-clickfix-malware-distribution-framework
  title: 'Unveiling ErrTraffic: a growing ClickFix malware distribution framework'
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


# ErrTraffic ClickFix Lure and Infostealer Execution

ErrTraffic (also known as ClickFix) leverages deceptive lures like fake browser updates or CAPTCHAs to persuade users to execute PowerShell commands. This hunt identifies the initial execution pattern—PowerShell spawned from a browser or explorer with download keywords—and corroborates it by looking for rare processes accessing browser login databases and DNS traffic to the specific TLDs used by ErrTraffic's Traffic Distribution System (TDS).

## scope-to-browsers
<!-- Scope to hosts with installed browsers -->
Identify hosts running browsers that are the primary targets for ClickFix social engineering lures.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with at least one major browser installed. This provides
  the initial population for the behavioral hunt.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%edge%') AND asset_scope = 'endpoint'
```

## powershell-lure-execution
<!-- PowerShell lures from browsers or shells -->
Detect the execution of PowerShell with download-related keywords or shorthand encoded flags, often manually triggered from a clipboard paste following a social engineering lure.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, lure_keywords=lure_keywords)
~~~yaml
expected: A PowerShell process spawned from a browser or the shell with commands indicating
  network content retrieval or shorthand encoded flags. Silence suggests no ClickFix-style
  execution occurred in this window.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\powershell.exe' OR LOWER(process_name) LIKE '%\\pwsh.exe') AND (LOWER(parent_process_name) LIKE '%chrome.exe' OR LOWER(parent_process_name) LIKE '%msedge.exe' OR LOWER(parent_process_name) LIKE '%firefox.exe' OR LOWER(parent_process_name) LIKE '%explorer.exe') AND (instr(LOWER(process_cmd_line), ' -e ') > 0 OR instr(LOWER(process_cmd_line), ' -en') > 0 OR instr(LOWER(process_cmd_line), ' -enco') > 0 OR instr(LOWER(process_cmd_line), 'iex') > 0 OR instr(LOWER(process_cmd_line), 'invoke-webrequest') > 0 OR instr(LOWER(process_cmd_line), 'downloadstring') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with script and file indicators -->
parallel:
- → script-block-deobfuscation
- → browser-credential-access
- → errtraffic-tld-dns
join: → triage-endpoint-activity

## script-block-deobfuscation
<!-- De-obfuscated PowerShell script content -->
Examine the content of executed script blocks to find hidden download URLs or C2 communications that were encoded in the process command line.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing web requests. This is critical if the original
  command line used Base64 encoding.
reads:
- device_hostname
- script_path
- script_content
- actor_user_name
- time
- script_type
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, script_path, script_content, actor_user_name, time FROM hb_script_activity WHERE script_type = 'PowerShell' AND (LOWER(script_content) LIKE '%http%' OR LOWER(script_content) LIKE '%system.net.webclient%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## browser-credential-access
<!-- Rare processes accessing browser credential stores -->
Identify processes other than the browser itself touching sensitive files like 'Login Data' across multiple profile directories, typical for infostealer behavior.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: 14d
expected: A non-browser process reading the login database. Stacking counts across
  the fleet helps isolate malicious payloads from legitimate system tools.
prevalence:
  by: device_hostname
  key:
  - process_name
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
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\\user data\\%\\login data' OR LOWER(file_path) LIKE '%\\mozilla\\firefox\\profiles\\%\\logins.json') AND LOWER(process_name) NOT LIKE '%chrome.exe' AND LOWER(process_name) NOT LIKE '%msedge.exe' AND LOWER(process_name) NOT LIKE '%firefox.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, file_path HAVING host_count <= 3
```

## errtraffic-tld-dns
<!-- DNS lookups to ErrTraffic infrastructure TLDs -->
Correlate host activity with lookups to the unusual TLDs identified in ErrTraffic's C2 and TDS infrastructure using the suspicious_tlds parameter.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, suspicious_tlds=suspicious_tlds)
~~~yaml
expected: Any resolution of .beer, .cfd, or other unusual domains by user processes
  following a ClickFix execution. Silence here is common as C2 rotates.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{suspicious_tlds}}' || ',', ',' || SUBSTR(LOWER(query_hostname), INSTR(LOWER(query_hostname), '.') + 1) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-endpoint-activity
<!-- Triage endpoint activity -->
```agent target=hunter
cite: required
context:
- powershell-lure-execution
- script-block-deobfuscation
- browser-credential-access
- errtraffic-tld-dns
max_iterations: 3
objective: Determine if any host has successfully executed a ClickFix lure and subsequently
  showed signs of infostealer activity (credential theft).
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign with citations.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for one or more hosts" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate password resets for all stored browser credentials for the affected user.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the PowerShell command lines and script contents. Verify if the file access was indeed malicious and not a legitimate backup or security tool. Update the lure_keywords list if new patterns are found.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document that no ClickFix execution or infostealer activity was found within the lookback window. Mark the hunt as complete.
```
→ end
