---
analysis: "This hunt correlates evidence across three surfaces\u2014DNS resolution\
  \ of suspicious domains, rare process access to browser credential stores, and specific\
  \ PowerShell command-line markers\u2014to identify a complete attack chain that\
  \ a single rule on any one surface would miss or over-alert on."
blind_spots:
- id: missing-endpoint-telemetry
  question: whether an infection occurred on a host that does not report process or
    file activity
  requires: EDR agent coverage on all assets
  risk: A host without an agent will return zero rows, leading to a false sense of
    security regarding the total infection rate.
- id: clipboard-visibility
  question: the exact contents of the clipboard lure before execution
  requires: clipboard monitoring surface
  risk: The hunt relies on seeing the execution after the user pastes the command;
    the injection of the command itself into the clipboard is not visible on the provided
    surfaces.
  stage: powershell-payload-execution
coverage:
- stage: powershell-payload-execution
  status: covered
  steps:
  - dns-to-errtraffic-c2
  - powershell-clickfix-execution
- stage: infostealer-credential-access
  status: covered
  steps:
  - rare-credential-file-access
- reason: Relates to initial compromise of the distribution infrastructure, not the
    victim endpoint.
  stage: wordpress-credential-compromise
  status: out_of_scope
- reason: WordPress server persistence is handled in a separate hunt.
  stage: backdoor-persistence
  status: out_of_scope
- reason: Monitoring of blockchain smart contracts is out of scope for endpoint telemetry.
  stage: blockchain-c2-resolution
  status: out_of_scope
- reason: Requires web server logs or browser instrumentation not present in the provided
    surfaces.
  stage: clickfix-lure-delivery
  status: out_of_scope
- reason: Endpoint surfaces cannot currently see the clipboard manipulation event.
  stage: clipboard-command-injection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ErrTraffic is a high-conversion MaaS framework. Detecting the endpoint
    results of its ClickFix lures is critical as its network infrastructure rotates
    frequently via blockchain resolvers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has tricked a user into running a PowerShell command via a
  ClickFix lure, which downloads an infostealer to harvest credentials and connect
  to blockchain-resolved C2 domains.
labels:
- hunt
- attack.t1059.001
- attack.t1555
- attack.t1071
name: ErrTraffic ClickFix PowerShell and Infostealer Activity
parameters:
  c2_domains:
    default:
    - llc-image-ico.click
    - llc-image-ico.beer
    - exploit.in
    description: ErrTraffic C2 domains and related infrastructure observed in campaigns.
    from:
      kind: article
      observed: '2026-06-22'
      ref: sekoia-errtraffic
    type: list[domain]
  credential_file_names:
    default:
    - login data
    - web data
    - cookies
    description: Targeted browser credential files (case-insensitive match).
    from:
      kind: manual
      observed: '2026-06-22'
      ref: default
    type: list[string]
  legitimate_browsers:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    description: Known browser processes allowed to access credential stores.
    from:
      kind: manual
      observed: '2026-06-22'
      ref: default
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-22'
      ref: default
    type: number
  powershell_binaries:
    default:
    - powershell.exe
    - pwsh.exe
    description: PowerShell executable names to monitor.
    from:
      kind: manual
      observed: '2026-06-22'
      ref: default
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames from the scoping step to narrow the search.
    from:
      kind: manual
      observed: '2026-06-22'
      ref: default
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin with Windows workstations and specifically examine DNS resolution
  of blockchain-derived domains. Use the results of the DNS query to narrow the scope
  for subsequent process and file queries.
references:
- name: "Sekoia \u2014 Unveiling ErrTraffic: inside a growing ClickFix malware distribution\
    \ framework"
  url: https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: wordpress-backdoor-persistence
  reason: This hunt focuses on the victim endpoints; investigating the server-side
    WordPress backdoors used to deliver ErrTraffic requires separate analysis of PHP
    activity.
  relation: out-of-scope-alternative
- hunt: errtraffic-infrastructure-delivery
  relation: follows
scenario:
  stages:
  - name: WordPress Account Compromise
    observables:
    - harvested credentials
    - WordPress sites
    - Exploit.IN forum
    slug: wordpress-credential-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: PHP Backdoor Deployment
    observables:
    - PHP backdoors
    - malicious WordPress plugin
    - ErrTraffic framework injection
    slug: backdoor-persistence
    tactic: persistence
    techniques:
    - T1190
  - name: EtherHiding C2 Resolution
    observables:
    - Polygon blockchain
    - '0x08207B087F61d7e95E441E15fd6d40BEfd6eD308'
    - Quicknode RPC
    - llc-image-ico.click
    - .beer
    - .cfd
    - .club
    - .click
    - .cyou
    - .lat
    - .sbs
    - .shop
    - .xyz
    slug: blockchain-c2-resolution
    tactic: command-and-control
    techniques:
    - T1071
  - name: Social Engineering Lure Delivery
    observables:
    - /cf.js
    - /api/css.js
    - /api/index.php
    - BSOD lure
    - reCAPTCHA lure
    - Cloudflare Turnstile lure
    slug: clickfix-lure-delivery
    tactic: execution
    techniques:
    - T1071
  - name: Malicious Clipboard Injection
    observables:
    - PowerShell command copied to clipboard
    slug: clipboard-command-injection
    tactic: collection
    techniques:
    - T1115
  - name: User-Executed PowerShell Payload
    observables:
    - powershell.exe
    - Net.WebClient download
    - mode=download
    slug: powershell-payload-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Infostealer Data Theft
    observables:
    - Vidar
    - Stealc
    - Remus
    - Salat
    slug: infostealer-credential-access
    tactic: credential-access
    techniques:
    - T1555
  summary: ErrTraffic is a Malware-as-a-Service (MaaS) framework that compromises
    WordPress sites to distribute infostealers using the 'ClickFix' social engineering
    technique. It uses the EtherHiding technique to resolve its command-and-control
    infrastructure via blockchain smart contracts and delivers malicious PowerShell
    commands that victims are tricked into executing manually.
series:
  index: 2
  slug: errtraffic-a-growing-clickfix-malware-distribution-framework
  title: 'ErrTraffic: A Growing ClickFix Malware Distribution Framework'
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


# ErrTraffic ClickFix PowerShell and Infostealer Activity

This hunt identifies the endpoint manifestations of the ErrTraffic framework, a Malware-as-a-Service (MaaS) system that uses ClickFix social engineering. It targets the execution of PowerShell commands containing specific download parameters, correlates this with unauthorized access to browser credential stores by non-browser processes, and identifies DNS activity targeting blockchain-resolved C2 infrastructure.

## dns-to-errtraffic-c2
<!-- DNS lookups to ErrTraffic C2 -->
Identify hosts resolving domains associated with the ErrTraffic framework to narrow the estate for behavioural queries.

```sqlite target=endpoint role=scoping params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving known C2 domains. Silence indicates no direct resolution
  of the provided domains, which may occur if the attacker rotates blockchain-derived
  infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate
<!-- Corroborate ClickFix execution and harvesting -->
parallel:
- → powershell-clickfix-execution
- → rare-credential-file-access
join: → triage-infection

## powershell-clickfix-execution
<!-- PowerShell execution with ClickFix lures -->
Find PowerShell commands containing the specific download parameters and lure markers described in the report.

```sqlite target=endpoint role=detection-candidate params=(powershell_binaries=powershell_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process rows showing PowerShell used with ClickFix download markers. Silence
  means no such commands were executed within the window.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{powershell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND LOWER(process_cmd_line) LIKE '%mode=download%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-credential-file-access
<!-- Rare process access to browser data -->
Identify non-browser processes reading sensitive browser credential files to establish harvesting behaviour.

```sqlite target=endpoint role=baseline params=(credential_file_names=credential_file_names, legitimate_browsers=legitimate_browsers, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process that is not a browser reading browser databases. Silence suggests
  no suspicious harvesting occurred on those hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_name, file_path, COUNT(*) AS access_count, MIN(time) AS first_seen FROM hb_file_activity WHERE instr(',' || '{{credential_file_names}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND NOT (instr(',' || '{{legitimate_browsers}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_name, file_path HAVING access_count < 50
```

## triage-infection
<!-- Triage ErrTraffic infection -->
```agent target=hunter
cite: required
context:
- dns-to-errtraffic-c2
- powershell-clickfix-execution
- rare-credential-file-access
max_iterations: 4
objective: Determine if a host was compromised by an ErrTraffic lure and if credential
  harvesting occurred.
success_criteria: A per-host verdict that identifies the malicious binary responsible
  for file access and its origin via PowerShell.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-infection verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint from the network and revoke any active cloud sessions for the affected user.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited rows from the triage step. Verify the binary that accessed the credential stores. Search for other persistence mechanisms installed by the payload.
```
→ close-out

## close-out
<!-- Hunt closure -->
```manual target=analyst
Record the results of the hunt. If new C2 domains were identified during forensic review, update the c2_domains parameter for future runs.
```
→ end
