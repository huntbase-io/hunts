---
analysis: A simple detection rule might catch the specific scottvmorton domain, but
  this hunt correlates the initial PowerShell execution with rare ProgramData persistence
  and gateway connections, allowing an analyst to see the full intrusion chain rather
  than a single disjointed alert.
blind_spots:
- id: limited-process-telemetry
  question: What specifically did the obfuscated PowerShell script do after downloading
    the payload?
  requires: hb_script_activity for script block logging
  risk: The hunt relies on the first command-line downloader; if the attacker changes
    the delivery command but keeps the script behavior, the lead query will fail to
    fire.
  stage: powershell-payload-execution
- id: no-network-telemetry
  question: Was data exfiltrated to /fakeurl.htm?
  requires: hb_http_activity with URI inspection
  risk: DNS lookups confirm the host talked to the C2, but cannot confirm if data
    exfiltration occurred without HTTP URI visibility.
  stage: netsupport-rat-c2-and-data-theft
coverage:
- stage: powershell-payload-execution
  status: covered
  steps:
  - lead-powershell-downloader
- stage: rat-persistence-and-dropper-cleanup
  status: covered
  steps:
  - rare-programdata-binaries
- stage: netsupport-rat-c2-and-data-theft
  status: covered
  steps:
  - c2-dns-lookups
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: compromised-wordpress-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: tds-redirection-and-payload-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: clickfix-clipboard-social-engineering
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: iClickFix is a widespread malware framework that has compromised
    thousands of sites to deliver NetSupport RAT; a negative result over the estate
    confirms the current social engineering campaign has not successfully landed a
    beachhead.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a ClickFix social engineering lure to execute a PowerShell
  downloader that installs NetSupport RAT and establishes persistent communication
  with a multi-hop proxy C2 infrastructure.
labels:
- hunt
- attack.t1059.001
- attack.t1566
- attack.t1547.001
- attack.t1041
- attack.t1090.003
- attack.t1021.001
name: 'iClickFix: NetSupport RAT Execution and Persistence'
parameters:
  c2_domains:
    default:
    - pusykakimao.com
    - fnotusykakimao.com
    - scottvmorton.com
    description: C2 domains identified in the iClickFix research; these are used for
      payload delivery and NetSupport gateway communication.
    from:
      kind: article
      observed: '2025-12-09'
      ref: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows endpoints with direct internet access and active human
  users, as the ClickFix lure requires interaction through a browser.
references:
- name: "Sekoia \u2014 IClickFix: WordPress-targeting framework using ClickFix"
  url: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
related:
- hunt: iclickfix-wordpress-injection-discovery
  reason: Tracking the compromised WordPress sites and the TDS redirection belongs
    to an external-scanning or network-centric hunt.
  relation: out-of-scope-alternative
- hunt: iclickfix-web-redirection-delivery
  relation: follows
scenario:
  stages:
  - name: Malicious JavaScript Injection
    observables:
    - ic-tracker-js
    - ksfldfklskdmbxcvb.com
    - ahpc.gov.gh
    - dns-prefetch
    slug: compromised-wordpress-injection
    tactic: initial-access
    techniques:
    - T1566
  - name: TDS Redirection and Script Fetching
    observables:
    - ototaikfffkf.com/fffa.js
    - ksdkgsdkgkgmgm.pro/ofofo.js
    - booksbypatriciaschultz.com/liner.php
    - 'x-robots-tag: noindex'
    - YOURLS admin panel
    slug: tds-redirection-and-payload-delivery
    tactic: execution
    techniques:
    - T1566
  - name: ClickFix Clipboard Social Engineering
    observables:
    - navigator.clipboard.writeText
    - Verify you are human
    - Ctrl + V
    - Win + R
    - Unusual Web Traffic Detected
    slug: clickfix-clipboard-social-engineering
    tactic: collection
    techniques:
    - T1115
  - name: Malicious PowerShell Downloader
    observables:
    - powershell -w hidden -nop -c
    - scottvmorton.com/tytuy.json
    - 05b03a25e10535c5c8e2327ee800ff5894f5dbfaf72e3fdcd9901def6f072c6d
    - 8db6.ps1
    slug: powershell-payload-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT Persistence and Evasion
    observables:
    - ProgramData\S1kCMNfZi3\
    - client32.exe
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - SecureModule Engine v1.0.0
    - RunMRU
    slug: rat-persistence-and-dropper-cleanup
    tactic: persistence
    techniques:
    - T1555
  - name: Command and Control and Data Theft
    observables:
    - pusykakimao.com:443
    - fnotusykakimao.com:443
    - /fakeurl.htm
    - client32.ini
    - licensee KAKAN
    slug: netsupport-rat-c2-and-data-theft
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
    - T1021.001
    - T1555
  summary: IClickFix is a WordPress-targeting framework that compromises legitimate
    sites to inject malicious JavaScript and redirect users through a YOURLS-based
    Traffic Distribution System. Victims are tricked by a ClickFix-style fake CAPTCHA
    lure into executing a PowerShell command that downloads and deploys the NetSupport
    RAT for persistent remote access and data exfiltration.
series:
  index: 2
  slug: iclickfix-wordpress-targeting-framework-using-clickfix
  title: 'iClickFix: WordPress-targeting framework using ClickFix'
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


# iClickFix: NetSupport RAT Execution and Persistence

The adversary uses compromised WordPress sites to deliver a fake CAPTCHA that tricks users into executing malicious PowerShell. This hunt identifies the initial hidden PowerShell downloader pattern. If the hunt finds suspicious execution, it fans out to look for rare NetSupport binaries in ProgramData and network traffic to the infrastructure named in recent research. An agent weighs the execution and post-exploitation evidence to identify compromised hosts for isolation.

## lead-powershell-downloader
<!-- PowerShell Hidden Downloader -->
Identify the initial ClickFix-delivered command that uses hidden PowerShell windows to download the second-stage payload.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows show PowerShell executing with hidden windows and downloader cmdlets
  targeting the delivery domain scottvmorton.com. Silence means no overt ClickFix
  execution was detected.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%powershell.exe' AND LOWER(process_cmd_line) LIKE '%-w hidden%' AND (LOWER(process_cmd_line) LIKE '%iwr%' OR LOWER(process_cmd_line) LIKE '%invoke-webrequest%' OR LOWER(process_cmd_line) LIKE '%scottvmorton.com%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-lead-read
<!-- Initial Lead Assessment -->
```agent target=hunter
cite: required
context:
- lead-powershell-downloader
max_iterations: 3
objective: 'Determine if the PowerShell command found in the lead matches the iClickFix
  pattern: hidden window, execution policy bypass, and use of iwr or invoke-webrequest
  to the scottvmorton delivery domain.'
success_criteria: A verdict of malicious or suspicious for the lead command.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Proceed to Enrichment? -->
if~: "the agent-lead-read verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → fan-out-enrichment
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-process-telemetry)
else: → close-out

## fan-out-enrichment
<!-- Enrich with Persistence and C2 Lookups -->
parallel:
- → rare-programdata-binaries
- → c2-dns-lookups
join: → agent-final-triage

## rare-programdata-binaries
<!-- Rare ProgramData Process Paths -->
Identify NetSupport RAT binaries like client32.exe in unique, non-standard ProgramData subdirectories per host.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary path seen on only a few hosts across the fleet; legitimate ProgramData
  software is typically widespread.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 5
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, LOWER(process_path) AS path, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\programdata\%' AND (LOWER(process_path) LIKE '%client32.exe' OR LOWER(process_path) LIKE '%\s1kcmnfzi3\%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, path
```

## c2-dns-lookups
<!-- DNS Lookups to NetSupport C2 -->
Find connections to the specific domains used by the NetSupport RAT gateways as identified in the research.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: DNS resolutions for pusykakimao.com or fnotusykakimao.com associated with
  processes like explorer.exe or client32.exe.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-triage
<!-- Consolidate Infection Evidence -->
```agent target=hunter
cite: required
context:
- agent-lead-read
- rare-programdata-binaries
- c2-dns-lookups
max_iterations: 5
objective: Determine if the host is compromised by NetSupport RAT by weighing the
  lead execution, the presence of rare ProgramData binaries, and network traffic to
  known gateway domains.
success_criteria: A verdict of malicious per host citing the PowerShell process, the
  local file path, and the DNS lookup.
tools:
- endpoint
```

## decision-route-response
<!-- Route on Verdict -->
if~: "the agent-final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, preserve the ProgramData subdirectories for forensics, and identify the user credentials that were active at the time of the PowerShell execution.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the cited rows from the triage step. Verify the ProgramData path and the DNS connection process. If confirmed, check for lateral movement attempts via RDP and check the clipboard content if possible.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record the hunt results. If no malicious activity was found, note any false positives from common PowerShell updaters for future exclusion.
```
→ end
