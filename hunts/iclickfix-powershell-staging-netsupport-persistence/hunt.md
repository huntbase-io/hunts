---
analysis: A simple rule might flag 'powershell hidden', but this hunt uses a baseline
  of ProgramData processes and corroborates with registry, script, and DNS telemetry
  to confirm a multi-stage infection, providing the context an analyst needs to justify
  isolation.
blind_spots:
- id: incomplete-telemetry
  owner: Endpoint Engineering
  question: whether the RAT persists on hosts without registry or process monitoring
  remediation: Audit agent health across the estate.
  requires: EDR agent coverage on all endpoints
  risk: Endpoints without full agent coverage may host persistence that remains invisible
    to this hunt.
  stage: persistence-and-payload-delivery
- id: no-script-logging
  owner: Security Engineering
  question: the full content of the obfuscated stager logic
  remediation: Enable PowerShell Script Block Logging (Event ID 4104).
  requires: hb_script_activity (PowerShell Event 4104)
  risk: Without script block logging, heavily obfuscated or in-memory PowerShell commands
    might not be fully decodable.
  stage: powershell-stager-execution
coverage:
- stage: powershell-stager-execution
  status: covered
  steps:
  - hidden-powershell-staging
  - stager-script-logic
- stage: persistence-and-payload-delivery
  status: covered
  steps:
  - run-key-persistence
  - rare-programdata-processes
- stage: c2-communication-netsupport
  status: covered
  steps:
  - netsupport-c2-dns
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: initial-access-wordpress-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: tds-redirection-js
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: clickfix-social-engineering
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The IClickFix framework has compromised over 3,800 WordPress sites
    to deliver NetSupport RAT. Detecting the persistence and C2 communication on the
    endpoint is the last opportunity to stop data exfiltration from the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a hidden PowerShell stager to drop NetSupport RAT
  into ProgramData and established persistence via a Run key following a ClickFix
  social engineering prompt.
labels:
- hunt
- attack.t1059.001
- attack.t1547.001
- attack.t1041
- attack.t1566
name: 'iClickFix: PowerShell Staging and NetSupport RAT Persistence'
parameters:
  c2_domains:
    default:
    - scottvmorton.com
    - pusykakimao.com
    - fnotusykakimao.com
    description: Stager hosting and NetSupport C2 domains named in the research.
    from:
      kind: article
      observed: '2025-12-09'
      ref: Sekoia IClickFix
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt.
    type: list[host]
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
rationale: Focus on Windows workstations and general user-profile systems where web
  browsing is prevalent. Start with systems that have PowerShell execution logged
  in the last 14 days.
references:
- name: 'Sekoia - Meet IClickFix: a widespread WordPress-targeting framework using
    the ClickFix tactic'
  url: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
related:
- hunt: iclickfix-delivery-redirection
  reason: This hunt focuses on the endpoint staging; the initial delivery and TDS
    redirection are handled in a separate browser/network-focused hunt.
  relation: out-of-scope-alternative
- hunt: iclickfix-redirection-lure-delivery
  relation: follows
scenario:
  stages:
  - name: Compromised WordPress Injection
    observables:
    - <script id="ic-tracker-js">
    - ksfldfklskdmbxcvb.com/gigi?ts=
    slug: initial-access-wordpress-injection
    tactic: initial-access
    techniques:
    - T1566
  - name: Traffic Distribution Redirection
    observables:
    - ototaikfffkf.com/fffa.js
    - ksdkgsdkgkgmgm.pro/ofofo.js
    - 'x-robots-tag: noindex'
    slug: tds-redirection-js
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: ClickFix Social Engineering
    observables:
    - navigator.clipboard.writeText
    - booksbypatriciaschultz.com/liner.php
    - Verify you are human
    slug: clickfix-social-engineering
    tactic: collection
    techniques:
    - T1115
  - name: PowerShell Stager Execution
    observables:
    - powershell -w hidden -nop -c
    - scottvmorton.com/tytuy.json
    - 8db6.ps1
    slug: powershell-stager-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT Persistence and Installation
    observables:
    - client32.exe
    - ProgramData\S1kCMNfZi3\
    - Software\Microsoft\Windows\CurrentVersion\Run
    slug: persistence-and-payload-delivery
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT C2 Communication
    observables:
    - pusykakimao.com:443
    - fnotusykakimao.com:443
    - fakeurl.htm
    slug: c2-communication-netsupport
    tactic: exfiltration
    techniques:
    - T1041
  summary: The iClickFix campaign leverages compromised WordPress websites to inject
    a malicious JavaScript framework that delivers the ClickFix social engineering
    lure. Victims are induced to run a PowerShell command that executes a downloader
    script, ultimately installing the NetSupport RAT with persistence via the Windows
    registry.
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


# iClickFix: PowerShell Staging and NetSupport RAT Persistence

This hunt targets the endpoint-resident stages of the iClickFix framework. It identifies hidden PowerShell commands used to download script payloads from attacker-controlled JSON endpoints, monitors for rare executables launched from ProgramData (a common NetSupport staging area), and verifies persistence mechanisms in the Windows Registry. The hunt correlates these behaviors with script block contents and NetSupport C2 network activity to differentiate automated installers from malicious staging.

## hidden-powershell-staging
<!-- Hidden PowerShell Stager Execution -->
Identify the initial ClickFix-delivered command which uses hidden/non-interactive flags to download payloads.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A PowerShell process with hidden window flags downloading a file (often
  .json or .ps1) to ProgramData. Silence is not evidence of absence if the stager
  used a different interpreter.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\powershell.exe' OR LOWER(process_name) LIKE '%\\pwsh.exe') AND (process_cmd_line LIKE '%-w hidden%' OR process_cmd_line LIKE '%-WindowStyle Hidden%') AND (process_cmd_line LIKE '%-nop%' OR process_cmd_line LIKE '%-NoProfile%') AND (process_cmd_line LIKE '%iwr%' OR process_cmd_line LIKE '%Invoke-WebRequest%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate Persistence and C2 -->
parallel:
- → stager-script-logic
- → run-key-persistence
- → rare-programdata-processes
- → netsupport-c2-dns
join: → triage-agent

## stager-script-logic
<!-- Stager Logic in Script Activity -->
Capture the script logic and file download behavior directly from script block telemetry, even if command lines were truncated.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing references to the stager domain or NetSupport filenames
  like client32.exe.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%scottvmorton%' OR LOWER(script_content) LIKE '%client32%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## run-key-persistence
<!-- Persistence via Run Keys -->
Identify registry Run keys pointing to components in ProgramData or user-writable paths.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A Run key created or modified to point to an executable in ProgramData.
  Silence means no registry writes to these paths were logged.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\currentversion\\run%' AND (LOWER(reg_value_data) LIKE '%\\programdata\\%' OR LOWER(reg_value_data) LIKE '%client32.exe%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-programdata-processes
<!-- Rare Processes in ProgramData -->
Identify rare binaries executing from non-Microsoft subfolders of ProgramData.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Executables in ProgramData subfolders seen on very few hosts. Silence is
  evidence of absence for established RAT presence in those paths.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_file_description
- process_path
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_path, process_file_description, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE 'c:\\programdata\\%' AND LOWER(process_path) NOT LIKE 'c:\\programdata\\microsoft\\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING host_count < 3 ORDER BY host_count ASC
```

## netsupport-c2-dns
<!-- NetSupport RAT C2 DNS Activity -->
Correlate host activity with known C2 infrastructure using the report's indicators.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
expected: DNS queries to the named domains, particularly from processes identified
  in the ProgramData step.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Correlate iClickFix Indicators -->
```agent target=hunter
cite: required
context:
- hidden-powershell-staging
- stager-script-logic
- run-key-persistence
- rare-programdata-processes
- netsupport-c2-dns
max_iterations: 6
objective: 'Determine if any hosts show the complete iClickFix endpoint lifecycle:
  hidden PowerShell download -> rare ProgramData executable -> C2 communication.'
success_criteria: A per-host verdict citing evidence for each stage of the scenario.
tools:
- endpoint
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## contain-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host using the endpoint management tool and proceed to analyst review for forensic collection of the ProgramData directory.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Confirm the agent's findings. Check for additional persistence in scheduled tasks and perform a memory sweep if available to confirm NetSupport RAT process injection.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the absence of iClickFix staging and persistence on monitored hosts.
```
→ end
