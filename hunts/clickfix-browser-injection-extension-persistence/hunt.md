---
analysis: A standard rule might fire on the gviz string, but a hunt is required to
  follow the chain from an HTTP lure to manual injection and finally to persistence
  in an extension. This hunt correlates software inventory, HTTP, script blocks, file
  activity, and process prevalence to confirm an intrusion.
blind_spots:
- id: browser-memory-blind-spot
  question: Was the script injected only into memory via the navigation bar without
    triggering script-block logging?
  requires: Browser-internal instrumentation
  risk: A user-injected script that does not trigger persistence may execute entirely
    in-memory and be invisible to script surfaces.
  stage: user-assisted-script-injection
- id: encrypted-extension-data
  question: What is the content of the scripts stored inside Tampermonkey's private
    database?
  requires: Extension-specific database parsing
  risk: The hunt can see file writes to extension folders, but cannot read the script
    text inside extension-managed IndexedDB or storage files without forensic tooling.
  stage: browser-extension-persistence
coverage:
- stage: social-engineering-lure-delivery
  status: covered
  steps:
  - lure-delivery-http
- stage: user-assisted-script-injection
  status: covered
  steps:
  - loader-execution-scripts
- stage: browser-extension-persistence
  status: covered
  steps:
  - scoping-tampermonkey
  - persistence-tampermonkey-files
- stage: cryptocurrency-theft-and-skimming
  status: covered
  steps:
  - collection-clipboard-skimmer
- reason: 'Belongs to another part of the ''ClickFix moves into the browser: Cryptocurrency
    theft with Google-hosted C2'' series.'
  stage: google-visualization-api-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Browser-based script injection and persistence bypass traditional
    OS security controls and directly threaten financial assets; confirming the integrity
    of the user's web interaction surface is essential.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a social engineering lure to trick a user into manually
  injecting a JavaScript loader or installing a malicious Tampermonkey script that
  facilitates persistent cryptocurrency theft via the Google Visualization API.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1176
- attack.t1115
name: ClickFix Browser Injection and Extension Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_domains:
    default:
    - paste.sh
    - docs.google.com
    description: Domains used to host lures and first-stage loader scripts.
    from:
      kind: article
      observed: '2026-09-08'
      ref: talos-clickfix-2026
    type: list[domain]
  lure_path_patterns:
    default:
    - /document/d/
    - /spreadsheets/d/
    description: Specific URL path patterns or fragments found in social engineering
      lures.
    from:
      kind: article
      observed: '2026-09-08'
      ref: talos-clickfix-2026
    type: list[string]
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty to scan the entire
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/clickfix-moves-into-the-browser/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints with Tampermonkey installed first. Prioritize users
  with known access to financial or cryptocurrency domains.
references:
- name: "Cisco Talos \u2014 ClickFix moves into the browser: Cryptocurrency theft\
    \ with Google-hosted C2"
  url: https://blog.talosintelligence.com/clickfix-moves-into-the-browser/
related:
- hunt: google-visualization-api-c2
  reason: The C2 hunt focuses on broader network patterns of Gviz abuse, while this
    hunt focuses on the user-assisted injection and extension persistence scenario.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering Lure Delivery
    observables:
    - Telegram channel posts
    - DarkForums posts
    - paste.sh links
    - 'Google Docs filename: ''API Logic Flaw'''
    - 'Google Docs URL: docs.google.com/document/d/'
    slug: social-engineering-lure-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: User-Assisted Script Injection
    observables:
    - 'javascript: protocol used in Chrome navigation bar'
    - Pasting obfuscated JS from paste.sh
    - Base64 encoded strings in browser memory
    - Injection into DOM <script> elements
    slug: user-assisted-script-injection
    tactic: execution
    techniques:
    - T1059.001
  - name: Browser Extension Persistence
    observables:
    - Tampermonkey extension installation
    - Malicious loader script in Tampermonkey configuration
    - Scripts targeting simpleswap.io or swapzone.io
    slug: browser-extension-persistence
    tactic: persistence
    techniques:
    - T1176
  - name: Google Visualization API C2
    observables:
    - docs.google.com/spreadsheets/d/*/gviz/tq
    - 'Visualization API queries: SELECT B, SELECT A'
    - JSON formatted data returned from Google Sheets
    - Appended data via HTML POST to Google Forms
    slug: google-visualization-api-c2
    tactic: command-and-control
    techniques:
    - T1071
  - name: Cryptocurrency Theft and Skimming
    observables:
    - Hooking browser fetch API
    - Replacing cryptocurrency deposit addresses in server responses
    - Replacing user clipboard content
    - Displaying counterfeit 'bonus' UI elements
    slug: cryptocurrency-theft-and-skimming
    tactic: collection
    techniques:
    - T1115
  summary: Actors lure cryptocurrency traders via Telegram and dark web forums to
    'exploit' non-existent API flaws using a variation of ClickFix social engineering.
    Victims are tricked into manually injecting malicious JavaScript into their browsers
    or the Tampermonkey extension, which establishes persistence and uses the Google
    Visualization API to fetch second-stage skimmers from public Google Sheets to
    steal cryptocurrency by hijacking the clipboard.
series:
  index: 1
  slug: clickfix-moves-into-the-browser-cryptocurrency-theft-with-google-hosted-c2
  title: 'ClickFix moves into the browser: Cryptocurrency theft with Google-hosted
    C2'
  total: 2
severity: medium
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


# ClickFix Browser Injection and Extension Persistence

This hunt identifies ClickFix campaigns targeting browser sessions rather than the operating system. It identifies the delivery of social engineering lures via Google Docs and the subsequent persistence through the Tampermonkey extension. The hunt follows a phased flow: first scoping for the extension, then identifying initial delivery and execution signals, and finally corroborating with file-based persistence and behavioral indicators of cryptocurrency skimming like rare clipboard manipulation.

## scoping-tampermonkey
<!-- Scope hosts with Tampermonkey installed -->
Identify hosts where the Tampermonkey extension is present, as it is the campaign's primary method for script persistence.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with the extension. Silence indicates low baseline risk
  for the persistence stage of this specific campaign.
reads:
- asset_scope
- device_hostname
- package_name
- package_uid
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, package_name, package_version, package_uid FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%tampermonkey%' OR package_uid = 'dhdgffkkebhmkfjojejmpbldmpobfkfo') AND asset_scope = 'endpoint'
```

## parallel-early-signals
<!-- Initial lure and loader signals -->
parallel:
- → lure-delivery-http
- → loader-execution-scripts
join: → agent-early-triage

## lure-delivery-http
<!-- HTTP traffic to lure domains -->
Identify users accessing the Google Docs or Paste sites mentioned in the social engineering lures.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, lure_domains=lure_domains, lure_path_patterns=lure_path_patterns, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts visiting the specific Google Docs or Paste.sh links. This provides
  the context for subsequent script execution.
reads:
- device_hostname
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND (LOWER(url_path) LIKE '%/document/d/%' OR LOWER(url_path) LIKE '%/spreadsheets/d/%' OR instr(',' || '{{lure_path_patterns}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## loader-execution-scripts
<!-- Google Visualization API script execution -->
Detect the execution of the first-stage loader script which uses the Gviz API for C2.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script contents showing query construction against Google spreadsheets.
  This is the primary indicator of the ClickFix loader.
reads:
- actor_user_name
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(LOWER(script_content), 'gviz/tq') > 0 OR instr(LOWER(script_content), 'google.visualization') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage early loader activity -->
```agent target=hunter
cite: required
context:
- lure-delivery-http
- loader-execution-scripts
max_iterations: 3
objective: Determine if any host has both accessed a lure domain and executed a script
  containing Gviz API patterns.
success_criteria: A per-host verdict of suspicious or malicious citing the specific
  URL and script content.
tools:
- endpoint
- web
```

## parallel-follow-on
<!-- Persistence and skimming behavior -->
parallel:
- → persistence-tampermonkey-files
- → collection-clipboard-skimmer
join: → agent-final-synthesis

## persistence-tampermonkey-files
<!-- Tampermonkey persistence files -->
Find file modifications in the Tampermonkey storage directory.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Writes to extension storage. This confirms the 'persistence' stage of the
  campaign.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(file_path) LIKE '%tampermonkey%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## collection-clipboard-skimmer
<!-- Rare clipboard manipulation -->
Detect the address-swapping behavior of the skimmer by identifying rare usage of clipboard interaction tools.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Low-prevalence clipboard manipulation. Fleet-wide admin scripts will be
  filtered out, leaving manual or malicious activity.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%clip.exe' OR LOWER(process_cmd_line) LIKE '%get-clipboard%' OR LOWER(process_cmd_line) LIKE '%set-clipboard%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3
```

## agent-final-synthesis
<!-- Synthesize full attack chain -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- persistence-tampermonkey-files
- collection-clipboard-skimmer
max_iterations: 5
objective: Confirm the presence of a persistent browser-based skimmer by correlating
  the early triage results with follow-on persistence and collection signals.
success_criteria: A final malicious verdict citing the specific gviz loader and the
  associated persistence or skimming activity.
tools:
- endpoint
- web
```

## infection-decision
<!-- Infection routing -->
if~: "the agent-final-synthesis verdict is malicious for at least one host, citing gviz loader execution and either file persistence or skimmer activity" (confidence: high, judge=hunter)
then: → action-contain-host
indeterminate: → task-forensic-audit
unavailable: → task-forensic-audit (blind_spot: browser-memory-blind-spot)
else: → task-close-out

## action-contain-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Inform the user of browser compromise and revoke active web sessions, specifically targeting crypto trading sites SimpleSwap and SwapZone.
```
→ task-forensic-audit

## task-forensic-audit
<!-- Forensic extension audit -->
```manual target=analyst
Audit the user's Chrome Profile. Inspect Tampermonkey's private storage (Local Extension Settings) for scripts targeting SimpleSwap or SwapZone. Extract any spreadsheet IDs from gviz URLs.
```
→ task-close-out

## task-close-out
<!-- Close out and document -->
```manual target=analyst
Document the hosts examined. If malicious Tampermonkey scripts were found, contribute their signatures to detection engineering for a standing rule.
```
→ end
