---
analysis: This hunt uses a robust behavioral lead (HTTP /config/ POST patterns) to
  gate expensive extension inventory and file searches. This correlation between network
  behavior and file-level extension activity is more resilient than a single rule
  matching a static extension ID.
blind_spots:
- id: limited-network-visibility
  question: Whether the /config/ URI paths are visible within encrypted WebSocket
    traffic.
  requires: TLS inspection on port 443
  risk: Adversaries using encrypted channels without a proxy or TLS offload will not
    show path-level indicators in hb_http_activity.
  stage: falcon-browser-c2
- id: limited-telemetry-retention
  question: Whether the initial extension sideload occurred outside the 14-day window.
  requires: Enhanced log retention for HTTP and File events
  risk: Persistence established before the lookback window will not show the installation
    or initial configuration activity.
  stage: initial-access-web-compromise
coverage:
- stage: initial-access-web-compromise
  status: covered
  steps:
  - http-config-path-lead
- stage: browser-extension-persistence
  status: covered
  steps:
  - find-falcon-extension-id
  - extension-file-activity
- stage: falcon-browser-c2
  status: covered
  steps:
  - http-config-path-lead
- reason: 'Belongs to another part of the ''The XG Files: Falcon C2 Flying Under The
    (Browser) Radar'' series.'
  stage: antino-implant-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''The XG Files: Falcon C2 Flying Under The
    (Browser) Radar'' series.'
  stage: antino-host-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''The XG Files: Falcon C2 Flying Under The
    (Browser) Radar'' series.'
  stage: antino-onedrive-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The Falcon framework targets government and defense sectors for intelligence
    collection. Negative results confirm that the estate is not currently reporting
    this specific behavioral pattern or malicious extension.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence via a malicious browser extension
  and is using it to communicate with a C2 framework via specific /config/ path structures
  and POST requests.
labels:
- hunt
- attack.t1176
- attack.t1071.001
- attack.t1566
- attack.t1190
- command and control
- execution
- initial access
- persistence
name: Falcon Browser Compromise and Extension Persistence
parameters:
  c2_domains:
    default:
    - fonts.tarotfree101.top
    - fonts.chrorne.com
    - robot.avbliud.com
    description: Known C2 domains associated with the Falcon framework.
    from:
      kind: article
      observed: '2026-11-11'
      ref: unit42-falcon-c2
    type: list[domain]
  extension_files:
    default:
    - analytics-core.js
    - background.js
    - content-script.js
    - offscreen.js
    - page.js
    - sandbox.js
    description: Specific filenames within the Falcon extension package.
    from:
      kind: article
      observed: '2026-11-11'
      ref: unit42-falcon-c2
    type: list[string]
  extension_id:
    default: mbidcmlcbgbphpoacojjbmfpohcimjji
    description: The Chrome extension ID for the Falcon implant.
    from:
      kind: article
      observed: '2026-11-11'
      ref: unit42-falcon-c2
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine for network and file activity.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the expensive queries; leave empty
      for fleet-wide.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target all corporate and administrative endpoints. Prioritize hosts that
  access government portals or webmail. Use the lookback period to cover the initial
  compromise and follow-on C2 phases.
references:
- name: "Unit 42 \u2014 The XG Files: Falcon C2 Flying Under The (Browser) Radar"
  url: https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
related:
- hunt: falcon-antino-host-persistence
  reason: This hunt targets the browser-based persistence; the Antino implant uses
    standard Windows persistence mechanisms and is a separate stage.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Strategic Web Compromise
    observables:
    - fonts.tarotfree101.top
    - fonts.chrorne.com
    - robot.avbliud.com
    - victim_common.js
    - victim.js
    slug: initial-access-web-compromise
    tactic: initial-access
    techniques:
    - T1190
    - T1566
  - name: Software Extension Persistence
    observables:
    - mbidcmlcbgbphpoacojjbmfpohcimjji
    - Hm_lvt_$
    - Hm_lvt__
    - background.js
    - content-script.js
    - analytics-core.js
    - offscreen.html
    - page.html
    - sandbox.html
    slug: browser-extension-persistence
    tactic: persistence
    techniques:
    - T1176
  - name: Falcon Browser-Based C2
    observables:
    - /config/
    - /config/*/hta
    - /config/*/html
    - /config/*/wscript
    - port 443
    - port 8080
    - WebSocket connection
    slug: falcon-browser-c2
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Antino Payload Execution
    observables:
    - flashcenter_pp_ax_install_en.exe
    - microsoft-flash.com
    - wps-cn.com
    slug: antino-implant-delivery
    tactic: execution
    techniques:
    - T1218
    - T1574.002
  - name: Endpoint Persistence and Execution
    observables:
    - Registry Run keys
    - PowerShell commands
    slug: antino-host-persistence
    tactic: persistence
    techniques:
    - T1547.001
    - T1059.001
  - name: Exfiltration via OneDrive C2
    observables:
    - Microsoft OneDrive API
    - window.fetch
    - xmlhttprequest.open
    slug: antino-onedrive-c2
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1041
  summary: Falcon C2 (aka XG) is a browser-centric threat framework that compromises
    government web applications to inject malicious JavaScript and install rogue browser
    extensions. These extensions facilitate credential and email theft while acting
    as a delivery mechanism for the Antino implant, which establishes persistence
    on the host and utilizes Microsoft OneDrive as an obfuscated C2 channel.
series:
  index: 1
  slug: the-xg-files-falcon-c2-flying-under-the-browser-radar
  title: 'The XG Files: Falcon C2 Flying Under The (Browser) Radar'
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


# Falcon Browser Compromise and Extension Persistence

This hunt identifies the Falcon (XG) browser-based C2 framework by searching for its characteristic /config/ URL patterns and rare POST traffic using Baidu-mimicking tracking markers. When a behavioral match is found, the hunt gates more expensive inventory and file telemetry searches to locate the specific malicious Chrome extension and its core JavaScript components within browser profile directories. This gated approach prioritizes robust behavioral indicators over static extension IDs while ensuring file-level corroboration within the user's extension folder.

## http-config-path-lead
<!-- Identify Falcon Behavioral HTTP Activity -->
Establish a behavioral lead by finding rare POST requests or Baidu-mimicking query parameters directed at /config/ paths or known C2 domains.

```sqlite target=web role=detection-candidate params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare HTTP POSTs to /config/ paths or query parameters mimicking Baidu analytics.
  Silence indicates no active framework-style communication was captured during the
  window.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 5
reads:
- device_hostname
- url_hostname
- url_path
- http_method
- url_query
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, url_query, COUNT(*) AS requests, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/config/%' OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND (LOWER(http_method) = 'post' OR LOWER(url_query) LIKE '%hm_lvt_%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4, 5 HAVING COUNT(DISTINCT device_hostname) <= 5 ORDER BY requests DESC
```

## assess-http-lead
<!-- Assess HTTP Lead -->
```agent target=hunter
cite: required
context:
- http-config-path-lead
max_iterations: 3
objective: Determine if the identified HTTP POSTs or query parameters match the Falcon
  (XG) command-and-control behavior.
success_criteria: A clear determination of malicious | suspicious | benign for the
  network activity.
tools:
- endpoint
- web
```

## gate-on-http
<!-- Gate on HTTP Behavior -->
if~: "the assess-http-lead verdict confirms Falcon-like network communication" (confidence: high, judge=hunter)
then: → corroborate-extension-presence
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-network-visibility)
else: → close-out

## corroborate-extension-presence
<!-- Corroborate Extension Presence -->
parallel:
- → find-falcon-extension-id
- → extension-file-activity
join: → final-triage

## find-falcon-extension-id
<!-- Search for Falcon Extension ID -->
Check the software inventory for the specific malicious extension ID on hosts showing network leads.

```sqlite target=endpoint role=scoping params=(extension_id=extension_id, scope_hosts=scope_hosts)
~~~yaml
expected: Specific hits for the Falcon extension ID. Silence proves it is not currently
  registered in the managed inventory.
reads:
- device_hostname
- package_name
- package_uid
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, package_name, package_uid, package_version FROM hb_software_inventory WHERE (LOWER(package_uid) = '{{extension_id}}' OR LOWER(package_name) LIKE '%falcon%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## extension-file-activity
<!-- Monitor Extension File Activity -->
Search for core extension filenames within browser profile directories to identify sideloaded or manual installations.

```sqlite target=endpoint role=enrichment params=(extension_files=extension_files, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Touches on core JS files within legitimate extension directories. Silence
  suggests the extension files are not being accessed or do not exist in the common
  paths.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE instr(',' || '{{extension_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND LOWER(file_path) LIKE '%\\extensions\\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final Triage and Correlation -->
```agent target=hunter
cite: required
context:
- assess-http-lead
- find-falcon-extension-id
- extension-file-activity
max_iterations: 5
objective: Analyze whether the network behavior, extension inventory, and file activity
  together indicate a Falcon compromise on the host.
success_criteria: A final verdict citing specific rows from all three surfaces.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-telemetry-retention)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Remove the malicious browser extension and its associated files. Collect browser local storage and cookies to verify the presence of Hm_lvt markers.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review all cited HTTP and file activity. Confirm the /config/ POST requests are unauthorized and correlate with browser-based file touches.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Document findings and false positives. If the network behavioral query was confirmed malicious, recommend promotion to a standing detection rule.
```
→ end
