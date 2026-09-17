---
analysis: OWAReaper utilizes legitimate services (GitHub, public image CDNs) to obfuscate
  its traffic. A single detection rule on CDN traffic would generate excessive noise;
  this hunt uses prevalence counting on DNS subdomains and correlates GitHub API activity
  with specific, encrypted URI patterns to provide context that a standing rule cannot.
blind_spots:
- id: no-http-body-inspection
  owner: Network Engineering
  question: whether the file contents exfiltrated via POST requests match the sensitive
    OWA files named in the report
  remediation: Deploy TLS inspection on egress proxies.
  requires: Deep Packet Inspection (DPI) or Full Packet Capture
  risk: Exfiltration of files via HTTP POST is only detectable via URI path substrings;
    content cannot be verified without body inspection.
  stage: exfiltration-and-tunneling
- id: browser-localstorage-invisibility
  owner: Endpoint Engineering
  question: whether OWAReaper has written its encrypted payload to PageDataPayload.OwaUserDefaultSettings
  remediation: Implement osquery extensions for Chrome/Edge localStorage monitoring.
  requires: Browser artifact collection (localStorage)
  risk: The primary persistence mechanism is stored in browser memory/local storage
    and is not visible to standard file or registry surfaces.
coverage:
- stage: multi-channel-c2
  status: covered
  steps:
  - github-commit-search
  - cdn-proxy-activity
- stage: exfiltration-and-tunneling
  status: covered
  steps:
  - cdn-proxy-activity
  - dns-tunneling-analysis
- reason: Covered by the first hunt in this series focusing on hb_http_activity and
    exploit triggers.
  stage: initial-access-owa-exploit
  status: out_of_scope
- reason: Implant resides in browser localStorage and OWA context; not visible to
    hb_process_activity or hb_file_activity.
  stage: owareaper-execution-and-persistence
  status: not_visible
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: credential-and-token-theft
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: mailbox-permission-manipulation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: TA488 is a sophisticated actor targeting high-value sectors. The
    OWAReaper implant represents an evolution in stealthy, browser-based persistence
    that survives traditional host-level remediation. Identifying the network-based
    exfiltration and C2 channels is the most reliable way to detect active compromises
    that have already bypassed endpoint controls.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed OWAReaper to exfiltrate session data and receive
  commands via GitHub commit searches and public image CDN proxies, blending with
  legitimate browser traffic.
labels:
- hunt
- attack.t1102.001
- attack.t1090.003
- attack.t1071.001
- attack.t1041
- attack.t1572
name: Network-Based C2 and Exfiltration (TA488 OWAReaper)
parameters:
  c2_relay_domains:
    default:
    - acocdn.com
    description: The final actor-controlled C2 relay domain.
    from:
      kind: article
      observed: '2026-07-22'
      ref: proofpoint-ta488-owareaper
    type: list[domain]
  cdn_domains:
    default:
    - weserv.nl
    - images.weserv.nl
    - i3.wp.com
    - slack-imgs.com
    description: Legitimate image CDN domains used as C2 proxies.
    from:
      kind: article
      observed: '2026-07-22'
      ref: proofpoint-ta488-owareaper
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
    from: https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially focus on systems identified in hb_vulnerability_finding
  with CVE-2026-42897. If the vulnerability finding surface is empty, widen the scope
  to all hosts accessing OWA via hb_http_activity.
references:
- name: 'Cleaning Out Inboxes: TA488 Comes for Outlook with Another Half-Click Exploit'
  url: https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit
related:
- hunt: owareaper-persistence-and-permission-manipulation
  reason: This hunt focuses on the network telemetry; mailbox permission changes and
    OWA add-in theft require identity and mailbox-native auditing.
  relation: out-of-scope-alternative
- hunt: owareaper-browser-implant-mechanics
  relation: follows
scenario:
  stages:
  - name: Exploitation of Outlook Web Access
    observables:
    - CVE-2026-42897
    - 'Lure emails with subjects: ''Semiconductor Supply Chain Indicators'', ''Global
      Gas Markets'''
    - Social media icons in HTML message body containing Base64-encoded JavaScript
    - onload= event handlers used to trigger script execution
    slug: initial-access-owa-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: OWAReaper Execution and Local Persistence
    observables:
    - PageDataPayload.OwaUserDefaultSettings key in localStorage
    - Requests to /owa/sessiondata.ashx gathering user and mailbox info
    - Hidden iframe added to OWA IndexedDB message cache
    - Disabled OWA pop-ups and right-click functionality
    slug: owareaper-execution-and-persistence
    tactic: persistence
    techniques:
    - T1204.001
  - name: Credential and OAuth Token Theft
    observables:
    - Invisible input elements at -9999px/-9998px for autofill harvesting
    - Calls to GetClientAccessToken to steal OAuth tokens from Outlook add-ins
    slug: credential-and-token-theft
    tactic: credential-access
    techniques:
    - T1056.001
    - T1528
  - name: Server-Side Mailbox Manipulation
    observables:
    - UpdateFolder calls to grant Owner-level permissions to the 'Default' user alias
    - Unauthorized access to mailboxes via the 'Default' user identity
    slug: mailbox-permission-manipulation
    tactic: persistence
    techniques:
    - T1098.002
  - name: Command and Control via GitHub and CDNs
    observables:
    - GitHub Commit Search API queries for victim email addresses
    - Traffic to images.weserv.nl, i3.wp.com, and slack-imgs.com
    - 'C2 relay domain: acocdn.com'
    - AES-CTR encrypted URI paths
    slug: multi-channel-c2
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1090.003
    - T1071.001
  - name: Exfiltration and DNS Tunneling
    observables:
    - URI pattern /assets/v1_ containing Base64-encoded AES-CTR data
    - DNS label tunneling for exfiltration fallback
    - 'HTTP POST requests for files: msanalytics.json, ews_extensions_debug.json,
      poison_wizard_error_dom.html'
    slug: exfiltration-and-tunneling
    tactic: exfiltration
    techniques:
    - T1041
    - T1572
  summary: TA488 (Void Blizzard) exploited CVE-2026-42897, an XSS vulnerability in
    Outlook Web Access, to deploy the OWAReaper JavaScript implant. The malware persists
    via browser LocalStorage and manipulation of Exchange mailbox permissions, using
    GitHub and image CDNs to proxy command and control traffic and exfiltrate data
    via DNS tunneling.
series:
  index: 3
  slug: ta488-outlook-half-click-exploit
  title: TA488 Outlook half-click exploit
  total: 3
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Network-Based C2 and Exfiltration (TA488 OWAReaper)

This hunt identifies the network-based command and control (C2) and exfiltration channels utilized by TA488's OWAReaper implant. OWAReaper is a browser-based implant that leverages Outlook Web Access (OWA) to maintain persistence. It utilizes non-traditional C2 channels, including GitHub's Commit Search API to fetch victim-specific commands and public image CDNs (e.g., weserv.nl, WordPress, Slack) to relay encrypted exfiltration data, effectively bypassing host-level detections. The hunt focuses on correlating GitHub API queries for commit data with rare proxy patterns and DNS tunneling indicators to the C2 relay infrastructure.

## scope-vulnerable-exchange
<!-- Systems with CVE-2026-42897 findings -->
Identify systems where the OWA server vulnerability exploited by TA488 has been detected.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of device UIDs that have not yet been patched for the OWA XSS vulnerability.
  Silence indicates no known vulnerable OWA servers in the managed estate.
reads:
- device_uid
- cve_uid
- affected_package_name
- affected_package_version
- severity
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_uid, cve_uid, affected_package_name, affected_package_version, severity FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-42897'
```

## parallel-c2-exfiltration
<!-- Examine C2 and Exfiltration Channels -->
parallel:
- → github-commit-search
- → cdn-proxy-activity
- → dns-tunneling-analysis
join: → triage-implant-activity

## github-commit-search
<!-- GitHub Commit Search API Traffic -->
Identify hosts querying GitHub for commit data, a method OWAReaper uses to fetch victim-specific commands.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Requests to the GitHub Commit Search API. Frequent queries from non-developer
  machines are suspicious.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, time FROM hb_http_activity WHERE LOWER(url_hostname) = 'api.github.com' AND LOWER(url_path) LIKE '%/search/commits%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## cdn-proxy-activity
<!-- CDN Proxying and Data Exfiltration -->
Detect traffic to public image CDNs with URI patterns matching OWAReaper's exfiltration and file upload methods.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, cdn_domains=cdn_domains)
~~~yaml
expected: POST or GET requests containing the OWAReaper assets pattern or specific
  Exchange-related diagnostic filenames in the URI.
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
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{cdn_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_hostname) = 'acocdn.com') AND (LOWER(url_path) LIKE '%/assets/v1_%' OR LOWER(url_path) LIKE '%msanalytics.json%' OR LOWER(url_path) LIKE '%ews_extensions_debug.json%' OR LOWER(url_path) LIKE '%poison_wizard_error_dom.html%' OR LOWER(url_path) LIKE '%sessiondata.ashx%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-tunneling-analysis
<!-- DNS Tunneling Baseline -->
Identify potential exfiltration over DNS by finding hosts with high volumes of unique subdomains for the C2 relay.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single host making many distinct DNS requests to subdomains of acocdn.com.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, COUNT(DISTINCT query_hostname) as unique_queries, COUNT(*) as total_queries, MIN(time) as first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.acocdn.com' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING unique_queries > 5
```

## triage-implant-activity
<!-- Triage Implant Network Activity -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-exchange
- github-commit-search
- cdn-proxy-activity
- dns-tunneling-analysis
max_iterations: 4
objective: Determine whether the combination of GitHub commit searches, rare CDN URI
  patterns, and DNS tunneling indicates an active TA488 OWAReaper infection.
success_criteria: A verdict of malicious, suspicious, or benign per host with citations.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-body-inspection)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate an incident response ticket for OWA session revocation and server-side mailbox cleanup.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the HTTP logs for the identified hosts. Check for encoded data in URI paths and correlate with the vulnerable Exchange findings. Coordinate with Exchange admins to check for mailbox permission changes.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the absence of OWAReaper network activity and record the scope of the systems examined.
```
→ end
