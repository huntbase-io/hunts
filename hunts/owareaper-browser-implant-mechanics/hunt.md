---
analysis: A single rule could flag the EWS API calls, but this hunt correlates those
  leads with subsequent cross-mailbox authentication anomalies. It uses a baseline
  to distinguish legitimate shared-access from the broad 'Default' permission elevation
  described in the TA488 research.
blind_spots:
- id: limited-http-visibility
  owner: Network Operations
  question: Was PageDataPayload.OwaUserDefaultSettings actually written into localStorage?
  remediation: Implement TLS inspection for internal OWA traffic.
  requires: Full TLS decryption of HTTP traffic to/from OWA endpoints.
  risk: Without body inspection, we only see the URL path; persistence setup is inferred
    from subsequent session activity.
  stage: owareaper-execution-and-persistence
- id: dom-visibility-gap
  owner: Security Engineering
  question: Did the browser create the invisible input elements used for harvesting?
  remediation: Enforce browser security policies that restrict cross-site scripting
    and unauthorized DOM manipulation.
  requires: Browser monitoring extensions or endpoint logs that record DOM interactions.
  risk: The creation of -9999px elements is entirely client-side and invisible to
    standard HTTP or process telemetry.
  stage: credential-and-token-theft
coverage:
- stage: owareaper-execution-and-persistence
  status: covered
  steps:
  - owa-api-telemetry
  - triage-implants
- stage: credential-and-token-theft
  status: covered
  steps:
  - owa-api-telemetry
- stage: mailbox-permission-manipulation
  status: covered
  steps:
  - owa-api-telemetry
  - mailbox-access-anomalies
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: initial-access-owa-exploit
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: multi-channel-c2
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: exfiltration-and-tunneling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: OWAReaper bypasses traditional host isolation and credential rotation
    by manipulating server-side permissions. A negative result confirms that organizational
    mailbox security has not been undermined via the 'Default' user alias preset.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed a JavaScript implant in Outlook Web Access (OWA)
  that persists in browser storage and hijacks Exchange APIs to harvest tokens and
  modify folder permissions for organizational access.
labels:
- hunt
- attack.t1056.001
- attack.t1528
- attack.t1098.002
- attack.t1204.001
name: 'OWAReaper: Browser-Based Persistence and Identity Theft'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-07-25'
      ref: standard-lookback
    type: number
  target_cve:
    default: CVE-2026-42897
    description: The OWA XSS vulnerability exploited to deliver OWAReaper.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint TA488 OWA
    type: string
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
rationale: The hunt focuses on Exchange servers (scoping via vulnerabilities) and
  OWA-heavy user populations. The HTTP analysis targets the server-side proxy/logging
  interface.
references:
- name: "Proofpoint \u2014 Cleaning Out Inboxes: TA488 Outlook half-click exploit"
  url: https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit
related:
- hunt: owareaper-delivery-and-exploitation
  reason: Handles the XSS lure and initial delivery phase.
  relation: precedes
- hunt: owareaper-c2-and-exfiltration
  reason: Handles the GitHub commit C2 and image CDN exfiltration.
  relation: follows
- hunt: owa-vulnerability-exploit-exposure
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
  index: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# OWAReaper: Browser-Based Persistence and Identity Theft

This hunt targets the runtime behavior of the OWAReaper implant, focusing on its interaction with internal Exchange handlers for session data collection and permission manipulation. While the implant resides in the browser's localStorage, its activity is reflected in HTTP request patterns to OWA session logic and EWS endpoints. We simultaneously baseline cross-mailbox access to identify accounts where the 'Default' user alias has been granted Owner-level permissions, enabling unauthorized lateral access by other authenticated users in the organization.

## vulnerable-owa-exposure
<!-- Identify vulnerable OWA exposure -->
Find the Exchange servers or related endpoints vulnerable to the XSS vulnerability that facilitates OWAReaper delivery.

```sqlite target=endpoint role=scoping params=(target_cve=target_cve)
~~~yaml
expected: A list of unpatched OWA-related resources. Silence indicates the estate
  is patched against this specific exploit vector.
reads:
- affected_package_name
- affected_package_version
- cve_uid
- first_seen
- resource_uid
- severity
- status
silence: evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT resource_uid, affected_package_name, affected_package_version, severity, first_seen FROM hb_vulnerability_finding WHERE cve_uid = '{{target_cve}}' AND status != 'resolved'
```

## detect-implant-activity
<!-- Monitor for implant leads -->
parallel:
- → owa-api-telemetry
- → mailbox-access-anomalies
join: → triage-implants

## owa-api-telemetry
<!-- OWAReaper HTTP API interactions -->
Identify OWA internal requests used by the implant to gather session data, steal tokens, and update mailbox folders.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Requests to sessiondata.ashx and EWS calls for token/permission theft. Seeing
  multiple distinct OWA-internal calls from a single client IP suggests implant orchestration.
reads:
- device_hostname
- http_method
- src_endpoint_ip
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_path, http_method, src_endpoint_ip, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/owa/sessiondata.ashx%' OR LOWER(url_path) LIKE '%getclientaccesstoken%' OR LOWER(url_path) LIKE '%updatefolder%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## mailbox-access-anomalies
<!-- Anomalous cross-mailbox access -->
Detect mailboxes accessed by multiple distinct users, suggesting the impact of granting 'Default' user permissions.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of target mailboxes accessed by more than one account. Frequent cross-access
  for accounts not normally associated with shared mailboxes is suspicious.
prevalence:
  by: actor_user_name
  key:
  - target_mailbox
  rare_below: 3
reads:
- actor_user_name
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT dst_endpoint_name AS target_mailbox, COUNT(DISTINCT actor_user_name) AS unique_accessors, MIN(time) AS first_access, MAX(time) AS last_access FROM hb_auth_signin WHERE status_id = 1 AND LOWER(actor_user_name) != LOWER(dst_endpoint_name) AND dst_endpoint_name IS NOT NULL AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name HAVING unique_accessors > 1 ORDER BY unique_accessors DESC
```

## triage-implants
<!-- Triage OWA Implant Evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-owa-exposure
- owa-api-telemetry
- mailbox-access-anomalies
max_iterations: 5
objective: Determine if the sequence of API calls (session data harvesting, UpdateFolder)
  on a host correlates with unauthorized cross-mailbox sign-ins on the same target
  mailboxes.
success_criteria: A verdict for every suspicious host/mailbox combination citing the
  specific HTTP or Auth rows.
tools:
- endpoint
- identity
- web
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host or mailbox" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-http-visibility)
else: → close-out

## isolate-and-remediate
<!-- Remediate mailbox permissions -->
```action target=endpoint
~~~yaml
approval: required
~~~
1. Review and reset 'Default' user permissions on identified mailboxes using Exchange Management Shell. 2. Invalidate all current OAuth tokens for affected users. 3. Clear browser localStorage and IndexedDB for the affected hosts to remove OWAReaper persistence.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited HTTP paths and Auth sign-in events. Correlate with 'mailbox-access-anomalies' to determine if the 'Default' user alias hijack was the source of cross-mailbox access.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
No OWAReaper runtime behavior was identified. Verify Exchange patch levels for CVE-2026-42897 to ensure the vector is closed.
```
→ end
