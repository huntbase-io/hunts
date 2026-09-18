---
analysis: A single rule on acocdn.com is insufficient because the implant proxies
  via legitimate CDNs. This hunt correlates GitHub C2 polling with CDN-proxied HTTP
  exfiltration across multiple surfaces to find the rare combination indicative of
  the implant.
blind_spots:
- id: missing-http-telemetry
  owner: Network Engineering
  question: Can we see the /assets/v1_ URI path in encrypted web traffic?
  remediation: Enable TLS inspection for common CDN and developer service domains.
  requires: hb_http_activity with SSL/TLS inspection
  risk: If the exfiltration occurs over HTTPS and isn't decrypted, the specific OWAReaper
    signal is invisible.
  stage: exfiltration-cdn-and-dns-tunneling
- id: github-noise
  owner: Hunt Team
  question: How do we distinguish automated implant polling from manual developer
    searches?
  remediation: Focus on non-technical departments or baseline developer workstation
    hostnames.
  requires: hb_http_activity
  risk: Legitimate developer activity can result in false positives for GitHub API
    queries.
  stage: c2-github-and-email-polling
coverage:
- stage: c2-github-and-email-polling
  status: covered
  steps:
  - github-api-c2-activity
- stage: exfiltration-cdn-and-dns-tunneling
  status: covered
  steps:
  - cdn-proxied-exfiltration
  - dns-tunneling-fallback
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: initial-access-owa-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: persistence-browser-storage
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: credential-access-dom-manipulation
  status: out_of_scope
- reason: Belongs to another part of the 'TA488 Outlook half-click exploit' series.
  stage: lateral-movement-mailbox-permissions
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: TA488 utilizes sophisticated, server-side persistent implants that
    survive standard remediation; ensuring the OWA estate is clean is critical for
    long-term security.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An OWA-based implant is communicating with GitHub for command retrieval
  and exfiltrating data via proxied image CDN requests or DNS tunneling to actor-controlled
  infrastructure.
labels:
- hunt
- attack.t1071
- attack.t1041
- attack.t1090.003
- attack.t1572
name: OWAReaper Implant C2 and Exfiltration
parameters:
  actor_domain:
    default: acocdn.com
    description: Actor-controlled domain used for relaying exfiltrated data.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint TA488
    type: domain
  cdn_domains:
    default:
    - images.weserv.nl
    - weserv.nl
    - i3.wp.com
    - slack-imgs.com
    description: Legitimate CDN domains observed as proxies for OWAReaper exfiltration.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint TA488
    type: list[domain]
  cve_id:
    default: CVE-2026-42897
    description: Target Exchange Server vulnerability associated with the initial
      exploit.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint TA488
    type: string
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt (e.g., those running OWA/Exchange).
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: We begin by identifying vulnerable Exchange servers. We then pivot using
  authentication logs to identify client hosts that logged into those servers, focusing
  the behavioral search for browser-resident implants on those specific targets.
references:
- name: "Proofpoint \u2014 Cleaning Out Inboxes: TA488 Comes for Outlook with Another\
    \ Half-Click Exploit"
  url: https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit
related:
- hunt: owareaper-initial-access-and-persistence
  reason: This hunt focuses on network activity; a separate hunt focuses on exploitation
    and browser storage persistence.
  relation: precedes
- hunt: ta488-outlook-xss-exploitation-assessment
  relation: follows
scenario:
  stages:
  - name: Outlook Web Access XSS Exploitation
    observables:
    - CVE-2026-42897
    - Bland email lures with subjects like 'Semiconductor Supply Chain Indicators'
      or 'Global Gas Markets'
    - onload= event handler in email HTML for JavaScript execution
    - Base64 fragments stored in social media icons within email body
    slug: initial-access-owa-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1195
  - name: OWA Browser Storage Persistence
    observables:
    - localStorage key PageDataPayload.OwaUserDefaultSettings
    - IndexedDB poisoning with hidden iframes in offline message cache
    - OwaFrontendSyncState manipulation
    slug: persistence-browser-storage
    tactic: persistence
    techniques:
    - T1572
  - name: Autofill Sniffing and Token Theft
    observables:
    - Invisible input elements at -9999px and -9998px for autofill baiting
    - Abuse of GetClientAccessToken via Outlook add-ins
    - ReadWriteMailbox permissions on Outlook add-ins
    slug: credential-access-dom-manipulation
    tactic: credential-access
  - name: Mailbox Permission Abuse
    observables:
    - UpdateFolder calls granting Owner-level permissions to the 'Default' user
    slug: lateral-movement-mailbox-permissions
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: GitHub and Email C2 Channel
    observables:
    - GitHub Commit Search API queries (api.github.com)
    - Polling IndexedDB for emails with {target_email_address}{space}{Base64text}
      structure
    - Polling interval every 5 minutes for offline cache
    slug: c2-github-and-email-polling
    tactic: command-and-control
    techniques:
    - T1071
  - name: CDN-Proxied and DNS Data Exfiltration
    observables:
    - acocdn.com
    - images.weserv.nl
    - weserv.nl
    - i3.wp.com
    - slack-imgs.com
    - URI paths matching /assets/v1_
    - DNS label tunneling to actor-controlled domains
    - POST requests to /owa/sessiondata.ashx
    - 'Files: msanalytics.json, ews_extensions_debug.json, poison_wizard_error_dom.html'
    slug: exfiltration-cdn-and-dns-tunneling
    tactic: exfiltration
    techniques:
    - T1041
    - T1090.003
    - T1572
  summary: TA488 exploited a zero-day XSS vulnerability in Outlook Web Access (CVE-2026-42897)
    to deploy a browser-resident JavaScript implant named OWAReaper. The implant achieves
    persistence via OWA localStorage and IndexedDB, allowing it to steal credentials
    and exfiltrate data through image CDNs and DNS tunneling while maintaining a minimal
    host footprint.
series:
  index: 2
  slug: ta488-outlook-half-click-exploit
  title: TA488 Outlook half-click exploit
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


# OWAReaper Implant C2 and Exfiltration

This hunt focuses on the network footprint of OWAReaper, a JavaScript-based implant used by TA488. It specifically targets the visible indicators of the implant's C2 and exfiltration channels: GitHub Commit Search API queries, the use of legitimate image CDNs (Weserv, WordPress, Slack) to proxy traffic to the actor's 'acocdn.com' relay, and DNS label tunneling as a fallback exfiltration method.

## vulnerable-exchange-inventory
<!-- Scope to vulnerable Exchange servers -->
Identify Exchange servers vulnerable to CVE-2026-42897 that likely serve as the beachhead for OWAReaper delivery.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: A list of device_uids representing vulnerable Exchange servers. Absence
  means the estate is patched.
reads:
- cve_uid
- device_uid
- first_seen
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_uid, cve_uid, severity, first_seen FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status = 'UNRESOLVED'
```

## identify-owa-users
<!-- Identify users accessing vulnerable OWA -->
Find client hosts and users that have authenticated against the vulnerable servers to focus the behavioral hunt on potential victims.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Sign-ins to the Exchange infrastructure. The analyst should compare dst_endpoint_name
  against the hostnames of vulnerable servers from the scoping step to populate the
  scope_hosts parameter.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, actor_user_name, dst_endpoint_name, auth_protocol, time FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') AND status_id = 1
```

## network-activity-parallel
<!-- Corroborate C2 and Exfiltration across surfaces -->
parallel:
- → github-api-c2-activity
- → cdn-proxied-exfiltration
- → dns-tunneling-fallback
join: → triage-owareaper-implant

## github-api-c2-activity
<!-- GitHub API Commit Search polling -->
Identify browser-based polling of the GitHub Commit Search API used by the implant for command retrieval.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Anomalous commit search requests from browser processes. Normal developers
  typically use technical CLI tools or IDEs, whereas a browser-resident implant shows
  browser User-Agents.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- device_hostname
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, COUNT(*) as request_count FROM hb_http_activity WHERE LOWER(url_hostname) = 'api.github.com' AND LOWER(url_path) LIKE '/search/commits%' AND (LOWER(user_agent) LIKE '%mozilla%' OR LOWER(user_agent) LIKE '%chrome%' OR LOWER(user_agent) LIKE '%safari%' OR LOWER(user_agent) LIKE '%edge%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, url_hostname, url_path, user_agent
```

## cdn-proxied-exfiltration
<!-- CDN-proxied data exfiltration -->
Identify HTTP requests matching the /assets/v1_ pattern sent through legitimate CDNs to the actor relay.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, cdn_domains=cdn_domains, actor_domain=actor_domain, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to high-reputation CDNs with the specific /assets/v1_ prefix
  used for encrypted exfiltration.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
- user_agent
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{cdn_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_hostname) = '{{actor_domain}}') AND LOWER(url_path) LIKE '/assets/v1_%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## dns-tunneling-fallback
<!-- DNS tunneling exfiltration fallback -->
Detect DNS queries to the actor's domain (acocdn.com) that likely contain exfiltrated data in the subdomains.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, actor_domain=actor_domain, scope_hosts=scope_hosts)
~~~yaml
expected: Long, high-entropy DNS queries where the subdomain structure contains exfiltrated
  data. process_name identifies the originating application (e.g. Chrome).
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
SELECT device_hostname, process_name, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.{{actor_domain}}' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name, query_hostname HAVING LENGTH(query_hostname) > 35
```

## triage-owareaper-implant
<!-- Triage OWAReaper implant activity -->
```agent target=hunter
cite: required
context:
- vulnerable-exchange-inventory
- identify-owa-users
- github-api-c2-activity
- cdn-proxied-exfiltration
- dns-tunneling-fallback
max_iterations: 4
objective: Determine if the combined network signals indicate an active OWAReaper
  infection, specifically looking for the 'half-click' exploit aftermath where C2
  and exfiltration are established within the OWA context.
success_criteria: A verdict of malicious | suspicious | benign citing specific CDN
  domains and URI paths.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host and cites CDN exfiltration with /assets/v1_" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-http-telemetry)
else: → close-out

## isolate-compromised-host
<!-- Isolate host and verify Exchange permissions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Additionally, check the Exchange Server for any 'Default' user permissions assigned via UpdateFolder, which provides the actor with server-side mailbox persistence.
```
→ analyst-review

## analyst-review
<!-- Manual review of exfiltration signals -->
```manual target=analyst
Review the CDN URI paths and GitHub API traffic. Confirm if the activity corresponds to a user session in OWA. If confirmed, initiate the IR playbook for OWA implants.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
No activity detected. Document the patching status for CVE-2026-42897 in the estate.
```
→ end
