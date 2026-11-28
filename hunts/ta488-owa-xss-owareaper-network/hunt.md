---
analysis: A simple rule might detect requests to acocdn.com, but this hunt pivots
  from vulnerable infrastructure to anomalous authentication and then correlates GitHub
  C2 polling with legitimate CDN usage. This multi-stage behavioural chain is necessary
  to confirm the full OWAReaper infection and evict server-side persistence.
blind_spots:
- id: owa-storage-blind-spot
  question: Are OWAReaper payloads present in the browser's localStorage or IndexedDB?
  requires: direct endpoint browser forensics
  risk: The hunt cannot see the actual persistence mechanism on the client side; we
    rely on the network aftermath (C2/exfil).
  stage: owareaper-persistence-and-privilege
- id: mail-body-content-blind-spot
  question: What were the specific lure subjects and HTML contents of the delivered
    exploit emails?
  requires: email security gateway logs
  risk: Without the email body, we cannot confirm the initial XSS trigger (onload
    handlers in icons).
  stage: owa-xss-exploitation
coverage:
- stage: compromised-account-access
  status: covered
  steps:
  - anomalous-owa-logons
- stage: owa-xss-exploitation
  status: covered
  steps:
  - vulnerable-owa-hosts
  - owa-session-data-access
- stage: c2-via-github-polling
  status: covered
  steps:
  - github-c2-polling
- stage: covert-data-exfiltration
  status: covered
  steps:
  - cdn-proxied-exfiltration
- reason: Belongs to a dedicated hunt for Exchange mailbox permission and storage
    persistence.
  stage: owareaper-persistence-and-privilege
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: TA488 is a Russia-aligned threat actor using sophisticated OWA implants
    (OWAReaper) that achieve server-side persistence. This persistence survives credential
    resets and device re-imaging, making it a critical threat to long-term mailbox
    confidentiality.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited CVE-2026-42897 in Outlook Web Access to deploy
  the OWAReaper implant, evidenced by anomalous sign-ins, OWA session data access,
  and covert exfiltration via image CDNs and GitHub.
labels:
- hunt
- attack.t1190
- attack.t1071.001
- attack.t1102
- attack.t1090.003
- attack.t1572
- attack.t1041
- attack.t1078
- attack.t1021.001
name: TA488 OWA XSS Exploitation and OWAReaper Network Operations
parameters:
  actor_domain:
    default: acocdn.com
    description: The primary actor-controlled C2 and exfiltration relay domain.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint-TA488
    type: domain
  cdn_domains:
    default:
    - weserv.nl
    - images.weserv.nl
    - i3.wp.com
    - slack-imgs.com
    description: Legitimate CDN domains used by OWAReaper to proxy exfiltration.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint-TA488
    type: list[domain]
  cve_id:
    default: CVE-2026-42897
    description: The OWA XSS vulnerability ID exploited by TA488.
    from:
      kind: article
      observed: '2026-07-22'
      ref: Proofpoint-TA488
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine for exploitation and C2 activity.
    from:
      kind: manual
      observed: '2026-07-25'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt, such as known Exchange servers
      or user endpoints.
    from:
      kind: manual
      ref: analyst-scoping
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope the hunt to all internet-facing Microsoft Exchange servers and user
  endpoints known to access OWA. Prioritize servers where vulnerability findings for
  CVE-2026-42897 are unresolved.
references:
- name: "Proofpoint \u2014 Cleaning Out Inboxes: TA488 Comes to Outlook with Another\
    \ Half-Click Exploit"
  url: https://www.proofpoint.com/us/blog/threat-insight/cleaning-out-inboxes-ta488-comes-outlook-another-half-click-exploit
related:
- hunt: owa-permission-delegation-anomalies
  reason: OWAReaper grants itself Owner permissions to mail folders; this requires
    hb_auth_signin or Exchange audit logs specifically for permission changes.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Abuse of Compromised Accounts
    observables:
    - High volume outbound mail from compromised internal accounts
    - Sign-ins from unusual source IP addresses
    slug: compromised-account-access
    tactic: initial-access
    techniques:
    - T1078
  - name: OWA XSS Exploitation
    observables:
    - CVE-2026-42897
    - Lure emails with subjects such as 'Semiconductor Supply Chain Indicators' or
      'Global Tourism Indicators'
    - HTML message bodies containing icons with onload= event handlers
    - Base64 encoded JavaScript payload blobs in HTML icons
    slug: owa-xss-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Browser and Mailbox Persistence
    observables:
    - localStorage entries under PageDataPayload.OwaUserDefaultSettings
    - Modification of OwaFrontendSyncState
    - UpdateFolder API calls to grant 'Owner' permissions to the 'Default' user alias
    - Abuse of GetClientAccessToken for OAuth token theft
    slug: owareaper-persistence-and-privilege
    tactic: persistence
    techniques:
    - T1137
    - T1098.002
  - name: C2 via GitHub Search API
    observables:
    - HTTPS requests to GitHub Commit Search API
    - API queries containing the victim target email address
    - Encrypted command strings in GitHub commit messages
    slug: c2-via-github-polling
    tactic: command-and-control
    techniques:
    - T1102
    - T1071.001
  - name: Multi-protocol Exfiltration
    observables:
    - HTTP requests proxied through images.weserv.nl, i3.wp.com, and slack-imgs.com
    - HTTPS requests to acocdn.com
    - URI paths matching /assets/v1_<base64_aes_data>
    - DNS label tunneling to actor-controlled domains
    - 'HTTP POST of files: msanalytics.json, ews_extensions_debug.json, poison_wizard_error_dom.html'
    - Requests to /owa/sessiondata.ashx
    slug: covert-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1090.003
    - T1572
    - T1041
  summary: TA488 used a series of compromised accounts to deliver emails exploiting
    CVE-2026-42897, an XSS vulnerability in Outlook Web Access, to deploy the OWAReaper
    JavaScript implant. OWAReaper achieves stealthy persistence by modifying OWA settings
    and mailbox permissions, while utilizing GitHub and legitimate image CDNs for
    command retrieval and covert data exfiltration.
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


# TA488 OWA XSS Exploitation and OWAReaper Network Operations

This hunt targets the infection chain of TA488's OWAReaper implant. It begins by identifying hosts vulnerable to CVE-2026-42897 and correlating them with anomalous OWA authentication events and session data access. The second phase hunts for the implant's unique C2 polling via the GitHub Search API and its exfiltration mechanism, which proxies data through legitimate image CDNs (weserv.nl, wp.com, slack-imgs.com) to an actor-controlled domain (acocdn.com). The hunt concludes with a multi-surface triage to confirm persistent server-side mailbox compromise.

## vulnerable-owa-hosts
<!-- Identify Vulnerable OWA Infrastructure -->
Find systems reporting the CVE-2026-42897 vulnerability to scope the hunt to susceptible OWA targets.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: A list of device UIDs representing vulnerable Exchange servers. Absence
  suggests the estate is patched or scanning is incomplete.
reads:
- affected_package_name
- affected_package_version
- cve_uid
- device_uid
- first_seen
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_uid, affected_package_name, affected_package_version, severity, first_seen FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status = 'UNRESOLVED'
```

## early-stage-activity
<!-- Hunt for Initial Access and Exploitation Evidence -->
parallel:
- → anomalous-owa-logons
- → owa-session-data-access
join: → triage-initial-access

## anomalous-owa-logons
<!-- Anomalous OWA Authentication Events -->
Baseline OWA sign-ins to identify rare source IPs or high-frequency activity typical of compromised account abuse.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare login pairs from external IPs to OWA. These may represent the TA488
  beachhead or the source of lure emails.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 10
reads:
- actor_user_name
- dst_endpoint_name
- metadata_product
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, metadata_product, COUNT(*) as login_count, MIN(time) as first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%owa%' OR LOWER(dst_endpoint_name) LIKE '%outlook%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, metadata_product HAVING login_count < 10 ORDER BY login_count ASC
```

## owa-session-data-access
<!-- Access to OWA Session Data Blobs -->
Detect requests to sessiondata.ashx, which OWAReaper accesses to steal user identity and configuration info.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to the OWA session handler. While OWA uses this normally,
  it provides a pivot for an analyst to correlate with exfiltration activity.
reads:
- actor_user_name
- device_hostname
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, url_path, url_hostname, user_agent, time FROM hb_http_activity WHERE LOWER(url_path) LIKE '%/owa/sessiondata.ashx%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-initial-access
<!-- Triage Initial Access and OWA Interaction -->
```agent target=hunter
cite: required
context:
- vulnerable-owa-hosts
- anomalous-owa-logons
- owa-session-data-access
max_iterations: 3
objective: Determine if any host or user account identified in the early stages likely
  represents a TA488 beachhead.
success_criteria: A verdict citing specific users and IPs that should be tracked into
  the network operations phase.
tools:
- endpoint
- identity
- web
```

## follow-on-network-ops
<!-- Hunt for OWAReaper C2 and Exfiltration -->
parallel:
- → github-c2-polling
- → cdn-proxied-exfiltration
join: → triage-full-infection

## github-c2-polling
<!-- GitHub Commit Search API Polling -->
Find systems querying GitHub's search API for target email identifiers, matching OWAReaper's primary C2 method.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Frequent, automated-looking queries to api.github.com. Look for encoded
  strings or email addresses in the url_query.
reads:
- device_hostname
- time
- url_hostname
- url_path
- url_query
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, time FROM hb_http_activity WHERE LOWER(url_hostname) = 'api.github.com' AND (LOWER(url_path) LIKE '%/search/commits%' OR LOWER(url_path) LIKE '%/search/code%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## cdn-proxied-exfiltration
<!-- Exfiltration via Image CDNs and acocdn.com -->
Find the high-fidelity indicators of OWAReaper exfiltration: proxied asset requests via CDNs or direct POSTs to acocdn.com.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, cdn_domains=cdn_domains, actor_domain=actor_domain)
~~~yaml
expected: Requests to legitimate CDN domains with encrypted URI paths or POST requests
  to acocdn.com containing the specific exfiltration filenames.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{cdn_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_hostname) = '{{actor_domain}}') AND (LOWER(url_path) LIKE '/assets/v1_%' OR LOWER(url_path) LIKE '%msanalytics.json%' OR LOWER(url_path) LIKE '%ews_extensions_debug.json%' OR LOWER(url_path) LIKE '%poison_wizard_error_dom.html%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-infection
<!-- Triage Full OWAReaper Infection Chain -->
```agent target=hunter
cite: required
context:
- triage-initial-access
- github-c2-polling
- cdn-proxied-exfiltration
max_iterations: 5
objective: Weigh the sign-in patterns, session data access, and the unique GitHub/CDN
  network behavior to confirm a persistent OWA compromise.
success_criteria: A final verdict citing rows across the auth, vulnerability, and
  HTTP surfaces.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on Full Triage Verdict -->
if~: "the triage-full-infection verdict is malicious for at least one user or host" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: owa-storage-blind-spot)
else: → close-out

## isolate-and-revoke
<!-- Isolate Host and Revoke Exchange Permissions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host. Critically, review and revoke 'Owner' or 'ReadWrite' permissions granted to the 'Default' user or suspicious accounts on the Exchange server to evict the actor's server-side persistence.
```
→ forensic-investigation

## forensic-investigation
<!-- Detailed Forensic Investigation -->
```manual target=analyst
Examine the browser's localStorage for the 'PageDataPayload.OwaUserDefaultSettings' key and the offline IndexedDB for hidden iframes as described in the report.
```
→ remediation-verification

## remediation-verification
<!-- Verify Remediation and Patching -->
```manual target=analyst
Verify that Microsoft Exchange is patched for CVE-2026-42897. Perform a tenant-wide sweep for anomalous 'UpdateFolder' permission changes.
```
→ end

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record the hosts and users examined and any tuning recommendations for the HTTP exfiltration query.
```
→ end
