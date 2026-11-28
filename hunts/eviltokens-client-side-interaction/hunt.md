---
analysis: A standard rule might flag a known malicious URL; this hunt uses behavioral
  timing (the 3-5 second ping interval) and cross-surface correlation (file touch
  vs. network redirect) to find zero-day phishing infrastructure.
blind_spots:
- id: encrypted-http-visibility
  question: Can we see the URL path /state within encrypted HTTPS traffic?
  requires: TLS interception or EDR browser-extension visibility
  risk: If the network source only logs the hostname (via SNI) and not the path, the
    polling pattern cannot be confirmed, potentially hiding the automated nature of
    the phishing page.
  stage: device-code-polling-interaction
- id: memory-only-lures
  question: Does the hunt miss lures that never touch the disk?
  requires: hb_http_activity
  risk: EvilTokens can function purely via a link in a browser; if the user never
    downloads the PDF or HTML lure, the hb_file_activity step will return no rows.
  stage: initial-access-ai-phishing
coverage:
- stage: initial-access-ai-phishing
  status: covered
  steps:
  - suspicious-lure-files
- stage: device-code-polling-interaction
  status: covered
  steps:
  - background-state-polling
  - device-login-navigation
- reason: 'Belongs to another part of the ''Unmasking EvilTokens: Getting to the root
    of device code phishing'' series.'
  stage: unauthorized-device-code-authentication
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking EvilTokens: Getting to the root
    of device code phishing'' series.'
  stage: malicious-inbox-rule-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking EvilTokens: Getting to the root
    of device code phishing'' series.'
  stage: rogue-device-registration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking EvilTokens: Getting to the root
    of device code phishing'' series.'
  stage: graph-api-reconnaissance-and-collection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: EvilTokens has compromised over 10,000 organizations by automating
    the capture of session tokens. Identifying the interaction phase prevents unauthorized
    account access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has delivered an AI-tailored phishing lure that, when opened,
  initiates high-frequency background polling to a malicious Node.js endpoint while
  redirecting the user to the Microsoft device login portal.
labels:
- hunt
- attack.t1566.001
- attack.t1566.002
- attack.t1115
- attack.t1041
name: EvilTokens Client-Side Phishing Interaction
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_extensions:
    default:
    - .html
    - .htm
    - .pdf
    description: Common lure file extensions associated with EvilTokens campaigns.
    from:
      kind: article
      observed: '2026-09-22'
      ref: msrc-blog-eviltokens
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hostnames to scope the hunt; leave empty for fleet-wide.
    type: list[host]
  trusted_domains:
    default:
    - microsoft.com
    - google.com
    - bing.com
    - apple.com
    - linkedin.com
    description: Known-good domains to exclude from background polling results.
    from:
      kind: article
      observed: '2026-09-22'
      ref: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints with active users in the last 14 days. Prioritize users
  with roles often targeted by BEC lures, such as finance or HR.
references:
- name: 'MSRC - Unmasking EvilTokens: Getting to the root of device code phishing'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/
related:
- hunt: unauthorized-device-code-authentication
  reason: This hunt detects the interaction; a follow-on hunt is needed to identify
    successful, unauthorized sign-ins in the authentication logs.
  relation: follows
scenario:
  stages:
  - name: AI-Tailored Phishing Delivery
    observables:
    - PDF attachments
    - HTML file attachments
    - Invoices or RFP themes
    - 'High-pressure lures like ''Action Required: Password Expiration'''
    - Short-lived polling node URLs
    slug: initial-access-ai-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Client-Side Device Code Interaction
    observables:
    - checkStatus() function
    - setInterval polling every 3-5 seconds
    - Pings to /state endpoint
    - Automated clipboard copy of device codes
    - Redirects to microsoft.com/devicelogin
    - Buttons labeled 'Continue with Microsoft' or 'Copy Code'
    slug: device-code-polling-interaction
    tactic: execution
    techniques:
    - T1115
  - name: MFA Bypass via Device Code Flow
    observables:
    - Sign-in to 'Device Registration Service' resource
    - OAuth device code flow authentications from anomalous IPs
    - Authentication sessions decoupled from the originating lure session
    slug: unauthorized-device-code-authentication
    tactic: credential-access
  - name: Concealed Communication via Inbox Rules
    observables:
    - Creation of new inbox rules designed to hide communications
    - Rules filtering for specific keywords or alerting to Telegram
    slug: malicious-inbox-rule-persistence
    tactic: persistence
  - name: Long-Term Persistence via Device Registration
    observables:
    - Registration of new devices within 10 minutes of breach
    - Generation of Primary Refresh Tokens (PRT) for unauthorized devices
    slug: rogue-device-registration
    tactic: persistence
  - name: Graph API Recon and Email Exfiltration
    observables:
    - Microsoft Graph API calls for organizational structure mapping
    - Bulk email exfiltration using stolen tokens
    - AI-assisted analysis of compromised inbox content
    slug: graph-api-reconnaissance-and-collection
    tactic: collection
    techniques:
    - T1041
  summary: EvilTokens is a PhaaS platform operated by Storm-2992 that facilitates
    device code phishing via AI-tailored lures and automated polling infrastructure.
    The attack steals OAuth tokens to bypass MFA, enabling threat actors to maintain
    persistence through malicious inbox rules, register new devices, and exfiltrate
    email data via the Microsoft Graph API.
series:
  index: 1
  slug: unmasking-eviltokens-getting-to-the-root-of-device-code-phishing
  title: 'Unmasking EvilTokens: Getting to the root of device code phishing'
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


# EvilTokens Client-Side Phishing Interaction

EvilTokens is a PhaaS platform that specializes in device code phishing. This hunt identifies the early stages of an attack by detecting the characteristic 3-5 second polling interval of the background script ('checkStatus') and the concurrent user redirection to microsoft.com/devicelogin. By correlating these behaviors with the presence of suspicious invoice or RFP-themed lure files, we can identify sessions that are actively being phished before token theft is completed. This behavioral approach bypasses rotating domains and AI-generated lures that evade standard signature-based controls.

## suspicious-lure-files
<!-- Suspicious Lure File Creation -->
Identify the creation of potential phishing lures in user-writable paths with themes mentioned in the EvilTokens research.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, lure_extensions=lure_extensions)
~~~yaml
expected: Rows mapping lures to hosts. Silence is not evidence of absence as lures
  can be hosted purely in-browser without a file download.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%\\desktop\\%') AND (instr(',' || '{{lure_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, -4)) || ',') > 0 OR instr(',' || '{{lure_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, -5)) || ',') > 0) AND (LOWER(file_name) LIKE '%invoice%' OR LOWER(file_name) LIKE '%rfp%' OR LOWER(file_name) LIKE '%proposal%' OR LOWER(file_name) LIKE '%expiration%' OR LOWER(file_name) LIKE '%compensation%' OR LOWER(file_name) LIKE '%benefits%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-interaction
<!-- Examine Polling and Redirection -->
parallel:
- → background-state-polling
- → device-login-navigation
join: → triage-interaction

## background-state-polling
<!-- High-Frequency Background Polling -->
Identify the EvilTokens checkStatus polling behavior, which pings a /state endpoint every 3-5 seconds.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, trusted_domains=trusted_domains)
~~~yaml
expected: A single host making frequent requests to a non-Microsoft domain with a
  consistent sub-6-second gap. This indicates the phishing kit loop.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, COUNT(*) as request_count, MIN(time) as first_ping, MAX(time) as last_ping FROM hb_http_activity WHERE url_path LIKE '%/state%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{trusted_domains}}' || ',', ',' || LOWER(url_hostname) || ',') = 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, url_hostname HAVING request_count > 10 AND (strftime('%s', MAX(time)) - strftime('%s', MIN(time))) / request_count <= 6
```

## device-login-navigation
<!-- Navigation to Microsoft Device Login -->
Confirm the user navigated to the legitimate device login portal, which is the destination for the EvilTokens redirect.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A visit to the device login page. While legitimate, its timing must be weighed
  against lure delivery and polling behavior.
reads:
- device_hostname
- actor_user_name
- url_hostname
- url_path
- referrer
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, actor_user_name, url_hostname, url_path, referrer, time FROM hb_http_activity WHERE url_hostname = 'microsoft.com' AND url_path LIKE '/devicelogin%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-interaction
<!-- Triage Phishing Interaction -->
```agent target=hunter
cite: required
context:
- suspicious-lure-files
- background-state-polling
- device-login-navigation
max_iterations: 4
objective: Determine if any single host shows a combination of suspicious lure creation,
  consistent sub-6-second background polling to a non-trusted domain, and a visit
  to microsoft.com/devicelogin.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  rows for any host showing concurrent polling and redirection.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Interaction Verdict -->
if~: "the triage-interaction verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: encrypted-http-visibility)
else: → manual-analyst-review

## isolate-host
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Revoke all active sessions for the identified user in Azure AD/M365 and force a password reset immediately.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the url_hostname identified in the polling step. Use whois or threat intelligence to confirm Node.js infrastructure. Check for other hosts visiting the same domain.
```
→ close-out

## close-out
<!-- Hunt Close-Out -->
```manual target=analyst
Record the results. If the polling query produced high-fidelity results without false positives, promote it to a standing detection candidate.
```
→ end
