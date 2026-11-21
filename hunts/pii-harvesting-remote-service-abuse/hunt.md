---
analysis: A single rule on large uploads or rare DNS would be too noisy. This hunt
  correlates the temporal relationship between visiting a suspicious domain, performing
  a large upload, and the subsequent appearance of auth anomalies, providing the context
  an analyst needs to confirm identity theft.
blind_spots:
- id: no-dns-telemetry
  question: whether the initial redirection to the portal occurred via DoH or a non-enrolled
    resolver
  requires: hb_dns_activity from the endpoint or resolver
  risk: An attacker using DNS-over-HTTPS would bypass the lead query, making the harvesting
    interaction invisible.
  stage: phishing-redirection-and-seo
- id: encrypted-traffic-blind-spot
  question: whether the POST request body actually contained an image or passport
    scan
  requires: TLS inspection on hb_http_activity
  risk: Without TLS inspection, the query relies entirely on body length as a proxy
    for biometric upload, increasing false positives from legitimate encrypted traffic.
  stage: pii-biometric-harvesting
coverage:
- stage: phishing-redirection-and-seo
  status: covered
  steps:
  - dns-leads
  - evaluate-leads
- stage: pii-biometric-harvesting
  status: covered
  steps:
  - pii-upload-check
- stage: unauthorized-remote-access
  status: covered
  steps:
  - remote-access-check
  - final-triage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The harvesting of passport scans and biometrics is a critical precursor
    to high-impact identity theft and initial access. Detecting these interactions
    early allows for the revocation of identities before they are used to breach the
    environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has redirected users to a copycat visa or identity portal
  to harvest passport scans and selfies, then used the stolen identities to authenticate
  to external remote services from unusual locations.
labels:
- hunt
- attack.t1566
- attack.t1133
- initial access
name: PII Harvesting and Remote Service Abuse
parameters:
  identity_themed_domains:
    default:
    - uk-visa-portal.com
    - visa-verify-status.online
    - identity-check-portal.net
    - passport-verification.io
    - travel-permit-gov.info
    description: List of domains suspected of being copycat visa or identity portals.
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://www.welivesecurity.com/en/privacy/is-it-safe-upload-passport-id-online/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for the lead and subsequent activities.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to narrow follow-on queries after the lead identifies potential
      victims.
    type: list[host]
  upload_min_bytes:
    default: '100000'
    description: Minimum body size in bytes for an HTTP POST to be considered a document
      or biometric upload (100KB).
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/privacy/is-it-safe-upload-passport-id-online/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on users in departments that frequently handle international travel
  or visa documentation. Prioritize hosts with rare DNS resolutions matching travel-themed
  keywords.
references:
- name: "ESET Research \u2014 Is it safe to upload my passport or ID online?"
  url: https://www.welivesecurity.com/en/privacy/is-it-safe-upload-passport-id-online/
related:
- hunt: unusual-geo-remote-signin
  reason: This hunt specifically links the sign-in to the preceding PII harvesting
    interaction; a general geo-anomaly hunt is a sibling but lacks the causative chain.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Redirection via Copycat Phishing and SEO
    observables:
    - Copycat visa portals
    - Fake travel permit sites
    - Malicious search ranking links
    - Redirections to suspicious domains
    slug: phishing-redirection-and-seo
    tactic: initial-access
    techniques:
    - T1566
  - name: PII and Biometric Harvesting
    observables:
    - HTTP POST requests to unauthorized domains
    - Upload of passport scans
    - Upload of selfies or video-face scans
    - Data submission to intermediary sites
    slug: pii-biometric-harvesting
    tactic: initial-access
    techniques:
    - T1566
  - name: Unauthorized Access via Stolen ID
    observables:
    - Logins to VPN or Citrix gateways using stolen credentials
    - Remote service authentication from unfamiliar locations
    - Password resets using harvested PII
    - Account unlock attempts
    slug: unauthorized-remote-access
    tactic: initial-access
    techniques:
    - T1133
  summary: Adversaries use copycat phishing sites and SEO poisoning to lure users
    into uploading sensitive identification documents, such as passports and biometrics,
    to fake visa or travel portals. This harvested personally identifiable information
    (PII) is subsequently used to bypass security measures, commit identity fraud,
    or gain unauthorized access to accounts through external-facing remote services.
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


# PII Harvesting and Remote Service Abuse

This hunt identifies the progression from initial phishing redirection to credential abuse. It starts by finding rare DNS lookups to domains that mimic legitimate travel or identity portals. If an agent confirms these domains are suspicious, the hunt scopes to those hosts to find large HTTP POST requests (indicative of image uploads) and subsequent authentication anomalies on VPN or Citrix gateways. An analyst then weighs the complete chain to confirm a compromise.

## dns-leads
<!-- DNS lookups to identity copycat domains -->
Identify hosts that visited domains mimicking legitimate visa or identity portals.

```sqlite target=endpoint role=baseline params=(identity_themed_domains=identity_themed_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts visiting a domain that is visually or semantically
  similar to a government portal. Silence suggests no interaction with these specific
  copycats.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{identity_themed_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookup_count ASC
```

## evaluate-leads
<!-- Evaluate domain legitimacy -->
```agent target=hunter
cite: required
context:
- dns-leads
max_iterations: 3
objective: Examine the DNS hits; identify if any queried hostnames are likely copycats
  or fake portals based on the report parameters.
success_criteria: A list of suspicious domains and the hosts that visited them.
tools:
- endpoint
- identity
- web
```

## gate
<!-- Gate: Proceed with expensive scouting? -->
if~: "the evaluate-leads verdict classifies at least one domain as suspicious" (confidence: high, judge=hunter)
then: → parallel-scouting
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-telemetry)
else: → close-out

## parallel-scouting
<!-- Scout for uploads and abuse -->
parallel:
- → pii-upload-check
- → remote-access-check
join: → final-triage

## pii-upload-check
<!-- Potential PII uploads via HTTP POST -->
Find large outbound POST requests that may represent passport scans or biometric uploads.

```sqlite target=web role=enrichment params=(upload_min_bytes=upload_min_bytes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: POST requests over 100KB to suspicious or rare domains following the DNS
  lead hit. Silence suggests no large data was transmitted to the suspected portals.
reads:
- device_hostname
- url_hostname
- url_path
- request_body_len
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, url_hostname, url_path, request_body_len, time FROM hb_http_activity WHERE http_method = 'POST' AND request_body_len > {{upload_min_bytes}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## remote-access-check
<!-- Anomalous remote service sign-ins -->
Identify unauthorized access to gateways using credentials likely stolen via the harvesting site.

```sqlite target=identity role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Sign-ins from unfamiliar locations or unusual protocols for the users identified
  in the scoping phase.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- logon_type
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, logon_type, status, time FROM hb_auth_signin WHERE (logon_type IN ('Remote Interactive', 'Network') OR activity_id = 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## final-triage
<!-- Correlate harvesting and access anomalies -->
```agent target=hunter
cite: required
context:
- evaluate-leads
- pii-upload-check
- remote-access-check
max_iterations: 6
objective: Determine if users who visited the suspicious portals also performed large
  uploads and subsequently experienced anomalous remote authentication events.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  DNS, HTTP, and Auth rows.
tools:
- endpoint
- identity
- web
```

## outcome-route
<!-- Route based on compromise -->
if~: "the final-triage verdict is malicious for at least one host and user" (confidence: high, judge=hunter)
then: → contain-and-reset
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-traffic-blind-spot)
else: → close-out

## contain-and-reset
<!-- Isolate host and revoke session -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and revoke all active cloud/VPN sessions for the affected user. Force a password reset.
```
→ analyst-review

## analyst-review
<!-- Analyst manual review -->
```manual target=analyst
Review the DNS query times against the HTTP POST request times. Confirm if the remote access originated from a known malicious IP or unusual geographic region.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the identified malicious domains for perimeter blocking and document the host/user combinations examined.
```
→ end
