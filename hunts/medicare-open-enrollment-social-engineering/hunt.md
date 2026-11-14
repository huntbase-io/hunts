---
analysis: A single detection rule on Medicare keywords produces high false positives
  from legitimate government site usage. This hunt correlates DNS leads with rare
  HTTP POST behavior and downstream portal sign-ins, allowing an agent to weigh the
  entire attack chain.
blind_spots:
- id: tls-inspection-gap
  question: What specific personal data was submitted in the HTTP POST body?
  requires: TLS inspection or proxy body logs
  risk: While the hunt sees POST requests to suspicious domains, it cannot confirm
    if a Medicare number or SSN was actually transmitted without content inspection.
  stage: credential-access-data-harvesting
- id: dns-log-retention
  question: Did the user visit the lure before the current logging window?
  requires: hb_dns_activity retention >= lookback_days
  risk: Social engineering lures may persist for weeks; if the visit happened before
    the log window, the hunt will miss the initial breach.
  stage: initial-access-scam-lures
coverage:
- stage: initial-access-scam-lures
  status: covered
  steps:
  - lead-dns-lookups
- stage: credential-access-data-harvesting
  status: covered
  steps:
  - rare-http-post-targets
- stage: impact-monetization-and-fraud
  status: covered
  steps:
  - sensitive-portal-sign-ins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Medicare-themed social engineering causes high financial and identity
    risk to employees, which can bleed into corporate credential reuse; a negative
    result confirms robust user hygiene during peak scam season.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using lookalike domains during the Medicare Open Enrollment
  season to harvest personal and medical data via social engineering, subsequently
  using those credentials to access sensitive health and banking portals.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1056.003
- attack.t1078
- credential access
- impact
- initial access
name: Medicare Open Enrollment Social Engineering
parameters:
  legit_domains:
    default:
    - medicare.gov
    - healthcare.gov
    - reportfraud.ftc.gov
    - identitytheft.gov
    description: Legitimate government domains for Medicare and reporting; queries
      will filter these out to focus on lures.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://www.welivesecurity.com/en/scams/medicare-open-enrollment-season-scams/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead scoping step; populated by the analyst
      to narrow the deep-dive queries.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/scams/medicare-open-enrollment-season-scams/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on general user workstation segments. This hunt is highly seasonal
  and should be run periodically during the Medicare Open Enrollment period (Oct 15
  - Dec 7).
references:
- name: 'Medicare scam calls, texts and ads: What to watch for this Open Enrollment'
  url: https://www.welivesecurity.com/en/scams/medicare-open-enrollment-season-scams/
related:
- hunt: brand-impersonation-lookalike-domains
  reason: Generic lookalike hunts are broader but lack the seasonal context and specific
    impact assessment for healthcare-related fraud.
  relation: alternative
scenario:
  stages:
  - name: Social engineering via malvertising and phishing
    observables:
    - Google ads for Medicare plan comparisons or card updates
    - unsolicited emails or SMS mentioning the December 7 deadline
    - lookalike domains for medicare.gov or healthcare.gov lacking the .gov suffix
    - inbound calls from 800-633-4227 or 800-318-2596 impersonators
    slug: initial-access-scam-lures
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Personal and medical data harvesting
    observables:
    - HTTP POST requests to lookalike domains containing Medicare numbers or SSNs
    - accessing or updating onepassword_item_medical_record fields such as medication,
      dosage, or patient info in response to lures
    - entry of bank details, credit card information, or account passwords into non-official
      web forms
    slug: credential-access-data-harvesting
    tactic: credential-access
    techniques:
    - T1056.003
  - name: Fraudulent monetization and account abuse
    observables:
    - unauthorized sign-ins to health or banking portals using stolen credentials
    - manipulation of Medicare enrollment records for fraudulent commissions
    - suspicious Medicare claims for services or prescriptions never received
    slug: impact-monetization-and-fraud
    tactic: impact
    techniques:
    - T1078
  summary: A seasonal social engineering campaign during the Medicare Open Enrollment
    period (Oct 15 - Dec 7) uses Google ads, phishing emails, and SMS to direct victims
    to fraudulent lookalike websites. These sites are used to harvest Medicare numbers,
    Social Security numbers, and account credentials to facilitate identity theft,
    healthcare fraud, and fraudulent enrollment manipulation.
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


# Medicare Open Enrollment Social Engineering

This hunt identifies seasonal social engineering campaigns targeting Medicare beneficiaries. It uses a gated flow: first, a low-cost DNS scoping step identifies hosts interacting with non-government domains containing Medicare keywords. If an agent confirms these as suspicious lures, the hunt performs an expensive parallel fan-out to analyze HTTP POST data-harvesting patterns and concurrent unauthorized sign-ins to sensitive portals. This approach isolates the transition from the initial lure to the monetization of stolen identity and health data.

## lead-dns-lookups
<!-- Lead DNS lookups for Medicare lures -->
Identify potential social engineering lures by finding DNS queries for domains containing Medicare keywords that do not end in official .gov TLDs.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, legit_domains=legit_domains)
~~~yaml
expected: DNS queries for Medicare-themed domains on non-government infrastructure.
  Silence suggests no users have visited obvious lures in the window.
reads:
- device_hostname
- actor_user_name
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, query_hostname, process_name, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%medicare%' OR LOWER(query_hostname) LIKE '%healthcare%') AND LOWER(query_hostname) NOT LIKE '%.gov' AND LOWER(query_hostname) NOT LIKE '%.gov.%' AND instr(',' || '{{legit_domains}}' || ',', ',' || LOWER(query_hostname) || ',') = 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess lead DNS activity -->
```agent target=hunter
cite: required
context:
- lead-dns-lookups
max_iterations: 3
objective: Review the DNS results to identify hosts visiting domains that masquerade
  as Medicare services without legitimate government attribution.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- identity
- web
```

## gate-on-lead
<!-- Gate on lead assessment -->
if~: "the assess-lead verdict finds suspicious or malicious DNS queries for at least one host" (confidence: high, judge=hunter)
then: → deep-dive
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: dns-log-retention)
else: → close-out-task

## deep-dive
<!-- Deep dive into traffic and authentication -->
parallel:
- → rare-http-post-targets
- → sensitive-portal-sign-ins
join: → triage-synthesis

## rare-http-post-targets
<!-- Rare HTTP POST targets for Medicare keywords -->
Detect potential harvesting behavior by finding rare domains receiving POST requests containing Medicare keywords, filtered to the scoped hosts.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: POST requests to rare, non-government domains containing Medicare keywords.
  This identifies the data-submission stage of the phishing attack.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 3
reads:
- url_hostname
- url_path
- actor_user_name
- device_hostname
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT url_hostname, url_path, actor_user_name, device_hostname, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE http_method = 'POST' AND (LOWER(url_hostname) LIKE '%medicare%' OR LOWER(url_path) LIKE '%medicare%' OR LOWER(url_hostname) LIKE '%healthcare%' OR LOWER(url_path) LIKE '%healthcare%') AND LOWER(url_hostname) NOT LIKE '%.gov' AND LOWER(url_hostname) NOT LIKE '%.gov.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path, actor_user_name, device_hostname HAVING COUNT(DISTINCT device_hostname) <= 3 ORDER BY first_seen DESC
```

## sensitive-portal-sign-ins
<!-- Sign-ins to sensitive health and financial portals -->
Identify potential credential abuse by finding sign-in activity to sensitive portals from the same scoped hosts.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Authentication attempts to health or financial services from hosts that
  interacted with lures. Silence indicates no monetization was seen.
reads:
- device_hostname
- actor_user_name
- dst_endpoint_name
- src_endpoint_ip
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, dst_endpoint_name, src_endpoint_ip, status, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%medicare%' OR LOWER(dst_endpoint_name) LIKE '%healthcare%' OR LOWER(dst_endpoint_name) LIKE '%bank%' OR LOWER(dst_endpoint_name) LIKE '%insurance%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-synthesis
<!-- Synthesize social engineering attack chain -->
```agent target=hunter
cite: required
context:
- assess-lead
- rare-http-post-targets
- sensitive-portal-sign-ins
max_iterations: 6
objective: Determine if a host has been successfully phished and if the resulting
  credentials or personal data are being monetized.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  specific rows.
tools:
- endpoint
- identity
- web
```

## final-decision
<!-- Route on final triage -->
if~: "the triage-synthesis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: tls-inspection-gap)
else: → close-out-task

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the user to reset all personal and medical portal passwords immediately.
```
→ analyst-review

## analyst-review
<!-- Analyst review and documentation -->
```manual target=analyst
Review the cited DNS and HTTP rows. Confirm if the domains should be added to the enterprise-wide blocklist. Verify if the sign-in activity indicates a successful takeover of corporate or sensitive medical accounts.
```
→ end

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document the hosts and users examined. Record that no successful phishing attempts were observed during the Medicare Open Enrollment window.
```
→ end
