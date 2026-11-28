---
analysis: A static detection rule on Staples or Dell order domains would create excessive
  noise. This hunt uses a gated flow to baseline normal brand activity first, then
  uses an agent to correlate lure keywords in cloud audit logs with registration patterns,
  identifying the specific 'Platform-as-a-Proxy' tradecraft that single-surface rules
  miss.
blind_spots:
- id: no-dns-telemetry
  question: whether we see the lookup for the abused retail domain on every host
  requires: Endpoint DNS logging or full recursive resolver logs
  risk: Hosts using external DNS resolvers like 8.8.8.8 will not appear in hb_dns_activity,
    making the lead query incomplete.
  stage: legitimate-platform-phishing-delivery
- id: no-mail-body-inspection
  question: what the specific fraudulent phone number was inside the email body
  requires: Full email body indexing or Mail Gateway logs
  risk: M365 audit logs show subjects and metadata but not the body content where
    the Helpline numbers live, necessitating manual review.
  stage: legitimate-platform-phishing-delivery
- id: no-http-body-visibility
  question: what strings were injected into the POST body of registration forms
  requires: hb_http_activity (request_body_len or full request_body)
  risk: If the hostile string is sent in the request body rather than the URL query
    parameters, hb_http_activity will miss the lure content.
  stage: public-facing-input-injection
coverage:
- stage: public-facing-input-injection
  status: covered
  steps:
  - http-registration-abuse
- stage: legitimate-platform-phishing-delivery
  status: covered
  steps:
  - dns-brand-lead
  - m365-mail-lures
- stage: delivery-status-notification-abuse
  status: covered
  steps:
  - m365-mail-lures
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries use the inherent trust in commerce and SaaS infrastructure
    to bypass standard email authentication. A negative result confirms that these
    trusted delivery pipelines are not currently being used to deliver social-engineering
    lures to the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trusted third-party retail or SaaS infrastructure
  to deliver social-engineering lures by injecting fraudulent helpline numbers into
  transactional notification fields or abusing public-facing registration forms.
labels:
- hunt
- attack.t1190
- attack.t1566
- initial access
name: Platform-as-a-Proxy Phishing and Input Abuse
parameters:
  brand_domains:
    default:
    - orders.staples.com
    - order.dell.com
    - order.dellcom
    description: High-reputation domains identified in the report as being abused.
    from:
      kind: article
      observed: '2026-10-21'
      ref: https://blog.talosintelligence.com/parasitizing-trust-how-legitimate-infrastructure-becomes-a-delivery-pipeline-for-attackers/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts identified in the scoping step; leave empty
      to hunt across the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/parasitizing-trust-how-legitimate-infrastructure-becomes-a-delivery-pipeline-for-attackers/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying hosts running Microsoft 365, Office, or
  Cisco software. These systems are most relevant for phishing delivery and potential
  input abuse into corporate-facing applications.
references:
- name: "Talos \u2014 Parasitizing trust: How legitimate infrastructure becomes a\
    \ delivery pipeline for attackers"
  url: https://blog.talosintelligence.com/parasitizing-trust-how-legitimate-infrastructure-becomes-a-delivery-pipeline-for-attackers/
related:
- hunt: m365-social-engineering-lure-detection
  reason: This hunt focuses specifically on platform proxy abuse; broader phishing
    hunts cover general lure types.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Public-Facing Application Forms
    observables:
    - hostile string injected into name fields
    - malicious strings in company or title registration fields
    - cryptocurrency-themed lures in registration forms
    slug: public-facing-input-injection
    tactic: initial-access
    techniques:
    - T1190
  - name: High-Reputation Notification Phishing
    observables:
    - support@orders.staples.com
    - received@order.dellcom
    - order.dell.com
    - Helpline 806 283 7712
    - Helpline 808 232 6397
    - "Here\u2019s your Staples order #9939818875. Thanks for shopping with us."
    - 'We have your order | Dell Purchase ID: 2009829958247'
    - Confirmed Order in shipping fields
    - Call Our Sales Team in billing fields
    slug: legitimate-platform-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of Mail Delivery Status Reports
    observables:
    - Non-delivery report (NDR) carrying WeTransfer-themed lure
    - Delivery status notification (DSN) with encapsulated phishing link
    - WeTransfer file-sharing lure inside administrative mail wrapper
    slug: delivery-status-notification-abuse
    tactic: initial-access
    techniques:
    - T1566
  summary: Adversaries are exploiting unvalidated input fields on legitimate SaaS
    and commerce platforms to inject malicious content into automated, high-reputation
    notifications. These 'Platform-as-a-Proxy' (PaaP) attacks leverage trusted infrastructure
    like Staples, Dell, and WeTransfer to deliver phishing lures, fake helplines,
    and fraudulent delivery status reports that bypass traditional email security
    filters.
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


# Platform-as-a-Proxy Phishing and Input Abuse

This hunt identifies the subversion of legitimate commerce and SaaS pipelines where attackers inject malicious intent into fields that are later rendered into high-reputation, automated notifications. The hunt uses a gated flow, starting with a scoping of hosts running collaboration software and a cheap lead for DNS activity to abused retail domains, before fanning out to examine cloud audit logs for specific lures and HTTP traffic for registration form abuse.

## identify-relevant-software
<!-- Identify hosts with collaboration and mail software -->
Find the hosts running Microsoft 365, Office, or Cisco components that could be the recipients of high-reputation phishing or the origin of form abuse.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running products named in the threat research. These represent
  the likely targets for notification-based social engineering.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%office%' OR LOWER(package_name) LIKE '%cisco%')
```

## dns-brand-lead
<!-- DNS lookups to abused brand domains -->
Identify hosts interacting with the specific Staples and Dell domains named in the report as a low-cost lead.

```sqlite target=endpoint role=baseline params=(brand_domains=brand_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hosts resolving the order-related domains. While frequent for shoppers,
  lookups coinciding with lure keywords in other surfaces suggest the receipt of a
  fraudulent notification.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{brand_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## eval-lead
<!-- Evaluate brand interaction -->
```agent target=hunter
cite: required
context:
- dns-brand-lead
max_iterations: 3
objective: Review the DNS lookup volume and requesting processes. Identify hosts where
  lookups to order domains are rare or appear in tight clusters suggesting automated
  notifications.
success_criteria: A verdict per host indicating whether the lead is worth following.
tools:
- endpoint
- web
```

## gate-decision
<!-- Gate: Proceed to content analysis -->
if~: "the eval-lead verdict identifies at least one host resolving abused brand domains in a suspicious manner" (confidence: high, judge=hunter)
then: → expensive-content-checks
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-dns-telemetry)
else: → close-out

## expensive-content-checks
<!-- Fan out for mail lures and form abuse -->
parallel:
- → m365-mail-lures
- → http-registration-abuse
join: → final-triage

## m365-mail-lures
<!-- M365 notification and lure activity -->
Search Office 365 Unified Audit Logs for incoming mail items containing the specific report lures in the subject line.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Audit records reflecting the arrival of mail items with suspicious subjects
  like Helpline or Order Confirmed. M365 UAL captures subject lines in resource_name
  for certain Exchange operations.
reads:
- actor_user_name
- api_operation
- resource_name
- resource_uid
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT actor_user_name, api_operation, resource_name, resource_uid, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (instr(LOWER(resource_name), 'helpline') > 0 OR instr(LOWER(resource_name), 'order confirmed') > 0 OR instr(LOWER(resource_name), 'purchase id') > 0 OR instr(LOWER(resource_name), 'wetransfer') > 0 OR instr(LOWER(resource_name), 'non-delivery') > 0 OR instr(LOWER(resource_name), 'delivery status') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## http-registration-abuse
<!-- Platform registration and form input abuse -->
Find outbound web requests attempting to use registration forms with hostile strings, representing the input stage of the proxy abuse.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to registration or signup endpoints that contain crypto or
  helpline keywords in the query parameters. This indicates a host may be attempting
  to trigger reflexive notifications.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, http_method, time FROM hb_http_activity WHERE http_method = 'POST' AND (LOWER(url_path) LIKE '%signup%' OR LOWER(url_path) LIKE '%register%' OR LOWER(url_path) LIKE '%profile%') AND (LOWER(url_query) LIKE '%crypto%' OR LOWER(url_query) LIKE '%helpline%' OR LOWER(url_query) LIKE '%bitcoin%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Correlate platform abuse and notifications -->
```agent target=hunter
cite: required
context:
- eval-lead
- m365-mail-lures
- http-registration-abuse
max_iterations: 6
objective: Determine if a host has received a suspicious retail notification (from
  Staples/Dell) or if a host is attempting to inject lures into SaaS forms. Correlate
  the timing of DNS lookups to Staples/Dell with the arrival of mail items identified
  in the M365 logs.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  rows.
tools:
- endpoint
- web
```

## route-confirmed-threat
<!-- Route on confirmed threat -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-mail-body-inspection)
else: → close-out

## isolate-endpoint
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host. Revoke the M365 user session to prevent further engagement with fraudulent mail content.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the specific Exchange mail items found in the UAL. Check for the helpline numbers mentioned in the Talos report (806-283-7712 or 808-232-6397). Confirm if the user has made any outbound calls or browser connections to the retail brands immediately after receiving these notifications.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the examined hosts. If lookups to Staples/Dell were found but no lures were identified in mail logs, mark as benign retail activity. Document any new registration forms abused to update the HTTP keyword list.
```
→ end
