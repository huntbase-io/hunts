---
analysis: A standard rule would alert on the phishing email, but this hunt correlates
  the delivery with specific host interaction (DNS) and specific account impact (rare
  API calls) in one flow, providing the end-to-end evidence an analyst needs to confirm
  an intrusion.
blind_spots:
- id: mail-log-visibility
  owner: Messaging Team
  question: whether all delivered phishing emails were visible to the lead query
  remediation: Ensure all M365 tenants are enrolled in centralized audit logging.
  requires: Complete M365 Unified Audit Log ingestion
  risk: If certain mailbox types or external tenants are not integrated, the lead
    query will return zero rows even if phishing was successful.
  stage: initial-access-service-outage-phishing
- id: no-api-retention
  owner: Platform Engineering
  question: whether the impact occurred outside the current lookback window
  remediation: Increase cloud API log retention to at least 30 days.
  requires: hb_cloud_api_activity retention > 14 days
  risk: A compromise that happened 20 days ago would be missed if logs roll over quickly.
  stage: impact-account-compromise-activity
coverage:
- stage: initial-access-service-outage-phishing
  status: covered
  steps:
  - phishing-emails-lead
- stage: execution-tracking-link-interaction
  status: covered
  steps:
  - dns-tracking-interaction
- stage: impact-account-compromise-activity
  status: covered
  steps:
  - rare-cloud-api-impact
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Credential phishing impersonating platform outages has a high success
    rate. Confirming a negative result across the estate ensures the perimeter blocks
    were effective, while a positive result enables containment before mailbox data
    is exfiltrated.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained initial access by sending phishing emails that
  impersonate Microsoft 365 outage notifications, inducing users to click tracking
  links that lead to credential theft and subsequent unauthorized cloud API activity.
labels:
- hunt
- attack.t1566.002
- attack.t1566
- attack.t1036
- attack.t1204.001
- attack.t1071
- attack.t1190
- attack.t1041
- execution
- impact
- initial access
- microsoft-365
name: Microsoft 365 Service Health Impersonation and Account Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: huntbase-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the expensive DNS query; leave
      empty for fleet-wide.
    from:
      kind: manual
      ref: analyst-defined
    type: list[host]
  sender_domains:
    default:
    - moments-notice.com
    - planetmaison.com
    - newbooker.com
    - em4493.moments-notice.com
    - em.newbooker.com
    description: Observed sender domains from the campaign report.
    from:
      kind: article
      observed: '2026-11-13'
      ref: ms-blog-2026-11
    type: list[domain]
  tracking_domains:
    default:
    - u113727626.ct.sendgrid.net
    - u118254266.ct.sendgrid.net
    - u118250677.ct.sendgrid.net
    - url.newbooker.com
    - url7489.newbooker.com
    - reallifeaccounting.com
    - outagefixed.sbs
    - outagerestored.sbs
    description: Infrastructure used for click-tracking and redirection.
    from:
      kind: article
      observed: '2026-11-13'
      ref: ms-blog-2026-11
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The lead query is a cheap search on mail telemetry for specific lures.
  Because the campaign is high-volume and uses specific domains, we start broad across
  all mailboxes. Scoping is only applied at the DNS level if an analyst needs to re-run
  for specific hosts identified in the lead.
references:
- name: "High volume phishing campaign uses Microsoft 365 outage lures \u2014 Microsoft\
    \ Security Blog"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
related:
- hunt: m365-inbox-rule-manipulation-baseline
  reason: This hunt focuses on phishing-led rule changes; a sibling hunt baselines
    all rule changes regardless of vector.
  relation: sibling
scenario:
  stages:
  - name: Outage-Themed Phishing Delivery
    observables:
    - 'Sender domains: moments-notice.com, planetmaison.com, newbooker.com, em4493.moments-notice.com,
      em.newbooker.com'
    - "Subject patterns: 'Outage \u2013 ', 'Strengthen \u2013 Security ', 'Restore\
      \ \u2014 4 messages '"
    - Display names ending in 'Outage Notification' or 'Service Health'
    - Lure text referencing Exchange Online, Outlook, Teams, SharePoint, and Copilot
    - Urgency claims of 24-hour message deletion
    slug: initial-access-service-outage-phishing
    tactic: initial-access
    techniques:
    - T1566.002
    - T1566
    - T1036
  - name: Malicious Link Redirection
    observables:
    - 'Click-tracking domains: u113727626.ct.sendgrid.net, u118254266.ct.sendgrid.net,
      u118250677.ct.sendgrid.net'
    - 'Tracking subdomains: url.newbooker.com, url7489.newbooker.com'
    - 'Destination domains: reallifeaccounting.com, outagefixed.sbs, outagerestored.sbs'
    - 'URL paths: /themelist0.html, /topics_pxyk/themelist0.html'
    - 'Attacker IP: 162.120.17.69'
    slug: execution-tracking-link-interaction
    tactic: execution
    techniques:
    - T1204.001
    - T1071
    - T1190
  - name: Assessed Account Abuse
    observables:
    - Sign-ins from 162.120.17.69
    - Creation of new inbox or forwarding rules
    - OAuth application consent operations
    - Anomalous access to SharePoint or Teams data following login
    slug: impact-account-compromise-activity
    tactic: impact
    techniques:
    - T1041
  summary: A high-volume phishing campaign leveraged Microsoft 365 outage-themed lures
    to trick users into clicking recipient-specific tracking links. These links redirected
    victims to a common destination infrastructure for assessed credential phishing,
    often referencing Exchange Online disruptions and requiring immediate action to
    restore 'held' messages.
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
  microsoft-365:
    category: siem
    huntbase:
      product: microsoft-365
    name: microsoft 365
tlp: clear
type: investigation
---


# Microsoft 365 Service Health Impersonation and Account Abuse

This hunt targets a coordinated phishing campaign using service-health lures. It employs a gated flow where a cheap lead query on mail telemetry determines if campaign-specific lures exist. If confirmed, the hunt fans out to verify user interaction via DNS tracking infrastructure and identifies post-compromise impact through rare cloud API operations, such as the creation of new inbox rules or OAuth application consents. An agent correlates the delivery, interaction, and impact to confirm an active intrusion.

## phishing-emails-lead
<!-- Lead: Outage-themed phishing lures -->
Identify suspicious emails using the campaign's specific sender domains and subject line patterns.

```sqlite target=microsoft-365 role=scoping params=(sender_domains=sender_domains, lookback_days=lookback_days)
~~~yaml
expected: Rows identify specific phishing emails delivered to users. Silence suggests
  the campaign has not targeted the tenant in the current window.
reads:
- sender
- from
- subject
- sent_date_time
- internet_message_id
- tenant_id
silence: not_evidence_of_absence
source: microsoft365_mail_message
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT sender, "from", subject, sent_date_time, internet_message_id, tenant_id FROM microsoft365_mail_message WHERE (instr(',' || '{{sender_domains}}' || ',', ',' || LOWER(SUBSTR(sender, INSTR(sender, '@') + 1)) || ',') > 0 OR subject LIKE 'Outage -%' OR subject LIKE 'Strengthen - Security%' OR subject LIKE 'Restore — 4 messages%') AND sent_date_time >= datetime('now', '-{{lookback_days}} days')
```

## verify-lead
<!-- Verify phishing campaign relevance -->
```agent target=hunter
cite: required
context:
- phishing-emails-lead
max_iterations: 3
objective: Determine if the identified mail records represent the Microsoft 365 outage
  phishing campaign.
success_criteria: A per-row verdict of malicious or benign.
tools:
- endpoint
- microsoft-365
```

## is-lead-legit
<!-- Gate on phishing evidence -->
if~: "the verify-lead verdict is malicious for at least one email record" (confidence: high, judge=hunter)
then: → fan-out-expensive
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: mail-log-visibility)
else: → close-out

## fan-out-expensive
<!-- Expensive correlation fan-out -->
parallel:
- → dns-tracking-interaction
- → rare-cloud-api-impact
join: → triage-correlation

## dns-tracking-interaction
<!-- Scoped DNS interaction with tracking domains -->
Verify if scoped hosts resolved the campaign's tracking or redirection domains, indicating a link click.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, tracking_domains=tracking_domains, lookback_days=lookback_days)
~~~yaml
expected: Resolution of tracking domains by a host suggests a successful link click
  from a phishing email.
reads:
- device_hostname
- query_hostname
- answers
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, query_hostname, answers, time FROM hb_dns_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{tracking_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-cloud-api-impact
<!-- Rare cloud API inbox rule manipulation -->
Detect account impact by finding users performing rare inbox rule operations or OAuth consents typical of BEC.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Specific users creating inbox rules when such behavior is rare across the
  tenant. Silence suggests no automated rule manipulation has occurred.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 4
reads:
- api_operation
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT api_operation, actor_user_name, COUNT(DISTINCT actor_user_name) AS user_count, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE provider = 'm365' AND (api_operation IN ('New-InboxRule', 'Set-InboxRule', 'Consent to application')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY api_operation, actor_user_name HAVING user_count <= 3
```

## triage-correlation
<!-- Correlate email, interaction, and abuse -->
```agent target=hunter
cite: required
context:
- verify-lead
- dns-tracking-interaction
- rare-cloud-api-impact
max_iterations: 5
objective: Evaluate the sequence of phishing delivery, tracking resolution, and cloud
  API changes to determine if an account takeover occurred.
success_criteria: A verdict of malicious | suspicious | benign per user/host, citing
  rows from all surfaces.
tools:
- endpoint
- microsoft-365
```

## route-on-triage
<!-- Route on compromise verdict -->
if~: "the triage-correlation verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → isolate-account
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-api-retention)
else: → close-out

## isolate-account
<!-- Isolate compromised account -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active refresh tokens for the identified users, reset their passwords, and initiate an audit of their mailbox for new rules.
```
→ analyst-review

## analyst-review
<!-- Forensic analyst review -->
```manual target=analyst
Examine the timing between DNS resolution of the tracking domains and the creation of inbox rules. Check SharePoint and Teams logs for unusual file access from the same actor IP.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings. If inbox rule manipulation was confirmed, promote the rare-cloud-api-impact query to a standing detection.
```
→ end
