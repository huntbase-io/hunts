---
analysis: Simple detection rules alert on the domains themselves; this hunt links
  the DNS resolution lead to process-level socket state and HTTP URIs to determine
  if the social engineering was effective. The gated flow ensures that high-volume
  telemetry is only searched for specific high-fidelity leads.
blind_spots:
- id: encrypted-dns-visibility
  question: whether the host used DNS-over-HTTPS (DoH) to resolve lookalike domains
  requires: Network-level DNS logs (hb_dns_activity)
  risk: Modern browsers using DoH bypass traditional DNS resolvers, so the gate may
    close prematurely even if an interaction occurred.
  stage: infrastructure-setup
- id: endpoint-telemetry-gap
  question: which process initiated the connection to the fraud domains on unmanaged
    hosts
  requires: Endpoint agent coverage for hb_network_connection
  risk: If a target host lacks an agent, we see the connection at the network level
    but cannot attribute it to a specific user or application, leading to indeterminate
    verdicts.
  stage: fraudulent-interaction
- id: missing-email-context
  question: whether the initial phishing email was successfully delivered and seen
    by the user
  requires: hb_email_activity or M365 email logs
  risk: We are hunting interactions without visibility into the delivery mechanism,
    missing the chance to see headers or AI markers in the source email.
  stage: executive-impersonation-phishing
coverage:
- stage: infrastructure-setup
  status: covered
  steps:
  - dns-leads
- blind_spot: missing-email-context
  reason: The dossier provides no hb_email surface or M365-native email logs to examine
    message headers, separators, or HTML comments.
  stage: executive-impersonation-phishing
  status: not_visible
- stage: fraudulent-interaction
  status: covered
  steps:
  - socket-connections
  - web-requests
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Business Email Compromise (BEC) resulting in fraudulent ACH transfers
    is a direct financial loss risk. Validating whether employees have successfully
    interacted with known lookalike domains confirms whether the current campaign
    has breached the human layer.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An employee has received a BEC email and is interacting with lookalike
  infrastructure to view a fake invoice or initiate a fraudulent payment.
labels:
- hunt
- attack.t1566
- attack.t1598
- attack.t1583.001
- attack.t1591
name: Interaction with BEC Lookalike Infrastructure
parameters:
  bec_domains:
    default:
    - service-nowinc.com
    - domainlify.net
    description: Known lookalike domains from the campaign report.
    from:
      kind: article
      observed: '2026-09-10'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Filter interaction queries to these hosts; leave empty to check the
      whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize finance and executive workstations as they are the intended
  targets of the ACH fraud lures. Use the hosts found in the dns-leads step to populate
  the scope_hosts parameter for the parallel connection investigation.
references:
- name: "MSRC \u2014 Protecting organizations from AI-assisted executive impersonation\
    \ and invoice fraud"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/
related:
- hunt: m365-bec-forwarding-rules
  reason: This hunt focuses on infrastructure interaction; another hunt is required
    to find internal persistence via email forwarding rules used to hide BEC replies.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Lookalike Domain Registration
    observables:
    - service-nowinc.com
    - domainlify.net
    - Registration date 2026-07-31
    slug: infrastructure-setup
    tactic: resource-development
    techniques:
    - T1583.001
    - T1585.002
  - name: AI-Assisted Phishing Delivery
    observables:
    - 'Subject keywords: ''due bill'', ''ACH Parment'''
    - "ServiceNow Platform \u2014 Annual Subscription"
    - 'Reply-To: domainlify.net'
    - CEO signature impersonation
    - 'Banner separators: ==========='
    - HTML comments in email source
    - "Em-dash usage: \u2014"
    slug: executive-impersonation-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1598
    - T1090.003
  - name: Lookalike Domain Interaction
    observables:
    - service-nowinc.com
    - domainlify.net
    slug: fraudulent-interaction
    tactic: reconnaissance
    techniques:
    - T1591
  summary: A large-scale business email compromise campaign used AI-assisted templates
    to impersonate company executives and vendor representatives to facilitate ACH
    payment fraud. The threat actor registered lookalike domains and used third-party
    email infrastructure to deliver over a million phishing emails containing fabricated
    invoices and simulated internal conversation threads.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Interaction with BEC Lookalike Infrastructure

This hunt identifies internal interaction with infrastructure registered for AI-assisted executive impersonation. It uses a gated flow to first find low-cost DNS leads matching known lookalike patterns, then expands the investigation to process-level sockets and HTTP telemetry only when a lead is confirmed. The hunt distinguishes between simple email delivery and successful social engineering by verifying if an endpoint established a connection to the fraud domains.

## dns-leads
<!-- DNS lookups for lookalike domains -->
Identify any internal host attempting to resolve the campaign infrastructure.

```sqlite target=endpoint role=scoping params=(bec_domains=bec_domains, lookback_days=lookback_days)
~~~yaml
expected: A host resolving these domains suggests a potential victim who clicked a
  link. Silence proves no resolution occurred via monitored DNS resolvers.
reads:
- activity_id
- answers
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, answers, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE activity_id = 1 AND instr(',' || '{{bec_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, answers
```

## read-leads
<!-- Evaluate DNS leads -->
```agent target=hunter
cite: required
context:
- dns-leads
max_iterations: 3
objective: Determine if the DNS lookups for {{bec_domains}} indicate meaningful interaction
  that should open the gate for connection telemetry.
success_criteria: A per-host verdict on whether the DNS activity is a positive lead
  for follow-on queries.
tools:
- endpoint
- network
- web
```

## gate-on-leads
<!-- Gate on lead significance -->
if~: "the agent finds at least one host resolving lookalike domains" (confidence: high, judge=hunter)
then: → investigate-interaction
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-dns-visibility)
else: → close-out

## investigate-interaction
<!-- Investigate connection details -->
parallel:
- → socket-connections
- → web-requests
join: → final-triage

## socket-connections
<!-- Sockets to fraud domains -->
Identify the process and user that connected to the identified infrastructure.

```sqlite target=network role=detection-candidate params=(scope_hosts=scope_hosts, bec_domains=bec_domains, lookback_days=lookback_days)
~~~yaml
expected: A row identifies a browser or application talking to the BEC site. Silence
  means no established socket was recorded for those domains.
reads:
- activity_id
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_hostname, process_name, user_name, time FROM hb_network_connection WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{bec_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## web-requests
<!-- HTTP telemetry for fraud URIs -->
Inspect the full URL to determine if the user accessed specific invoice or payment portals.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, bec_domains=bec_domains, lookback_days=lookback_days)
~~~yaml
expected: Full URI paths show specific interaction targets (e.g., /invoice/ACH). Silence
  may mean the traffic was encrypted at the proxy.
reads:
- device_hostname
- time
- url_full
- url_hostname
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_full, user_agent, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{bec_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Synthesize interaction evidence -->
```agent target=hunter
cite: required
context:
- read-leads
- socket-connections
- web-requests
max_iterations: 6
objective: Determine if any host successfully engaged with lookalike infrastructure
  based on the combined telemetry.
success_criteria: A verdict that distinguishes between mere resolution and active
  session engagement.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route based on interaction -->
if~: "the triage confirms active interaction with fraud infrastructure for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate target endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke active identity sessions for the involved user account.
```
→ analyst-review

## analyst-review
<!-- Verify fraud completion -->
```manual target=analyst
Review the full URIs in the web-requests step. Check the user inbox for the impersonation emails to verify if they match the AI-generated patterns described in the report. Coordinate with finance to check for pending ACH transfers to unknown bank accounts.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record all hosts that were examined and found to have no interaction. Add any newly discovered fraudulent IPs to the perimeter blocklist.
```
→ end
