---
analysis: A standard detection rule might flag the static domains, but this hunt baselines
  all 'ServiceNow' variants and looks for the rare creation of PDF invoices across
  multiple surfaces, allowing it to catch infrastructure shifts that AI-assisted actors
  frequently deploy.
blind_spots:
- id: no-network-telemetry
  owner: Network Engineering
  question: Was the connection to the lookalike domain made via an ORB proxy network?
  remediation: Ensure hb_http_activity includes user_agent and authenticated user
    info.
  requires: Forward proxy or full HTTP inspection with user-agent logging
  risk: Attackers using multi-hop proxies (T1090.003) might appear as internal traffic
    or generic browser traffic, masking the adversary origin.
  stage: obfuscated-traffic-proxying
- id: no-email-telemetry
  owner: Messaging Team
  question: Did the email contain the specific AI-assisted markers (em-dash, custom
    banners)?
  remediation: Onboard hb_email_activity to enable keyword searches in subjects and
    bodies.
  requires: hb_email_activity or direct M365 audit logs
  risk: We are hunting for the aftermath (DNS/Files) rather than the delivery; if
    the user deletes the email without downloading the invoice, we may miss the targeting.
  stage: ai-assisted-phishing-delivery
coverage:
- stage: impersonation-infrastructure-registration
  status: covered
  steps:
  - dns-to-lookalikes
  - rare-servicenow-variants
- stage: ai-assisted-phishing-delivery
  status: covered
  steps:
  - pdf-invoice-artifacts
  - analyst-review
- blind_spot: no-network-telemetry
  reason: Attribution of multi-hop proxy chains (T1090.003) is not possible with the
    available endpoint or network connection surfaces.
  stage: obfuscated-traffic-proxying
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI-assisted BEC represents a material financial risk, as traditional
    phishing filters may miss the high-fidelity lures. This hunt provides assurance
    that the organizational accounting/finance departments have not been compromised
    by this specific $50,000 ACH campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using lookalike domains and AI-generated invoice lures
  to trick finance personnel into processing fraudulent ACH payments, following a
  pattern of impersonating executives and vendors like ServiceNow.
labels:
- hunt
- attack.t1566
- attack.t1598
- attack.t1583.001
- attack.t1585.002
- attack.t1591
- attack.t1090.003
name: AI-Assisted Executive Impersonation and Invoice Fraud
parameters:
  impersonation_domains:
    default:
    - service-nowinc.com
    - domainlify.net
    description: Lookalike domains used for phishing and reply-to infrastructure.
    from:
      kind: article
      observed: '2026-07-31'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts to narrow the search; leave empty to hunt across the estate.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying hosts with ServiceNow packages to find likely finance/admin
  targets; then expand to the whole estate via DNS if those hosts are clean.
references:
- name: Protecting organizations from AI-assisted executive impersonation and invoice
    fraud
  url: https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/
related:
- hunt: m365-executive-session-hijack
  reason: Executive impersonation often follows credential or session theft; this
    hunt should be paired with a search for anomalous executive logons.
  relation: sibling
scenario:
  stages:
  - name: Lookalike Domain Registration
    observables:
    - service-nowinc.com
    - domainlify.net
    - Registration date July 31 2026
    slug: impersonation-infrastructure-registration
    tactic: resource-development
    techniques:
    - T1583.001
  - name: AI-Assisted Phishing and Lure Interaction
    observables:
    - 'Subject keywords: ''due bill'', ''ACH Parment'''
    - "Lure text: 'ServiceNow Platform \u2014 Annual Subscription'"
    - "AI markers: HTML comments, em-dash symbols '\u2014', banner lines '==========='"
    - CEO/CFO impersonation in sender and reply-to display names
    - Request for 'PDF version' of invoice
    - Bank transfer instructions for ACH payments of nearly $50,000
    slug: ai-assisted-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1598
    - T1591
  - name: Multi-hop Traffic Obfuscation
    observables:
    - Traffic to impersonation domains via multi-hop proxies or ORB networks
    slug: obfuscated-traffic-proxying
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An AI-assisted business email compromise (BEC) campaign targeted finance
    teams with ACH payment fraud by impersonating executives and vendors like ServiceNow.
    The attackers used generative AI to create highly uniform templates, fabricated
    email threads, and itemized invoices, delivering them through lookalike domains
    and third-party email infrastructure.
severity: medium
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


# AI-Assisted Executive Impersonation and Invoice Fraud

This hunt identifies internal hosts interacting with lookalike infrastructure (e.g., service-nowinc.com) and the subsequent creation of fraudulent invoice PDF artifacts. It leverages the correlation between DNS resolutions, rare HTTP traffic to non-standard vendor domains, and file creation events in user-writable paths to isolate victims of high-fidelity Business Email Compromise (BEC).

## scope-potential-targets
<!-- Scope by ServiceNow software or connectors -->
Identify hosts that have ServiceNow software or related connectors installed, representing likely targets or relevant business units.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to users or departments that interact with
  ServiceNow.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%servicenow%' OR LOWER(vendor_name) LIKE '%servicenow%'
```

## gather-evidence
<!-- Gather independent evidence -->
parallel:
- → dns-to-lookalikes
- → rare-servicenow-variants
- → pdf-invoice-artifacts
join: → triage-fraud

## dns-to-lookalikes
<!-- DNS lookups to lookalike domains -->
Find any host resolving the specific impersonation domains identified in the research.

```sqlite target=endpoint role=enrichment params=(impersonation_domains=impersonation_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hostnames resolving domains like service-nowinc.com; silence means no interaction
  with the known primary infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{impersonation_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## rare-servicenow-variants
<!-- Rare HTTP variants of ServiceNow hostnames -->
Baseline web traffic to variants of 'ServiceNow' to catch domains not named in the initial report but following the same pattern.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hosts connecting to service-nowinc.com or other lookalikes that stand out
  from standard corporate traffic.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- url_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE url_hostname LIKE '%service-now%' AND url_hostname NOT LIKE '%.service-now.com' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname HAVING host_count < 3
```

## pdf-invoice-artifacts
<!-- ServiceNow PDF creation in user paths -->
Identify the creation of PDF files containing 'ServiceNow' in the filename, indicative of the fraudulent invoice being saved.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of PDF invoices in user profiles on hosts previously identified
  as targets or interactors.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND LOWER(file_name) LIKE '%.pdf%' AND LOWER(file_name) LIKE '%servicenow%' AND (LOWER(file_path) LIKE '%\downloads\%' OR LOWER(file_path) LIKE '%\desktop\%' OR LOWER(file_path) LIKE '%/downloads/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-fraud
<!-- Evaluate evidence of financial fraud -->
```agent target=hunter
cite: required
context:
- scope-potential-targets
- dns-to-lookalikes
- rare-servicenow-variants
- pdf-invoice-artifacts
max_iterations: 5
objective: 'Determine if any host shows the complete attack chain: infrastructure
  interaction followed by invoice download. Weigh the ''ServiceNow'' keyword across
  different surfaces.'
success_criteria: A per-host verdict (malicious/suspicious/benign) with citations
  of specific file paths and domains.
tools:
- endpoint
- web
```

## decision-route
<!-- Route on fraud verdict -->
if~: "the triage verdict is malicious for at least one host AND a PDF artifact was cited" (confidence: high, judge=hunter)
then: → isolate-victim
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → analyst-review

## isolate-victim
<!-- Isolate victim endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the user. Recover the identified PDF invoice for sandbox analysis.
```
→ analyst-review

## analyst-review
<!-- Coordinate with Finance and review communication -->
```manual target=analyst
Review the user's M365 mail flow for the subjects 'due bill' or 'ACH Parment'. Check for AI markers (em-dash, banner lines) in the message body. Contact Finance to ensure no ACH payments of ~$50,000 were processed for the impersonated vendors.
```
→ end
