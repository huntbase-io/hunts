---
analysis: A single rule could alert on the domain, but this hunt correlates the initial
  endpoint traffic with subsequent identity-plane modifications (recovery changes)
  to confirm a successful hijacking, providing the context an analyst needs to move
  straight to containment.
blind_spots:
- id: missing-http-visibility
  question: whether a user visited the fraudulent domain on their primary workstation
  requires: EDR HTTP logging or Forward Proxy logs (hb_http_activity)
  risk: The hunt depends on the HTTP lead to open the identity queries; if traffic
    is not visible, the whole chain is missed.
  stage: malicious-link-redirection
- id: cloud-logging-disabled
  question: whether the attacker modified recovery email or phone settings in the
    SaaS platform
  requires: Google Workspace / GCP Audit Logs (hb_cloud_api_activity)
  risk: The persistence mechanism remains invisible, allowing the attacker to maintain
    access even if the user changes their password on their own.
  stage: account-recovery-manipulation
coverage:
- stage: malicious-link-redirection
  status: covered
  steps:
  - lead-web-traffic
- stage: credential-token-harvesting
  status: covered
  steps:
  - google-auth-anomalies
- stage: account-recovery-manipulation
  status: covered
  steps:
  - cloud-recovery-modification
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: spearphishing-outreach
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: YouTube creator and corporate social media accounts are high-value
    targets for brand impersonation and scam distribution; hunting for these hijacking
    attempts early prevents permanent account loss and reputation damage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary impersonating a brand redirects a content creator to a fraudulent
  collaboration platform to harvest Google credentials and then modifies account recovery
  details to maintain permanent access.
labels:
- hunt
- attack.t1566.002
- attack.t1528
- attack.t1098
- attack.t1190
- credential access
- initial access
- persistence
name: YouTube Sponsorship Scam Redirection and Harvesting
parameters:
  brand_keywords:
    default:
    - /hollyland
    - /nike
    - /spotify
    - /scouty
    - /collab
    - /sponsorship
    description: URL path segments associated with the brand-impersonation campaign.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - joinmatchy.com
    description: Known phishing infrastructure domains from the report.
    from:
      kind: article
      observed: '2026-10-07'
      ref: https://www.welivesecurity.com/en/social-media/brand-deal-scam-targeting-youtube-creators/
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/social-media/brand-deal-scam-targeting-youtube-creators/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Limit the initial HTTP lead to devices used by marketing, PR, and content
  creation staff, as they are the specific targets of sponsorship lures.
references:
- name: Inside a brand deal scam targeting YouTube creators
  url: https://www.welivesecurity.com/en/social-media/brand-deal-scam-targeting-youtube-creators/
related:
- hunt: spearphishing-outreach-campaigns
  reason: This hunt starts at the link click; hunting for the initial email arrival
    requires email security Gateway logs which are handled in the spearphishing series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spearphishing Email Outreach
    observables:
    - 'Sender name: Brandi'
    - 'Sender domain: unrelated to Hollyland'
    - 'Subject lines: Paid collaboration opportunity'
    - 'Content: Specific references to target YouTube videos'
    slug: spearphishing-outreach
    tactic: initial-access
    techniques:
    - T1566.001
  - name: Redirection to Fake Collaboration Platform
    observables:
    - joinmatchy.com
    - joinmatchy.com/hollyland
    - Domains containing scouty
    slug: malicious-link-redirection
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Credential and OAuth Token Harvesting
    observables:
    - Requests for YouTube channel management permissions
    - Fake Google sign-in pages capturing MFA codes
    - Income calculator metrics on phishing site
    slug: credential-token-harvesting
    tactic: credential-access
    techniques:
    - T1556
    - T1528
  - name: Account Recovery and Persistence
    observables:
    - Replaced recovery phone number
    - Replaced recovery email address
    - Addition of new backup codes
    slug: account-recovery-manipulation
    tactic: persistence
    techniques:
    - T1098
    - T1556.006
  summary: A modular spearphishing campaign targets YouTube creators with personalized
    sponsorship offers for brands like Hollyland, Nike, and Spotify. Victims are lured
    to fake collaboration platforms where they are prompted to sign in with Google,
    leading to the theft of credentials or OAuth tokens and subsequent hijacking of
    the account via modified recovery settings.
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


# YouTube Sponsorship Scam Redirection and Harvesting

This hunt targets a modular phishing campaign that impersonates audiovisual and global brands to target social media influencers. The campaign uses personalized emails to drive victims to bogus sites like joinmatchy[.]com, where it lures them into 'signing in with Google' to verify channel metrics. Once inside, the attacker replaces recovery phone numbers and email addresses to lock out the legitimate owner. The hunt uses a gated flow, starting with a broad lead on web traffic to known phishing domains or brand-specific paths, then opening expensive identity-plane queries to find evidence of account hijacking and persistence.

## lead-web-traffic
<!-- Web traffic to campaign domains or paths -->
Identify initial visits to known phishing domains or URLs containing campaign-specific brand keywords.

```sqlite target=web role=baseline params=(phishing_domains=phishing_domains, brand_keywords=brand_keywords, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A row showing a device visiting a known phishing domain or a brand-specific
  partnership path. Silence proves no monitored host visited these specific URLs in
  the window.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 5
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) as request_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_http_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR instr(',' || '{{brand_keywords}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path
```

## evaluate-lead
<!-- Evaluate lead quality -->
```agent target=hunter
cite: required
context:
- lead-web-traffic
max_iterations: 3
objective: Determine if the web traffic observed in lead-web-traffic is consistent
  with a content creator visiting a fraudulent sponsorship platform.
success_criteria: A verdict citing specific host visits to the suspicious domains
  or paths.
tools:
- endpoint
- identity
- web
```

## gate-on-lead
<!-- Gate on lead traffic -->
if~: "The lead evaluation is suspicious or malicious for at least one host." (confidence: high, judge=hunter)
then: → corroborate-compromise
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: missing-http-visibility)
else: → close-out

## corroborate-compromise
<!-- Corroborate with identity plane findings -->
parallel:
- → google-auth-anomalies
- → cloud-recovery-modification
join: → triage-incident

## google-auth-anomalies
<!-- Google authentication anomalies -->
Identify authentication failures or unusual sign-ins in the Google environment following the web interaction.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Failed sign-in attempts that may represent MFA harvesting or brute force.
  Silence means no recorded Google sign-in failures occurred.
reads:
- actor_user_name
- src_endpoint_ip
- status_detail
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, status_detail, user_agent, time FROM hb_auth_signin WHERE provider = 'gcp' AND status_id = 2 AND time >= datetime('now', '-{{lookback_days}} days')
```

## cloud-recovery-modification
<!-- Cloud account recovery modifications -->
Detect changes to recovery information which indicates the attacker has successfully hijacked the account.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: API calls modifying user attributes, recovery emails, or phone numbers.
  This is the durable indicator of a successful hijacking.
reads:
- actor_user_name
- api_operation
- target_user_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT actor_user_name, api_operation, api_service_name, target_user_name, status, time FROM hb_cloud_api_activity WHERE provider = 'gcp' AND (api_operation LIKE '%UpdateUser%' OR api_operation LIKE '%Recovery%' OR api_operation LIKE '%Password%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-incident
<!-- Triage incident chain -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- google-auth-anomalies
- cloud-recovery-modification
max_iterations: 6
objective: Determine if a user who visited the phishing domains subsequently experienced
  authentication failures or recovery information changes in their Google account.
success_criteria: A detailed verdict citing the web visit, the authentication event,
  and the account change.
tools:
- endpoint
- identity
- web
```

## route-on-triage
<!-- Route on triage -->
if~: "Triage confirms a successful hijack (web traffic followed by recovery modification) for at least one account." (confidence: high, judge=hunter)
then: → lock-and-secure-account
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: cloud-logging-disabled)
else: → manual-review

## lock-and-secure-account
<!-- Lock and secure account -->
```action target=identity
~~~yaml
approval: required
~~~
Force sign-out of all sessions, reset the user's password, and revert any recovery email or phone number changes to the known-good corporate standards.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Examine the email communications sent to the user. If a new domain or brand was used, update the parameters for the next hunt iteration and communicate the threat to the marketing and social media teams.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the number of hits and the outcome of the remediations. If silence was observed, confirm that the HTTP and Cloud API sources are currently active.
```
→ end
