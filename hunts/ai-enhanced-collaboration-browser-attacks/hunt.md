---
analysis: A simple rule for new browser extensions is too noisy for most fleets. This
  hunt uses a phased sequence to pivot from HTTP traffic and cloud API grants into
  rare software inventory, providing the necessary context to identify a true malicious
  chain.
blind_spots:
- id: no-decryption
  question: What content was submitted to the phishing URL after the initial interaction.
  requires: TLS decryption on a forward proxy
  risk: We can see the domain visited but not whether credentials or tokens were exfiltrated
    in the request payload.
  stage: initial-access-phishing-collaboration
- id: extension-data-gap
  question: The specific internal capabilities or permissions of a loaded browser
    extension.
  requires: Browser internal database monitoring
  risk: The hunt sees the extension name and vendor but may not see if it has permissions
    to read page content or intercept form submissions.
  stage: malicious-browser-extensions
- id: cloud-api-latency
  question: Whether an OAuth grant occurred in the last few minutes.
  requires: Unified Audit Log (UAL) near-real-time streaming
  risk: There is a known delay in cloud API logging that might prevent identifying
    a very recent compromise.
  stage: oauth-phishing-and-consent
coverage:
- stage: initial-access-phishing-collaboration
  status: covered
  steps:
  - phishing-clicks
- stage: oauth-phishing-and-consent
  status: covered
  steps:
  - oauth-grants
- stage: malicious-browser-extensions
  status: covered
  steps:
  - rare-extensions
- stage: session-hijacking-credential-access
  status: covered
  steps:
  - anomalous-signins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Modern collaboration attacks use AI to bypass standard email gateways;
    organizations must confirm that post-click persistence mechanisms like malicious
    extensions are not present on critical assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed traditional email defenses using AI-enhanced
  social engineering to trick a user into granting OAuth permissions or installing
  a malicious browser extension, leading to session hijacking and persistent access.
labels:
- hunt
- attack.t1566
- attack.t1176
- attack.t1190
- attack.t1557
- credential access
- initial access
- persistence
name: AI-Enhanced Collaboration and Browser Attacks
parameters:
  browser_names:
    default:
    - chrome
    - firefox
    - msedge
    - safari
    description: Common browser package names to identify candidate hosts.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: hunt-standard
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: hunt-standard
    type: number
  phishing_domains:
    default:
    - proofpoint.com
    - secure-login-verify.com
    - microsoft-consent.net
    description: Known or suspicious domains linked to phishing; includes the article
      domain as a baseline.
    from:
      kind: article
      observed: '2026-09-22'
      ref: proofpoint-ai-era-press-release
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; typically populated from
      the scoping results.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: hunt-standard
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-stops-attacks-traditional-defenses-miss-ai-era
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope the hunt to critical business workstations first, particularly finance
  and executive users, as they are primary targets for AI-enhanced transaction fraud
  and social engineering.
references:
- name: Proofpoint Stops the Attacks Traditional Defenses Miss in the AI Era
  url: https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-stops-attacks-traditional-defenses-miss-ai-era
related:
- hunt: cloud-app-registration-monitoring
  reason: This hunt focuses on browser-borne threats and extensions; a broader cloud-native
    hunt for any application registration is a sibling.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering via Trusted Relationships
    observables:
    - Compromised supplier email threads
    - Fraudulent payment requests
    - Post-click phishing URLs
    - Phishing attachments
    slug: initial-access-phishing-collaboration
    tactic: initial-access
    techniques:
    - T1566
  - name: OAuth Phishing and Credential Theft
    observables:
    - Malicious OAuth consent requests
    - Credential theft via phishing landing pages
    - Abuse of trusted application permissions
    slug: oauth-phishing-and-consent
    tactic: initial-access
    techniques:
    - T1566
  - name: Persistence via Malicious Browser Extensions
    observables:
    - Installation of unauthorized browser extensions
    - Malicious extension files in user profiles
    - Suspicious extension-originating network traffic
    slug: malicious-browser-extensions
    tactic: persistence
    techniques:
    - T1176
  - name: Session Hijacking and Post-Click Theft
    observables:
    - Session cookie theft
    - Unauthorized session hijacking in the browser
    - Suspicious authentication attempts using stolen sessions
    slug: session-hijacking-credential-access
    tactic: credential-access
    techniques:
    - T1557
  summary: Attackers leverage compromised supplier email threads, fraudulent payment
    requests, and OAuth phishing to bypass traditional defenses. These sophisticated
    campaigns lead to the installation of malicious browser extensions and session
    hijacking to maintain persistent access to corporate collaboration environments.
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


# AI-Enhanced Collaboration and Browser Attacks

This hunt targets sophisticated collaboration attacks that use trusted relationships to move from a phishing click to a persistent browser implant. AI-generated lures often bypass standard signature-based gateways, requiring a search for behavioral anomalies across the entire attack chain. The hunt follows a phased approach: first identifying suspicious initial interactions and cloud permission grants, then searching for follow-on persistence in the form of rare browser extensions and anomalous sign-in patterns. By correlating these stages, the hunt identifies compromised accounts and hosts that traditional per-tool defenses miss.

## scoping-browsers
<!-- Identify hosts with active browsers -->
Identify the workstations that run common browsers where extensions could be installed as a baseline for the hunt.

```sqlite target=endpoint role=scoping params=(browser_names=browser_names)
~~~yaml
expected: A list of hosts currently running browsers. Zero hosts means no browsers
  are inventoried, suggesting a collection gap.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{browser_names}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%edge%')
```

## parallel-initial-access
<!-- Monitor for initial access indicators -->
parallel:
- → phishing-clicks
- → oauth-grants
join: → triage-initial-access

## phishing-clicks
<!-- Analyze phishing URL interactions -->
Find connections to known phishing domains or URLs with suspicious keywords indicating a social engineering lure.

```sqlite target=web role=enrichment params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicate a host interacted with a suspicious URL. Silence suggests
  no observed phishing traffic in the window.
reads:
- device_hostname
- url_full
- src_endpoint_ip
- user_agent
- time
- url_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, url_full, src_endpoint_ip, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_full) LIKE '%login%' OR LOWER(url_full) LIKE '%consent%' OR LOWER(url_full) LIKE '%authorize%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## oauth-grants
<!-- Suspicious cloud OAuth grants -->
Detect when a user grants permissions to an application, which often follows a successful phishing lure.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Users granting broad permissions to applications. Silence means no such
  cloud events were recorded.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
- provider
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (LOWER(api_operation) LIKE '%consent%' OR LOWER(api_operation) LIKE '%permission%' OR LOWER(api_operation) LIKE '%app role%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-initial-access
<!-- Triage initial access events -->
```agent target=hunter
cite: required
context:
- phishing-clicks
- oauth-grants
max_iterations: 4
objective: Identify users or hosts who visited phishing URLs and subsequently granted
  suspicious OAuth permissions.
success_criteria: A list of high-risk principals and endpoints.
tools:
- endpoint
- identity
- web
```

## parallel-follow-on
<!-- Search for persistence and session hijacking -->
parallel:
- → rare-extensions
- → anomalous-signins
join: → triage-final

## rare-extensions
<!-- Rare browser extension persistence -->
Find browser extensions seen on very few hosts, indicating a potential targeted malicious implant.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Extensions found on only one or two hosts. This is a durable signal of persistence
  if it follows a phishing interaction.
prevalence:
  by: device_hostname
  key:
  - package_name
  - vendor_name
  rare_below: 3
reads:
- package_name
- vendor_name
- device_hostname
- collected_at
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT package_name, vendor_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(collected_at) AS first_seen FROM hb_software_inventory WHERE package_type = 'extension' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY package_name, vendor_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## anomalous-signins
<!-- Anomalous sign-ins without MFA -->
Identify successful logins where MFA was not recorded, suggesting session hijacking from the browser.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Successful sign-ins without MFA, especially from IPs that match the phishing
  workstation.
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- mfa
- status
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, device_hostname, src_endpoint_ip, mfa, status, time FROM hb_auth_signin WHERE status_id = 1 AND (mfa = 'false' OR mfa IS NULL) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-final
<!-- Correlate attack chain evidence -->
```agent target=hunter
cite: required
context:
- rare-extensions
- anomalous-signins
- triage-initial-access
max_iterations: 6
objective: Determine if a phishing click or OAuth grant was followed by a rare extension
  installation or anomalous session reuse on the same host or user identity.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  connected rows across surfaces.
tools:
- endpoint
- identity
- web
```

## route-remediation
<!-- Route on attack chain verdict -->
if~: "the triage verdict is malicious for at least one user or host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-api-latency)
else: → close-out

## isolate-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified endpoints, revoke the malicious OAuth grants in the Microsoft 365 portal, and terminate all active sessions for the affected users.
```
→ analyst-review

## analyst-review
<!-- Analyst validation and tuning -->
```manual target=analyst
Review the cited rows for the phishing interaction, the OAuth grant, and the rare extension. Confirm if the extension behavior is truly malicious and if the sign-in without MFA represents a hijacked session.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the total number of hosts and users examined. Note any visibility gaps, such as hosts missing browser extension inventory or cloud API logs that were missing critical user agent details.
```
→ end
