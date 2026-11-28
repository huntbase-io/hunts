---
analysis: A single detection rule cannot correlate a DNS resolution of a redirector
  (Phase 1) with an anomalous programmatic sign-in (Phase 2) hours later. This phased
  hunt uses an agent to link user behavior across disparate surfaces.
blind_spots:
- id: encrypted-phishing-kit
  question: Whether the phishing kit successfully decrypted and executed in the user's
    browser
  requires: Endpoint script memory inspection
  risk: The kit is delivered as ciphertext and decrypted client-side; network sensors
    only see an encrypted blob, making it difficult to prove the kit ran.
  stage: phishing-infrastructure-interaction
- id: residential-proxy-origin
  question: Whether the source IP for a sign-in is a legitimate residential address
    or a known callback proxy node
  requires: Residential IP reputation feed
  risk: The attacker routes traffic through residential proxies; without specialized
    threat intelligence, these sign-ins appear as legitimate remote employees.
  stage: session-replay-and-abuse
coverage:
- stage: initial-access-redirect-chain
  status: covered
  steps:
  - dns-redirect-chain
- stage: phishing-infrastructure-interaction
  status: covered
  steps:
  - http-phishing-interaction
  - triage-early-interaction
- stage: credential-access-device-code
  status: covered
  steps:
  - anomalous-cmsi-logins
- stage: session-replay-and-abuse
  status: covered
  steps:
  - programmatic-ua-prevalence
  - correlate-attack-chain
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Device code phishing bypasses MFA by using the victim's own session.
    This hunt provides a negative result over the estate for a specific, highly-disguised
    campaign identified by recent threat research.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using a multi-stage redirect chain and a convincing Microsoft
  Teams booking lure to trick users into authorizing a device code, subsequently replaying
  the stolen session tokens via residential proxies using programmatic tools.
labels:
- hunt
- attack.t1566.002
- attack.t1204.001
- attack.t1027.013
- attack.t1684.001
- attack.t1528
- attack.t1539
- attack.t1557
- attack.t1550.004
- attack.t1090
- credential access
- execution
- initial access
- lateral movement
name: Microsoft Teams Booking Device Code Phishing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_backend:
    default:
    - gpimmlgration.com
    - cloudflare.com
    description: Domains hosting the phishing kit backend or lure page.
    from:
      kind: article
      observed: '2026-11-12'
      ref: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
    type: list[domain]
  programmatic_uas:
    default:
    - python-requests
    - node
    description: Programmatic user agents used for session replay and automation.
    from:
      kind: article
      observed: '2026-11-12'
      ref: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
    type: list[string]
  redirect_domains:
    default:
    - share.google
    - railway.com
    - safelinks.protection.outlook.com
    description: Domains observed in the initial redirection chain.
    from:
      kind: article
      observed: '2026-11-12'
      ref: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
    type: list[domain]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to hunt across the
      entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope to hosts with Microsoft Teams installed. Focus on users in executive
  or finance roles who are more likely to be targeted by such a sophisticated spear-phishing
  lure.
references:
- name: "Huntress \u2014 Crafty Microsoft Teams Booking Flow Disguises Device Code\
    \ Phishing"
  url: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
related:
- hunt: m365-token-theft-by-adversary-in-the-middle
  reason: This hunt focuses on device code lures specifically; AiTM attacks like Evilginx
    require different telemetry for proxy interception.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-stage Phishing Redirects
    observables:
    - nam12.safelinks.protection.outlook.com
    - share.google/?q=UltJkMsVWI5V9GJM1
    - www.google.com/share.google?q=UltJkMsVWI5V9GJM1
    slug: initial-access-redirect-chain
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Teams Booking Lure Interaction
    observables:
    - gpimmlgration.com
    - X-Antibot-Token
    - X-WinHello
    - X-Automatic-Target-Country
    - X-Visitor-Country
    - Idempotency-Key
    - /static-export/api/device/start
    - AES-256-GCM encrypted phishing kit
    slug: phishing-infrastructure-interaction
    tactic: execution
    techniques:
    - T1204.001
    - T1027.013
    - T1684.001
  - name: Device Code Token Theft
    observables:
    - microsoft.com/devicelogin
    - Cmsi:Cmsi login flow
    - Microsoft Authentication Broker client
    slug: credential-access-device-code
    tactic: credential-access
    techniques:
    - T1528
    - T1539
    - T1557
  - name: Session Replay via Residential Proxy
    observables:
    - python-requests
    - node
    - ASN and region change within same session ID
    - Residential callback proxy traffic
    slug: session-replay-and-abuse
    tactic: lateral-movement
    techniques:
    - T1550.004
    - T1078.004
    - T1090
  summary: This campaign leverages a deceptive Microsoft Teams booking workflow to
    facilitate device code phishing. Attackers lead victims through a multi-stage
    redirect chain to a typosquatted domain hosting an encrypted phishing kit that
    initiates a Microsoft device code sign-in, ultimately capturing OAuth tokens and
    session cookies for account takeovers via residential proxies.
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


# Microsoft Teams Booking Device Code Phishing

This hunt follows the lifecycle of a device code phishing attack identified in recent research. It identifies users who interacted with a typosquatted Teams booking site through a redirect chain involving Google short links and then correlates that web interaction with subsequent anomalous identity events. The follow-on phase looks for the specific 'Cmsi:Cmsi' login flow and session abuse by programmatic user agents (Python, Node) replaying tokens through residential proxies. An agent correlates these two surfaces to confirm successful compromise.

## identify-potential-targets
<!-- Identify potential targets with Microsoft Teams -->
Identify hosts that have Microsoft Teams installed, as they are the primary targets for this specific lure.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where Teams is present. Silence indicates no Teams installation
  was visible to the inventory provider.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%teams%'
```

## detect-web-indicators
<!-- Detect web-based indicators of the phishing lure -->
parallel:
- → dns-redirect-chain
- → http-phishing-interaction
join: → triage-early-interaction

## dns-redirect-chain
<!-- DNS resolutions for phishing redirectors -->
Identify hosts resolving domains used in the attacker's multi-stage redirect chain.

```sqlite target=endpoint role=enrichment params=(redirect_domains=redirect_domains, phishing_backend=phishing_backend, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving the known malicious or redirector domains. Silence means
  the lure was not triggered or used different domains.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{redirect_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{phishing_backend}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## http-phishing-interaction
<!-- HTTP traffic to the phishing kit API -->
Find direct HTTP requests to the attacker backend, specifically the /api/device/start endpoint described in the research.

```sqlite target=web role=detection-candidate params=(phishing_backend=phishing_backend, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Traffic matching the known backend infrastructure and API patterns. Silence
  suggests no active engagement with the kit.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{phishing_backend}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_path) LIKE '%/api/device/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-interaction
<!-- Triage early lure interaction -->
```agent target=hunter
cite: required
context:
- dns-redirect-chain
- http-phishing-interaction
max_iterations: 3
objective: Determine which users likely clicked through the booking lure and triggered
  the device code API based on DNS and HTTP telemetry.
success_criteria: A list of users and timestamps for further session abuse analysis.
tools:
- endpoint
- identity
- web
```

## detect-session-abuse
<!-- Detect session replay and identity abuse -->
parallel:
- → anomalous-cmsi-logins
- → programmatic-ua-prevalence
join: → correlate-attack-chain

## anomalous-cmsi-logins
<!-- Sign-ins with Cmsi login flow -->
Identify device code authentication events tagged with the Cmsi:Cmsi flow, as identified in the Huntress research.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Logins explicitly using the device code flow pattern associated with the
  campaign. Silence means no successful device code flow was recorded with this specific
  tag.
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- user_agent
- event_type
- status_detail
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, user_agent, event_type, status_detail, time FROM hb_auth_signin WHERE provider IN ('m365', 'azure_ad') AND (LOWER(event_type) LIKE '%cmsi:cmsi%' OR LOWER(status_detail) LIKE '%cmsi:cmsi%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## programmatic-ua-prevalence
<!-- Prevalence of programmatic user agents in sign-ins -->
Stack-count user agents to identify rare programmatic sign-ins (Python, Node) that stand out from standard browser traffic.

```sqlite target=identity role=baseline params=(programmatic_uas=programmatic_uas, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A programmatic user agent seen for only a few users, suggesting attacker
  automation replaying session tokens. Standard browser traffic should be common across
  the fleet.
prevalence:
  by: actor_user_name
  key:
  - user_agent
  rare_below: 3
reads:
- actor_user_name
- user_agent
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT LOWER(user_agent) AS ua, COUNT(DISTINCT actor_user_name) AS users, COUNT(*) AS signins, MIN(time) AS first_seen FROM hb_auth_signin WHERE provider IN ('m365', 'azure_ad') AND (instr(',' || '{{programmatic_uas}}' || ',', ',' || LOWER(user_agent) || ',') > 0 OR LOWER(user_agent) LIKE 'python%' OR LOWER(user_agent) LIKE 'node%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(user_agent) HAVING users <= 3 ORDER BY users ASC
```

## correlate-attack-chain
<!-- Correlate attack chain across surfaces -->
```agent target=hunter
cite: required
context:
- triage-early-interaction
- anomalous-cmsi-logins
- programmatic-ua-prevalence
max_iterations: 5
objective: Determine if any user who interacted with the phishing loader subsequently
  showed signs of session abuse, such as Cmsi logins or programmatic access from anomalous
  IPs.
success_criteria: A per-user verdict citing specific rows from HTTP, DNS, and sign-in
  logs.
tools:
- endpoint
- identity
- web
```

## route-on-evidence
<!-- Route on evidence of compromise -->
if~: "the correlated attack chain shows a user interacting with the lure and subsequent anomalous sign-ins" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: residential-proxy-origin)
else: → close-out

## isolate-identity
<!-- Revoke sessions and isolate identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365 sessions for the compromised user and force a password reset. Review the account for new MFA enrollments or mailbox rules.
```
→ forensic-review

## forensic-review
<!-- Forensic analyst review -->
```manual target=analyst
Verify the correlated events in the raw logs. Check for lateral movement or data exfiltration performed via the programmatic user agents (Python/Node).
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record all findings. If the programmatic user agent list is too noisy, refine it to only includes those not typically used for legitimate automation in this environment.
```
→ end
