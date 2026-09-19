---
analysis: "A standard rule alerts on any access to /devicelogin, but this hunt correlates\
  \ the preceding SaaS redirect and the rarity of the referring .vu domain\u2014a\
  \ behavioral chain that reduces false positives from legitimate IT activity."
blind_spots:
- id: email-content-gap
  question: whether the 'lmportant' character-substitution was present in the email
    body
  requires: Mailbox audit or Email Gateway logs
  risk: The hunt starts at the network/HTTP level; the initial delivery of the lure
    via email is invisible on the provided endpoint surfaces.
  stage: spearphishing-lure
- id: residential-proxy-noise
  question: whether a source IP belongs to a callback proxy network
  requires: Residential IP intelligence (e.g., Spur)
  risk: Residential proxies are used to blend with legitimate work-from-home traffic;
    without specific IP intelligence metadata, these connections appear benign.
  stage: aitm-token-theft
- id: no-tls-decryption
  question: the specific 'deviceauth' code being entered by the user
  requires: TLS decryption or endpoint-local browser monitoring
  risk: We see the access to the endpoint (/devicelogin) but cannot see the payload
    data being entered, which confirms the capture.
  stage: aitm-token-theft
coverage:
- blind_spot: email-content-gap
  reason: Character substitution in email subjects/bodies is not visible on the provided
    hb_ surfaces.
  stage: spearphishing-lure
  status: not_visible
- stage: redirect-chain
  status: covered
  steps:
  - fleet-wide-vu-dns
  - saas-to-vu-referrers
- stage: aitm-token-theft
  status: covered
  steps:
  - device-auth-login
  - kit-infrastructure-connections
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: session-token-replay
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: rogue-device-registration
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: whfb-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Knight Office specifically targets valid session tokens to bypass
    MFA. Identifying the capture phase provides a narrow window for intervention before
    persistence is achieved.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trusted SaaS redirectors and unusual .vu top-level
  domains to trick high-risk users into a Device Code authentication flow, capturing
  session tokens via residential proxies.
labels:
- hunt
- attack.t1566.002
- attack.t1090.003
- attack.t1557
name: Knight Office AiTM Phishing and Session Theft
parameters:
  kit_ips:
    default:
    - 154.127.53.78
    - 104.37.188.94
    description: IP addresses associated with Knight Office console and phishing delivery
      infrastructure.
    from:
      kind: article
      observed: '2026-09-02'
      ref: huntress-knight-office
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  saas_domains:
    default:
    - monday.com
    - notion.so
    - github.com
    - firebaseapp.com
    description: High-reputation SaaS domains commonly used as initial redirectors.
    from:
      kind: article
      observed: '2026-09-02'
      ref: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
    type: list[domain]
  scope_hosts:
    default: []
    description: List of hosts from the scoping step to focus the hunt; leave empty
      to hunt fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scoping targets 'Executive' or 'Finance' naming conventions for systems
  (e.g., EXE, FIN) to prioritize higher-impact potential thefts. DNS and HTTP queries
  are filtered by these hosts when the parameter is populated.
references:
- name: Inside Knight Office, a New M365 AiTM Phishing Kit
  url: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
related:
- hunt: knight-office-token-replay
  reason: This hunt focuses on initial capture; a follow-on hunt should examine hb_auth_signin
    for subsequent replays and device registrations.
  relation: follows
scenario:
  stages:
  - name: DocuSign-themed phishing email
    observables:
    - 'IP: 154.127.53.78'
    - 'Subject: Reminder: Signature Required - Approval Pending Your Review!!!'
    - 'Subject: You Missed (2) lmportant VoiceMessage'
    - 'Character substitution: lowercase ''L'' for ''i'' in ''lmportant'', ''Slgnature'',
      ''VERlVIED'''
    slug: spearphishing-lure
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Evasive redirection through trusted infrastructure
    observables:
    - 'Domain: monday.com'
    - 'Platform: Joomla'
    - 'TLD: .vu domains'
    slug: redirect-chain
    tactic: defense-evasion
    techniques:
    - T1566
  - name: AiTM session capture via device authentication
    observables:
    - Microsoft Device Authentication codes (deviceauth)
    - Spur callback proxies (Residential IP ranges)
    - Knight Office kit landing pages
    slug: aitm-token-theft
    tactic: credential-access
    techniques:
    - T1566
    - T1090.003
  - name: Authentication bypass via token replay
    observables:
    - 'IP: 104.37.188.94'
    - 'User-Agent: python-requests/2.34.2, OAuth2:Token'
    - Post-MFA authentication against Microsoft Authentication Broker
    slug: session-token-replay
    tactic: initial-access
    techniques:
    - T1550.004
  - name: Unauthorized Entra ID device enrollment
    observables:
    - 'IP: 104.37.188.94'
    - Microsoft Entra ID host enrollment
    slug: rogue-device-registration
    tactic: persistence
    techniques:
    - T1098.005
  - name: Windows Hello for Business key binding
    observables:
    - 'User-Agent: Dsreg/10.0 (Windows 10.0.19044.1826)'
    - Windows Hello for Business (WHfB) key binding
    - WHfB passwordless authentication successful sign-in
    slug: whfb-persistence
    tactic: persistence
    techniques:
    - T1556.007
  summary: The Knight Office phishing campaign targets Microsoft 365 users using an
    Adversary-in-the-Middle (AiTM) kit to bypass MFA by capturing session tokens.
    Attackers use trusted redirects and residential proxies to steal tokens, subsequently
    registering rogue devices and binding Windows Hello for Business keys to maintain
    persistent access.
series:
  index: 1
  slug: inside-knight-office-a-new-m365-aitm-phishing-kit
  title: Inside Knight Office, a New M365 AiTM Phishing Kit
  total: 2
severity: high
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
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


# Knight Office AiTM Phishing and Session Theft

This hunt identifies the capture phase of the Knight Office AiTM attack chain. It scopes the estate to high-risk department hosts, then monitors for a behavioral sequence: DNS resolutions for rare .vu domains, HTTP traffic with SaaS referrers (e.g., Monday.com) leading to .vu sites, and the interaction with the Microsoft Device Login endpoint. By correlating these triggers, an agent can distinguish malicious session capture from legitimate developer or IoT device registration.

## high-risk-scoping
<!-- Identify High-Risk Department Hosts -->
Identify hosts likely belonging to sensitive departments (Executive, Finance) which are primary targets for Knight Office session theft.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames matching sensitive naming conventions. This focuses
  the triage agent's attention on the most damaging potential compromises.
reads:
- hostname
- device_uid
- device_owner
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT hostname as device_hostname, device_uid, device_owner FROM hb_devices WHERE (LOWER(hostname) LIKE '%exe%' OR LOWER(hostname) LIKE '%fin%' OR LOWER(hostname) LIKE '%dir%' OR LOWER(hostname) LIKE '%treasury%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## fleet-wide-vu-dns
<!-- Fleet-Wide .vu TLD Resolution Rarity -->
Establish a baseline of .vu TLD usage across the entire estate to identify rare phishing infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare .vu domain resolutions. Frequent resolutions might indicate legitimate
  region-specific software; single-host hits are high-priority.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 10
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.vu' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 5 ORDER BY host_count ASC
```

## corroborate-kit-activity
<!-- Corroborate Phishing Activity -->
parallel:
- → saas-to-vu-referrers
- → device-auth-login
- → kit-infrastructure-connections
join: → triage-kit-activity

## saas-to-vu-referrers
<!-- SaaS Redirects to .vu Domains -->
Identify HTTP requests where high-reputation SaaS platforms are the referrers for unusual .vu destinations.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, saas_domains=saas_domains, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to .vu domains triggered by clicks on trusted platforms. This
  is a classic evasion technique to bypass simple URL reputation filters.
reads:
- device_hostname
- url_hostname
- url_path
- referrer
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, referrer, time FROM hb_http_activity WHERE LOWER(url_hostname) LIKE '%.vu' AND (instr(',' || '{{saas_domains}}' || ',', ',' || LOWER(referrer) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## device-auth-login
<!-- Microsoft Device Auth Flow -->
Identify visits to the /devicelogin endpoint, which is where the victim enters the code provided by the phishing site.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Access to the device login page. If the referrer is a .vu domain, this is
  highly indicative of token capture.
reads:
- device_hostname
- url_hostname
- url_path
- referrer
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, referrer, user_agent, time FROM hb_http_activity WHERE LOWER(url_hostname) LIKE '%microsoft.com' AND LOWER(url_path) LIKE '%/devicelogin%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## kit-infrastructure-connections
<!-- Known Kit Infrastructure Connections -->
Find direct network connections to the IP addresses identified as hosting the Knight Office kit or console.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, kit_ips=kit_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to kit IPs. Process names like 'chrome.exe' or 'msedge.exe'
  suggest a user being directed to the phishing site.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{kit_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-kit-activity
<!-- Triage Session Capture Evidence -->
```agent target=hunter
cite: required
context:
- high-risk-scoping
- fleet-wide-vu-dns
- saas-to-vu-referrers
- device-auth-login
- kit-infrastructure-connections
max_iterations: 5
objective: Determine if any host, particularly high-risk ones, shows the sequence
  of SaaS redirect -> rare .vu domain resolution -> /devicelogin interaction, suggesting
  a successful Knight Office session capture.
success_criteria: A per-host verdict citing specific DNS and HTTP events.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: residential-proxy-noise)
else: → close-out

## revoke-sessions
<!-- Revoke Session Tokens -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365 session tokens for the affected user, initiate a password reset, and check for rogue device registrations in Entra ID.
```
→ analyst-review

## analyst-review
<!-- Downstream Impact Review -->
```manual target=analyst
1. Review Entra ID logs for the affected user for successful logins from unusual IPs (specifically check for the residential proxies and 104.37.188.94). 2. Inspect for 'Add device' or 'Update WHfB credential' events. 3. Monitor for replay activity involving User-Agents like 'python-requests'.
```
→ close-out

## close-out
<!-- Hunt Close-Out -->
```manual target=analyst
Document the triage findings. If the /devicelogin query had high noise from legitimate IT operations, record those hostnames for future exclusions.
```
→ end
