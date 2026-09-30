---
analysis: A simple rule might fire on a kit IP, but this hunt correlates the initial
  deviceauth flow on the endpoint with the follow-on persistence mechanism in the
  cloud. It uses a baseline to find rare User-Agents that standard rules would miss
  and pivots between network activity and identity inventory to settle the verdict.
blind_spots:
- id: external-token-replay-visibility
  question: Whether a stolen token was replayed from an external VPS via python-requests
  remediation: Ingest M365/Entra ID Unified Audit Logs (UAL) to capture all authentication
    attempts and User-Agents globally.
  requires: Native Entra ID sign-in logs
  risk: Corporate HTTP telemetry only sees the victim's interaction with the kit;
    the subsequent authentication from the attacker's infrastructure is invisible
    to endpoint-based sensors.
  stage: aitm-device-code-theft
- id: device-inventory-sync-delay
  question: Whether a newly registered device has populated the inventory during the
    lookback window
  requires: hb_devices (azure_ad provider)
  risk: Cloud inventory collectors may have a lag between a device registration event
    and its appearance in the hb_devices surface, leading to a temporary coverage
    gap.
  stage: rogue-device-persistence
coverage:
- stage: aitm-device-code-theft
  status: covered
  steps:
  - kit-interaction-lead
  - rare-user-agents-to-microsoft
- stage: rogue-device-persistence
  status: covered
  steps:
  - rogue-device-registration
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: phishing-lure-delivery
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: redirect-chain-obfuscation
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: whfb-key-binding
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Knight Office specifically bypass MFA by stealing persistent session
    tokens; a negative result over the enrolled estate confirms that no rogue devices
    have been registered through this specific kit chain, which is a critical persistence
    indicator.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has stolen Microsoft 365 session tokens via a device-code
  phishing flow and secured persistence by enrolling an unauthorized rogue device
  into the Entra ID tenant.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1098
name: Knight Office Token Theft and Device Persistence
parameters:
  attacker_ips:
    default:
    - 104.37.188.94
    - 154.127.53.78
    description: Known Knight Office management and delivery IPs.
    from:
      kind: article
      observed: '2026-09-02'
      ref: huntress-knight-office
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead step; leave empty for a global check.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: analyst-scoping
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
rationale: The lead query identifies users interacting with the deviceauth flow, which
  is the kit's primary method for token theft. Focus on identities that visited the
  Microsoft devicelogin page followed by any interaction with the identified kit IPs.
  If the HTTP surface is encrypted or unavailable, prioritize the rogue-device-registration
  check.
references:
- name: Inside Knight Office, a New M365 AiTM Phishing Kit
  url: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
related:
- hunt: phishing-redirect-obfuscation
  reason: The redirect chain involving Monday.com and compromised Joomla sites is
    better handled on proxy or web-filter logs.
  relation: out-of-scope-alternative
- hunt: knight-office-delivery-redirection
  relation: follows
scenario:
  stages:
  - name: DocuSign-themed Phishing Delivery
    observables:
    - 'IP: 154.127.53.78'
    - 'Subject: Reminder: Signature Required - Approval Pending Your Review!!!'
    - 'Character substitution: lmportant, Slgnature, VERlVIED (l instead of i)'
    slug: phishing-lure-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-stage URL Redirection
    observables:
    - 'Domain: monday.com'
    - Compromised Joomla websites
    - 'TLD: .vu domains'
    slug: redirect-chain-obfuscation
    tactic: initial-access
    techniques:
    - T1090.003
  - name: AiTM Token Theft via Device Code Flow
    observables:
    - 'URL: microsoft.com/devicelogin'
    - Nine-letter deviceauth codes
    - 'IP: 73.125.13.x (Callback proxy)'
    - 'User-Agent: Microsoft Authentication Broker / OfficeHome'
    slug: aitm-device-code-theft
    tactic: credential-access
    techniques:
    - T1566
    - T1090.003
  - name: Entra ID Rogue Device Registration
    observables:
    - 'IP: 104.37.188.94'
    - 'User-Agent: python-requests/2.34.2'
    - Unauthorized host enrollment into Microsoft Entra ID
    slug: rogue-device-persistence
    tactic: persistence
    techniques:
    - T1098
  - name: Windows Hello for Business Key Binding
    observables:
    - 'User-Agent: Dsreg/10.0 (Windows 10.0.19044.1826)'
    - NGC key binding
    - WHfB passwordless authentication success
    slug: whfb-key-binding
    tactic: persistence
    techniques:
    - T1098
  summary: Threat actors use the Knight Office phishing kit to perform Adversary-in-the-Middle
    (AiTM) attacks against Microsoft 365 accounts via the Device Code flow. After
    harvesting session tokens using residential callback proxies and redirect infrastructure,
    the attackers establish persistence by enrolling rogue devices in Microsoft Entra
    ID and binding Windows Hello for Business (WHfB) keys to the compromised accounts.
series:
  index: 2
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


# Knight Office Token Theft and Device Persistence

This hunt identifies the lifecycle of a Knight Office kit attack, focusing on the transition from initial phishing to long-term persistence. It begins by scoping users and hosts interacting with the Microsoft device login endpoint or known kit infrastructure. It then correlates these leads with rare User-Agents on endpoint HTTP traffic and unauthorized device registrations in Entra ID. An agent weighs the evidence to confirm if a successful token theft led to a rogue host enrollment, which survives password resets and MFA changes.

## kit-interaction-lead
<!-- Lead interaction with kit infrastructure -->
Identify hosts and identities interacting with the device-code login flow or known kit management IPs.

```sqlite target=web role=scoping params=(attacker_ips=attacker_ips, lookback_days=lookback_days)
~~~yaml
expected: Internal identities and hostnames visiting the device login page or kit
  management infrastructure. Results scope the subsequent behavioral queries.
reads:
- device_hostname
- actor_user_name
- dst_endpoint_ip
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, actor_user_name, dst_endpoint_ip, url_hostname, url_path, time FROM hb_http_activity WHERE ((instr(LOWER(url_hostname), 'microsoft.com') > 0 AND instr(LOWER(url_path), 'devicelogin') > 0) OR instr(',' || '{{attacker_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Correlate traffic and cloud inventory -->
parallel:
- → rare-user-agents-to-microsoft
- → rogue-device-registration
join: → triage-knight-office

## rare-user-agents-to-microsoft
<!-- Rare User-Agents to authentication endpoints -->
Stack-count User-Agents on interaction with login infrastructure to find automated kit tools like python-requests.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare User-Agents like python-requests or Microsoft Authentication Broker
  associated with a small number of hosts.
prevalence:
  by: device_hostname
  key:
  - user_agent
  - url_hostname
  rare_below: 3
reads:
- user_agent
- url_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT user_agent, url_hostname, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (instr(LOWER(url_hostname), 'microsoft.com') > 0 OR instr(LOWER(url_hostname), 'login') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent, url_hostname HAVING host_count <= 3 ORDER BY host_count ASC
```

## rogue-device-registration
<!-- New Entra ID device registration -->
Find newly enrolled cloud devices that may represent the attacker's persistence mechanism.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Newly registered devices in Entra ID. The hostname typically differs from
  the victim's standard machine, identifying the rogue enrollment.
reads:
- hostname
- device_owner
- os_name
- os_version
- device_uid
- provider
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname, device_owner, os_name, os_version, device_uid, provider, time FROM hb_devices WHERE provider = 'azure_ad' AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-knight-office
<!-- Triage Knight Office indicators -->
```agent target=hunter
cite: required
context:
- kit-interaction-lead
- rare-user-agents-to-microsoft
- rogue-device-registration
max_iterations: 4
objective: Determine if any user who visited the device login flow or kit infrastructure
  also registered a new Azure AD device and utilized a rare User-Agent during authentication.
success_criteria: A verdict citing specific identities, the rare HTTP indicators,
  and the rogue cloud device identifiers.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Knight Office verdict -->
if~: "the triage verdict is malicious for at least one identity, indicating both suspicious deviceauth interaction and an unauthorized device enrollment" (confidence: high, judge=hunter)
then: → contain-compromised-identity
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: external-token-replay-visibility)
else: → close-out-clean

## contain-compromised-identity
<!-- Revoke sessions and remove device -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365 refresh tokens and sessions for the affected identities. Remove the rogue device UID identified in the triage step from the Microsoft Entra ID tenant.
```
→ verify-key-persistence

## verify-key-persistence
<!-- Verify Windows Hello persistence -->
```manual target=analyst
Inspect native Entra ID audit logs for the compromised users to identify 'Add registered key to device' events. Confirm if the Dsreg User-Agent was used to bind a WHfB key, as this allows the attacker to regain access after token revocation.
```
→ close-out-clean

## close-out-clean
<!-- Hunt closure -->
```manual target=analyst
Record the identified malicious IPs and User-Agents in the organization's perimeter security controls. Document the efficacy of the rarity-based HTTP triage for future tuning.
```
→ end

## analyst-investigation
<!-- Analyst manual investigation -->
```manual target=analyst
Manually review the cited HTTP interactions and cross-reference with Entra ID sign-in logs. Look for replayed tokens from unusual ASN/IP ranges that match the timing of the kit interaction.
```
→ close-out-clean
