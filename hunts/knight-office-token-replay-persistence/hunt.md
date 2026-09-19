---
analysis: A static detection rule for the IPs is too brittle. This hunt leverages
  a baseline of User-Agent activity across the fleet to find the rare 'Dsreg' registration
  signature and correlates it with non-MFA authenticated sessions in the cloud, providing
  the cross-surface context required to confirm persistence.
blind_spots:
- id: missing-auth-ua
  owner: Identity Engineering
  question: Which sign-in events specifically used the python-requests or Dsreg User-Agents?
  remediation: Enable advanced Entra ID logging to capture User-Agent strings for
    all sign-in events.
  requires: User-Agent visibility in hb_auth_signin
  risk: Correlation depends on IP or User cross-referencing between HTTP and Auth
    surfaces, which fails if the adversary uses different IPs for replay than for
    the initial theft.
  stage: session-token-replay
- id: ephemeral-proxy-ips
  owner: SOC Intel
  question: Are the successful logins originating from known callback proxy nodes?
  remediation: Integrate a real-time proxy/VPN threat feed into the authentication
    monitoring pipeline.
  requires: Residential Proxy intelligence (e.g. Spur)
  risk: Knight Office specifically uses residential proxies that rotate frequently;
    the provided IP list is likely to grow stale quickly.
  stage: session-token-replay
coverage:
- stage: session-token-replay
  status: covered
  steps:
  - detect-broker-token-replay
  - rare-user-agent-activity
- stage: rogue-device-registration
  status: covered
  steps:
  - rare-user-agent-activity
  - dsreg-authentication-events
- stage: whfb-persistence
  status: covered
  steps:
  - dsreg-authentication-events
  - triage-knight-office
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: spearphishing-lure
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: redirect-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: aitm-token-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Knight Office session token theft bypasses traditional MFA. Hunting
    for the replay activity and resulting identity persistence (rogue device/WHfB)
    is the only way to detect a compromise after a user completes the AiTM prompt.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is replaying stolen session tokens to bypass MFA and register
  rogue Windows Hello for Business keys for persistent M365 access.
labels:
- hunt
- attack.t1550.004
- attack.t1098.005
- attack.t1556.007
name: 'Knight Office: M365 Token Replay and Identity Persistence'
parameters:
  knight_office_ips:
    default:
    - 104.37.188.94
    - 154.127.53.78
    description: IPs linked to Knight Office token replay and command consoles.
    from:
      kind: article
      observed: '2026-08-18'
      ref: huntress-knight-office
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts with M365/Office installed; populate from the scoping step.
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
rationale: First, identify hosts using M365 or Office software. Focused behavioral
  analysis of HTTP User-Agents is most effective on these assets.
references:
- name: "Huntress \u2014 Inside Knight Office, a New M365 AiTM Phishing Kit"
  url: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
related:
- hunt: knight-office-initial-access
  reason: The precursor lure delivery, Monday.com redirects, and phishing page interactions
    are handled in a separate network-focused hunt.
  relation: out-of-scope-alternative
- hunt: knight-office-aitm-phishing-session-theft
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Knight Office: M365 Token Replay and Identity Persistence

This hunt identifies post-access behavior associated with the Knight Office AiTM kit. It specifically targets the replay of session tokens by looking for successful authentication events against the Microsoft Authentication Broker where MFA was not re-satisfied, often originating from known malicious IPs. To corroborate these logins, the hunt baselines rare User-Agent activity (python-requests and Dsreg) typically used by the kit's automated components and device registration processes. An agent then correlates these cloud-plane anomalies with endpoint HTTP telemetry to identify compromised identities.

## scope-m365-assets
<!-- Scope M365 and Office Assets -->
Identify hosts in the estate that use Microsoft 365 or Office software to narrow the volume of HTTP telemetry to analyze.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. If empty, the estate likely lacks managed M365 reporting,
  and the hunt will run unscoped.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%office%' OR LOWER(vendor_name) LIKE '%microsoft%'
```

## detect-broker-token-replay
<!-- Token Replay via Authentication Broker -->
Identify successful logins where the expected MFA challenge was bypassed or that originate from known Knight Office infrastructure.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, knight_office_ips=knight_office_ips)
~~~yaml
expected: Logins to the Broker without MFA or from the kit's IPs. Successful login
  without MFA on sensitive endpoints is a strong indicator of token replay.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- auth_protocol
- mfa
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, mfa, time FROM hb_auth_signin WHERE status_id = 1 AND (instr(',' || '{{knight_office_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR (LOWER(dst_endpoint_name) LIKE '%authentication broker%' AND (mfa IS NULL OR LOWER(mfa) = 'none' OR LOWER(mfa) = 'false'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence-gathering
<!-- Parallel Correlation of UA and Auth Shifts -->
parallel:
- → rare-user-agent-activity
- → dsreg-authentication-events
join: → triage-knight-office

## rare-user-agent-activity
<!-- Rare Scripted User-Agents from Endpoints -->
Baseline and identify the rare use of kit-specific User-Agents (python-requests and Dsreg) which facilitate token replay and rogue device enrollment.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare python-requests strings from endpoints suggests kit interaction; rare
  Dsreg strings suggests unauthorized device registration attempts.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 3
reads:
- user_agent
- device_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_agent, device_hostname, src_endpoint_ip, COUNT(*) as request_count, MIN(time) as first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(user_agent) LIKE '%python-requests%' OR LOWER(user_agent) LIKE '%dsreg%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent, device_hostname, src_endpoint_ip HAVING COUNT(DISTINCT device_hostname) <= 3 ORDER BY request_count DESC
```

## dsreg-authentication-events
<!-- Non-MFA Cloud Sign-ins and Device Registration -->
Capture sign-ins to M365 and device registration endpoints that occur without MFA, characterizing the token replay and persistence phase.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Accounts showing successful logins to sensitive resources (OfficeHome/Dsreg)
  without an active MFA challenge, aligning with rare UA activity.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- auth_protocol
- mfa
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, mfa, time FROM hb_auth_signin WHERE status_id = 1 AND provider = 'm365' AND (mfa IS NULL OR LOWER(mfa) = 'none' OR LOWER(mfa) = 'false') AND (LOWER(auth_protocol) = 'oauth' OR LOWER(dst_endpoint_name) LIKE '%officehome%' OR LOWER(dst_endpoint_name) LIKE '%dsreg%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-knight-office
<!-- Triage Token Replay and Persistence -->
```agent target=hunter
cite: required
context:
- detect-broker-token-replay
- rare-user-agent-activity
- dsreg-authentication-events
max_iterations: 5
objective: Determine if any identity shows session takeover signatures, specifically
  replaying tokens from proxy/malicious IPs or using scripted User-Agents to register
  rogue devices.
success_criteria: A verdict of malicious | suspicious | benign per user account, citing
  the specific IP, UA, and non-MFA sign-in events.
tools:
- endpoint
- identity
- web
```

## decision-on-verdict
<!-- Decision on Verdict -->
if~: "the triage verdict is malicious or suspicious for at least one identity, citing successful broker logins from Knight Office infrastructure or rogue Dsreg User-Agents." (confidence: high, judge=hunter)
then: → revoke-sessions-action
indeterminate: → analyst-review-task
unavailable: → analyst-review-task (blind_spot: missing-auth-ua)
else: → close-out-task

## revoke-sessions-action
<!-- Revoke Sessions and Investigate Rogue Keys -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365 session tokens for the affected user. Review Entra ID for newly registered devices or Windows Hello for Business keys added during the window. Isolate associated endpoints identified in HTTP logs.
```
→ analyst-review-task

## analyst-review-task
<!-- Analyst Review of Persistence -->
```manual target=analyst
Manually verify the removal of any WHfB keys or rogue devices from Entra ID. Check Entra Audit logs for 'Add device' or 'Add user credential' events using the identified suspicious IP and User-Agent fragments as filters.
```
→ end

## close-out-task
<!-- Close Out Hunt -->
```manual target=analyst
Document that no token replay activity or unauthorized device registration was found for the reporting period.
```
→ end
