---
analysis: A standard detection rule for logins from rare countries often produces
  high false positives. This hunt uses a lead query to define the VPN scope and then
  fans out to correlate location rarity with subsequent administrative API behavior,
  allowing an agent to confirm if a session was used for malicious intent rather than
  just firing on a location change.
blind_spots:
- id: no-vpn-logs
  owner: Infrastructure Team
  question: whether unauthorized logins occurred on unmonitored VPN appliances
  remediation: Audit VPN gateway log exporters and ensure they are reporting to the
    central lake.
  requires: Ingestion of all VPN gateway authentication logs into hb_auth_signin
  risk: A VPN gateway that does not export its logs remains a blind spot where credentials
    can be abused without detection.
  stage: external-service-login
- id: residential-proxy-evasion
  owner: Security Engineering
  question: whether the attacker is using a residential IP that mimics a real user's
    home network
  remediation: Integrate advanced IP reputation feeds that distinguish residential
    ISPs from commercial hosting providers.
  requires: Advanced IP reputation including residential ISP flagging
  risk: If an attacker uses a residential proxy in the same country as the user, 'src_location_country'
    rarity will not trigger, potentially hiding the intrusion.
  stage: external-service-login
coverage:
- stage: external-service-login
  status: covered
  steps:
  - lead-vpn-gateways
  - rare-vpn-source-locations
  - post-auth-cloud-actions
  - triage-sessions
- reason: Handled by the lure-access hunt in this series.
  stage: seo-poisoning-redirection
  status: out_of_scope
- reason: Handled by the lure-access hunt in this series.
  stage: lure-site-access
  status: out_of_scope
- reason: Handled by the lure-access hunt in this series.
  stage: credential-harvesting
  status: out_of_scope
- reason: Handled by the lure-access hunt in this series.
  stage: legitimate-payload-delivery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Initial access via stolen VPN credentials is the primary mechanism
    for this campaign. Detecting these logins at the identity plane prevents the adversary
    from establishing an internal foothold or performing lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are using credentials stolen from lookalike WatchGuard VPN
  download sites to authenticate to corporate VPNs from anomalous geographic regions
  or hosting provider IP space.
labels:
- hunt
- attack.t1133
- credential access
- execution
- initial access
name: Unauthorized VPN Access via Stolen WatchGuard Credentials
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for VPN logins and subsequent activity.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: Standard hunt window
    type: number
  scope_hosts:
    default: []
    description: Optional list of VPN gateway hostnames to narrow the search.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: Estate inventory
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should start by identifying the hostnames of VPN gateways. If
  the organization uses cloud-native VPN services (e.g., AWS Client VPN), the device_hostname
  may be the service provider name. Focus on servers and high-privilege user accounts
  first.
references:
- name: "Huntress \u2014 Fake WatchGuard VPN Site Steals Credentials"
  url: https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing
related:
- hunt: watchguard-lure-site-access
  reason: This hunt focuses on the aftermath (unauthorized access); monitoring for
    user access to the spoofed download site is a separate behavioral hunt.
  relation: out-of-scope-alternative
- hunt: watchguard-vpn-lookalike-phishing
  relation: follows
scenario:
  stages:
  - name: SEO Poisoning Redirection
    observables:
    - bing.com/ck/a
    - u=aHR0cHM6Ly93d3cud2F0Y2hndWFyZC12cG4ubmV0Lw
    - 'search query: watchguard vpn sll download'
    slug: seo-poisoning-redirection
    tactic: initial-access
    techniques:
    - T1566
  - name: Phishing Lure Site Access
    observables:
    - watchguard-vpn.net
    - watchguard-vpn.com
    - 80.249.132.140
    - 74.208.236.39
    - www.watchguard-vpn.net/index.php
    slug: lure-site-access
    tactic: initial-access
    techniques:
    - T1566
  - name: Credential Harvesting
    observables:
    - popup.js
    - JSON POST to watchguard-ssl.online
    - 158.94.209.19
    - 'fields: server, login, password, attempt'
    - Incorrect data, please enter again to start installation
    slug: credential-harvesting
    tactic: credential-access
    techniques:
    - T1566
  - name: Legitimate Payload Delivery
    observables:
    - cdn.watchguard.com
    - WG-MVPN-SSL_12_11_5.exe
    - 'SHA256: fb3c39ba...0032ac1f'
    - WatchGuard Technologies, Inc. (Inno Setup)
    slug: legitimate-payload-delivery
    tactic: execution
    techniques:
    - T1195.002
  - name: External Remote Service Access
    observables:
    - VPN login from hosting provider IPs
    - VPN login from unfamiliar ASNs
    - SSL VPN login for WatchGuard client
    slug: external-service-login
    tactic: initial-access
    techniques:
    - T1133
  summary: The Storm-2561 campaign uses SEO poisoning on search engines like Bing
    to direct users to lookalike VPN download sites. These sites harvest credentials
    through a multi-stage JavaScript prompt before delivering a legitimate, signed
    WatchGuard installer to avoid suspicion. Stolen credentials are then utilized
    for unauthorized access to external remote services.
series:
  index: 2
  slug: fake-watchguard-vpn-site-steals-credentials
  title: Fake WatchGuard VPN Site Steals Credentials
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
tlp: clear
type: investigation
---


# Unauthorized VPN Access via Stolen WatchGuard Credentials

This hunt examines the identity plane for unauthorized VPN sessions that match the Storm-2561 phishing profile. It looks for successful authentications from rare countries or proxies, then fans out to correlate those sessions with potentially sensitive administrative actions in the cloud. By weighing the source rarity against the user's subsequent behavior, an agent can identify session hijacking or credential abuse that bypasses standard login rules. This hunt focuses on the initial access stage where stolen credentials are used to bypass the perimeter.

## lead-vpn-gateways
<!-- Identify Active VPN Gateways -->
Identify the hostnames and service names acting as VPN gateways to scope the subsequent behavioral analysis.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames reporting VPN-related authentication. Silence indicates
  no VPN logs matched the keywords.
reads:
- device_hostname
- service_name
- dst_endpoint_name
- logon_process_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT DISTINCT device_hostname, service_name, dst_endpoint_name FROM hb_auth_signin WHERE (LOWER(service_name) LIKE '%vpn%' OR LOWER(dst_endpoint_name) LIKE '%vpn%' OR LOWER(logon_process_name) LIKE '%vpn%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate Source and Behavior -->
parallel:
- → rare-vpn-source-locations
- → post-auth-cloud-actions
join: → triage-sessions

## rare-vpn-source-locations
<!-- Rare VPN Source Locations -->
Stack-count VPN logins by country and city to identify successful authentications from locations that are statistically rare for the organization.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: VPN logins from countries or cities with very few associated users. Large
  user counts indicate known regional offices or remote work hubs.
prevalence:
  by: actor_user_name
  key:
  - src_location_country
  - src_location_city
  rare_below: 3
reads:
- src_location_country
- src_location_city
- is_proxy
- actor_user_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT src_location_country, src_location_city, is_proxy, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_count FROM hb_auth_signin WHERE activity_id = 1 AND status_id = 1 AND (LOWER(service_name) LIKE '%vpn%' OR LOWER(dst_endpoint_name) LIKE '%vpn%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_location_country, src_location_city, is_proxy HAVING user_count <= 3
```

## post-auth-cloud-actions
<!-- Post-Authentication Cloud Actions -->
Identify administrative or impactful cloud API operations that occurred after a user logged in, which may indicate an attacker using the session.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Create, Update, or Delete API calls. These are enriched for the analyst
  to correlate with rare VPN logins.
reads:
- actor_user_name
- src_endpoint_ip
- api_operation
- api_service_name
- resource_name
- status
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, src_endpoint_ip, api_operation, api_service_name, resource_name, status, time FROM hb_cloud_api_activity WHERE activity_id IN (1, 3, 4) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-sessions
<!-- Triage Suspected Sessions -->
```agent target=hunter
cite: required
context:
- lead-vpn-gateways
- rare-vpn-source-locations
- post-auth-cloud-actions
max_iterations: 4
objective: Determine if any users exhibit anomalous VPN logins from rare countries
  or proxies that are immediately followed by significant cloud API changes (Create/Update/Delete).
success_criteria: A verdict of malicious | suspicious | benign for each user identified
  in the logins, citing specific IP and action rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Access Verdict -->
if~: "the triage verdict is malicious for at least one user account" (confidence: high, judge=hunter)
then: → revoke-compromised-session
indeterminate: → analyst-verification
unavailable: → analyst-verification (blind_spot: no-vpn-logs)
else: → analyst-verification

## revoke-compromised-session
<!-- Revoke Compromised Session -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the malicious user account and disable the account in the identity provider. Enforce a password reset and MFA re-enrollment.
```
→ analyst-verification

## analyst-verification
<!-- Analyst Verification -->
```manual target=analyst
Examine the internal traffic logs (e.g., hb_smb_activity) for the source IP associated with the suspicious VPN login. Confirm with the user if they were traveling or using a proxy.
```
→ hunt-closure

## hunt-closure
<!-- Hunt Closure -->
```manual target=analyst
Record the number of false positives and update the organization's travel baseline if rare locations were found to be legitimate.
```
→ end
