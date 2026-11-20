---
analysis: A simple detection rule on these IP ranges would produce too many false
  positives for legitimate developers. We use a gated flow to first confirm successful
  logins, then stack protocols for rarity, and finally correlate with host-side connections
  to differentiate between a developer and an adversary.
blind_spots:
- id: no-auth-logging
  question: Are we seeing sign-ins from these ranges in tenants where audit logging
    is disabled?
  requires: hb_auth_signin or Entra ID P1 logging
  risk: A negative result may be a false negative if the tenant lacks the licensing
    (Entra P1/P2) or configuration to log these events.
- id: ip-rotation-drift
  question: Has the attacker moved to a new developer cloud range not in our list?
  requires: updated malicious_ranges
  risk: The hunt depends on the quality of the IP list; as adversaries rotate infrastructure,
    this durable list will become obsolete.
  stage: c2-infrastructure-token-replay
coverage:
- stage: initial-access-device-code-phishing
  status: covered
  steps:
  - identify-infrastructure-signins
  - stack-auth-protocols
- stage: credential-access-ropc-password-spray
  status: covered
  steps:
  - identify-infrastructure-signins
  - stack-auth-protocols
- stage: c2-infrastructure-token-replay
  status: covered
  steps:
  - correlate-host-connections
  - analyst-review
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries scale identity attacks by renting legitimate infrastructure
    that standard risk scoring cannot distinguish from normal traffic. This hunt provides
    the manual oversight needed to identify these clusters across a fleet.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses trusted developer or cloud hosting platforms to bypass
  identity risk scoring, using legacy protocols (ROPC) or Device Code Flow to steal
  or replay session tokens.
labels:
- hunt
- attack.t1110.003
- attack.t1566
- attack.t1572
- command and control
- credential access
- initial access
name: Abuse of Clean Hosting Infrastructure for Identity Attacks
parameters:
  legacy_protocols:
    default:
    - ROPC
    - DeviceCode
    - IMAP4
    - POP3
    description: Auth protocols or flows used to bypass MFA or modern risk scoring.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_ranges:
    default:
    - 193.26.115.
    - 185.199.108.
    - 185.199.109.
    - 185.199.110.
    - 185.199.111.
    description: Known malicious IP prefixes associated with documented hosting abuse.
    from:
      kind: article
      observed: '2026-11-05'
      ref: huntress-itdr-infrastructure
    type: list[ip]
  scope_hosts:
    default: []
    description: 'Optional: Paste hostnames from the lead query to focus the enrichment
      steps.'
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/itdr-adversary-infrastructure
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The lead query focuses on successful logins from documented hosting clusters.
  If the initial lead results in high volume, use the scope_hosts parameter to focus
  the network connection correlate step on the most active beachhead machines.
references:
- name: "Huntress \u2014 Adversary Infrastructure: Herd Immunity for Microsoft 365"
  url: https://www.huntress.com/blog/itdr-adversary-infrastructure
related:
- hunt: mfa-bypass-device-code-flow
  reason: This hunt focuses on the infrastructure origin (hosting providers), while
    the sibling hunt focuses on the protocol mechanics across all IP ranges.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Device Code Phishing with AI Lures
    observables:
    - AI-tailored phishing lures
    - Railway developer cloud IP ranges
    - Device code flow authentication attempts
    slug: initial-access-device-code-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Legacy Auth Password Spraying
    observables:
    - ROPC (Resource Owner Password Credentials) legacy auth flow
    - 81 million login attempts from specific IPv6 ranges
    - MFA-skipping authentication patterns
    slug: credential-access-ropc-password-spray
    tactic: credential-access
    techniques:
    - T1110.003
  - name: Token Replay via AiTM Relays
    observables:
    - 193.26.115.0/24 (1337 Services GmbH)
    - German hosting provider IP ranges
    - AiTM (Adversary-in-the-Middle) relays
    - Railway-based token relays
    slug: c2-infrastructure-token-replay
    tactic: command-and-control
    techniques:
    - T1572
  summary: Attackers utilize clean hosting infrastructure and AI-generated phishing
    lures to conduct high-volume identity attacks against Microsoft 365 tenants. These
    campaigns involve device-code phishing and password spraying via legacy ROPC flows
    to bypass MFA and harvest session tokens for replay through German hosting relays.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
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
tlp: clear
type: investigation
---


# Abuse of Clean Hosting Infrastructure for Identity Attacks

This hunt targets the use of clean cloud infrastructure, specifically Railway and 1337 Services GmbH ranges, to host AiTM relays and execute password sprays. Attackers use these platforms because they have high IP reputation, causing standard Entra ID risk scoring to ignore them. The hunt starts by identifying successful sign-ins from these known malicious hosting ranges, then fans out to analyze the prevalence of specific auth protocols (ROPC, Device Code Flow) and corroborates with endpoint-side network connections to the same infrastructure.

## identify-infrastructure-signins
<!-- Sign-ins from malicious hosting ranges -->
Identify initial leads by finding successful sign-ins originating from documented adversary infrastructure.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, malicious_ranges=malicious_ranges)
~~~yaml
expected: Successful sign-in logs originating from the German hosting or Railway ranges.
  None means no confirmed logins from these specific clusters.
reads:
- time
- actor_user_name
- src_endpoint_ip
- auth_protocol
- auth_requirement
- status_code
- device_hostname
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-07'
~~~
SELECT time, actor_user_name, src_endpoint_ip, auth_protocol, auth_requirement, status_code, device_hostname FROM hb_auth_signin WHERE EXISTS (SELECT 1 FROM json_each('["' || replace('{{malicious_ranges}}', ',', '","') || '"]') WHERE src_endpoint_ip LIKE value || '%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-infrastructure-lead
<!-- Assess Infrastructure Lead -->
```agent target=hunter
cite: required
context:
- identify-infrastructure-signins
max_iterations: 3
objective: Review the sign-ins from the documented malicious ranges and confirm which
  accounts and hosts are involved.
success_criteria: A verdict confirming the presence of hits from the targeted infrastructure.
tools:
- identity
- network
```

## is-lead-worthy
<!-- Is Lead Worthy? -->
if~: "The first-read agent confirmed successful sign-ins from the malicious infrastructure prefixes." (confidence: high, judge=hunter)
then: → fan-out-telemetry
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-auth-logging)
else: → close-out

## fan-out-telemetry
<!-- Fan out to Protocol and Network Evidence -->
parallel:
- → stack-auth-protocols
- → correlate-host-connections
join: → triage-infrastructure-abuse

## stack-auth-protocols
<!-- Prevalence of Legacy and MFA-Skipping Protocols -->
Detect rare IPs that use ROPC or DeviceCode flow.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, legacy_protocols=legacy_protocols)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare IP addresses that use ROPC or DeviceCode flow against a limited number
  of users.
prevalence:
  by: actor_user_name
  key:
  - auth_protocol
  - src_endpoint_ip
  rare_below: 3
reads:
- auth_protocol
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-07'
~~~
SELECT auth_protocol, src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_attempts FROM hb_auth_signin WHERE instr(',' || '{{legacy_protocols}}' || ',', ',' || auth_protocol || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY auth_protocol, src_endpoint_ip HAVING user_count <= 3 ORDER BY user_count ASC, login_attempts DESC
```

## correlate-host-connections
<!-- Endpoint connections to malicious infrastructure -->
Corroborate the cloud-side sign-in by finding if any process on the identified hosts is talking to the same IP ranges.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, malicious_ranges=malicious_ranges, scope_hosts=scope_hosts)
~~~yaml
expected: Process-to-IP connections on the beachhead hosts that match the documented
  relay infrastructure.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-07'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE EXISTS (SELECT 1 FROM json_each('["' || replace('{{malicious_ranges}}', ',', '","') || '"]') WHERE dst_endpoint_ip LIKE value || '%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infrastructure-abuse
<!-- Triage Infrastructure Abuse -->
```agent target=hunter
cite: required
context:
- assess-infrastructure-lead
- stack-auth-protocols
- correlate-host-connections
max_iterations: 6
objective: Determine if the sign-ins from clean infrastructure combined with rare
  protocol use and host-side connections indicate a confirmed compromise.
success_criteria: A verdict of malicious | suspicious | benign per host or user.
tools:
- identity
- network
```

## compromise-confirmed
<!-- Compromise Confirmed? -->
if~: "The triage verdict is malicious for at least one account." (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-auth-logging)
else: → close-out

## revoke-sessions
<!-- Revoke Sessions and Force Password Change -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identified user accounts and force a password reset immediately.
```
→ analyst-review

## analyst-review
<!-- Remediation and Post-Compromise Review -->
```manual target=analyst
Inspect hb_cloud_api_activity for the compromised users. ensure the adversary did not establish persistence by looking for New-InboxRule or Update-MfaDevice. identify calls the adversary made after the initial sign-in from the malicious range.
```
→ close-out

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record whether the malicious_ranges parameter needs updating based on current Huntress research. If confirmed malicious, ensure the team adds the ranges to the permanent blocklist.
```
→ end
