---
analysis: A single rule might catch a login from a new country, but it cannot weigh
  that against a subsequent shift to service-account behavior or the context of a
  long-standing unrotated admin credential. This hunt uses a phased flow and two agents
  to bridge the gap between individual authentication events and the lifecycle of
  identity abuse.
blind_spots:
- id: no-session-details
  owner: IAM Operations
  question: Was a specific session token hijacked from a trusted device?
  remediation: Enable and ingest debug-level IDP logs including user_agent and session
    identifiers.
  requires: Advanced IDP logging for session-specific attributes
  risk: Without session-level tracking, attackers can mask shifts using proxies that
    mimic a user's known geolocation.
  stage: defense-evasion-session-hijacking
- id: jit-log-absence
  owner: Security Engineering
  question: Was an administrative action preceded by a legitimate JIT elevation request?
  remediation: Integrate a PAM solution that logs JIT elevations into the primary
    telemetry stream.
  requires: Just-In-Time (JIT) access logs from a PAM solution
  risk: In the absence of JIT logs, malicious use of standing admin rights is indistinguishable
    from legitimate maintenance.
  stage: privilege-escalation-standing-admin
coverage:
- stage: initial-access-aitm-phishing
  status: covered
  steps:
  - mfa-push-fatigue
  - triage-access
- stage: initial-access-vpn-exploitation
  status: covered
  steps:
  - scoping-vpn-gateways
  - vpn-ioc-traffic
- stage: defense-evasion-session-hijacking
  status: covered
  steps:
  - triage-access
- stage: persistence-non-human-identities
  status: covered
  steps:
  - rare-nhi-signins
  - triage-persistence
- stage: privilege-escalation-standing-admin
  status: covered
  steps:
  - standing-admin-inventory
  - triage-persistence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Modern identity attacks frequently bypass static MFA and exploit
    the lack of governance over non-human identities; a negative result confirms that
    identity resilience controls are effective.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has bypassed traditional MFA via session hijacking or push
  fatigue and established persistence using overprivileged non-human identities or
  standing administrative accounts.
labels:
- hunt
- attack.t1566
- attack.t1133
- attack.t1190
- attack.t1550
- attack.t1078
- defense evasion
- initial access
- persistence
- privilege escalation
name: Bypass of Legacy Identity Controls and Persistence via NHIs
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the network search.
    type: list[host]
  vpn_domains:
    default:
    - vpn.com
    description: Known VPN or remote access domains to monitor.
    from:
      kind: article
      observed: '2026-11-10'
      ref: proofpoint-iam-assumptions
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/18-outdated-identity-and-access-management-assumptions-retire
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing gateways identified in software inventory; focus
  the identity search on accounts with privileged status if the estate size requires
  narrowing.
references:
- name: "Proofpoint \u2014 18 Outdated Identity And Access Management Assumptions\
    \ To Retire"
  url: https://www.proofpoint.com/us/newsroom/news/18-outdated-identity-and-access-management-assumptions-retire
related:
- hunt: non-human-identity-governance-audit
  reason: This hunt identifies active abuse; a full audit is required to identify
    all overprivileged NHIs regardless of current activity.
  relation: follows
scenario:
  stages:
  - name: AitM Phishing and Push Fatigue
    observables:
    - Adversary-in-the-middle (AitM) proxies
    - SMS code interception
    - MFA push notification fatigue (multiple rapid requests)
    - Phishing domains mimicking login portals
    slug: initial-access-aitm-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Exploitation of External Remote Services
    observables:
    - VPN connections (vpn.com)
    - Checkpoint VPN gateway logs
    - Exploitation of vulnerabilities in internet-facing access gateways
    slug: initial-access-vpn-exploitation
    tactic: initial-access
    techniques:
    - T1133
    - T1190
  - name: Session Token Theft and MFA Bypass
    observables:
    - Captured session tokens used from new/unknown devices
    - Bypassing push-based MFA via fatigue
    - Login from anonymizing proxies or unusual geolocations
    slug: defense-evasion-session-hijacking
    tactic: defense-evasion
    techniques:
    - T1550
  - name: Abuse of Non-Human Identities
    observables:
    - Service accounts with standing overprivileged access
    - AI agents performing actions outside of normal user intent
    - Orchestrator sub-agents acting within application processes
    - Stale service accounts from offboarded employees
    slug: persistence-non-human-identities
    tactic: persistence
    techniques:
    - T1133
  - name: Exploitation of Standing Privileges
    observables:
    - Permanent administrative credentials used for high-impact tasks
    - Lack of Just-In-Time (JIT) elevation for sensitive commands
    - Administrative access to service accounts
    slug: privilege-escalation-standing-admin
    tactic: privilege-escalation
    techniques:
    - T1078
  summary: This scenario represents a modern identity-focused intrusion where attackers
    bypass traditional MFA via adversary-in-the-middle phishing or push-fatigue tactics
    to hijack sessions. The campaign transitions from human identity compromise to
    long-term persistence by exploiting overprivileged non-human identities (NHIs)
    and standing administrative permissions that lack continuous verification.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Bypass of Legacy Identity Controls and Persistence via NHIs

An adversary steals active sessions or triggers push fatigue to bypass traditional authentication hurdles. The hunt first identifies internet-facing gateways and scans for high-frequency MFA failures that culminate in a single success. By correlating these access anomalies with the behavior of non-human identities and standing administrative accounts, the hunt identifies identities an intruder has repurposed for persistence. An analyst then reviews the linked chain of events to revoke compromised credentials and recommend phishing-resistant controls.

## scoping-vpn-gateways
<!-- Identify Remote Access Gateways -->
Identify hosts running VPN or remote access software to focus the later network traffic analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts acting as remote gateways. Silence indicates no managed
  VPN software is recorded in inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%checkpoint%' OR LOWER(package_name) LIKE '%vpn%')
```

## initial-access-parallel
<!-- Monitor for Early-Stage Identity Bypass -->
parallel:
- → mfa-push-fatigue
- → vpn-ioc-traffic
join: → triage-access

## mfa-push-fatigue
<!-- Patterns of MFA Push Fatigue -->
Identify accounts experiencing high failure rates followed by a successful login, typical of push fatigue.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: High failure counts (activity_id 5) coupled with a final success (activity_id
  1) for the same user and IP.
reads:
- actor_user_name
- src_endpoint_ip
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT actor_user_name, src_endpoint_ip, activity_id, COUNT(*) AS count, MIN(time) AS first_event, MAX(time) AS last_event FROM hb_auth_signin WHERE activity_id IN (1, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, activity_id
```

## vpn-ioc-traffic
<!-- Connections to VPN IOC Domains -->
Corroborate whether identified gateways or other hosts are communicating with the reported VPN IOC domain.

```sqlite target=network role=enrichment params=(vpn_domains=vpn_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound traffic to vpn.com or related domains from internal hosts. Silence
  indicates no traffic to these domains in the window.
reads:
- time
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT time, device_hostname, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port FROM hb_network_connection WHERE instr(',' || '{{vpn_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-access
<!-- Triage Initial Access Lead -->
```agent target=hunter
cite: required
context:
- mfa-push-fatigue
- vpn-ioc-traffic
max_iterations: 5
objective: Determine if the patterns of MFA fatigue and VPN connections identify compromised
  user accounts or exposed gateways.
success_criteria: A per-user or per-host verdict of suspicious or malicious, citing
  specific failure/success sequences or IOC connections.
tools:
- endpoint
- identity
- network
```

## persistence-parallel
<!-- Hunt for Identity Persistence -->
parallel:
- → rare-nhi-signins
- → standing-admin-inventory
join: → triage-persistence

## rare-nhi-signins
<!-- Rare Non-Human Identity Sign-ins -->
Identify service accounts signing in from unusual or rare source IPs, which may indicate attacker reuse.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Service accounts appearing on a small number of hosts or new IPs. Silence
  means no service accounts matched naming patterns in the window.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- src_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE (LOWER(actor_user_name) LIKE 'svc_%' OR LOWER(actor_user_name) LIKE '%bot%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING host_count < 3
```

## standing-admin-inventory
<!-- Inventory of Standing Administrative Privileges -->
Retrieve a list of accounts with permanent administrative roles to cross-reference with early-stage anomalies.

```sqlite target=identity role=enrichment
~~~yaml
expected: A list of standing administrators. The agent will compare these against
  identities performing suspicious transactions.
reads:
- id
- name
- email
- privileged
- status
- provider
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT id, name, email, privileged, status, provider FROM hb_users WHERE (LOWER(privileged) = 'true') AND status = 'active'
```

## triage-persistence
<!-- Triage Identity Persistence -->
```agent target=hunter
cite: required
context:
- triage-access
- rare-nhi-signins
- standing-admin-inventory
max_iterations: 6
objective: Determine if the suspicious access identified in the first triage stage
  has transitioned into persistence through service accounts or standing administrative
  abuse.
success_criteria: A final malicious verdict if an account compromised via fatigue/session
  theft is seen interacting with or utilizing administrative or service account privileges
  from the same source infrastructure.
tools:
- endpoint
- identity
- network
```

## route-on-risk
<!-- Route on Persistence Verdict -->
if~: "The triage-persistence verdict identifies a malicious linkage between initial access anomalies and subsequent NHI or standing administrative abuse." (confidence: high, judge=hunter)
then: → suspend-account
indeterminate: → iam-governance-review
unavailable: → iam-governance-review (blind_spot: no-session-details)
else: → iam-governance-review

## suspend-account
<!-- Suspend Compromised Accounts -->
```action target=identity
~~~yaml
approval: required
~~~
Suspend the primary user account and any service accounts identified by the agent as being under attacker control. Revoke all active session tokens immediately.
```
→ iam-governance-review

## iam-governance-review
<!-- IAM Governance Review -->
```manual target=analyst
Evaluate why standing privileges were available to the compromised user. Identify service accounts that lack distinct ownership or periodic review. Propose moving to FIDO2 or phishing-resistant MFA for the affected groups.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document all malicious activity confirmed. Record any telemetry blind spots identified, such as lack of session-level IDP tracking.
```
→ end
