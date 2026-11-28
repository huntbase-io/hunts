---
analysis: A standard detection rule fires on a single impossible travel event; this
  hunt pivots to the external attack surface and vulnerability findings to prioritize
  ingress points that are both unpatched and showing anomalous authentication traffic,
  weighing the correlation across multiple surfaces.
blind_spots:
- id: missing-auth-geolocation
  question: Was this login part of an impossible travel sequence or a geo-fenced violation?
  requires: hb_auth_signin with src_location_country and MFA status
  risk: Without geographic context, automated ingress from distant locations is indistinguishable
    from standard remote work until after lateral movement occurs.
  stage: ai-enhanced-phishing
- id: unmonitored-gateways
  question: Which users are authenticating specifically through the VPN vs. SaaS directly?
  requires: VPN/Firewall logs integrated into hb_auth_signin
  risk: If gateway logs are not forwarded, the 'front door' remains a black box until
    an attacker reaches a managed endpoint.
  stage: external-service-compromise
coverage:
- stage: ai-enhanced-phishing
  status: covered
  steps:
  - rare-auth-geolocations
  - triage-ingress
- stage: external-service-compromise
  status: covered
  steps:
  - identify-perimeter
  - gateway-vulnerabilities
  - triage-ingress
- reason: "Belongs to another part of the 'AI Attacks Move Faster. Huntress\u2019\
    \ Agentic SOC Keeps Up' series."
  stage: automated-internal-discovery
  status: out_of_scope
- reason: "Belongs to another part of the 'AI Attacks Move Faster. Huntress\u2019\
    \ Agentic SOC Keeps Up' series."
  stage: credential-and-token-theft
  status: out_of_scope
- reason: "Belongs to another part of the 'AI Attacks Move Faster. Huntress\u2019\
    \ Agentic SOC Keeps Up' series."
  stage: rapid-data-triage-and-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI-driven attacks use speed to move from initial access to full compromise
    in minutes; securing the identity and perimeter ingress plane is a critical business
    obligation to prevent mass compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated attacker is exploiting unpatched perimeter services or using
  AI-refined phishing to compromise identities, resulting in successful sign-ins from
  rare geolocations that correlate with known gateway vulnerabilities.
labels:
- hunt
- attack.t1133
- attack.t1190
- attack.t1566
- attack.t1078
name: Machine-Speed Perimeter and Identity Ingress
parameters:
  gateway_products:
    default:
    - vpn
    - fortinet
    - cisco
    - anyconnect
    - citrix
    - globalprotect
    - firewall
    - gateway
    description: Keywords identifying remote access products in logs.
    from:
      kind: article
      observed: '2026-09-22'
      ref: huntress-ai-attackers-machine-speed
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication and exposure events.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames or IPs to narrow the hunt; paste identifiers from
      the scoping step here.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ai-attackers-machine-speed-huntress-athena
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on the internet-exposed perimeter. The scoping query identifies domains
  and IPs; analysts should use these values to populate the scope_hosts parameter
  for identity and vulnerability queries. Ensure VPN and gateway logs are forwarding
  to the authentication surface.
references:
- name: "Huntress \u2014 Inside the Agentic Huntress Platform: Beating Adversaries\
    \ at Machine Speed"
  url: https://www.huntress.com/blog/ai-attackers-machine-speed-huntress-athena
related:
- hunt: mfa-bypass-geo-anomalies
  reason: Both hunts examine authentication anomalies, but this hunt specifically
    correlates them with the external attack surface and critical gateway vulnerabilities.
  relation: alternative
scenario:
  stages:
  - name: AI-Enhanced Phishing and Social Engineering
    observables:
    - Phishing emails with AI-refined language
    - Video calls with AI-altered faces (deepfakes)
    - Compromised accounts used for high-volume phishing
    slug: ai-enhanced-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Compromise of External Remote Services
    observables:
    - Anomalous VPN authentications without MFA
    - Connections from unusual geolocations via VPN
    - Exploitation of vulnerable network appliances or firewalls
    - Exposed services on ports 443 or 1194
    slug: external-service-compromise
    tactic: initial-access
    techniques:
    - T1133
    - T1190
  - name: Automated Internal Reconnaissance
    observables:
    - High-speed internal network scanning and enumeration
    - Rapid execution of system discovery commands
    - Unusual outbound internal traffic patterns from recently accessed hosts
    slug: automated-internal-discovery
    tactic: discovery
    techniques:
    - T1083
    - T1018
  - name: Credential Dumping and Session Token Theft
    observables:
    - Theft of API keys and session tokens for AI models (e.g., Anthropic, OpenAI)
    - Memory dumping of lsass.exe
    - Loading of dbghelp.dll or dbgcore.dll from non-standard paths
    - Access to local credential stores or browser profile directories
    slug: credential-and-token-theft
    tactic: credential-access
    techniques:
    - T1003
  - name: Automated Data Triage and Impact
    observables:
    - AI-assisted scanning of files for PII, PHI, or intellectual property
    - Rapid traversal of file shares and local directories
    - Bulk file encryption and renaming (ransomware activity)
    - Execution of scripts or binaries for automated data classification
    slug: rapid-data-triage-and-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Attackers are utilizing AI to accelerate traditional tradecraft, moving
    from initial access via compromised VPNs or firewalls to rapid internal discovery
    and automated data triage. While AI enhances the speed of reconnaissance and phishing,
    the core post-exploitation behaviors such as credential dumping and lateral movement
    remain observable through endpoint and identity telemetry.
series:
  index: 1
  slug: ai-attacks-move-faster-huntress-agentic-soc-keeps-up
  title: "AI Attacks Move Faster. Huntress\u2019 Agentic SOC Keeps Up"
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


# Machine-Speed Perimeter and Identity Ingress

This hunt targets the initial ingress points where AI-driven automation significantly compresses the time between initial access and lateral movement. It identifies exposed remote access infrastructure, correlates it with known critical vulnerabilities, and examines authentication patterns for signs of identity compromise or MFA bypass. By fanning out to evaluate perimeter risk and authentication anomalies simultaneously, an agent determines if an ingress event is part of a machine-speed automated attack.

## identify-perimeter
<!-- Identify exposed perimeter assets -->
Define the external attack surface by locating every internet-exposed gateway or VPN service.

```sqlite target=endpoint role=scoping params=(gateway_products=gateway_products, lookback_days=lookback_days)
~~~yaml
expected: A list of IP addresses and domains running remote access software. Absence
  indicates no such assets were discovered by external scanning.
reads:
- domain_or_ip
- product
- port
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT domain_or_ip, product, port, discovered_at FROM hb_exposed_assets WHERE (instr(',' || '{{gateway_products}}' || ',', ',' || LOWER(product) || ',') > 0) AND discovered_at >= datetime('now', '-{{lookback_days}} days')
```

## ingress-fan-out
<!-- Evaluate ingress and identity risk -->
parallel:
- → rare-auth-geolocations
- → gateway-vulnerabilities
join: → triage-ingress

## rare-auth-geolocations
<!-- Identify rare authentication geolocations -->
Find successful sign-ins from locations that are rare for a specific user, indicating potential identity compromise.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Logins from countries that a user does not typically inhabit. Silence suggests
  authentication patterns follow historical baselines.
prevalence:
  by: actor_user_name
  key:
  - src_location_country
  rare_below: 2
reads:
- actor_user_name
- src_location_country
- mfa
- status_id
- device_hostname
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT actor_user_name, src_location_country, mfa, COUNT(*) AS login_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_location_country HAVING login_count <= 2 ORDER BY login_count ASC
```

## gateway-vulnerabilities
<!-- Check for critical gateway vulnerabilities -->
Enrich the hunt with known exploitable vulnerabilities on the remote access assets identified in scoping.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, gateway_products=gateway_products, lookback_days=lookback_days)
~~~yaml
expected: Vulnerability findings on the perimeter. High-severity results combined
  with rare logins indicate a high-risk ingress event.
reads:
- device_uid
- cve_uid
- affected_package_name
- severity
- severity_id
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, cve_uid, affected_package_name, severity, collected_at FROM hb_vulnerability_finding WHERE severity_id >= 4 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_uid || ',') > 0) AND (instr(',' || '{{gateway_products}}' || ',', ',' || LOWER(affected_package_name) || ',') > 0) AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-ingress
<!-- Triage machine-speed ingress risk -->
```agent target=hunter
cite: required
context:
- identify-perimeter
- rare-auth-geolocations
- gateway-vulnerabilities
max_iterations: 5
objective: Determine if successful sign-ins from rare geolocations occur on users
  with single-factor auth or target systems with known critical perimeter vulnerabilities.
  Identify if multiple distant geolocations appear for one user within the lookback
  window.
success_criteria: A verdict of malicious, suspicious, or benign per host and account,
  citing the evidence from all contexts.
tools:
- endpoint
- identity
```

## route-risk
<!-- Route on ingress risk -->
if~: "The triage verdict is malicious for at least one account or host based on rare geolocation or unpatched gateway exploitation." (confidence: high, judge=hunter)
then: → isolate-or-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-auth-geolocation)
else: → close-out

## isolate-or-revoke
<!-- Isolate host or revoke identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke active sessions and reset passwords for compromised accounts; isolate hosts if the agent found evidence of host-level vulnerability exploitation.
```
→ analyst-review

## analyst-review
<!-- Analyst review and verification -->
```manual target=analyst
Examine the auth_signin rows for flagged users; check for shared source IPs and geolocation proximity. Verify the presence of critical vulnerabilities on the target gateways.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the number of vulnerable assets and rare sign-ins observed. Note users who frequently trigger geolocation anomalies for allow-listing or policy adjustment.
```
→ end
