---
analysis: A standard detection rule alerts on known IPs; this hunt links the existence
  of M365 software, rare .vu DNS resolutions, and Monday.com redirect signals into
  a single decision funnel to confirm the kit's multi-stage delivery behavior.
blind_spots:
- id: no-network-visibility
  question: whether a host without an endpoint agent performed the DNS resolution
  requires: hb_network_connection or hb_dns_activity on the host
  risk: A host not in the inventory provides no telemetry, leading to a gap in the
    funnel.
  stage: redirect-chain-obfuscation
- id: no-email-telemetry
  question: the specific content of the email before a click occurs
  requires: hb_email_activity or Email Gateway Logs
  risk: We can only see the aftermath of the delivery (the network connection), not
    the email receipt itself.
  stage: phishing-lure-delivery
coverage:
- stage: phishing-lure-delivery
  status: covered
  steps:
  - connections-to-phishing-ips
  - manual-analyst-review
- stage: redirect-chain-obfuscation
  status: covered
  steps:
  - dns-lookups-for-landing-pages
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: aitm-device-code-theft
  status: out_of_scope
- reason: Belongs to another part of the 'Inside Knight Office, a New M365 AiTM Phishing
    Kit' series.
  stage: rogue-device-persistence
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
  handoff: promote-to-detection
  justification: Knight Office specifically targets session tokens via AiTM; detecting
    the initial redirect chain on M365-equipped hosts is the earliest possible behavioral
    detection point.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Monday.com redirects and .vu landing pages to deliver
  Knight Office phishing lures to M365 users.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Knight Office Phishing Delivery and Redirects
parameters:
  knight_ips:
    default:
    - 104.37.188.94
    - 154.127.53.78
    description: Known Knight Office phishing sender and console IPs.
    from:
      kind: article
      observed: '2026-09-02'
      ref: huntress-knight-office
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  monday_domains:
    default:
    - monday.com
    description: Monday.com domains used for initial redirect tracking.
    from:
      kind: article
      observed: '2026-09-02'
      ref: huntress-knight-office
    type: list[domain]
  scope_hosts:
    default: []
    description: Hosts identified with M365 or Office software; leave empty to hunt
      all hosts.
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
rationale: The hunt scopes to hosts with Microsoft 365 or Office as these are the
  intended targets for Entra ID token theft. If the scoping step is too broad, focus
  on executive workstations or hosts with high integrity levels first.
references:
- name: Inside Knight Office, a New M365 AiTM Phishing Kit
  url: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
related:
- hunt: knight-office-token-theft-and-persistence
  reason: This follow-on hunt addresses the identity-provider side (Entra ID) and
    the theft of tokens, which requires hb_auth_signin.
  relation: out-of-scope-alternative
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Knight Office Phishing Delivery and Redirects

This hunt identifies the early delivery and redirection stages of a Knight Office AiTM attack. It first scopes the environment to hosts with Microsoft 365 or Office software, then searches for direct connections to known phishing sender IPs and DNS lookups for the .vu top-level domains used by the kit. By correlating these network signals with legitimate Monday.com redirect infrastructure, we identify hosts that have likely interacted with the phishing lure before session theft occurs.

## scope-to-m365-users
<!-- Scope to M365 and Office users -->
Identify hosts that have Microsoft 365 or Office software installed, as they are the primary targets for this campaign.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames. None means no hosts are reported with M365/Office installed.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%office%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## corroborate-delivery-traffic
<!-- Corroborate delivery traffic -->
parallel:
- → connections-to-phishing-ips
- → dns-lookups-for-landing-pages
join: → triage-delivery-verdict

## connections-to-phishing-ips
<!-- Direct connections to Knight infrastructure -->
Identify hosts communicating with known IPs used by the phishing sender or the operator console.

```sqlite target=network role=detection-candidate params=(knight_ips=knight_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A connection from a browser or script to the identified IPs. Silence means
  no recorded interaction with the specific IOCs.
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, time FROM hb_network_connection WHERE instr(',' || '{{knight_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-lookups-for-landing-pages
<!-- Suspicious redirects and phishing domains -->
Find DNS requests for the .vu TLD used for landing pages or the Monday.com domains used for redirect chains.

```sqlite target=endpoint role=baseline params=(monday_domains=monday_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare .vu domain resolution or a Monday.com resolution that precedes Knight
  infrastructure traffic.
prevalence:
  by: device_hostname
  key:
  - domain
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(query_hostname) AS domain, device_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE ((LOWER(query_hostname) LIKE '%.vu' AND LOWER(query_hostname) NOT LIKE '%.vu.%') OR (instr(',' || '{{monday_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY domain, device_hostname
```

## triage-delivery-verdict
<!-- Triage delivery verdict -->
```agent target=hunter
cite: required
context:
- connections-to-phishing-ips
- dns-lookups-for-landing-pages
max_iterations: 4
objective: Determine if the observed network activity indicates a successful redirection
  from Monday.com to a Knight Office phishing site on a .vu domain or direct interaction
  with phishing sender IPs.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  rows from network and DNS sources.
tools:
- endpoint
- network
```

## evaluate-delivery-threat
<!-- Evaluate delivery threat -->
if~: "The triage verdict identifies at least one host as malicious or highly suspicious for phishing interaction." (confidence: high, judge=hunter)
then: → isolate-affected-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: no-network-visibility)
else: → close-out

## isolate-affected-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and initiate a password reset and M365 session revocation for the primary user.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review email gateway logs for subjects containing 'Signature Required' or 'Approval Pending'. Look for character substitutions like 'lmportant'. Correlate identified email recipients with the hosts seen in this hunt. If the host was identified in the scoping step but yielded no network evidence, investigate potential gaps in telemetry coverage (e.g. agent health) for that specific asset.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record any new .vu domains or redirector URLs found. If token theft is confirmed, transition to the identity-focused follow-on hunt.
```
→ end
