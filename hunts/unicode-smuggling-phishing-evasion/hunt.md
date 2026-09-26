---
analysis: Simple keyword rules fail when terms like funding are split by invisible
  characters. This hunt pivots across DNS, HTTP, and Network prevalence to confirm
  the presence of percent-encoded smuggling markers that would be otherwise ignored
  by static signatures.
blind_spots:
- id: no-dns-logging
  question: whether the host resolved a campaign domain using DoH or an unmonitored
    resolver
  requires: Endpoint DNS resolution logging
  risk: The lead query would fail to find the initial interaction, stopping the hunt
    at the gate.
  stage: phishing-campaign-delivery
- id: no-http-proxy
  question: whether the smuggling markers were present in encrypted HTTPS traffic
  requires: hb_http_activity with full URL/Referrer capture
  risk: Encrypted traffic without proxy-level inspection prevents visibility into
    the percent-encoded smuggling markers in URL paths or referrers.
  stage: keyword-obfuscation-evasion
coverage:
- stage: phishing-campaign-delivery
  status: covered
  steps:
  - dns-campaign-lead
- stage: keyword-obfuscation-evasion
  status: covered
  steps:
  - http-smuggling-check
- stage: multi-hop-proxy-redirection
  status: covered
  steps:
  - network-connection-pivot
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries are repurposing AI prompt injection techniques for traditional
    phishing evasion. These invisible characters successfully bypass keyword-based
    filters; detecting this crossover tradecraft provides high-fidelity signals for
    active fraud campaigns targeting financial assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using invisible Unicode tag characters to split keywords
  in finance-themed phishing lures, bypassing traditional email filters and redirecting
  victims to disposable infrastructure.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Unicode-Smuggling Financial Phishing Evasion
parameters:
  campaign_domains:
    default:
    - guardiangrowthfunding.com
    - digitalcapitalboost.com
    - thebusinessloanexpress.com
    - yourlocfunding.com
    description: Disposable finance-themed domains identified in the campaign.
    from:
      kind: article
      observed: '2026-09-03'
      ref: msrc-blog-ascii-smuggling
    type: list[domain]
  encoded_tag_prefix:
    default: '%f3%a0'
    description: The percent-encoded UTF-8 prefix for characters in the Unicode Tags
      block.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts with Microsoft 365 or Office installed, identified in the scoping
      step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Targets hosts with Office/M365 installed as primary candidates for email-based
  phishing interactions. The hunt assumes these hosts are the most likely to be targeted
  with business-finance lures.
references:
- name: "MSRC Blog \u2014 ASCII smuggling crosses over from AI prompt injection to\
    \ phishing evasion"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/
related:
- hunt: homoglyph-phishing-domains
  reason: That hunt focuses on visually similar characters in domain names, whereas
    this hunt focuses on invisible smuggling characters inside keywords.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing Campaign Delivery
    observables:
    - guardiangrowthfunding.com
    - digitalcapitalboost.com
    - thebusinessloanexpress.com
    - yourlocfunding.com
    - ActiveCampaign infrastructure
    - Financial lures regarding business loans or line-of-credit
    slug: phishing-campaign-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Keyword Obfuscation via ASCII Smuggling
    observables:
    - Unicode tag characters range U+E0000 to U+E007F
    - Invisible TAG SPACE U+E0020
    - Split keywords like 'f<U+E0020>unding'
    - Invisibility in human-facing UI while appearing to machine parsers
    slug: keyword-obfuscation-evasion
    tactic: defense-evasion
    techniques:
    - T1566
  - name: Multi-hop Proxy Redirection
    observables:
    - Disposable finance-themed domains
    - Multi-hop proxy infrastructure to disguise traffic source
    slug: multi-hop-proxy-redirection
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: A high-volume phishing campaign leveraged invisible Unicode tag characters
    (ASCII Smuggling) to split financial keywords such as 'funding' in email lures,
    successfully evading literal keyword filters and NLP-based tokenizers. The campaign
    utilized over 150 finance-themed domains and followed a strict weekday-only cadence
    for three months starting in February 2026.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Unicode-Smuggling Financial Phishing Evasion

This hunt identifies the use of ASCII smuggling characters (U+E0000 to U+E007F) within phishing campaigns targeting financial departments. By inserting invisible TAG characters into lure words like funding, attackers evade literal keyword matching and modern NLP-based classifiers. The hunt uses a gated flow to first identify interactions with campaign-specific domains before performing a deep dive into HTTP headers for percent-encoded smuggling markers and corroborating the activity with network connection patterns that suggest multi-hop redirection.

## scoping-office-hosts
<!-- Identify hosts with Office software -->
Focus the hunt on endpoints running software typically used for processing the phishing lures described in the research.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Since this is an inventory snapshot, silence means
  no matching software was found on the monitored fleet.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%office%') GROUP BY device_hostname, package_name, package_version
```

## dns-campaign-lead
<!-- DNS hits on campaign domains -->
Identify hosts that have interacted with the known campaign infrastructure as a primary lead.

```sqlite target=endpoint role=triage params=(campaign_domains=campaign_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any hostname resolving the campaign domains is a lead. Silence suggests
  no direct interaction with the known IOC list occurred via monitored resolvers.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_hit, MAX(time) as last_hit FROM hb_dns_activity WHERE (instr(',' || '{{campaign_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookup_count DESC
```

## evaluate-lead
<!-- Evaluate DNS lead -->
```agent target=hunter
cite: required
context:
- dns-campaign-lead
max_iterations: 3
objective: Determine if the DNS lookups in dns-campaign-lead represent a suspicious
  interaction with confirmed campaign domains.
success_criteria: A per-host verdict of suspicious or benign.
tools:
- endpoint
- network
- web
```

## gate-on-lead
<!-- Gate on lead verdict -->
if~: "the evaluate-lead verdict identifies at least one host with suspicious domain resolutions" (confidence: high, judge=hunter)
then: → deep-dive-checks
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-logging)
else: → close-out

## deep-dive-checks
<!-- Parallel corroboration -->
parallel:
- → http-smuggling-check
- → network-connection-pivot
join: → final-triage

## http-smuggling-check
<!-- HTTP smuggling check -->
Identify HTTP requests where the URL or referrer contains the specific percent-encoded prefix for Unicode tag characters.

```sqlite target=web role=detection-candidate params=(encoded_tag_prefix=encoded_tag_prefix, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A hit identifies the presence of the smuggling block in transit. This is
  a very rare and high-fidelity indicator of evasion tradecraft.
reads:
- device_hostname
- url_hostname
- url_full
- referrer
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_full, referrer, user_agent, time FROM hb_http_activity WHERE (LOWER(url_full) LIKE '%' || '{{encoded_tag_prefix}}' || '%' OR LOWER(referrer) LIKE '%' || '{{encoded_tag_prefix}}' || '%') AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-connection-pivot
<!-- Network connection prevalence -->
Evaluate whether connections to the campaign domains are persistent and rare across the fleet.

```sqlite target=network role=baseline params=(campaign_domains=campaign_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A low host count for a high-volume connection pattern confirms the domains
  are rare targets rather than legitimate shared infrastructure.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_hostname
  rare_below: 5
reads:
- dst_endpoint_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_hostname, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE (instr(',' || '{{campaign_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_hostname HAVING host_count <= 5 ORDER BY host_count ASC, connection_count DESC
```

## final-triage
<!-- Final triage -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- http-smuggling-check
- network-connection-pivot
max_iterations: 4
objective: Determine if any host successfully established communication with the campaign
  infrastructure using ASCII smuggling techniques.
success_criteria: A per-host verdict of malicious, suspicious, or benign.
tools:
- endpoint
- network
- web
```

## route-remediation
<!-- Route on final verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-proxy)
else: → close-out

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate any active network sessions to the campaign domains.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the HTTP referrer and full URL columns for the smuggling prefix. Confirm if the interaction resulted in a login attempt or file download. Check for related emails in the user's inbox to identify new lure keywords.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts examined. If new campaign domains were found, add them to the campaign_domains parameter for future runs.
```
→ end
