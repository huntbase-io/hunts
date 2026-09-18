---
analysis: A simple detection rule matches the domains; this hunt adds value by scoping
  to vulnerable software, stack-counting rare Office resolutions to catch rotated
  domains, and using an agent to weigh success (HTTP 200) against background noise.
blind_spots:
- id: no-email-body-telemetry
  owner: Security Engineering
  question: whether the 'ASCII Smuggling' tag characters were present in the delivered
    lure
  remediation: Integrate mail server logs (M365 Audit) to inspect message bodies for
    the U+E0000 range.
  requires: hb_email_content surface (not currently available)
  risk: We can only observe the outcome of the phish (the domain resolution/interaction),
    not the specific evasion technique used in the body.
  stage: initial-access-ascii-smuggling
- id: tls-blindness
  owner: Network Infrastructure
  question: what data was posted to the phishing domain (e.g. credentials)
  remediation: Deploy TLS inspection for newly registered or uncategorized domains.
  requires: TLS decryption on hb_http_activity
  risk: We see the interaction but not the specific payload or harvested data.
  stage: initial-access-ascii-smuggling
coverage:
- stage: initial-access-ascii-smuggling
  status: covered
  steps:
  - dns-campaign-leads
  - office-rare-dns-resolutions
  - http-landing-page-success
- stage: c2-multi-hop-obfuscation
  status: covered
  steps:
  - dns-campaign-leads
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ASCII Smuggling is a novel evasion technique that bypasses traditional
    NLP-based email filters. A negative result across the estate confirms that current
    layered protections are effective or that the specific campaign did not gain a
    beachhead.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using invisible Unicode Tag characters to bypass email
  filters and deliver phishing lures for finance-themed domains, leading to initial
  access and subsequent command-and-control activity.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Phishing evasion via Unicode tag obfuscation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  office_processes:
    default:
    - outlook.exe
    - winword.exe
    - excel.exe
    - powerpnt.exe
    description: Office suite executables to monitor for rare DNS resolutions.
    type: list[string]
  phishing_domains:
    default:
    - guardiangrowthfunding.com
    - digitalcapitalboost.com
    - thebusinessloanexpress.com
    - yourlocfunding.com
    description: Campaign-associated domains used for delivery and landing pages.
    from:
      kind: article
      observed: '2026-09-03'
      ref: msrc-blog
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts from the scoping step to focus the hunt.
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
rationale: The hunt begins by narrowing the scope to hosts with M365 or Office components,
  as the 'ASCII Smuggling' technique specifically targets those users through email
  lures.
references:
- name: "MSRC \u2014 ASCII smuggling crosses over from AI prompt injection to phishing\
    \ evasion"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/
related:
- hunt: homoglyph-domain-triage
  reason: Both hunts deal with character-level evasion in phishing, but one uses look-alike
    characters in domains while this hunt focuses on invisible characters in keywords.
  relation: sibling
scenario:
  stages:
  - name: Phishing with ASCII Smuggling Evasion
    observables:
    - Unicode Tag characters U+E0000-U+E007F
    - U+E0020 tag space
    - guardiangrowthfunding.com
    - digitalcapitalboost.com
    - thebusinessloanexpress.com
    - yourlocfunding.com
    - invisible character insertion in 'funding'
    - finance-themed sender domains
    slug: initial-access-ascii-smuggling
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-hop Proxy Infrastructure
    observables:
    - Traffic to campaign-associated sender domains
    - Multi-hop proxy chains used for delivery or landing page hosting
    slug: c2-multi-hop-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: A high-volume phishing campaign leveraged 'ASCII smuggling' to evade email
    filters by inserting invisible Unicode tag characters (U+E0000 to U+E007F) into
    financial lure keywords. The campaign, which generated millions of messages daily,
    used a weekly weekday-focused cadence and a rotating infrastructure of over 150
    finance-themed domains to deliver SBA-themed lures.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Phishing evasion via Unicode tag obfuscation

This hunt identifies the execution of phishing lures associated with 'ASCII Smuggling' campaigns. While endpoint telemetry cannot directly observe the Unicode tag characters in the email body, it can observe the interaction with the reported finance-themed sender domains and landing pages. We scope the hunt to hosts with Microsoft 365 components, identify resolutions to known campaign domains, and behaviorally hunt for rare domain resolutions originating from Office processes that may indicate novel lure delivery.

## office-software-scoping
<!-- Scope to hosts with M365/Office -->
Identify hosts that could be affected by the phishing campaign based on the presence of Microsoft 365 or Office components.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Silence means no hosts in the estate have the target
  software installed.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%outlook%' OR LOWER(package_name) LIKE '%office%' OR LOWER(package_name) LIKE '%microsoft 365%'
```

## dns-campaign-leads
<!-- DNS resolutions to campaign domains -->
Find any host resolving the specific domains associated with the Unicode-obfuscated phishing campaign.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: Rows indicate hosts and processes interacting with known malicious domains.
  This is the primary lead for the hunt.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## corroborate-activity
<!-- Corroborate on behavior and prevalence -->
parallel:
- → http-landing-page-success
- → office-rare-dns-resolutions
join: → agent-triage

## http-landing-page-success
<!-- HTTP landing page activity -->
Identify successful connections to phishing landing pages by looking for HTTP 200 responses to the campaign domains.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: A successful HTTP 200 to a phishing domain is strong evidence of a user
  clicking the lure.
reads:
- device_hostname
- url_hostname
- url_path
- status_code
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, status_code, user_agent, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND status_code = 200 AND time >= datetime('now', '-{{lookback_days}} days')
```

## office-rare-dns-resolutions
<!-- Rare DNS resolutions from Office processes -->
Identify potential 'unseen' phishing interaction by stack-counting any domain resolved by an Office process that is rare across the fleet.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, office_processes=office_processes, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A behavioral signal identifying rare domains resolved by Office apps, which
  may indicate a new phishing domain not yet in the known list.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{office_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname, process_name HAVING host_count <= 2 ORDER BY host_count ASC
```

## agent-triage
<!-- Triage phishing interaction evidence -->
```agent target=hunter
cite: required
context:
- office-software-scoping
- dns-campaign-leads
- http-landing-page-success
- office-rare-dns-resolutions
max_iterations: 4
objective: Determine if any host has successfully interacted with the phishing campaign,
  prioritizing cases where a known domain resolution is corroborated by an HTTP 200
  or a rare resolution from an Office process.
success_criteria: A per-host verdict for every host seen in the lead steps.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on phishing verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-email-body-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host and trigger a password reset for the logged-in user.
```
→ analyst-review

## analyst-review
<!-- Analyst verification -->
```manual target=analyst
Review the rows cited by the triage agent. For any suspicious hosts, check the HTTP User-Agent and path for commonalities. If new phishing domains are identified in the 'office-rare-dns-resolutions' step, add them to the phishing_domains parameter for the next run.
```
→ end
