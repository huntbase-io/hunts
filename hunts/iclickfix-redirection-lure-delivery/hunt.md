---
analysis: A simple detection rule may miss rotated domains. This hunt uses the baseline
  step to stack-count hosts receiving fingerprint-like query strings (data={...})
  and correlates this with your internal WordPress inventory to identify novel or
  unreported infrastructure.
blind_spots:
- id: https-decryption-blind-spot
  question: whether URL paths (e.g., /gigi) are visible in HTTPS traffic
  requires: TLS/SSL decryption at the network layer
  risk: Without decryption, the hunt relies on hostname-level DNS and stacking, which
    may miss traffic to benign hostnames used as relays.
  stage: tds-redirection-js
- id: response-body-missing
  question: whether the 'ic-tracker-js' ID is actually present in the HTML of our
    WordPress sites
  requires: HTTP response body logging
  risk: We can only infer the presence of the injection from subsequent redirection
    traffic, not observe the injection itself directly.
  stage: initial-access-wordpress-injection
coverage:
- stage: initial-access-wordpress-injection
  status: covered
  steps:
  - identify-wordpress-servers
  - http-tds-uri-patterns
- stage: tds-redirection-js
  status: covered
  steps:
  - dns-to-redirection-infra
  - http-tds-uri-patterns
  - rare-fingerprint-exfiltration
- reason: Covered via identification of requests to /liner.php and subsequent exfiltration
    patterns.
  stage: clickfix-social-engineering
  status: covered
  steps:
  - http-tds-uri-patterns
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: powershell-stager-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: persistence-and-payload-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: c2-communication-netsupport
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: iClickFix is a widespread malware distribution framework that exploits
    trusted sites (WordPress) to deliver RATs via social engineering. Ensuring internal
    servers are not compromised and clients are not successfully lured is vital for
    preventing the final NetSupport RAT payload.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Internal WordPress servers have been compromised to act as watering holes,
  using a Traffic Distribution System (YOURLS) to redirect visitors to a ClickFix
  social engineering lure.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1115
name: 'iClickFix: Web-based Redirection and ClickFix Lure Delivery'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-01-06'
      ref: standard-lookback
    type: number
  malicious_domains:
    default:
    - ksfldfklskdmbxcvb.com
    - ksdkgsdkgkgmgm.pro
    - booksbypatriciaschultz.com
    - ototaikfffkf.com
    - scottvmorton.com
    description: Known domains in the iClickFix infrastructure.
    from:
      kind: article
      observed: '2025-12-09'
      ref: Sekoia Blog
    type: list[domain]
  redirection_paths:
    default:
    - /gigi
    - /fffa.js
    - /ofofo.js
    - /liner.php
    description: Specific URL paths used for TDS redirection and script delivery.
    from:
      kind: article
      observed: '2025-12-09'
      ref: Sekoia Blog
    type: list[path]
  scope_hosts:
    default: []
    description: WordPress servers identified in the scoping step; paste hostname
      strings here.
    from:
      kind: manual
      observed: '2026-01-06'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should begin by identifying all WordPress servers in the environment
  via hb_software_inventory. These servers are the 'affected hosts' that may have
  been compromised to host the initial tracker script.
references:
- name: 'Sekoia Blog - Meet IClickFix: A widespread WordPress-targeting framework'
  url: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
related:
- hunt: iclickfix-powershell-and-netsupport-persistence
  reason: This hunt identifies the web delivery; a subsequent hunt is needed to cover
    the PowerShell stager execution and NetSupport RAT persistence.
  relation: follows
scenario:
  stages:
  - name: Compromised WordPress Injection
    observables:
    - <script id="ic-tracker-js">
    - ksfldfklskdmbxcvb.com/gigi?ts=
    slug: initial-access-wordpress-injection
    tactic: initial-access
    techniques:
    - T1566
  - name: Traffic Distribution Redirection
    observables:
    - ototaikfffkf.com/fffa.js
    - ksdkgsdkgkgmgm.pro/ofofo.js
    - 'x-robots-tag: noindex'
    slug: tds-redirection-js
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: ClickFix Social Engineering
    observables:
    - navigator.clipboard.writeText
    - booksbypatriciaschultz.com/liner.php
    - Verify you are human
    slug: clickfix-social-engineering
    tactic: collection
    techniques:
    - T1115
  - name: PowerShell Stager Execution
    observables:
    - powershell -w hidden -nop -c
    - scottvmorton.com/tytuy.json
    - 8db6.ps1
    slug: powershell-stager-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT Persistence and Installation
    observables:
    - client32.exe
    - ProgramData\S1kCMNfZi3\
    - Software\Microsoft\Windows\CurrentVersion\Run
    slug: persistence-and-payload-delivery
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT C2 Communication
    observables:
    - pusykakimao.com:443
    - fnotusykakimao.com:443
    - fakeurl.htm
    slug: c2-communication-netsupport
    tactic: exfiltration
    techniques:
    - T1041
  summary: The iClickFix campaign leverages compromised WordPress websites to inject
    a malicious JavaScript framework that delivers the ClickFix social engineering
    lure. Victims are induced to run a PowerShell command that executes a downloader
    script, ultimately installing the NetSupport RAT with persistence via the Windows
    registry.
series:
  index: 1
  slug: iclickfix-wordpress-targeting-framework-using-clickfix
  title: 'iClickFix: WordPress-targeting framework using ClickFix'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# iClickFix: Web-based Redirection and ClickFix Lure Delivery

This hunt targets the initial stages of the iClickFix infection chain: the compromise of WordPress infrastructure and the subsequent traffic distribution used to deliver malicious lures. It starts by identifying known WordPress instances in the estate, then correlates DNS and HTTP telemetry to identify redirection patterns (e.g., /gigi, /ofofo.js) and fingerprint exfiltration common to the iClickFix framework. The hunt identifies successful lure delivery by tracking referrers from internal sites to known-malicious redirection domains.

## identify-wordpress-servers
<!-- Identify WordPress infrastructure -->
Find our own WordPress servers that may be serving as watering holes for iClickFix.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running WordPress. These should be reviewed and used
  to populate the scope_hosts parameter for subsequent steps.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%wordpress%'
```

## dns-to-redirection-infra
<!-- DNS queries to redirection infrastructure -->
Identify any host (server or client) resolving domains associated with the iClickFix framework.

```sqlite target=endpoint role=detection-candidate params=(malicious_domains=malicious_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts communicating with known-malicious domains. If scoped to WordPress
  servers, this identifies C2 or prefetch activity from the watering hole; if unscoped,
  it identifies potential victims.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{malicious_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## corroborate-web-activity
<!-- Corroborate with HTTP patterns -->
parallel:
- → http-tds-uri-patterns
- → rare-fingerprint-exfiltration
join: → triage-activity

## http-tds-uri-patterns
<!-- HTTP TDS URI patterns -->
Find traffic matching the specific YOURLS redirection and script delivery paths named in the report.

```sqlite target=web role=enrichment params=(redirection_paths=redirection_paths, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to /gigi, /ofofo.js, or /liner.php. The referrer may identify
  the compromised source.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- referrer
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, referrer, time FROM hb_http_activity WHERE instr(',' || '{{redirection_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-fingerprint-exfiltration
<!-- Prevalence of fingerprint exfiltration -->
Stack-count hostnames receiving JSON-like fingerprint data in query parameters, which iClickFix uses to filter visitors.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare hostnames receiving JSON exfiltration via PHP query parameters. This
  identifies rotated or novel TDS/lure infrastructure.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- url_hostname
- url_query
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS events, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_query) LIKE '%data=%host%' AND LOWER(url_query) LIKE '%now=%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-activity
<!-- Triage the redirection chain -->
```agent target=hunter
cite: required
context:
- identify-wordpress-servers
- dns-to-redirection-infra
- http-tds-uri-patterns
- rare-fingerprint-exfiltration
max_iterations: 3
objective: Determine if a host successfully navigated from a (potentially compromised)
  WordPress site through the TDS infrastructure to the ClickFix lure stage.
success_criteria: A verdict citing specific hostnames, malicious domains, and TDS
  paths identified in the HTTP/DNS logs.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host reaching the liner.php or final lure stage" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: https-decryption-blind-spot)
else: → manual-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and investigate the user's browser history and clipboard for traces of the ClickFix command.
```
→ manual-review

## manual-review
<!-- Manual review -->
```manual target=analyst
Examine the HTTP sessions flagged. If iClickFix redirection is confirmed, proceed to the follow-on hunt for PowerShell stagers and NetSupport RAT.
```
→ end
