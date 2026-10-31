---
analysis: A simple rule for 'password' in a URL generates many false positives. This
  hunt combines encoded parameter patterns with developer-host scoping and a stack-count
  on DNS destinations to isolate the rare exfiltration signal from normal web development
  traffic.
blind_spots:
- id: no-http-decryption
  question: whether credentials were sent in the request body of a POST request
  requires: hb_http_activity with decrypted payloads or endpoint browser instrumentation
  risk: The hunt only sees parameters in the URL; exfiltration hidden in an encrypted
    POST body remains invisible.
  stage: exfiltration-over-c2
- id: ephemeral-domains
  question: whether a previously unknown domain is a phishing proxy
  requires: real-time threat intelligence feed for newly registered domains
  risk: Static indicator lists will miss phishing infrastructure that rotates daily.
  stage: initial-access-phishing-delivery
coverage:
- stage: initial-access-phishing-delivery
  status: covered
  steps:
  - detect-rare-dns
- stage: exfiltration-over-c2
  status: covered
  steps:
  - detect-encoded-http
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: execution-npm-install-scripts
  status: out_of_scope
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: defense-evasion-script-obfuscation
  status: out_of_scope
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: persistence-browser-extensions
  status: out_of_scope
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: collection-credential-and-cookie-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Phishing kits use obfuscation to bypass static email and web filters.
    Detecting successful exfiltration via behavioral patterns like high-entropy URL
    parameters on developer assets is critical for containing active intrusions.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed an obfuscated phishing kit on an asset with
  developer tools like npm, using encoded HTTP query parameters to exfiltrate stolen
  credentials and session cookies to rare or known-malicious domains.
labels:
- hunt
- attack.t1566
- attack.t1041
- attack.t1115
- attack.t1176
- collection
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: Obfuscated Phishing and Exfiltration in Node Environments
parameters:
  lookback_days:
    default: '14'
    description: Days of telemetry history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: standard-retention
    type: number
  phishing_domains:
    default:
    - example.com
    - phish-kit.live
    - auth-verify.net
    description: Known phishing or exfiltration domains from threat intelligence.
    from:
      kind: article
      observed: '2026-08-27'
      ref: https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/
    type: list[domain]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to query all hosts
      with npm installed.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt first identifies hosts with npm installed. Narrowing to these
  developer-focused assets reduces noise from general web browsing and focuses on
  a high-risk group where obfuscated scripts are frequently observed during installation
  or development.
references:
- name: 'JavaScript obfuscation: From party trick to phishing kit'
  url: https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/
related:
- hunt: npm-malicious-install-scripts
  reason: This hunt focuses on the network exfiltration of phishing kits; malicious
    install scripts are a separate stage involving process and file telemetry.
  relation: out-of-scope-alternative
- hunt: obfuscated-js-and-local-collection
  relation: follows
scenario:
  stages:
  - name: Phishing Kit and Social Engineering Delivery
    observables:
    - phishing kit
    - fake CAPTCHA
    - fake update flows
    - compromised website injections
    slug: initial-access-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Malicious Package Installation
    observables:
    - npm package install scripts
    - npm tokens
    slug: execution-npm-install-scripts
    tactic: execution
    techniques:
    - T1566
  - name: JavaScript Obfuscation and Anti-Analysis
    observables:
    - eval()
    - atob()
    - String.fromCharCode()
    - atob('ZXZhbA==')
    - JSFuck
    - navigator.webdriver
    - control-flow flattening
    - _0x identifiers
    slug: defense-evasion-script-obfuscation
    tactic: defense-evasion
    techniques:
    - T1176
  - name: Browser Extension Abuse
    observables:
    - browser extension abuse
    - malicious software extensions
    slug: persistence-browser-extensions
    tactic: persistence
    techniques:
    - T1176
  - name: Credential and Browser Data Collection
    observables:
    - window.document.cookie
    - clipboard contents
    - clip.exe
    - pbpaste
    slug: collection-credential-and-cookie-theft
    tactic: collection
    techniques:
    - T1115
  - name: Exfiltration via Web Request
    observables:
    - https://example.com
    - fetch
    - ?password=
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Threat actors employ sophisticated JavaScript obfuscation techniques, including
    packing, encoding, and JSFuck, to conceal malicious payloads in phishing kits,
    malware loaders, and npm packages. These scripts often include anti-analysis features
    like browser fingerprinting and control-flow flattening to evade detection while
    exfiltrating credentials and cookies from victim systems.
series:
  index: 2
  slug: javascript-obfuscation-from-party-trick-to-phishing-kit
  title: 'JavaScript obfuscation: From party trick to phishing kit'
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


# Obfuscated Phishing and Exfiltration in Node Environments

This hunt targets the delivery and exfiltration stages of a phishing attack. It specifically scopes to hosts running the npm package manager, where malicious install scripts or dev-tooling compromises are more likely. The hunt searches for application-layer indicators of exfiltration, such as high-entropy query strings or Base64 padding in URLs, and corroborates these with rare DNS resolutions to known phishing infrastructure. An agent evaluates the combined evidence to distinguish benign dev traffic from active credential theft.

## scope-npm-hosts
<!-- Find hosts with npm installed -->
Identify the subset of the estate with development tools installed, as these are the primary targets for this scenario.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that have npm installed. No rows means no npm installations
  are visible in software inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'npm' OR LOWER(package_type) = 'npm')
```

## parallel-corroboration
<!-- Corroborate HTTP and DNS telemetry -->
parallel:
- → detect-encoded-http
- → detect-rare-dns
join: → triage-agent

## detect-encoded-http
<!-- HTTP exfiltration via encoded parameters -->
Identify HTTP requests containing high-entropy or Base64-encoded query parameters typical of exfiltration scripts on developer assets.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Requests showing sensitive or encoded data in the URL. Benign hits include
  development testing; exfiltration typically hits rare or non-corporate domains.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (LENGTH(url_query) > 60 OR url_query LIKE '%==%' OR url_query LIKE '%d=%' OR url_query LIKE '%p=%' OR url_query LIKE '%token%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## detect-rare-dns
<!-- DNS lookups for rare or known phishing infrastructure -->
Identify resolutions for known malicious domains or rare domains resolved by only a few hosts within the scoped developer population.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS resolutions of intelligence-listed domains or rare domains. Rare domains
  on developer assets may indicate new phishing proxies.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY query_hostname HAVING host_count <= 2
```

## triage-agent
<!-- Evaluate delivery and exfiltration evidence -->
```agent target=hunter
cite: required
context:
- scope-npm-hosts
- detect-encoded-http
- detect-rare-dns
max_iterations: 4
objective: Determine if the observed high-entropy HTTP parameters and rare DNS lookups
  indicate a successful phishing attack and data exfiltration from hosts with npm
  installed.
success_criteria: A per-host verdict citing specific HTTP requests and DNS resolutions.
tools:
- endpoint
- web
```

## route-decision
<!-- Route based on verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-decryption)
else: → close-out

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate a credential reset for the users identified in the HTTP logs.
```
→ analyst-review

## analyst-review
<!-- Analyst manual review -->
```manual target=analyst
Review the full URL patterns and DNS results. Check if the destination domains have been recently registered or are associated with known phishing kits. Attempt to decode Base64 parameters to confirm credential theft.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the exfiltration domains and user accounts involved. Provide tuning suggestions for the detection candidate if necessary.
```
→ end
