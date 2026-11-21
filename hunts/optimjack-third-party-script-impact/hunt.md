---
analysis: This is a hunt because it correlates legitimate activity (CDN usage) with
  rare malicious follow-on activity across multiple surfaces. A single rule on Optimizely
  CDN traffic would be far too noisy to be actionable; an analyst must weigh the presence
  of exploit-kit markers against the CDN interaction to reach a verdict.
blind_spots:
- id: limited-proxy-visibility
  question: Are the full URL paths for exploit kit requests visible?
  requires: SSL/TLS decryption on the proxy gateway
  risk: If the proxy only sees the destination IP/hostname due to encryption, specific
    exploit kit URI patterns will be missed, leading to false negatives.
  stage: mobile-exploit-kit-delivery
- id: unmanaged-mobile-exposure
  question: Did the exploit kit successfully execute on personal mobile devices?
  requires: Mobile Device Management (MDM) telemetry
  risk: The attack targets iOS and iPad devices. If these are not managed or do not
    route traffic through corporate inspection, the actual exploitation stage remains
    invisible.
  stage: mobile-exploit-kit-delivery
coverage:
- stage: malicious-script-distribution
  status: covered
  steps:
  - optimizely-cdn-interaction
- stage: mobile-exploit-kit-delivery
  status: covered
  steps:
  - exploit-kit-http-traffic
  - exploit-kit-dns-resolutions
- reason: Exploitation of the vendor's internal platform is only visible in the vendor's
    own logs, not on the customer estate.
  stage: vendor-platform-exploitation
  status: out_of_scope
- reason: Wallet swapping and card skimming occur within the user's browser memory
    and are not typically captured in proxy or endpoint process logs unless exfiltration
    occurs to a known domain.
  stage: client-side-financial-collection
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: A negative result across the estate provides assurance that the OPTIMJACK
    campaign did not lead to mobile exploit execution or financial data theft within
    the enterprise, despite the use of trusted CDN infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a trusted third-party vendor to distribute
  malicious JavaScript via their CDN, leading to mobile exploit delivery and credential
  skimming on internal corporate assets.
labels:
- hunt
- attack.t1195.002
- attack.t1190
- attack.t1203
- collection
- execution
- initial access
name: OPTIMJACK Third-Party Script Supply Chain Impact
parameters:
  cdn_domains:
    default:
    - cdn.optimizely.com
    - optimizely.com
    - logx.optimizely.com
    description: Legitimate vendor CDN domains that served the malicious script.
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: Standard lookback for recent supply chain compromise
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts if needed; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on administrative and developer workstations first, as these
  roles often browse technical documentation or platforms that integrate Optimizely
  tags. Widen the scope to all hosts with external browsing capability if the lead
  query returns broad results.
references:
- name: "Unit 42 \u2014 OPTIMJACK Supply Chain Attack"
  url: https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
related:
- hunt: client-side-js-skimming-behavior
  reason: Detecting the actual theft of card data or wallet swapping requires DOM-level
    monitoring or specialized client-side telemetry not available in these surfaces.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Vendor Platform Exploitation
    observables:
    - Optimizely Web Experimentation platform vulnerability
    - Project JavaScript field modification
    - Nov 16, 2026
    slug: vendor-platform-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1195
  - name: Malicious Script Distribution
    observables:
    - Optimizely CDN
    - Legitimate vendor security certificate
    - Malicious JavaScript snippets
    - optimizely.com
    slug: malicious-script-distribution
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Client-Side Financial Collection
    observables:
    - Cryptocurrency wallet address swapping
    - Payment card skimming
    - Checkout form data collection
    slug: client-side-financial-collection
    tactic: collection
    techniques:
    - T1539
    - T1557
  - name: Mobile Exploit Kit Delivery
    observables:
    - Coruna exploit kit
    - DarkSword exploit kit
    - iOS devices
    - iPad devices
    slug: mobile-exploit-kit-delivery
    tactic: execution
    techniques:
    - T1203
  summary: The OPTIMJACK campaign involved the compromise of Optimizely's Web Experimentation
    platform to inject malicious JavaScript into the websites of at least 178 organizations.
    The tampered code, delivered via the vendor's legitimate CDN, was used to skim
    payment card data, swap cryptocurrency wallet addresses, and deliver mobile exploit
    kits to iOS users.
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


# OPTIMJACK Third-Party Script Supply Chain Impact

This hunt identifies hosts that interacted with the compromised Optimizely CDN infrastructure and subsequently engaged with known mobile exploit kit infrastructure (Coruna or DarkSword). By correlating trusted CDN traffic with rare exploit-delivery signatures across HTTP and DNS telemetry, the hunt uncovers potential data exposure even when delivered from a legitimate, certificate-validated source.

## optimizely-cdn-interaction
<!-- Interactions with Optimizely CDN -->
Identify hosts that interacted with the Optimizely CDN during the vulnerability window to establish a candidate pool for script execution.

```sqlite target=web role=scoping params=(cdn_domains=cdn_domains, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating which hosts visited the affected infrastructure. Silence
  means no recorded interaction with the CDN during the window.
reads:
- device_hostname
- src_endpoint_ip
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, url_path, user_agent, MIN(time) AS first_access, MAX(time) AS last_access FROM hb_http_activity WHERE instr(',' || '{{cdn_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, url_hostname, url_path, user_agent
```

## exploit-kit-activity-check
<!-- Check for Exploit Kit Activity -->
parallel:
- → exploit-kit-http-traffic
- → exploit-kit-dns-resolutions
join: → agent-triage

## exploit-kit-http-traffic
<!-- Exploit Kit HTTP Traffic -->
Find HTTP requests containing keywords associated with the Coruna and DarkSword exploit kits.

```sqlite target=web role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Presence of exploit kit names in URL paths or hostnames. Silence indicates
  no clear HTTP markers for these kits were detected.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, user_agent, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(LOWER(url_full), 'coruna') > 0 OR instr(LOWER(url_full), 'darksword') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exploit-kit-dns-resolutions
<!-- Exploit Kit DNS Resolutions -->
Search DNS history for infrastructure associated with the Coruna and DarkSword kits that may not have full HTTP URL logging.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions for domains including exploit kit keywords. Silence suggests
  no resolution of those kit-specific domains occurred.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS count, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(LOWER(query_hostname), 'coruna') > 0 OR instr(LOWER(query_hostname), 'darksword') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## agent-triage
<!-- Weigh CDN and Exploit Evidence -->
```agent target=hunter
cite: required
context:
- optimizely-cdn-interaction
- exploit-kit-http-traffic
- exploit-kit-dns-resolutions
max_iterations: 4
objective: Determine if any host visiting the Optimizely CDN also shows signs of exploit
  kit delivery (Coruna/DarkSword) based on the HTTP and DNS telemetry.
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the sequence of events.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the agent-triage identifies at least one host with confirmed exploit kit traffic following a CDN interaction" (confidence: high, judge=hunter)
then: → isolate-impacted-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: limited-proxy-visibility)
else: → close-out-hunt

## isolate-impacted-host
<!-- Isolate Impacted Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to prevent further exploitation and preserve the state for forensic imaging.
```
→ analyst-investigation

## analyst-investigation
<!-- Detailed Analyst Investigation -->
```manual target=analyst
Examine the host's browser logs for interaction with 'cdn.optimizely.com' and any subsequent redirects or requests to Coruna/DarkSword infrastructure. Check for signs of payment card data theft or mobile exploit downloads.
```
→ close-out-hunt

## close-out-hunt
<!-- Close Out Hunt -->
```manual target=analyst
Document the scope of the investigation, the hosts identified as interacting with the malicious CDN, and whether any compromise was verified. Review segmentation policies for third-party scripts.
```
→ end
