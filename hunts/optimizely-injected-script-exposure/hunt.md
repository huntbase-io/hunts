---
analysis: A blocklist rule would flag 1688360.cc and stop. The hunt has to decide,
  per person, whether the script only loaded or also took card data, cookies or an
  iPhone exploit attempt, then follow cookies into sign-ins and cards and phones into
  manual checks, and look for a host the published list misses. That needs judgement
  across proxy, DNS, connection and sign-in data.
blind_spots:
- id: no-url-path-visibility
  question: Did the browser fetch /track.js or POST to /card.php and /hit.php, or
    only connect to the host?
  requires: TLS inspection on the forward proxy (or a secure web gateway that logs
    full URLs and methods)
  risk: Without decryption the proxy logs the host but not the path or method, so
    card and cookie theft cannot be told apart from a script load and every visitor
    must be treated as possibly skimmed.
  stage: card-skimming
- id: unmanaged-mobile-devices
  question: Which iPhones and iPads visited an affected site, on what iOS version,
    and off the corporate network?
  requires: MDM inventory with iOS versions and mobile threat defence on corporate
    and BYOD iPhones and iPads
  risk: Phones on cellular data or home Wi-Fi never touch the proxy or DNS logs, and
    the exploit kits targeted exactly those devices.
  stage: ios-exploit-delivery
- id: browser-dns-over-https
  question: Did browsers resolve 1688360.cc through a built-in DoH resolver?
  requires: DNS-over-HTTPS disabled by browser policy, or DoH resolver traffic logged
  risk: Lookups made over DoH do not reach hb_dns_activity, so the scoping step under-counts
    exposed hosts.
  stage: visitor-exposure
- id: proxy-and-dns-retention
  question: Do the logs still cover 9 to 17 Nov 2026?
  requires: At least 30 days of proxy and DNS log retention, reaching back to 9 Nov
    2026
  risk: Short retention removes the exposure window entirely and silence then means
    nothing.
- id: inline-fallback-variant
  question: Did a browser run the inline copy of the payload that needs no track.js
    fetch?
  requires: Client-side script monitoring or CSP reporting on the visited sites
  risk: One loader variant ran an embedded copy of the payload with eval when track.js
    could not load, so no script fetch is logged; only its later POSTs to the payload
    host can show, and a network block on that host stops those too. (The atob() variant
    still fetches track.js; it only defeats string searches of the snippet.)
  stage: visitor-exposure
- id: session-replay-not-in-signin-logs
  question: Was a cookie sent to /hit.php replayed against the app it came from?
  requires: Audit logs of the affected SaaS apps (session and IP history) and the
    HttpOnly flags of their session cookies
  risk: Replaying a cookie does not create an identity-provider sign-in, so hb_auth_signin
    can be silent while a session is abused. HttpOnly cookies were not readable by
    the script, so the real risk depends on each site's cookie flags.
  stage: session-theft
- id: optimizely-change-history
  question: Was the organisation's own Optimizely project changed on 16 Nov 2026?
  requires: Optimizely project change history, API token list and CSP violation reports
    for the organisation's own sites
  risk: None of this is in hb_ telemetry; if the organisation's snippet carried the
    payload, its customers were the victims and only the manual review finds it.
  stage: project-tampering
- id: in-page-address-swap
  question: Did anyone send cryptocurrency to a swapped address?
  requires: Transfer records from exchanges and wallets used by the organisation
  risk: The swap happens in the page and clipboard; only /hit.php shows it fired,
    and only with TLS inspection.
  stage: crypto-address-swapping
coverage:
- blind_spot: optimizely-change-history
  reason: The change was made inside Optimizely; only the project change history,
    token list and CSP reports show it, so the site-owner check is a manual step.
  stage: project-tampering
  status: not_visible
  steps:
  - site-owner-review
- stage: visitor-exposure
  status: covered
  steps:
  - resolve-attacker-hosts
  - requests-to-attacker-hosts
  - connections-to-attacker-ips
  - new-script-hosts-after-optimizely
  - new-domains-on-exposed-hosts
- stage: card-skimming
  status: covered
  steps:
  - data-sent-to-attacker-hosts
  - exposed-user-follow-up
- stage: session-theft
  status: covered
  steps:
  - data-sent-to-attacker-hosts
  - sign-ins-from-new-sources
  - assess-session-reuse
- stage: ios-exploit-delivery
  status: covered
  steps:
  - apple-mobile-requests
  - exposed-user-follow-up
- reason: The swap itself is invisible; a /hit.php POST shows it fired on a page,
    and the transfer check against the wallet list is manual.
  stage: crypto-address-swapping
  status: covered
  steps:
  - data-sent-to-attacker-hosts
  - wallet-transfer-check
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: A domain block stops nothing that already ran and did not stop the
    inline variant. Visitors who typed a card or were signed in on an affected page
    need follow-up whether or not the domain is now dead, and an Optimizely customer
    must check its own project.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Staff browsers that visited a site carrying the tampered Optimizely snippet
  on 16 Nov 2026 loaded the attacker's script, and some sent card details, readable
  cookies or iPhone traffic to the attacker; separately, the organisation's own Optimizely
  project may have served the script to its customers.
labels:
- hunt
- attack.t1195.002
- attack.t1189
- attack.t1059.007
- attack.t1056.003
- attack.t1041
- attack.t1539
- attack.t1113
- attack.t1550.004
- attack.t1203
- attack.t1565.002
- collection
- credential access
- execution
- impact
- initial access
name: 'Optimizely Injected Script: Visitor, Session and Site-Owner Exposure'
parameters:
  attacker_ips:
    default:
    - 136.113.106.136
    - 34.96.213.201
    - 34.87.36.58
    description: 'Last known addresses of 1688360.cc and the .icu iOS hosts (Google
      Cloud). Shared cloud ranges: treat a match as a lead, not a verdict.'
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
    type: list[ip]
  exfil_paths:
    default:
    - /card.php
    - /hit.php
    description: 'Paths on the payload host that received stolen data: /card.php (card
      number, expiry, CVV via sendBeacon) and /hit.php (page URL, readable cookies,
      screenshot).'
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    type: list[path]
  exposure_end:
    default: '2026-11-17T06:00:00Z'
    description: End of the exposure window (UTC). All files were clean by 23:11 UTC
      on 16 Nov and 1688360.cc was suspended at 00:37 UTC on 17 Nov; the extra hours
      allow for cached snippets and open tabs (an assumption, not a published time).
    type: string
  exposure_start:
    default: '2026-11-16T04:00:00Z'
    description: Start of the exposure window (UTC). The first Optimizely injection
      was seen at 04:21 UTC on 16 Nov 2026; researchers advise searching from 04:00.
    type: string
  ios_stage_domains:
    default:
    - 5vobauua3ojpklx.icu
    - eil786npto9u5bq.icu
    - l7bcsnwc7nzr3uo.icu
    - je4ft3gn8vxudum.icu
    - q1ls1ho9x7wsxlu.icu
    - ios-hack.icu
    - p55abnw2pnsz0bo.icu
    - 1y69gy2mdzaltz1.icu
    - gm38duxoihbmy5o.icu
    description: Hosts that track.js used on iPhone and iPad to load boot.js and the
      exploit kits, plus fallback C2s and hosts sharing their certificates and IPs.
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    type: list[domain]
  lookback_days:
    default: '30'
    description: Days of history to read. It must reach back to 9 Nov 2026, when the
      first .icu hosts were registered, and give the baseline steps clean history
      before exposure_start. Increase it if you run the hunt after 9 Dec 2026.
    type: number
  optimizely_domains:
    default:
    - cdn.optimizely.com
    description: Hosts that serve Optimizely Web Experimentation snippets. Add a first-party
      snippet host (such as opt.<site>) if your proxy sees one.
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    type: list[domain]
  payload_domains:
    default:
    - 1688360.cc
    - webshell.lol
    description: Hosts the injected Optimizely code loaded from and sent data to.
      1688360.cc served /track.js and received /card.php and /hit.php; webshell.lol
      (/get.js) was the injector in the first Optimizely injection at 04:21 UTC on
      16 Nov 2026.
    from:
      kind: article
      observed: '2026-11-16'
      ref: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    type: list[domain]
  pivot_minutes:
    default: '5'
    description: How soon after an Optimizely snippet fetch a request to a new host
      counts as following it.
    type: number
  scope_hosts:
    default: []
    description: Hosts that resolved or connected to the attacker hosts, pasted from
      the scoping step. Empty means every host.
    type: list[host]
  scope_users:
    default: []
    description: Users named by the exposure triage (proxy actor_user_name or the
      owner of an exposed host). Empty means every user, which is noisy.
    type: list[user]
provenance:
  authors:
  - name: Huntbase
    org: huntbase.io
  generated:
    by: hand-authored-with-claude
    from: https://www.bleepingcomputer.com/news/security/optimizely-supply-chain-attack-delivers-malware-to-cnn-fox-news-bbc-salesforce-sites/
    gates:
    - dry-run
    - lint
    model: claude-opus-5-5
rationale: Run it for the window 04:00 UTC 16 Nov to 06:00 UTC 17 Nov 2026 and check
  first that proxy and DNS logs still cover it. Start with the scoping step and paste
  its hosts into scope_hosts, then paste the users the first triage names into scope_users
  before the sign-in step. Finance, purchasing and anyone who uses crypto or pays
  by card on the listed sites come first.
references:
- name: 'BleepingComputer: Optimizely hack infected CNN, Fox News, BBC, Salesforce sites with malware'
  url: https://www.bleepingcomputer.com/news/security/optimizely-supply-chain-attack-delivers-malware-to-cnn-fox-news-bbc-salesforce-sites/
- name: 'Scott Helme (Report URI): World''s largest brands infected with malware via
    Optimizely'
  url: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
- name: 'StepSecurity: OPTIMJACK, Optimizely-hosted scripts with crypto clipper and
    card skimmer'
  url: https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
- name: 'Optimizely status: Web Experimentation security incident'
  url: https://status.optimizely.com/incidents/ftw0fh9wx43z
related:
- hunt: optimjack-third-party-script-impact
  reason: The Unit 42 generated hunt for the same incident scopes Optimizely CDN traffic;
    this one adds the attacker hosts, the exfiltration paths, session reuse and the
    site-owner and wallet checks.
  relation: sibling
scenario:
  stages:
  - name: Optimizely project tampering
    observables:
    - Project JavaScript field changed on 16 Nov 2026
    - loader for https://1688360.cc/track.js, plain or atob()-encoded
    - inline payload run with eval when the host is blocked
    slug: project-tampering
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Visitor browsers load the payload
    observables:
    - 1688360.cc/track.js fetched with an affected site as referrer
    - webshell.lol/get.js
    - cdn.optimizely.com snippet fetched just before
    slug: visitor-exposure
    tactic: initial-access
    techniques:
    - T1189
    - T1059.007
  - name: Card skimming
    observables:
    - sendBeacon POST to 1688360.cc/card.php with fields n, e, c, u
    slug: card-skimming
    tactic: collection
    techniques:
    - T1056.003
    - T1041
  - name: Cookie and screenshot theft
    observables:
    - POST to 1688360.cc/hit.php with page URL, document.cookie and screenshot
    - html2canvas.min.js loaded from 1688360.cc
    - sign-in or session use from a new address after exposure
    slug: session-theft
    tactic: credential-access
    techniques:
    - T1539
    - T1113
    - T1550.004
  - name: iOS exploit kit delivery
    observables:
    - boot.js from .icu hosts on iPhone and iPad user agents
    - hidden iframe /JIUJIU888/weifile.html on iOS 18.6 or earlier
    - kit paths /A8/, /B9/, /D11/, /D12/, /C10/
    slug: ios-exploit-delivery
    tactic: execution
    techniques:
    - T1203
  - name: Crypto address swapping
    observables:
    - wallet addresses on the page or clipboard replaced with attacker wallets
    slug: crypto-address-swapping
    tactic: impact
    techniques:
    - T1565.002
  summary: On 16 Nov 2026 an attacker added JavaScript to the Project JavaScript of
    Optimizely Web Experimentation projects belonging to 178 organisations, so major
    sites served it from Optimizely's own CDN. The code loaded track.js from 1688360.cc,
    which swapped cryptocurrency addresses, skimmed card details to /card.php, sent
    readable cookies and screenshots to /hit.php, and loaded iOS exploit kits on iPhones
    and iPads. Most files were clean by 21:52 UTC and all by 23:11 UTC.
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


# Optimizely Injected Script: Visitor, Session and Site-Owner Exposure

On 16 Nov 2026 malicious JavaScript was added to Optimizely Web Experimentation projects of 178 organisations, so sites such as BBC, CNN, Zoom, GitLab and Salesforce served it to their visitors from Optimizely's own CDN for most of a day. This hunt answers three questions. Which of our people loaded it, and what did it take from them: card details, cookies, or an iPhone exploit attempt? Was any stolen session reused? And, if we run Optimizely ourselves, did our own site serve it? It starts from DNS, proxy and connection logs for the published hosts, adds two behaviour steps that look for new cross-site script hosts so a rotated host is not missed, checks sign-ins for the exposed users, and ends with manual checks for cards, iPhones, our own Optimizely projects and crypto transfers.

## resolve-attacker-hosts
<!-- Hosts that resolved the attacker domains -->
Find managed devices that looked up the payload host or the iOS stage hosts. DNS sees the lookup even when the proxy cannot see the URL, so this is the widest list of browsers that ran the injected code.

```sqlite target=endpoint role=scoping params=(payload_domains=payload_domains, ios_stage_domains=ios_stage_domains, lookback_days=lookback_days)
~~~yaml
expected: 'Devices and users whose browser looked up 1688360.cc, webshell.lol or an
  iOS stage host, with first and last lookup. Paste the hosts into scope_hosts. Silence
  does not clear the estate: browsers using DNS-over-HTTPS bypass these logs.'
reads:
- actor_user_name
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, actor_user_name, process_name, LOWER(query_hostname) AS domain, COUNT(*) AS lookups, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE (instr(',' || '{{payload_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{ios_stage_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, process_name, LOWER(query_hostname) ORDER BY first_seen
```

## exposure-evidence
<!-- Gather exposure evidence -->
parallel:
- → requests-to-attacker-hosts
- → data-sent-to-attacker-hosts
- → apple-mobile-requests
- → connections-to-attacker-ips
- → new-script-hosts-after-optimizely
- → new-domains-on-exposed-hosts
join: → weigh-exposure

## requests-to-attacker-hosts
<!-- Proxy requests to the attacker hosts -->
List every proxied request to the payload host, with the referring page. The referrer names the site the user was on when the injected snippet ran, and the user agent shows the browser and device.

```sqlite target=web role=triage params=(payload_domains=payload_domains, lookback_days=lookback_days)
~~~yaml
expected: GET /track.js (or /get.js on webshell.lol) with a referrer on a site that
  used Optimizely, from a named user or client IP. Here device_hostname is the proxy,
  so identify the person by actor_user_name or src_endpoint_ip. Without TLS inspection
  only the host is logged, not the path.
reads:
- actor_user_name
- http_method
- referrer
- src_endpoint_ip
- status_code
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT src_endpoint_ip, actor_user_name, LOWER(url_hostname) AS host, url_path, http_method, referrer, user_agent, status_code, COUNT(*) AS requests, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE instr(',' || '{{payload_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, LOWER(url_hostname), url_path, http_method, referrer, user_agent, status_code ORDER BY first_seen
```

## data-sent-to-attacker-hosts
<!-- Card and cookie data sent to the payload host -->
Find requests that carried stolen data out: /card.php receives card number, expiry and CVV after a card form is submitted; /hit.php receives the page URL, readable cookies and a screenshot after a wallet address is swapped. Any POST to the payload host is included, because the inline fallback variant sends data without first fetching track.js.

```sqlite target=web role=triage params=(payload_domains=payload_domains, exfil_paths=exfil_paths, lookback_days=lookback_days)
~~~yaml
expected: A POST to /card.php means that user submitted a card on an affected page;
  a POST to /hit.php means the clipper fired on a wallet or payment page and sent
  the page's readable cookies. The referrer is the affected page. Needs TLS inspection
  to see the path and method.
reads:
- activity_id
- actor_user_name
- http_method
- referrer
- request_body_len
- src_endpoint_ip
- status_code
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT src_endpoint_ip, actor_user_name, LOWER(url_hostname) AS host, url_path, http_method, referrer, user_agent, request_body_len, status_code, time FROM hb_http_activity WHERE instr(',' || '{{payload_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND (instr(',' || '{{exfil_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR UPPER(http_method) = 'POST' OR activity_id = 6) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time
```

## apple-mobile-requests
<!-- iPhone and iPad traffic to the exploit hosts -->
Find iPhones and iPads that reached the iOS stage hosts, or that loaded the payload. track.js only loaded the exploit chain for iPhone and iPad user agents.

```sqlite target=web role=triage params=(payload_domains=payload_domains, ios_stage_domains=ios_stage_domains, lookback_days=lookback_days)
~~~yaml
expected: boot.js from a .icu host, or requests under /A8/, /B9/, /D11/, /D12/, /C10/
  or /JIUJIU888/, from a corporate-Wi-Fi or VPN iPhone or iPad. The iOS version in
  the user agent decides the follow-up. iPadOS Safari often sends a desktop Mac user
  agent, so a .icu hit from a 'Mac' still counts.
reads:
- actor_user_name
- referrer
- src_endpoint_ip
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT src_endpoint_ip, actor_user_name, LOWER(url_hostname) AS host, url_path, referrer, user_agent, COUNT(*) AS requests, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE (instr(',' || '{{ios_stage_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR (instr(',' || '{{payload_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND (LOWER(user_agent) LIKE '%iphone%' OR LOWER(user_agent) LIKE '%ipad%' OR LOWER(user_agent) LIKE '%ipod%'))) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, LOWER(url_hostname), url_path, referrer, user_agent ORDER BY first_seen
```

## connections-to-attacker-ips
<!-- Connections to the attacker addresses -->
Catch browsers whose lookups never reached the DNS logs (DNS-over-HTTPS) and whose traffic did not pass the proxy, by the last known IP addresses.

```sqlite target=network role=triage params=(attacker_ips=attacker_ips, lookback_days=lookback_days)
~~~yaml
expected: A browser process connecting to one of the addresses on 443 inside the exposure
  window. These are Google Cloud addresses that can be reassigned, so a match outside
  9 to 17 Nov 2026 is weak on its own.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, user_name, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connections, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE instr(',' || '{{attacker_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name, process_name, dst_endpoint_ip, dst_endpoint_port ORDER BY first_seen
```

## new-script-hosts-after-optimizely
<!-- New cross-site script and .php hosts -->
Behaviour that survives a change of host: during the exposure window, find hosts never seen in the baseline that browsers fetched script or .php paths from while on a different site. Rank them by how many unrelated sites referred to them and by how often the same client fetched an Optimizely snippet just before. One new host referred to by many unrelated sites is the shape of an injected third-party script.

```sqlite target=web role=baseline params=(optimizely_domains=optimizely_domains, exposure_start=exposure_start, exposure_end=exposure_end, pivot_minutes=pivot_minutes, lookback_days=lookback_days)
~~~yaml
expected: 1688360.cc near the top if the proxy saw it. Any other first-seen host with
  many unrelated referring pages, POSTs to .php, and fetches soon after an Optimizely
  snippet is a candidate rotated host. Expect noise from new ad, analytics and CDN
  hosts; the referring-pages count and after_optimizely are what separate them. Snippets
  served from a first-party host or a consent manager do not show as Optimizely fetches.
reads:
- actor_user_name
- http_method
- referrer
- src_endpoint_ip
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT LOWER(h.url_hostname) AS host, COUNT(DISTINCT h.referrer) AS referring_pages, COUNT(DISTINCT h.src_endpoint_ip) AS clients, COUNT(DISTINCT h.actor_user_name) AS users, SUM(CASE WHEN UPPER(h.http_method) = 'POST' THEN 1 ELSE 0 END) AS posts, SUM(CASE WHEN EXISTS (SELECT 1 FROM hb_http_activity o WHERE o.src_endpoint_ip = h.src_endpoint_ip AND instr(',' || '{{optimizely_domains}}' || ',', ',' || LOWER(o.url_hostname) || ',') > 0 AND julianday(o.time) BETWEEN julianday(h.time) - {{pivot_minutes}} / 1440.0 AND julianday(h.time)) THEN 1 ELSE 0 END) AS after_optimizely, MIN(h.time) AS first_seen, MAX(h.time) AS last_seen FROM hb_http_activity h WHERE h.time >= datetime('now', '-{{lookback_days}} days') AND julianday(h.time) BETWEEN julianday('{{exposure_start}}') AND julianday('{{exposure_end}}') AND (LOWER(h.url_path) LIKE '%.js' OR LOWER(h.url_path) LIKE '%.php') AND h.referrer IS NOT NULL AND h.referrer != '' AND instr(LOWER(h.referrer), LOWER(h.url_hostname)) = 0 AND NOT EXISTS (SELECT 1 FROM hb_http_activity b WHERE LOWER(b.url_hostname) = LOWER(h.url_hostname) AND b.time >= datetime('now', '-{{lookback_days}} days') AND julianday(b.time) < julianday('{{exposure_start}}')) GROUP BY LOWER(h.url_hostname) ORDER BY referring_pages DESC, after_optimizely DESC, posts DESC LIMIT 200
```

## new-domains-on-exposed-hosts
<!-- First-seen domains on exposed hosts -->
On the hosts from the scoping step, stack-count the domains first looked up during the exposure window across the fleet. Rare domains looked up only by exposed hosts may be a rotated payload or exfiltration host the published list misses.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, exposure_start=exposure_start, exposure_end=exposure_end, lookback_days=lookback_days)
~~~yaml
expected: Newly seen domains shared by several exposed hosts, especially random-looking
  .cc or .icu names like the published ones. Most rows will be ordinary new domains;
  read it with the referrers from the proxy steps.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT LOWER(d.query_hostname) AS domain, COUNT(DISTINCT d.device_hostname) AS devices, GROUP_CONCAT(DISTINCT d.process_name) AS processes, MIN(d.time) AS first_seen, MAX(d.time) AS last_seen FROM hb_dns_activity d WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || d.device_hostname || ',') > 0) AND d.time >= datetime('now', '-{{lookback_days}} days') AND julianday(d.time) BETWEEN julianday('{{exposure_start}}') AND julianday('{{exposure_end}}') AND NOT EXISTS (SELECT 1 FROM hb_dns_activity b WHERE LOWER(b.query_hostname) = LOWER(d.query_hostname) AND b.time >= datetime('now', '-{{lookback_days}} days') AND julianday(b.time) < julianday('{{exposure_start}}')) GROUP BY LOWER(d.query_hostname) HAVING COUNT(DISTINCT d.device_hostname) < 20 ORDER BY devices DESC LIMIT 200
```

## weigh-exposure
<!-- Weigh exposure per user and device -->
```agent target=hunter
cite: required
context:
- resolve-attacker-hosts
- requests-to-attacker-hosts
- data-sent-to-attacker-hosts
- apple-mobile-requests
- connections-to-attacker-ips
- new-script-hosts-after-optimizely
- new-domains-on-exposed-hosts
max_iterations: 6
objective: 'For each user, client IP or device that appears in the evidence, decide
  which of these happened, citing rows: (a) the browser loaded the injected code (lookup,
  connection or track.js/get.js fetch); (b) card data was sent (/card.php); (c) readable
  cookies and a screenshot were sent after a wallet swap (/hit.php); (d) an iPhone
  or iPad reached an iOS stage host, with the iOS version from the user agent; (e)
  a first-seen host from the behaviour steps looks like a rotated payload or exfil
  host. Name the referring site for each hit and say whether it is one of the organisation''s
  own sites. Produce the user list for scope_users.'
success_criteria: A table of users and devices with exposure level (loaded, card sent,
  cookies sent, iOS reached, none), the referring site, first-seen time and cited
  rows, plus any candidate new host with the reason.
tools:
- endpoint
- identity
- network
- web
```

## sign-ins-from-new-sources
<!-- Sign-ins from new addresses after exposure -->
For the exposed users, find successful sign-ins from source addresses the user had not used before the exposure window. Stolen cookies are replayed rather than signed in with, so this catches only the cases where the cookie led to a new sign-in or token refresh the identity provider logged.

```sqlite target=identity role=enrichment params=(scope_users=scope_users, exposure_start=exposure_start, lookback_days=lookback_days)
~~~yaml
expected: 'A successful sign-in for an exposed user from a new address or country
  after the exposure, especially to Salesforce, GitLab, Zoom, Smartsheet or Bitly,
  whose public pages carried the snippet. Silence is weak: cookie replay into the
  SaaS app itself appears in that app''s audit log, not here.'
reads:
- actor_user_name
- app_id
- client_app
- dst_endpoint_name
- provider
- src_endpoint_ip
- src_location_country
- status_id
- time
- user_agent
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT s.actor_user_name, s.provider, s.app_id, s.dst_endpoint_name, s.client_app, s.src_endpoint_ip, s.src_location_country, s.user_agent, COUNT(*) AS sign_ins, MIN(s.time) AS first_seen, MAX(s.time) AS last_seen FROM hb_auth_signin s WHERE s.time >= datetime('now', '-{{lookback_days}} days') AND julianday(s.time) >= julianday('{{exposure_start}}') AND s.status_id = 1 AND s.src_endpoint_ip IS NOT NULL AND ('{{scope_users}}' = '' OR instr(',' || LOWER('{{scope_users}}') || ',', ',' || LOWER(s.actor_user_name) || ',') > 0) AND NOT EXISTS (SELECT 1 FROM hb_auth_signin b WHERE LOWER(b.actor_user_name) = LOWER(s.actor_user_name) AND b.src_endpoint_ip = s.src_endpoint_ip AND b.time >= datetime('now', '-{{lookback_days}} days') AND julianday(b.time) < julianday('{{exposure_start}}')) GROUP BY s.actor_user_name, s.provider, s.app_id, s.dst_endpoint_name, s.client_app, s.src_endpoint_ip, s.src_location_country, s.user_agent ORDER BY first_seen
```

## assess-session-reuse
<!-- Assess session theft and reuse -->
```agent target=hunter
cite: required
context:
- weigh-exposure
- data-sent-to-attacker-hosts
- sign-ins-from-new-sources
max_iterations: 5
objective: 'For each user with a /hit.php POST or a new-source sign-in, decide whether
  a session was stolen or reused. Cookies sent to /hit.php were only those page JavaScript
  can read: HttpOnly cookies were not exposed, so judge the risk from the affected
  site and whether the user was signed in to it. Compare new sign-in addresses with
  the user''s known travel, VPN and devices. Treat users whose iPhone or iPad reached
  an iOS stage host on an unpatched version (below 18.7.3, or 26 below 26.3) as session
  at risk too: in earlier campaigns these kits'' payloads took cookies and keychain
  data. Note which users submitted a card and which devices need an iOS check.'
success_criteria: A verdict per user (session reused | session at risk | exposed only
  | not exposed) citing rows, and lists of card-submitting users and at-risk iOS devices.
tools:
- endpoint
- identity
- network
- web
```

## route-on-session-verdict
<!-- Route on session verdict -->
if~: "the assess-session-reuse verdict is 'session reused' or 'session at risk' for at least one user" (confidence: medium, judge=hunter)
then: → revoke-exposed-sessions
indeterminate: → exposed-user-follow-up
unavailable: → exposed-user-follow-up (blind_spot: no-url-path-visibility)
else: → exposed-user-follow-up

## revoke-exposed-sessions
<!-- Revoke sessions of affected users -->
```action target=identity
~~~yaml
approval: required
~~~
For each user judged 'session reused' or 'session at risk': revoke active sessions and refresh tokens in the identity provider and in the affected SaaS app (for example Salesforce, GitLab, Zoom, Smartsheet or Bitly) and require MFA at next sign-in. Reset the password only where a sign-in from a new source succeeded. Do not isolate the laptop: the code ran in a web page and left nothing on the device.
```
→ exposed-user-follow-up

## exposed-user-follow-up
<!-- Follow up cards and iPhones -->
```manual target=analyst
Cards: for every user with a /card.php POST, and for anyone who paid by card on an affected site between 04:00 and 23:11 UTC on 16 Nov 2026, check the corporate or purchasing card statements, ask the issuer to reissue the card and watch for fraud. Tell users to do the same with personal cards. iPhones and iPads: for each device that reached an iOS stage host or loaded the payload, check the iOS version and Lockdown Mode status in MDM. In this campaign Coruna was served to iOS 13 to 17 (Google's analysis of the kit gives 13.0 to 17.2.1), DarkSword to iOS 18.x (Google: 18.4 to 18.7), and iOS 26 was only fingerprinted. The kit treats 18.7.3 and 26.3 as patched; one DarkSword bug stays open until 26.3. Devices on iOS 18.6 or earlier also loaded a hidden iframe and reloaded the page every 60 seconds. Update every device below 26.3 (or 18.7.3 where 26 is not available), review mobile threat defence alerts, and send any device with signs of compromise for forensic review with the vendor's tooling (for example MVT with the iVerify Coruna indicators). Lockdown Mode stops both kits. No source has shown a device was actually exploited in this campaign.
```
→ site-owner-review

## site-owner-review
<!-- Check your own Optimizely projects -->
```manual target=analyst
Skip this if you do not use Optimizely Web Experimentation. Otherwise: in each project, read the Project JavaScript and every experiment's custom code as served on 16 Nov 2026 and now, looking for 1688360.cc, webshell.lol, atob( and code you did not write; check the snippet's Last-Modified header and the project change history for edits on 16 Nov. Include snippets served from your own domain. List Optimizely users, API tokens and integrations, confirm Optimizely rotated them, and rotate any you did not create or cannot account for. Search CSP violation reports for 1688360.cc and the .icu hosts. If the snippet ran on login, checkout or payment pages, rotate secrets kept in non-HttpOnly cookies, and decide with legal and privacy whether customers must be told.
```
→ wallet-transfer-check

## wallet-transfer-check
<!-- Check crypto transfers against attacker wallets -->
```manual target=analyst
Ask treasury and finance whether anyone sent cryptocurrency between 04:00 UTC on 16 Nov and 06:00 UTC on 17 Nov 2026, from any device. Check each destination address against the attacker's swap-in wallets: BTC 19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW; ETH and BSC 0xC4026b06D82b0F0B363eda0642D61CfbDc17884e; TRON THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa; SOL FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n; TON UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p; LTC ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5; BCH qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58; DOGE DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5. A user with a /hit.php POST had an address swapped on that page. Report any match to the exchange and the police, and record the hunt outcome.
```
→ end
