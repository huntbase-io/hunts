---
analysis: A detection rule would only trigger on a legitimate binary name. This hunt
  provides the necessary context by correlating the preceding SEO redirect and phishing
  lure interaction with the download.
blind_spots:
- id: no-http-path-visibility
  question: Did the user reach the popup.js specifically?
  requires: hb_http_activity with full URI paths
  risk: Without path visibility, interaction with the modal must be inferred from
    the follow-on installer download.
  stage: lure-site-access
- id: encrypted-credential-post
  question: Were credentials actually transmitted?
  requires: TLS inspection at the proxy
  risk: POST requests to watchguard-ssl.online indicate intent, but content is not
    visible.
  stage: credential-harvesting
coverage:
- stage: seo-poisoning-redirection
  status: covered
  steps:
  - http-lure-activity
- stage: lure-site-access
  status: covered
  steps:
  - scoping-dns-lookups
  - http-lure-activity
  - network-infra-hits
- stage: credential-harvesting
  status: covered
  steps:
  - http-lure-activity
  - network-infra-hits
- stage: legitimate-payload-delivery
  status: covered
  steps:
  - installer-file-events
  - installer-execution-events
- reason: Belongs to another part of the 'Fake WatchGuard VPN Site Steals Credentials'
    series.
  stage: external-service-login
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: credential phishing through lookalike domains bypasses endpoint malware
    detections by serving legitimate binaries. This hunt detects the full access chain
    to identify compromised credentials.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using SEO poisoning to lead users to fake WatchGuard VPN
  download sites that harvest credentials via a JavaScript modal before delivering
  the legitimate, signed installer.
labels:
- hunt
- attack.t1566
- attack.t1195.002
- attack.t1133
- credential access
- execution
- initial access
name: WatchGuard VPN Lookalike Phishing and Payload Delivery
parameters:
  installer_name:
    default: WG-MVPN-SSL_12_11_5.exe
    description: The name of the legitimate WatchGuard installer delivered as a payload.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_domains:
    default:
    - watchguard-vpn.com
    - watchguard-vpn.net
    - www.watchguard-vpn.net
    - watchguard-ssl.online
    description: Lookalike and collection domains associated with the campaign.
    from:
      kind: article
      observed: '2026-10-13'
      ref: Huntress Blog 2026-10-13
    type: list[domain]
  lure_ips:
    default:
    - 80.249.132.140
    - 74.208.236.39
    - 158.94.209.19
    description: IP addresses hosting lure sites and credential collectors.
    from:
      kind: article
      observed: '2026-10-13'
      ref: Huntress Blog 2026-10-13
    type: list[ip]
  lure_paths:
    default:
    - /index.php
    - /popup.js
    description: Specific URL paths associated with the credential harvesting modal.
    from:
      kind: article
      observed: '2026-10-13'
      ref: Huntress Blog 2026-10-13
    type: list[path]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty to search
      all.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints that performed searches for VPN software or resolved
  the phishing domains identified in the DNS scoping step.
references:
- name: "Huntress \u2014 Fake WatchGuard VPN Site Steals Credentials"
  url: https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing
related:
- hunt: external-service-login-anomaly
  reason: This hunt identifies the theft; the follow-on identifies the use of stolen
    credentials.
  relation: follows
scenario:
  stages:
  - name: SEO Poisoning Redirection
    observables:
    - bing.com/ck/a
    - u=aHR0cHM6Ly93d3cud2F0Y2hndWFyZC12cG4ubmV0Lw
    - 'search query: watchguard vpn sll download'
    slug: seo-poisoning-redirection
    tactic: initial-access
    techniques:
    - T1566
  - name: Phishing Lure Site Access
    observables:
    - watchguard-vpn.net
    - watchguard-vpn.com
    - 80.249.132.140
    - 74.208.236.39
    - www.watchguard-vpn.net/index.php
    slug: lure-site-access
    tactic: initial-access
    techniques:
    - T1566
  - name: Credential Harvesting
    observables:
    - popup.js
    - JSON POST to watchguard-ssl.online
    - 158.94.209.19
    - 'fields: server, login, password, attempt'
    - Incorrect data, please enter again to start installation
    slug: credential-harvesting
    tactic: credential-access
    techniques:
    - T1566
  - name: Legitimate Payload Delivery
    observables:
    - cdn.watchguard.com
    - WG-MVPN-SSL_12_11_5.exe
    - 'SHA256: fb3c39ba...0032ac1f'
    - WatchGuard Technologies, Inc. (Inno Setup)
    slug: legitimate-payload-delivery
    tactic: execution
    techniques:
    - T1195.002
  - name: External Remote Service Access
    observables:
    - VPN login from hosting provider IPs
    - VPN login from unfamiliar ASNs
    - SSL VPN login for WatchGuard client
    slug: external-service-login
    tactic: initial-access
    techniques:
    - T1133
  summary: The Storm-2561 campaign uses SEO poisoning on search engines like Bing
    to direct users to lookalike VPN download sites. These sites harvest credentials
    through a multi-stage JavaScript prompt before delivering a legitimate, signed
    WatchGuard installer to avoid suspicion. Stolen credentials are then utilized
    for unauthorized access to external remote services.
series:
  index: 1
  slug: fake-watchguard-vpn-site-steals-credentials
  title: Fake WatchGuard VPN Site Steals Credentials
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# WatchGuard VPN Lookalike Phishing and Payload Delivery

This hunt identifies hosts that interacted with lookalike WatchGuard VPN domains identified in recent threat research. The attack chain involves a redirection from search engines like Bing, interaction with a phishing lure site, and a forced credential entry prompt. The hunt first identifies candidate hosts via DNS activity, then examines HTTP and network traffic to identify lure interaction and credential POSTing. Finally, it correlates this activity with the subsequent download and execution of the legitimate WatchGuard SSL VPN installer, which is used to mask the theft and satisfy the user's original intent.

## scoping-dns-lookups
<!-- Scope hosts by DNS lookups to lure domains -->
Identify any hosts that attempted to resolve the lookalike or collector domains to narrow the investigation and provide prevalence context.

```sqlite target=endpoint role=scoping params=(lure_domains=lure_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving the phishing domains. Host prevalence shows if a domain
  is unique to one user or common across the fleet.
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, (SELECT COUNT(DISTINCT device_hostname) FROM hb_dns_activity WHERE LOWER(query_hostname) = LOWER(d.query_hostname) AND time >= datetime('now', '-{{lookback_days}} days')) AS host_prevalence, MIN(time) AS first_seen FROM hb_dns_activity d WHERE instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## early-stage-parallel
<!-- Parallel search for lure interaction -->
parallel:
- → http-lure-activity
- → network-infra-hits
join: → early-stage-triage

## http-lure-activity
<!-- Search for search-redirects and lure URI hits -->
Find HTTP evidence of the SEO redirection from search engines and interaction with the harvesting infrastructure.

```sqlite target=web role=triage params=(lure_domains=lure_domains, lure_paths=lure_paths, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests showing the user arriving at a lure domain from a search engine
  and interacting with index.php or popup.js.
reads:
- actor_user_name
- device_hostname
- referrer
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, actor_user_name, url_hostname, url_path, referrer, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND (LOWER(referrer) LIKE '%bing.com%' OR LOWER(referrer) LIKE '%google.com%') AND (instr(',' || '{{lure_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR url_path = '/') AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-infra-hits
<!-- Network connections to malicious IPs -->
Corroborate HTTP hits with raw network traffic to known lure and collection IPs.

```sqlite target=network role=enrichment params=(lure_ips=lure_ips, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from browser processes to the reported IP addresses.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{lure_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early-stage phishing interaction -->
```agent target=hunter
cite: required
context:
- scoping-dns-lookups
- http-lure-activity
- network-infra-hits
max_iterations: 3
objective: Identify hosts that reached the credential harvesting page and extract
  the actor_user_name from the HTTP telemetry to pinpoint the victim.
success_criteria: A list of hosts and specific user accounts with confirmed phishing
  lure interactions.
tools:
- endpoint
- network
- web
```

## follow-on-parallel
<!-- Parallel search for payload delivery -->
parallel:
- → installer-file-events
- → installer-execution-events
join: → follow-on-triage

## installer-file-events
<!-- Detection of installer file creation -->
Look for the specific WatchGuard installer being written to disk by a browser process.

```sqlite target=endpoint role=enrichment params=(installer_name=installer_name, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File creation events for the installer name on candidate hosts.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(file_name) = LOWER('{{installer_name}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## installer-execution-events
<!-- Installer process execution -->
Detect the actual execution of the installer, using company name metadata to find renamed binaries.

```sqlite target=endpoint role=detection-candidate params=(installer_name=installer_name, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process launch events for binaries identified as belonging to WatchGuard.
reads:
- device_hostname
- process_cmd_line
- process_file_company
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, process_file_company, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%' || LOWER('{{installer_name}}') OR LOWER(process_file_company) LIKE '%watchguard%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Correlate full phishing and execution chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- installer-file-events
- installer-execution-events
max_iterations: 4
objective: Synthesize the entire chain from SEO redirection to legitimate installer
  execution, building on the victim identification in the early-stage read.
success_criteria: A timeline of events for each affected host confirming the harvesting
  modal was shown followed by installer delivery.
tools:
- endpoint
- network
- web
```

## routing-decision
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host, indicating successful navigation to the lure followed by installer delivery" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-path-visibility)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the identity team to reset the VPN credentials for the affected user immediately.
```
→ analyst-review

## analyst-review
<!-- Detailed Analyst Review -->
```manual target=analyst
Review the HTTP telemetry specifically for POST requests to watchguard-ssl.online. Check for VPN logins from unusual geolocations for the affected user.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Update domain and IP blocklists. Confirm MFA-backed password resets for all identified victims.
```
→ end
