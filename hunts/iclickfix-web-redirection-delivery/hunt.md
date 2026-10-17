---
analysis: A static domain blocklist is insufficient for an ephemeral TDS. This hunt
  correlates rare domain lookups (baseline role) with specific URI patterns and JSON-formatted
  exfiltration queries across two different telemetry surfaces (DNS and HTTP), something
  a single rule cannot perform without significant noise.
blind_spots:
- id: no-http-path-visibility
  question: whether a host requested a specific .js file or .php endpoint
  requires: TLS interception or browser-level telemetry
  risk: If HTTPS traffic is not intercepted, the url_path column in hb_http_activity
    will be empty or unavailable, leaving the hunt to rely solely on rare domain lookups
    in DNS.
  stage: tds-redirection-and-payload-delivery
- id: dns-over-https-blindness
  question: what domains were resolved via non-standard DNS resolvers
  requires: endpoint-level DoH query logging
  risk: If the browser or malware uses DNS-over-HTTPS (DoH), the queries will not
    appear in hb_dns_activity, missing the TDS infrastructure resolution.
  stage: compromised-wordpress-injection
coverage:
- stage: compromised-wordpress-injection
  status: covered
  steps:
  - wordpress-inventory-scoping
  - rare-tds-dns-lookups
- stage: tds-redirection-and-payload-delivery
  status: covered
  steps:
  - payload-script-http-activity
  - rare-tds-dns-lookups
- reason: Handled in the follow-on hunt focusing on the PowerShell dropper and clipboard
    interaction.
  stage: clickfix-clipboard-social-engineering
  status: out_of_scope
- reason: Requires hb_process_activity and hb_script_activity; out of scope for the
    web delivery phase.
  stage: powershell-payload-execution
  status: out_of_scope
- reason: Belongs to the infection aftermath hunt.
  stage: rat-persistence-and-dropper-cleanup
  status: out_of_scope
- reason: Involves specific RAT C2 traffic patterns handled in a separate network
    hunt.
  stage: netsupport-rat-c2-and-data-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The iClickFix framework has compromised over 3,800 WordPress sites
    and uses a novel YOURLS-based TDS to evade detection; identifying these redirections
    early prevents the critical NetSupport RAT payload from executing.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised WordPress sites to redirect visitors
  through a YOURLS-based Traffic Distribution System to fetch ClickFix-style malicious
  scripts.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1090.003
name: iClickFix Web Redirection and Delivery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  payload_paths:
    default:
    - /fffa.js
    - /ofofo.js
    - /liner.php
    - /gigi
    description: Specific URI paths used for stage delivery scripts.
    from:
      kind: article
      observed: '2025-11-01'
      ref: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    type: list[path]
  scope_hosts:
    default: []
    description: Optionally narrow the hunt to specific hosts; leave empty for the
      whole estate.
    type: list[host]
  tds_domains:
    default:
    - ksfldfklskdmbxcvb.com
    - ototaikfffkf.com
    - ksdkgsdkgkgmgm.pro
    - booksbypatriciaschultz.com
    - ahpc.gov.gh
    description: Infrastructure domains identified in the iClickFix report.
    from:
      kind: article
      observed: '2025-11-01'
      ref: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    type: list[domain]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying local WordPress installations as they are
  the strategic entry points. However, the redirection and payload delivery typically
  occur on user workstations visiting these sites. Analysts should run the DNS and
  HTTP queries unscoped if no internal WordPress servers are found.
references:
- name: 'Meet IClickFix: a widespread WordPress-targeting framework using the ClickFix
    tactic'
  url: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
related:
- hunt: iclickfix-powershell-payload-execution
  reason: This hunt identifies the web-based redirection; a subsequent hunt focuses
    on the PowerShell command execution and RAT deployment.
  relation: follows
scenario:
  stages:
  - name: Malicious JavaScript Injection
    observables:
    - ic-tracker-js
    - ksfldfklskdmbxcvb.com
    - ahpc.gov.gh
    - dns-prefetch
    slug: compromised-wordpress-injection
    tactic: initial-access
    techniques:
    - T1566
  - name: TDS Redirection and Script Fetching
    observables:
    - ototaikfffkf.com/fffa.js
    - ksdkgsdkgkgmgm.pro/ofofo.js
    - booksbypatriciaschultz.com/liner.php
    - 'x-robots-tag: noindex'
    - YOURLS admin panel
    slug: tds-redirection-and-payload-delivery
    tactic: execution
    techniques:
    - T1566
  - name: ClickFix Clipboard Social Engineering
    observables:
    - navigator.clipboard.writeText
    - Verify you are human
    - Ctrl + V
    - Win + R
    - Unusual Web Traffic Detected
    slug: clickfix-clipboard-social-engineering
    tactic: collection
    techniques:
    - T1115
  - name: Malicious PowerShell Downloader
    observables:
    - powershell -w hidden -nop -c
    - scottvmorton.com/tytuy.json
    - 05b03a25e10535c5c8e2327ee800ff5894f5dbfaf72e3fdcd9901def6f072c6d
    - 8db6.ps1
    slug: powershell-payload-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: NetSupport RAT Persistence and Evasion
    observables:
    - ProgramData\S1kCMNfZi3\
    - client32.exe
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - SecureModule Engine v1.0.0
    - RunMRU
    slug: rat-persistence-and-dropper-cleanup
    tactic: persistence
    techniques:
    - T1555
  - name: Command and Control and Data Theft
    observables:
    - pusykakimao.com:443
    - fnotusykakimao.com:443
    - /fakeurl.htm
    - client32.ini
    - licensee KAKAN
    slug: netsupport-rat-c2-and-data-theft
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
    - T1021.001
    - T1555
  summary: IClickFix is a WordPress-targeting framework that compromises legitimate
    sites to inject malicious JavaScript and redirect users through a YOURLS-based
    Traffic Distribution System. Victims are tricked by a ClickFix-style fake CAPTCHA
    lure into executing a PowerShell command that downloads and deploys the NetSupport
    RAT for persistent remote access and data exfiltration.
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


# iClickFix Web Redirection and Delivery

The iClickFix framework compromises WordPress sites to redirect visitors through a YOURLS-based Traffic Distribution System (TDS). This hunt identifies the early stages of the infection chain. It starts by identifying hosts that could be affected (those running WordPress), then fans out to monitor DNS for rare lookups and HTTP telemetry for specific JavaScript payload patterns like ofofo.js and liner.php. An agent weighs the evidence from these surfaces to distinguish the TDS from legitimate traffic, and an analyst reviews the hits to confirm the redirection.

## wordpress-inventory-scoping
<!-- Scope WordPress infrastructure -->
Find hosts that run WordPress or related packages, as they represent the compromised entry points or strategic internal targets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running WordPress. Silence means no local WordPress installations
  were detected, though the hunt still proceeds to find workstation victims who visit
  external compromised sites.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%wordpress%' OR LOWER(vendor_name) LIKE '%wordpress%'
```

## redirection-analysis-fan-out
<!-- Analyze redirection infrastructure -->
parallel:
- → rare-tds-dns-lookups
- → payload-script-http-activity
join: → triage-redirection-verdict

## rare-tds-dns-lookups
<!-- Rare lookups to TDS domains -->
Identify hosts resolving the reported TDS domains, focusing on those that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(tds_domains=tds_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts resolving malicious or suspicious .pro domains. Malicious
  TDS domains should have very low prevalence. Silence means no known TDS infrastructure
  was resolved.
prevalence:
  by: device_hostname
  key:
  - domain
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(query_hostname) AS domain, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{tds_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.pro') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(query_hostname) HAVING hosts <= 5 ORDER BY hosts ASC
```

## payload-script-http-activity
<!-- Detection of iClickFix script fetching -->
Detect the actual transfer of the ClickFix-style JavaScript payloads using reported path patterns and URI exfiltration formats.

```sqlite target=web role=detection-candidate params=(payload_paths=payload_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to payloads like ofofo.js or URI queries containing JSON-formatted
  host data. This is a high-fidelity indicator of redirection activity.
reads:
- device_hostname
- time
- url_hostname
- url_path
- url_query
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, time FROM hb_http_activity WHERE (instr(',' || '{{payload_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR (LOWER(url_path) LIKE '%.php' AND url_query LIKE '%"host":%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-redirection-verdict
<!-- Triage redirection evidence -->
```agent target=hunter
cite: required
context:
- rare-tds-dns-lookups
- payload-script-http-activity
max_iterations: 3
objective: Determine if any host resolved a malicious domain and then fetched a JavaScript
  payload associated with the iClickFix framework.
success_criteria: A list of malicious or suspicious hosts with cited rows from both
  DNS and HTTP logs.
tools:
- endpoint
- web
```

## redirection-routing
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving both a rare domain and a payload path" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-redirection-review
unavailable: → manual-redirection-review (blind_spot: no-http-path-visibility)
else: → manual-redirection-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and clear the clipboard of the current user to prevent accidental ClickFix execution.
```
→ manual-redirection-review

## manual-redirection-review
<!-- Manual redirection review -->
```manual target=analyst
Check the browser history on affected hosts for visits to the compromised WordPress sites and subsequent hops to TDS domains like ksdkgsdkgkgmgm.pro.
```
→ reporting-and-cleanup

## reporting-and-cleanup
<!-- Reporting and cleanup -->
```manual target=analyst
Document the found indicators and whether the redirection led to the PowerShell execution stage; update the detection team if the YOURLS redirection patterns have evolved.
```
→ end
