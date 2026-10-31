---
analysis: This hunt correlates software versions (inventory) with authenticated access
  anomalies (prevalence) and multi-surface behavior (HTTP traversal and file reads)
  to distinguish exploitation from benign administrative activity.
blind_spots:
- id: missing-web-logs
  question: whether path traversal attempts occurred without triggering file system
    events
  requires: hb_http_activity (full access logs)
  risk: Unsuccessful traversal probes or probes targeting cached data would not be
    seen without complete HTTP telemetry.
  stage: path-traversal-exploitation
- id: phishing-telemetry-gap
  question: how the initial credentials for the authenticated traversal were acquired
  requires: email_activity or proxy_logs
  risk: The hunt begins at the authentication stage; the precursor phishing activity
    is invisible to the provided surfaces.
  stage: initial-access-phishing
coverage:
- stage: path-traversal-exploitation
  status: covered
  steps:
  - inventory-vulnerable-torrent-suite
  - http-path-traversal-activity
- stage: unauthorized-file-disclosure
  status: covered
  steps:
  - web-service-file-reads
- stage: external-remote-service-access
  status: covered
  steps:
  - rare-auth-on-torrent-servers
- blind_spot: phishing-telemetry-gap
  reason: No email or messaging telemetry is provided in the available surfaces.
  stage: initial-access-phishing
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Torrent Servers manage sensitive genomic and healthcare data. File
    disclosure via path traversal leads to significant regulatory violations and breach
    of privacy. Verifying exploitation status is critical for patient data safety.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An authenticated intruder is exploiting a path traversal vulnerability
  (CVE-2026-107777) in Thermo Fisher Torrent Suite Software to exfiltrate sensitive
  configuration and system files from healthcare servers.
labels:
- hunt
- attack.t1190
- attack.t1133
- attack.t1090.003
- attack.t1566
- collection
- initial access
name: Thermo Fisher Torrent Suite Path Traversal Exposure
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames running Torrent Suite Software; leave empty to
      search the whole estate.
    type: list[host]
  sensitive_files:
    default:
    - /etc/passwd
    - /etc/shadow
    - /etc/hosts
    - c:\windows\win.ini
    - c:\windows\system32\drivers\etc\hosts
    - web.config
    - .env
    description: Sensitive files an attacker might target; provided defaults are lowercase
      for exact matching.
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-01
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers running Torrent Suite Software. Prioritize internet-exposed
  servers or those accessible via VPN, as authenticated traversal is the primary risk.
references:
- name: CISA Advisory ICSMA-26-288-01
  url: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-01
related:
- hunt: credential-harvesting-phishing-analysis
  reason: Phishing detection requires email and network proxy surfaces not focused
    on in this vulnerability-centric hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing for Credentials
    observables:
    - Links in unsolicited email messages
    - Attachments in unsolicited email messages
    - Social engineering lures
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Access via Remote Services
    observables:
    - VPN connection attempts
    - Successful authenticated logins to remote access gateways
    slug: external-remote-service-access
    tactic: initial-access
    techniques:
    - T1133
  - name: Exploitation of CVE-2026-107777
    observables:
    - Torrent Suite Software version <= 5.18
    - HTTP requests with dot-dot-slash (../) sequences in the URL path or query
    - Targeting Thermo Fisher Torrent Suite Server
    slug: path-traversal-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Arbitrary File Read
    observables:
    - Web service account accessing system files (e.g., /etc/passwd)
    - Web service account accessing configuration files outside the web root
    - Reads of arbitrary files on the Torrent Server
    slug: unauthorized-file-disclosure
    tactic: collection
    techniques:
    - T1190
  summary: Authenticated attackers exploit a path traversal vulnerability (CVE-2026-107777)
    in Thermo Fisher Torrent Suite Software versions 5.18 and earlier to read arbitrary
    files accessible to the web service account. Access is typically gained through
    stolen credentials via phishing or by leveraging external remote services like
    VPNs.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Thermo Fisher Torrent Suite Path Traversal Exposure

This hunt identifies servers running vulnerable versions (<= 5.18) of Thermo Fisher Torrent Suite Software and examines them for exploitation. It first scopes the estate using software inventory data, then baselines user authentication to identify rare or anomalous access. Finally, it searches for behavioral indicators: HTTP requests containing traversal sequences and the web service account reading files in sensitive system paths. This multi-surface approach ensures that even if web logs are missing or traversal characters are obfuscated, the downstream file access behavior is captured.

## inventory-vulnerable-torrent-suite
<!-- Inventory vulnerable Torrent Suite installations -->
Identify hosts running Thermo Fisher Torrent Suite Software version 5.18 or lower to narrow the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running versions prior to 5.2. Silence means no vulnerable
  software is installed or the inventory is out of date.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%torrent suite%' AND package_version < '5.2'
```

## rare-auth-on-torrent-servers
<!-- Rare authentication on Torrent servers -->
Identify anomalous authenticated access, as the vulnerability requires a valid account for exploitation.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Accounts with very few successful logins to the targeted servers. In healthcare
  systems, even a single login from an unusual geography is more significant than
  the raw count.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  rare_below: 5
reads:
- actor_user_name
- device_hostname
- src_location_country
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT actor_user_name, device_hostname, src_location_country, src_endpoint_ip, COUNT(*) AS login_count, MIN(time) AS first_login, MAX(time) AS last_login FROM hb_auth_signin WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname, src_location_country, src_endpoint_ip HAVING login_count < 5 ORDER BY login_count ASC
```

## http-path-traversal-activity
<!-- HTTP path traversal attempts -->
Find HTTP requests containing dot-dot-slash sequences that attempt to break out of the web root.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests targeting the Torrent Suite servers that include traversal
  characters. Requests returning a 200 OK status are highly suspicious as they indicate
  successful processing.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- status_code
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, status_code, user_agent, time FROM hb_http_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(LOWER(url_full), '../') > 0 OR instr(LOWER(url_full), '..\') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## web-service-file-reads
<!-- Sensitive file reads by web service -->
Confirm successful traversal by identifying the web service account reading files from the sensitive files list.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days, sensitive_files=sensitive_files)
~~~yaml
expected: The web service account or Torrent process reading files that should not
  be accessible via the application. This confirms successful arbitrary file disclosure.
reads:
- device_hostname
- actor_user_name
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, process_name, file_path, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(LOWER(actor_user_name), 'www') > 0 OR instr(LOWER(actor_user_name), 'apache') > 0 OR instr(LOWER(actor_user_name), 'nginx') > 0 OR instr(LOWER(process_name), 'torrent') > 0) AND instr(',' || '{{sensitive_files}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-exposure
<!-- Analyze exposure and activity -->
```agent target=hunter
cite: required
context:
- inventory-vulnerable-torrent-suite
- rare-auth-on-torrent-servers
- http-path-traversal-activity
- web-service-file-reads
max_iterations: 5
objective: Review the authentication trends, HTTP requests, and file access events
  to determine if any Thermo Fisher Torrent Suite Servers have been exploited via
  CVE-2026-107777.
success_criteria: A verdict per host citing specific rows that indicate software version,
  rare login activity, and specific file or HTTP indicators.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-exposure verdict indicates successful traversal attempts (HTTP 200) or sensitive file reads by a web service account" (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: missing-web-logs)
else: → close-out

## remediation-review
<!-- Remediation and access review -->
```manual target=analyst
1. Prioritize updating all Thermo Fisher Torrent Suite Software to version 5.22 or later. 2. Audit the logins identified in the rare authentication step; rotate credentials for any account that shows unusual activity or geographic anomalies. 3. Audit file system permissions to ensure the web service account cannot read sensitive system directories like /etc.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the vulnerable hosts found in the scoping step and ensure they are scheduled for patching. Confirm that no active traversal strings or sensitive file reads were detected during the lookback period.
```
→ end
