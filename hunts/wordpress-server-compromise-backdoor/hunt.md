---
analysis: A simple detection rule for PHP file creation in WordPress directories would
  trigger on legitimate plugin updates. This hunt uses software inventory for scoping,
  fleet-wide stack-counting to identify rare/bespoke files, and corroborates against
  cluster-specific HTTP endpoints (/cf.js) to provide a high-fidelity signal that
  warrants immediate host isolation.
blind_spots:
- id: wordpress-internal-logging
  question: Which WordPress user account was used to install the malicious plugin?
  requires: WordPress application audit logs
  risk: Without internal application logs, we cannot distinguish between a legitimate
    admin compromise (credential theft) and an automated exploit (T1190).
  stage: initial-access-wordpress-compromise
- id: encrypted-traffic-payloads
  question: What parameters were passed to the PHP backdoors to control their behavior?
  requires: TLS decryption or WAF logs
  risk: HTTP telemetry shows the GET/POST endpoint but not the encrypted payload body,
    obscuring the exact commands sent to the backdoor.
  stage: persistence-backdoor-installation
coverage:
- stage: initial-access-wordpress-compromise
  status: covered
  steps:
  - identify-wordpress-inventory
  - triage-compromise
- stage: persistence-backdoor-installation
  status: covered
  steps:
  - new-php-backdoor-files
  - rare-php-backdoor-prevalence
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: c2-etherhiding-resolution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: delivery-clickfix-lure
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: execution-malicious-powershell
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: impact-infostealer-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ErrTraffic converts compromised WordPress servers into malware distribution
    points. Identifying these servers disrupts the framework's reach and protects
    downstream clients from ClickFix lures and subsequent infostealer infections.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised WordPress servers to install PHP backdoors
  that serve as ClickFix lure distribution points for the ErrTraffic framework.
labels:
- hunt
- attack.t1190
- attack.t1505.003
- attack.t1555
name: WordPress Server Compromise and Backdoor Deployment
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  lure_endpoints:
    default:
    - /cf.js
    - /api/css.js
    - /api/index.php
    description: ErrTraffic distribution endpoints used to serve malicious lures.
    from:
      kind: article
      observed: '2026-06-02'
      ref: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    type: list[path]
  scope_hosts:
    default: []
    description: Specific hostnames to scope the hunt to; leave empty for the entire
      estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes using software inventory for 'WordPress' to identify primary
  targets. If no hosts are found but WordPress is known to be in use, widen the scope
  manually by pasting hostnames into the scope_hosts parameter.
references:
- name: "Sekoia \u2014 Unveiling ErrTraffic: a growing ClickFix malware distribution\
    \ framework"
  url: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: errtraffic-clickfix-client-execution
  reason: This hunt identifies the malicious servers; the follow-up hunt identifies
    the client-side execution of the PowerShell lures delivered by these servers.
  relation: follows
scenario:
  stages:
  - name: WordPress Account Compromise
    observables:
    - harvested credentials
    - compromised WordPress accounts
    - exploit.in
    slug: initial-access-wordpress-compromise
    tactic: initial-access
    techniques:
    - T1190
    - T1555
  - name: PHP Backdoor and Plugin Persistence
    observables:
    - Malicious WordPress plugin
    - PHP backdoors
    - Analytics cluster backdoor
    - Beer cluster backdoor
    slug: persistence-backdoor-installation
    tactic: persistence
    techniques:
    - T1505.003
  - name: Blockchain-based C2 Resolution
    observables:
    - Polygon smart contract 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
    - Quicknode public RPC endpoints
    - .beer TLD
    - .cfd
    - .click
    - .shop
    - .xyz
    - llc-image-ico.click
    - EtherHiding technique
    slug: c2-etherhiding-resolution
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: ClickFix Social Engineering Lure
    observables:
    - BSOD screen lure
    - reCAPTCHA lure
    - Cloudflare Turnstile CAPTCHA lure
    - /cf.js
    - /api/css.js
    - /api/index.php
    - index.php?a=ctx&os=windows&src=cloudflare
    slug: delivery-clickfix-lure
    tactic: execution
    techniques:
    - T1204.001
  - name: PowerShell Command Execution
    observables:
    - PowerShell command lines copied to clipboard
    - malicious command execution via user interaction
    slug: execution-malicious-powershell
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Infostealer Payload Activity
    observables:
    - Vidar infostealer
    - Stealc infostealer
    - Remus infostealer
    - Salat infostealer
    slug: impact-infostealer-deployment
    tactic: credential-access
    techniques:
    - T1555
  summary: ErrTraffic is a Malware-as-a-Service ClickFix framework that leverages
    compromised WordPress sites to deliver social engineering lures. The framework
    uses EtherHiding techniques to resolve C2 infrastructure via blockchain smart
    contracts, ultimately tricking users into executing PowerShell commands that install
    infostealers like Vidar and Stealc.
series:
  index: 1
  slug: unveiling-errtraffic-a-growing-clickfix-malware-distribution-framework
  title: 'Unveiling ErrTraffic: a growing ClickFix malware distribution framework'
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


# WordPress Server Compromise and Backdoor Deployment

This hunt focuses on the server-side infrastructure of ErrTraffic. It identifies compromised WordPress instances by first scoping the estate to known WordPress installations, then identifying the creation of rare PHP files in sensitive plugin and include directories. These behavioral signals are corroborated by identifying the cluster-specific HTTP request patterns used by ErrTraffic to serve ClickFix lures, allowing for high-fidelity identification of compromised distribution points.

## identify-wordpress-inventory
<!-- Identify WordPress inventory -->
Scope the hunt to systems officially running WordPress based on installed packages.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with WordPress installed. If empty, it suggests WordPress
  may be installed via manual unzipped archives, which requires process-based scoping.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%wordpress%' OR LOWER(vendor_name) LIKE '%wordpress%')
```

## parallel-signals
<!-- Examine compromise signals -->
parallel:
- → new-php-backdoor-files
- → rare-php-backdoor-prevalence
- → errtraffic-request-patterns
join: → triage-compromise

## new-php-backdoor-files
<!-- New PHP files in plugin directories -->
Detect the creation of new PHP files in directories associated with WordPress persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of PHP files. Randomly named files or files created by unexpected
  web processes (e.g. www-data) in these paths are high-fidelity indicators.
reads:
- device_hostname
- file_path
- file_name
- process_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/wp-content/plugins/%' OR LOWER(file_path) LIKE '%/wp-includes/%' OR LOWER(file_path) LIKE '%\\wp-content\\plugins\\%' OR LOWER(file_path) LIKE '%\\wp-includes\\%') AND LOWER(file_name) LIKE '%.php' AND activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-php-backdoor-prevalence
<!-- Rare PHP filenames in sensitive paths -->
Identify bespoke backdoors by stack-counting filenames across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: PHP filenames appearing on only a few hosts; genuine plugins should be widespread
  or documented in software inventory.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- file_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(file_name) AS backdoor_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/wp-content/plugins/%' OR LOWER(file_path) LIKE '%/wp-includes/%' OR LOWER(file_path) LIKE '%\\wp-content\\plugins\\%' OR LOWER(file_path) LIKE '%\\wp-includes\\%') AND LOWER(file_name) LIKE '%.php' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## errtraffic-request-patterns
<!-- ErrTraffic lure distribution requests -->
Confirm the server is acting as an ErrTraffic distributor by finding hits to unique lure endpoints.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lure_endpoints=lure_endpoints)
~~~yaml
expected: HTTP 200 OK responses for /cf.js, /api/css.js, or /api/index.php. These
  paths are distinctive to the Analytics and Beer clusters.
reads:
- device_hostname
- url_path
- src_endpoint_ip
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, status_code, time FROM hb_http_activity WHERE (instr(',' || '{{lure_endpoints}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage WordPress compromise -->
```agent target=hunter
cite: required
context:
- identify-wordpress-inventory
- new-php-backdoor-files
- rare-php-backdoor-prevalence
- errtraffic-request-patterns
max_iterations: 4
objective: Identify hosts that show evidence of both a recently created rare PHP file
  in a WordPress sensitive directory AND HTTP requests to ErrTraffic distribution
  endpoints.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  rare file path and the lure request volume.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: wordpress-internal-logging)
else: → analyst-review

## isolate-server
<!-- Isolate compromised server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the identified PHP backdoor files for forensic analysis. Collect logs from the web service to identify the initial access vector (vulnerability vs. stolen credentials).
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the triage verdict and cited rows. Check hb_auth_signin for signs of credential stuffing or unauthorized logins to the WordPress server's IP. Check hb_vulnerability_finding for unpatched vulnerabilities in WordPress or its plugins that could have allowed RCE/backdoor installation.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the number of confirmed compromised servers, the cluster type (Analytics/Beer), and any new PHP shell variants observed. Schedule a follow-up hunt to identify clients that visited these lures.
```
→ end
