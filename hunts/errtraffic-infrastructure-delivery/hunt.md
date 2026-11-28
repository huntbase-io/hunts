---
analysis: This hunt pivots between server-side process identification, unauthorized
  file changes, specific JS delivery paths, and the underlying blockchain resolution
  behavior, requiring correlation across four different surfaces that a single static
  rule cannot achieve.
blind_spots:
- id: limited-telemetry
  question: whether a PHP file was legitimately updated or maliciously modified
  requires: detailed file hashing and change auditing
  risk: Attackers may modify existing core WordPress files with minimal code changes
    that lack high-fidelity process signals.
  stage: backdoor-persistence
- id: blockchain-obfuscation
  question: the specific C2 domain being retrieved from the smart contract
  requires: deep packet inspection of RPC traffic
  risk: If the RPC traffic is encrypted or the smart contract logic changes, identifying
    the secondary C2 via DNS alone becomes harder.
  stage: blockchain-c2-resolution
coverage:
- stage: backdoor-persistence
  status: covered
  steps:
  - wordpress-persistence-files
- stage: blockchain-c2-resolution
  status: covered
  steps:
  - blockchain-resolution-dns
- stage: clickfix-lure-delivery
  status: covered
  steps:
  - lure-delivery-endpoints
- reason: 'Belongs to another part of the ''ErrTraffic: A Growing ClickFix Malware
    Distribution Framework'' series.'
  stage: wordpress-credential-compromise
  status: out_of_scope
- reason: 'Belongs to another part of the ''ErrTraffic: A Growing ClickFix Malware
    Distribution Framework'' series.'
  stage: clipboard-command-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''ErrTraffic: A Growing ClickFix Malware
    Distribution Framework'' series.'
  stage: powershell-payload-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''ErrTraffic: A Growing ClickFix Malware
    Distribution Framework'' series.'
  stage: infostealer-credential-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ErrTraffic is a growing distribution framework used to deliver multiple
    infostealer families. Compromised company infrastructure serving malware to external
    visitors presents a high reputational and legal risk.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has compromised WordPress servers to host the ErrTraffic framework,
  which currently resolves C2 via blockchain RPCs and serves ClickFix lures from specific
  JavaScript endpoints.
labels:
- hunt
- attack.t1190
- attack.t1071
- attack.t1059.001
name: ErrTraffic Infrastructure and Delivery Monitoring
parameters:
  blockchain_rpc_domains:
    default:
    - polygon-rpc.com
    - quiknode.pro
    - quicknode.com
    description: Public blockchain RPC endpoints used for EtherHiding C2 resolution.
    from:
      kind: article
      observed: '2026-06-22'
      ref: sekoia-errtraffic
    type: list[domain]
  errtraffic_endpoints:
    default:
    - /cf.js
    - /api/css.js
    - /api/index.php
    description: Specific HTTP endpoints used by ErrTraffic clusters to serve lures.
    from:
      kind: article
      observed: '2026-06-22'
      ref: sekoia-errtraffic
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to scan all WordPress-identified
      servers.
    type: list[host]
  suspicious_tlds:
    default:
    - .beer
    - .cfd
    - .sbs
    - .click
    - .cyou
    - .lat
    - .shop
    - .xyz
    description: Suspicious TLDs observed in ErrTraffic C2 infrastructure.
    from:
      kind: article
      observed: '2026-06-22'
      ref: sekoia-errtraffic
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets WordPress servers by identifying active PHP and web server
  processes associated with WordPress directories, ensuring it catches unmanaged or
  containerized installations alongside managed software inventory.
references:
- name: 'ErrTraffic: A Growing ClickFix Malware Distribution Framework'
  url: https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: clipboard-command-injection-clickfix
  reason: This hunt identifies the delivery server; the sibling hunt identifies client-side
    execution via the clipboard.
  relation: follows
scenario:
  stages:
  - name: WordPress Account Compromise
    observables:
    - harvested credentials
    - WordPress sites
    - Exploit.IN forum
    slug: wordpress-credential-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: PHP Backdoor Deployment
    observables:
    - PHP backdoors
    - malicious WordPress plugin
    - ErrTraffic framework injection
    slug: backdoor-persistence
    tactic: persistence
    techniques:
    - T1190
  - name: EtherHiding C2 Resolution
    observables:
    - Polygon blockchain
    - '0x08207B087F61d7e95E441E15fd6d40BEfd6eD308'
    - Quicknode RPC
    - llc-image-ico.click
    - .beer
    - .cfd
    - .club
    - .click
    - .cyou
    - .lat
    - .sbs
    - .shop
    - .xyz
    slug: blockchain-c2-resolution
    tactic: command-and-control
    techniques:
    - T1071
  - name: Social Engineering Lure Delivery
    observables:
    - /cf.js
    - /api/css.js
    - /api/index.php
    - BSOD lure
    - reCAPTCHA lure
    - Cloudflare Turnstile lure
    slug: clickfix-lure-delivery
    tactic: execution
    techniques:
    - T1071
  - name: Malicious Clipboard Injection
    observables:
    - PowerShell command copied to clipboard
    slug: clipboard-command-injection
    tactic: collection
    techniques:
    - T1115
  - name: User-Executed PowerShell Payload
    observables:
    - powershell.exe
    - Net.WebClient download
    - mode=download
    slug: powershell-payload-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Infostealer Data Theft
    observables:
    - Vidar
    - Stealc
    - Remus
    - Salat
    slug: infostealer-credential-access
    tactic: credential-access
    techniques:
    - T1555
  summary: ErrTraffic is a Malware-as-a-Service (MaaS) framework that compromises
    WordPress sites to distribute infostealers using the 'ClickFix' social engineering
    technique. It uses the EtherHiding technique to resolve its command-and-control
    infrastructure via blockchain smart contracts and delivers malicious PowerShell
    commands that victims are tricked into executing manually.
series:
  index: 1
  slug: errtraffic-a-growing-clickfix-malware-distribution-framework
  title: 'ErrTraffic: A Growing ClickFix Malware Distribution Framework'
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


# ErrTraffic Infrastructure and Delivery Monitoring

The ErrTraffic Malware-as-a-Service (MaaS) distribution framework delivers payloads using the ClickFix social engineering technique. The adversary compromises WordPress servers to host the framework. The framework relies on EtherHiding, a technique where C2 domains are retrieved from blockchain smart contracts, allowing for rapid infrastructure rotation. This hunt monitors for server-side components of this framework on compromised WordPress infrastructure. The hunt identifies servers running WordPress processes or containing WordPress directories. It then collects evidence from three telemetry surfaces: HTTP activity targeting known delivery endpoints, file system changes involving unauthorized PHP backdoors, and DNS resolution of blockchain RPC providers or suspicious TLDs. An agent weighs these signals to determine if a server acts as a distribution point, and an analyst performs final forensic verification.

## wordpress-process-identification
<!-- Identify WordPress servers via processes -->
Find hosts running web servers or PHP processes associated with WordPress to identify managed and unmanaged installations.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts likely serving WordPress based on active processes. Silence
  indicates no active WordPress processes were observed.
reads:
- device_hostname
- process_cmd_line
- current_directory
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%wordpress%' OR LOWER(current_directory) LIKE '%wordpress%' OR LOWER(process_name) IN ('php-fpm', 'httpd', 'nginx', 'apache2')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evidence-fan-out
<!-- Collect independent evidence -->
parallel:
- → lure-delivery-endpoints
- → wordpress-persistence-files
- → blockchain-resolution-dns
join: → errtraffic-triage

## lure-delivery-endpoints
<!-- Monitor for lure delivery endpoints -->
Identify HTTP requests directed at specific ErrTraffic JavaScript delivery paths, normalizing for leading slashes.

```sqlite target=web role=detection-candidate params=(errtraffic_endpoints=errtraffic_endpoints, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Requests to /cf.js, /api/css.js, or /api/index.php regardless of the source
  log's slash convention. This is a high-fidelity indicator of an active lure delivery
  node.
reads:
- device_hostname
- url_hostname
- url_path
- src_endpoint_ip
- user_agent
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, src_endpoint_ip, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{errtraffic_endpoints}}' || ',', ',' || CASE WHEN url_path LIKE '/%' THEN LOWER(url_path) ELSE '/' || LOWER(url_path) END || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## wordpress-persistence-files
<!-- Unauthorized PHP file persistence -->
Find new or modified PHP files within WordPress plugin and theme directories.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Unusual PHP files created or modified by web server processes. This represents
  the persistence stage.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE activity_id IN (1, 3) AND LOWER(file_path) LIKE '%.php' AND (LOWER(file_path) LIKE '%wp-content/plugins%' OR LOWER(file_path) LIKE '%wp-content/themes%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## blockchain-resolution-dns
<!-- Blockchain RPC and suspicious TLD lookups -->
Identify EtherHiding C2 resolution by monitoring for blockchain RPCs and suspicious TLDs using a robust suffix match.

```sqlite target=endpoint role=enrichment params=(blockchain_rpc_domains=blockchain_rpc_domains, suspicious_tlds=suspicious_tlds, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving blockchain RPCs or domains ending in suspicious TLDs like
  .beer or .cfd. Robust suffix matching ensures TLDs of any length are captured.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as count FROM hb_dns_activity WHERE (instr(',' || '{{blockchain_rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{suspicious_tlds}}' || ',', ',' || '.' || REPLACE(LOWER(query_hostname), RTRIM(LOWER(query_hostname), 'abcdefghijklmnopqrstuvwxyz'), '') || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## errtraffic-triage
<!-- Triage ErrTraffic activity -->
```agent target=hunter
cite: required
context:
- wordpress-process-identification
- lure-delivery-endpoints
- wordpress-persistence-files
- blockchain-resolution-dns
max_iterations: 3
objective: Determine if any WordPress servers show a combination of unauthorized PHP
  file changes, lookups to blockchain RPCs or suspicious TLDs, and HTTP traffic on
  lure delivery endpoints.
success_criteria: A verdict of malicious, suspicious, or benign per host citing specific
  rows.
tools:
- endpoint
- web
```

## errtraffic-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for any server showing correlated indicators across multiple telemetry surfaces" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: limited-telemetry)
else: → close-out

## isolate-server
<!-- Isolate compromised server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host at the network level and revoke any active WordPress administrative sessions to prevent the adversary from maintaining access.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Inspect the identified PHP files for XOR-obfuscated or Base64-encoded strings. Verify if the HTTP Referer routing matches the behaviors described in the Sekoia report.
```
→ close-out

## close-out
<!-- Remediation and close out -->
```manual target=analyst
If malicious activity was confirmed, ensure all unauthorized plugins are removed and core WordPress files are restored from known good backups. Document the entry vector to prevent re-infection.
```
→ end
