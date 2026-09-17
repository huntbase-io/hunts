---
analysis: This is a hunt because a rule on 'blockchain DNS' is too noisy. This design
  contextually joins WordPress server inventory with anomalous file writes and correlates
  client-side RPC resolution with rare TLD browsing across three surfaces (Software,
  File, DNS).
blind_spots:
- id: no-agent-on-webserver
  question: Are we seeing all file modifications on WordPress servers?
  requires: EDR agent with file activity monitoring on the web host
  risk: A web server without an agent might host ErrTraffic backdoors undetected.
  stage: wordpress-server-compromise
- id: encrypted-rpc-traffic
  question: What parameters are sent to RPC providers?
  requires: TLS inspection for HTTP activity
  risk: We can see the DNS resolution for RPC providers, but not the specific smart
    contract queries unless TLS is decrypted.
  stage: etherhiding-c2-resolution
coverage:
- stage: wordpress-server-compromise
  status: covered
  steps:
  - wordpress-inventory
  - wordpress-file-activity
- stage: etherhiding-c2-resolution
  status: covered
  steps:
  - suspicious-tld-prevalence
  - blockchain-rpc-resolution
- stage: clickfix-payload-delivery
  status: covered
  steps:
  - clickfix-path-activity
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: social-engineering-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unveiling ErrTraffic: a growing ClickFix
    malware distribution framework'' series.'
  stage: infostealer-payload-activity
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ErrTraffic uses blockchain rotation (EtherHiding) to maintain C2
    persistence, making static domain blocks ineffective. This hunt detects the underlying
    resolution behavior to catch rotated infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised internal WordPress servers to host backdoors,
  or internal clients are interacting with ClickFix lures that resolve C2 infrastructure
  via blockchain RPC endpoints (EtherHiding).
labels:
- hunt
- attack.t1190
- attack.t1071
- attack.t1090.003
name: 'ErrTraffic: Web Compromise and Blockchain Resolution'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  suspicious_tlds:
    default:
    - .beer
    - .cfd
    - .club
    - .click
    - .cyou
    - .lat
    - .sbs
    - .shop
    - .xyz
    description: Suspicious TLDs used by ErrTraffic for C2 rotation.
    from:
      kind: article
      observed: '2026-06-02'
      ref: sekoia-errtraffic
    type: list[string]
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
rationale: Scoping targets known WordPress servers for the distribution side. Resolution
  checks apply fleet-wide as any host can be a victim of malvertising or ClickFix
  lures.
references:
- name: "Sekoia \u2014 Unveiling ErrTraffic: a growing ClickFix malware distribution\
    \ framework"
  url: https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework
related:
- hunt: errtraffic-payload-execution
  reason: This hunt targets resolution; the subsequent hunt in the series focuses
    on PowerShell execution and infostealer behavior.
  relation: follows
scenario:
  stages:
  - name: WordPress Initial Access and Persistence
    observables:
    - PHP backdoors
    - Malicious WordPress plugin
    - Exploited WordPress accounts
    - index.php
    slug: wordpress-server-compromise
    tactic: initial-access
    techniques:
    - T1190
  - name: Blockchain-based C2 Resolution
    observables:
    - Polygon blockchain smart contract 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
    - Quicknode RPC endpoints
    - EtherHiding technique
    - Base64-encoded XOR-obfuscated JS
    slug: etherhiding-c2-resolution
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: ClickFix Lure Delivery
    observables:
    - /cf.js
    - /api/css.js
    - /api/index.php
    - llc-image-ico.click
    - Domains with .beer, .cfd, .club, .click, .cyou, .lat, .sbs, .shop, or .xyz TLDs
    slug: clickfix-payload-delivery
    tactic: command-and-control
    techniques:
    - T1071
  - name: User-Driven PowerShell Execution
    observables:
    - Fake BSOD lure
    - Fake Cloudflare Turnstile CAPTCHA
    - Malicious PowerShell command copied to clipboard
    - PowerShell download commands
    slug: social-engineering-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Infostealer Credential Theft
    observables:
    - Vidar infostealer
    - Stealc infostealer
    - Remus infostealer
    - Salat infostealer
    - Access to browser password stores
    slug: infostealer-payload-activity
    tactic: credential-access
    techniques:
    - T1555
  summary: ErrTraffic is a Malware-as-a-Service framework that compromises WordPress
    sites to inject malicious JavaScript and deliver 'ClickFix' social engineering
    lures. It utilizes 'EtherHiding' by querying Polygon blockchain smart contracts
    for resilient C2 infrastructure resolution and tricks users into running PowerShell
    commands that download infostealers like Vidar and Stealc.
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


# ErrTraffic: Web Compromise and Blockchain Resolution

This hunt targets the dual nature of ErrTraffic: the server-side compromise of WordPress infrastructure for payload hosting and the client-side use of EtherHiding (blockchain-based dead drop resolvers) to identify rotated C2 domains. It identifies vulnerable WordPress assets, monitors for unauthorized PHP modifications, and identifies anomalous client traffic to blockchain RPC providers and suspicious TLDs like .beer and .cfd.

## wordpress-inventory
<!-- Identify WordPress infrastructure -->
Find hosts running WordPress to narrow the scope for server-side compromise indicators.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with WordPress. Silence indicates no WordPress detected
  in inventory, shifting focus to client-side lure interaction.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%wordpress%'
```

## wordpress-file-activity
<!-- Unauthorized WordPress PHP activity -->
Detect the deployment of PHP backdoors (e.g., inside index.php or plugin directories) on servers identified in the scoping step.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: File writes or modifications to core WordPress files. Correlating these
  hits with non-admin accounts or unusual processes indicates compromise.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/index.php' OR LOWER(file_path) LIKE '%/wp-content/plugins/%') AND activity_id IN (1, 3, 4, 99) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-resolution
<!-- Corroborate resolution and delivery -->
parallel:
- → suspicious-tld-prevalence
- → blockchain-rpc-resolution
- → clickfix-path-activity
join: → triage-infrastructure

## suspicious-tld-prevalence
<!-- Rare DNS queries to campaign TLDs -->
Stack-count unusual TLDs to separate standard web browsing from rare, campaign-specific C2 infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare DNS queries to domains in the specified TLDs. Legitimate domains will
  be common; malicious C2s used in rotation will be unique to a few hosts.
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
verified_at: '2026-09-09'
~~~
SELECT query_hostname, MIN(time) AS first_seen FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.beer' OR LOWER(query_hostname) LIKE '%.cfd' OR LOWER(query_hostname) LIKE '%.club' OR LOWER(query_hostname) LIKE '%.click' OR LOWER(query_hostname) LIKE '%.cyou' OR LOWER(query_hostname) LIKE '%.lat' OR LOWER(query_hostname) LIKE '%.sbs' OR LOWER(query_hostname) LIKE '%.shop' OR LOWER(query_hostname) LIKE '%.xyz') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname
```

## blockchain-rpc-resolution
<!-- Anomalous blockchain RPC lookups -->
Detect EtherHiding by identifying hosts communicating with blockchain RPC providers like Quicknode, which are used to retrieve smart contract data.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving RPC endpoints. This is highly unusual for general-purpose
  workstations and strongly corroborates the use of blockchain-based DDR.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%quiknode.pro' OR LOWER(query_hostname) LIKE '%polygon-rpc.com' OR LOWER(query_hostname) LIKE '%quicknode.com') AND time >= datetime('now', '-{{lookback_days}} days')
```

## clickfix-path-activity
<!-- ClickFix lure delivery paths -->
Find HTTP requests to the specific endpoints used by ErrTraffic to serve malicious JavaScript and clipboard commands.

```sqlite target=web role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to campaign-specific paths. When combined with suspicious
  TLDs, these confirm active interaction with ErrTraffic lures.
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
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (url_path = '/cf.js' OR url_path = '/api/css.js' OR url_path = '/api/index.php') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infrastructure
<!-- Weigh compromise evidence -->
```agent target=hunter
cite: required
context:
- wordpress-inventory
- wordpress-file-activity
- suspicious-tld-prevalence
- blockchain-rpc-resolution
- clickfix-path-activity
max_iterations: 5
objective: Determine if any host shows WordPress compromise (unauthorized file writes)
  or ClickFix resolution (RPC lookups + rare TLD access + specific HTTP paths).
success_criteria: A per-host verdict (malicious | suspicious | benign) citing specific
  domains and file paths.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-agent-on-webserver)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. If it is a web server, preserve the WordPress directory and capture 'index.php' for forensics.
```
→ analyst-review

## analyst-review
<!-- Forensic validation -->
```manual target=analyst
Examine the files modified on the WordPress server for Base64/XOR scripts. For client hits, verify if the RPC activity correlates with access to the identified rare TLDs.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hosts examined. If no activity was found, update software inventory to ensure all WordPress instances are known.
```
→ end
