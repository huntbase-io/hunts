---
analysis: This hunt pivots between software inventory (scoping), DNS (phishing lead),
  rare blockchain traffic (resilience), and external stealer intel (Hudson Rock).
  A single rule could not correlate these four disparate signals into a high-confidence
  verdict.
blind_spots:
- id: encrypted-rpc-bodies
  owner: Network Engineering
  question: Which specific Polygon smart contract was queried?
  remediation: Enable HTTP visibility for known public JSON-RPC providers.
  requires: TLS inspection / HTTP POST body logging
  risk: Without inspection, we see connections to RPC providers but cannot see the
    contract bytecode or the decrypted C2 payload it returns.
  stage: c2-blockchain-dead-drop
- id: browser-referer-missing
  owner: Security Operations
  question: Did the request originate from a YouTube video link?
  remediation: Configure proxies to preserve/log Referer headers where possible.
  requires: Referer header logging in hb_http_activity
  risk: Missing Referer headers make it difficult to prove the YouTube social-engineering
    path even if the final domain is reached.
  stage: initial-access-phishing-lures
coverage:
- stage: initial-access-phishing-lures
  status: covered
  steps:
  - phishing-dns-lookup
- stage: c2-blockchain-dead-drop
  status: covered
  steps:
  - c2-network-activity
  - polygon-rpc-prevalence
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: execution-masquerading
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: discovery-profiling-and-evasion
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: credential-access-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: lateral-movement-proxy
  status: out_of_scope
- reason: 'Belongs to another part of the ''REVSTEALER ramps up: analysis of up-and-coming
    infostealer'' series.'
  stage: impact-resource-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: REVSTEALER's use of blockchain dead-drops represents a resilient
    evolution in C2 that bypasses static blocklists. A negative result confirms that
    the organization's identity surface is not currently being harvested via this
    specific mechanism.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is leveraging YouTube-promoted phishing lures to distribute
  infostealers that utilize Polygon blockchain smart contracts as a resilient C2 mechanism.
labels:
- hunt
- attack.t1566
- attack.t1071.004
- attack.t1133
- attack.t1555
name: REVSTEALER Phishing and Blockchain C2
parameters:
  c2_domains:
    default:
    - polygon.iwmukj.xyz
    - polygon.mnyhgxda.xyz
    - static4.livelab.one
    description: Primary and secondary C2 domains identified in samples.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs-revstealer
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of network and DNS history to examine.
    type: number
  phishing_domains:
    default:
    - elitecheatsx.live
    - resight-cheats.net
    description: Phishing domains promoted in YouTube descriptions.
    from:
      kind: article
      observed: '2026-09-02'
      ref: elastic-security-labs-revstealer
    type: list[domain]
  scope_hosts:
    default: []
    description: Narrow the hunt to these hosts; leave empty to hunt across the estate.
    type: list[host]
  tenant_domain:
    default: example.com
    description: Organizational domain to check in Hudson Rock logs.
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts identified in the software inventory step (Slack, VPN
  users). Phishing lures targeting gamers can reach any workstation, so widen the
  DNS scope if any initial hits are confirmed.
references:
- name: "Elastic Security Labs \u2014 REVSTEALER ramps up: analysis of up-and-coming\
    \ infostealer"
  url: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer
related:
- hunt: revstealer-harvesting-and-persistence
  reason: The file-level harvesting of gaming tokens and persistence behavior is handled
    in a companion hunt.
  relation: out-of-scope-alternative
- hunt: revstealer-host-activity-credential-theft
  relation: follows
scenario:
  stages:
  - name: YouTube Phishing and Malicious Downloads
    observables:
    - elitecheatsx.live
    - resight-cheats.net
    - YouTube video descriptions linking to game cheats
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: Masqueraded Binary Execution
    observables:
    - Slack.exe
    - qBittorrent.exe
    - SteelSeriesGG.exe
    - Blender.exe
    - VMProtect packer
    - 6-character token verification window
    slug: execution-masquerading
    tactic: execution
  - name: Victim Profiling and Sandbox Evasion
    observables:
    - GetEnvironmentStringsW
    - OpenClipboard
    - GetClipboardData
    - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    - CIS locale check (keyboard layout/language hash)
    - Sandbox scoring (CPU count, RAM threshold, GPU/PCI vendor)
    slug: discovery-profiling-and-evasion
    tactic: discovery
    techniques:
    - T1115
    - T1555
  - name: Credential and Application Harvesting
    observables:
    - '%LOCALAPPDATA%\Battle.net\Battle.net.config'
    - '%LOCALAPPDATA%\Steam\local.vdf'
    - '%LOCALAPPDATA%\Steam\loginusers.vdf'
    - '%LOCALAPPDATA%\Roblox\LocalStorage\RobloxCookies.dat'
    - '%USERPROFILE%\.lunarclient\settings\game\accounts.json'
    - Hardware breakpoints for App-Bound Encryption bypass
    - 225 Chromium extension identifiers
    slug: credential-access-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1176
  - name: Polygon Blockchain C2 Dead Drop
    observables:
    - polygon.iwmukj.xyz
    - polygon.mnyhgxda.xyz
    - static4.livelab.one
    - Port 443
    - Polygon JSON-RPC endpoints
    - '0x7e4126ADFE6679B3613F629CD49162Fb08fc53Bd'
    - '0x0EC6a6D31b36271eBD06450EA98c84eBa8a191d5'
    - '0x49cE5712164755ed212209bc71539bBc6fCFF541'
    slug: c2-blockchain-dead-drop
    tactic: command-and-control
  - name: Reverse SOCKS5 Proxy Deployment
    observables:
    - SoftManager module
    - Encrypted WebSocket protocol for backconnect
    slug: lateral-movement-proxy
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Cryptojacking Impact
    observables:
    - LockAppHost module
    - XMRig deployment
    slug: impact-resource-hijacking
    tactic: impact
    techniques:
    - T1496
  summary: REVSTEALER is an emerging infostealer distributed through YouTube-based
    phishing lures that impersonate legitimate software and game cheats. The malware
    profiles victims using sandbox scoring and CIS locale checks before harvesting
    credentials from browsers, cryptocurrency wallets, and gaming platforms like Steam
    and Battle.net. It utilizes Polygon blockchain smart contracts as a dead-drop
    mechanism for C2 resilience and can deploy follow-on modules for cryptojacking
    and reverse proxy access.
series:
  index: 2
  slug: revstealer-ramps-up-analysis-of-up-and-coming-infostealer
  title: 'REVSTEALER ramps up: analysis of up-and-coming infostealer'
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
  hudsonrock:
    category: siem
    huntbase:
      product: hudsonrock
    name: hudsonrock
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


# REVSTEALER Phishing and Blockchain C2

This hunt targets the initial access and resilient command-and-control phases of the REVSTEALER infostealer. It begins by identifying hosts running targeted software like Slack or VPNs, then looks for interactions with reported game-cheat phishing domains. To detect the 'EtherHiding' mechanism, it monitors for rare outbound HTTP traffic to Polygon blockchain RPC endpoints and corroborates this with known C2 infrastructure and external compromise data from Hudson Rock.

## scope-targeted-software
<!-- Find hosts with targeted software -->
Identify hosts running software mentioned in the report (Slack, VPNs) which are targeted for impersonation or credential theft.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the primary attack surface. This step scopes
  the hunt to vulnerable users.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%slack%' OR LOWER(vendor_name) LIKE '%slack%' OR LOWER(package_name) LIKE '%vpn%'
```

## phishing-dns-lookup
<!-- DNS queries to game-cheat phishing lures -->
Detect interaction with the malicious domains promoted via YouTube lures.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: A host resolving these domains is a likely victim of a phishing click. This
  is the primary behavioral lead.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as count, MIN(time) as first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## corroborate-c2
<!-- Corroborate C2 and external intel -->
parallel:
- → c2-network-activity
- → polygon-rpc-prevalence
- → hudson-rock-compromise-check
join: → triage-agent

## c2-network-activity
<!-- Network connections to REVSTEALER C2s -->
Identify direct outbound traffic to the primary and secondary C2 infrastructure.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Connections to these specific domains strongly indicate a successful infostealer
  infection.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_ip, process_name, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## polygon-rpc-prevalence
<!-- Rare interaction with Polygon RPCs -->
Detect the 'EtherHiding' mechanism where the malware queries public blockchain infrastructure for C2 pivots.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare connection to a Polygon RPC endpoint is highly suspicious in a non-web3
  development environment.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- url_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as request_count FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(url_hostname) LIKE '%rpc.polygon%' OR LOWER(url_hostname) LIKE '%matic.network%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## hudson-rock-compromise-check
<!-- Domain presence in external stealer logs -->
Verify if the organization's domain is already present in external infostealer intelligence datasets.

```sqlite target=hudsonrock role=enrichment params=(tenant_domain=tenant_domain)
~~~yaml
expected: A match in Hudson Rock data suggests active or prior compromise by stealer
  families including REVSTEALER.
reads:
- domain
- total_stealers
- stealer_families
- last_employee_compromised
silence: not_evidence_of_absence
source: hudsonrock_search_by_domain
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT domain, total_stealers, stealer_families, last_employee_compromised FROM hudsonrock_search_by_domain WHERE domain = '{{tenant_domain}}'
```

## triage-agent
<!-- Weigh phishing and blockchain C2 evidence -->
```agent target=hunter
cite: required
context:
- scope-targeted-software
- phishing-dns-lookup
- c2-network-activity
- polygon-rpc-prevalence
- hudson-rock-compromise-check
max_iterations: 4
objective: Decide whether the host's DNS lookups, rare RPC traffic, and direct C2
  connections indicate a REVSTEALER infection.
success_criteria: A verdict of malicious | suspicious | benign citing the relevant
  phishing domains or RPC endpoints.
tools:
- endpoint
- hudsonrock
- network
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for any host interacting with the phishing domains or confirmed C2 hosts." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-task
unavailable: → analyst-task (blind_spot: encrypted-rpc-bodies)
else: → analyst-task

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate processes associated with the identified C2 traffic, and initiate a global password reset for the affected user.
```
→ analyst-task

## analyst-task
<!-- Analyst review and close-out -->
```manual target=analyst
Review the DNS and RPC patterns. If confirmed, examine the host for signs of the follow-on modules like SoftManager or ProManager.
```
→ end
