---
analysis: A simple detection rule for jewishchoice.org is easily bypassed. This hunt
  combines specific scoping, behavioral network heuristics for WebSockets, and exfiltration
  pattern analysis into a single decision, which avoids the false positives a single
  heuristic rule would generate.
blind_spots:
- id: encrypted-websocket-blind-spot
  question: Are the high-volume outbound connections confirmed to be WebSocket (HTTP
    Upgrade) traffic?
  requires: TLS decryption at the network proxy
  risk: Standard endpoint telemetry shows encrypted 443 traffic but not the protocol
    upgrade, necessitating reliance on packet-volume heuristics.
  stage: exfiltration-interactive-credential-harvesting
- id: non-http-telegram
  question: Is the actor using a non-HTTP method or MTProto for Telegram exfiltration?
  requires: hb_network_connection with destination IP attribution for Telegram
  risk: If the kit bypasses the HTTPS Bot API, it will not appear on the hb_http_activity
    surface.
  stage: exfiltration-interactive-credential-harvesting
coverage:
- stage: command-and-control-dns-routing
  status: covered
  steps:
  - dns-infrastructure-leads
- stage: exfiltration-interactive-credential-harvesting
  status: covered
  steps:
  - interactive-websocket-heuristics
  - telegram-bot-exfiltration
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: reconnaissance-automated-cloud-profiling
  status: out_of_scope
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: initial-access-app-only-auth
  status: out_of_scope
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: persistence-account-manipulation
  status: out_of_scope
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: privilege-escalation-graph-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''The hidden network: Inside the phishing
    infrastructure ecosystem powering global cybercrime'' series.'
  stage: collection-resource-hosting-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: PaaS products like the Iron Man System bypass traditional MFA through
    real-time victim interaction. A negative result confirms that these sophisticated
    harvesting sessions are not active in the high-value software scope.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is operating the Iron Man System phishing kit to harvest
  credentials in real-time, using specific domains for infrastructure management and
  Telegram for automated exfiltration.
labels:
- hunt
- attack.t1566
- attack.t1041
- attack.t1090.003
- collection
- command and control
- exfiltration
- initial access
- persistence
- privilege escalation
- reconnaissance
name: Phishing Infrastructure and Interactive Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: Standard retention window
    type: number
  reported_domains:
    default:
    - jewishchoice.org
    description: Malicious domains linked to Storm-3119 infrastructure management.
    from:
      kind: article
      observed: '2026-10-14'
      ref: Microsoft Storm-3119 Report
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty to scan
      the estate.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: Analyst scoping
    type: list[host]
  target_software_keywords:
    default:
    - Google Drive
    - SharePoint
    - OneDrive
    - Microsoft 365
    description: Software keywords to identify high-value target hosts.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: Reported target platforms
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on departments with high-value cloud access, such as finance or executive
  administration, as these are the primary targets for tenant hijacking.
references:
- name: 'The hidden network: Inside the phishing infrastructure ecosystem powering
    global cybercrime'
  url: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/
related:
- hunt: cloud-tenant-takeover-graph-abuse
  reason: This hunt focuses on the endpoint exfiltration side; cloud-side resource
    and Graph abuse belong to the infrastructure takeover hunt.
  relation: out-of-scope-alternative
- hunt: cloud-tenant-hijacking-service-principal-abuse
  relation: follows
scenario:
  stages:
  - name: Automated Cloud Tenant Reconnaissance
    observables:
    - Flask-based reconnaissance tooling
    - Tor infrastructure for anonymity
    - Profiling of M365 tenant enrollment opportunities
    - Discovery of Azure cloud information
    slug: reconnaissance-automated-cloud-profiling
    tactic: reconnaissance
    techniques:
    - T1090.003
    - T1595
  - name: Application-Level Environment Takeover
    observables:
    - Application-only authentication flows
    - Usage of stolen client secrets
    - PHP, Java/Spring, and Cloudflare Workers admin panels
    - Client secret-based directory control
    slug: initial-access-app-only-auth
    tactic: initial-access
    techniques:
    - T1078.004
  - name: Silent Password Resets and License Assignment
    observables:
    - Silent password resets (without force-change requirement)
    - Assignment of education licenses
    - Granting of privileged account attributes
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1098
  - name: Graph API Privilege Escalation
    observables:
    - Self-provisioning of PnP Management Shell service principal
    - Granting AppCatalog.ReadWrite.All permission
    - Broad Microsoft Graph permissions grant
    - Full control over SharePoint API
    slug: privilege-escalation-graph-abuse
    tactic: privilege-escalation
    techniques:
    - T1098.003
  - name: SharePoint and OneDrive Storage Abuse
    observables:
    - Abuse of SharePoint as bulk hosting platform
    - Abuse of OneDrive for phishing content hosting
    - Conversion of hijacked storage into sellable products
    slug: collection-resource-hosting-abuse
    tactic: collection
    techniques:
    - T1560
  - name: DNS Management and Domain Routing
    observables:
    - Custom DNS management platform
    - Cloudflare domain-routing configurations
    - jewishchoice.org
    - AI-generated nonprofit web presence
    slug: command-and-control-dns-routing
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1568
  - name: Real-time Phishing and Exfiltration
    observables:
    - WebSocket connections for real-time victim interaction
    - Telegram bot tokens and chat IDs for exfiltration
    - Iron Man System phishing kit
    - Credential harvesting (usernames, passwords, credit card info)
    slug: exfiltration-interactive-credential-harvesting
    tactic: exfiltration
    techniques:
    - T1566
    - T1041
  summary: Storm-3119 (YAM Store) functions as an infrastructure broker that hijacks
    Microsoft 365 and Azure environments through automated reconnaissance and application-level
    credential abuse. These compromised environments and PaaS phishing kits (Storm-2990)
    are then used by downstream actors to conduct large-scale credential and financial
    theft, leveraging real-time victim interaction via WebSockets and Telegram.
series:
  index: 2
  slug: the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime
  title: 'The hidden network: Inside the phishing infrastructure ecosystem powering
    global cybercrime'
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


# Phishing Infrastructure and Interactive Exfiltration

This hunt targets the interactive phases of the Storm-2990 and Storm-3119 phishing ecosystem. It focuses on the behavioral hallmarks of the Iron Man System: high-frequency WebSocket-like traffic for real-time operator-victim interaction and exfiltration via the Telegram Bot API. The hunt first scopes to hosts running core productivity software targeted by this group, then fans out to identify connections to reported infrastructure and behavioral exfiltration patterns. An agent triages the converged evidence to distinguish legitimate application traffic from active phishing sessions.

## scoping-targeted-software
<!-- Scope to hosts with targeted productivity software -->
Find hosts running business productivity software that are the reported targets for this infrastructure abuse.

```sqlite target=endpoint role=scoping params=(target_software_keywords=target_software_keywords)
~~~yaml
expected: A list of hosts that run the software targeted for hijacking. Silence does
  not prove absence of threat but narrows the hunt to the most likely beachheads.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{target_software_keywords}}' || ',', ',' || package_name || ',') > 0 OR LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%sharepoint%')
```

## parallel-signal-search
<!-- Parallel search for C2 and exfiltration signals -->
parallel:
- → dns-infrastructure-leads
- → interactive-websocket-heuristics
- → telegram-bot-exfiltration
join: → triage-phishing-activity

## dns-infrastructure-leads
<!-- DNS lookups to reported management infrastructure -->
Find any host resolving domains linked to the Storm-3119 management infrastructure.

```sqlite target=endpoint role=triage params=(reported_domains=reported_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A resolution of jewishchoice.org or other reported domains. This is a high-confidence
  lead for interaction with the management infrastructure.
reads:
- device_hostname
- query_hostname
- query_type
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, query_hostname, query_type, time FROM hb_dns_activity WHERE (instr(',' || '{{reported_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%jewishchoice.org%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## interactive-websocket-heuristics
<!-- Interactive high-packet outbound sessions -->
Identify hosts with sustained, high-packet outbound traffic on port 443, characteristic of interactive phishing sessions.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: High packet volume to an external IP seen on few hosts suggests a long-lived
  session like a WebSocket used for interactive harvesting.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- traffic_packets
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) as connection_count, SUM(traffic_packets) as total_packets, MIN(time) as first_seen FROM hb_network_connection WHERE dst_endpoint_port = 443 AND state_kind = 'log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING total_packets > 500
```

## telegram-bot-exfiltration
<!-- Telegram Bot API exfiltration -->
Detect direct connections to the Telegram Bot API used for real-time exfiltration notifications.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Requests to api.telegram.org/bot are the primary channel for the Iron Man
  System's real-time exfiltration alerts.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE (LOWER(url_hostname) = 'api.telegram.org' AND LOWER(url_path) LIKE '/bot%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-phishing-activity
<!-- Phishing session triage -->
```agent target=hunter
cite: required
context:
- scoping-targeted-software
- dns-infrastructure-leads
- interactive-websocket-heuristics
- telegram-bot-exfiltration
max_iterations: 4
objective: Determine if any host shows signs of interactive phishing through a combination
  of Storm-3119 management domain hits, high-volume WebSocket heuristics, and Telegram
  exfiltration.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  rows from the DNS and HTTP surfaces.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on concurrent DNS and HTTP exfiltration signals" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: encrypted-websocket-blind-spot)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke any active Microsoft 365 or Google cloud sessions for the user logged in at the time of the exfiltration signal.
```
→ analyst-investigation

## analyst-investigation
<!-- Investigate interactive phishing lures -->
```manual target=analyst
Review browser history and cache on the isolated host to find the initial phishing URL. Extract bot tokens from the Telegram API request paths if visible in the HTTP logs.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the findings. Update organizational blocklists with any newly identified malicious domains or IPs found during the analyst investigation.
```
→ end
