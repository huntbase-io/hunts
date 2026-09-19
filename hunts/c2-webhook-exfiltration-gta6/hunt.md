---
analysis: A simple rule may alert on ngrok.io, but this hunt correlates infrastructure
  hits with rare HTTP exfiltration patterns and focuses on specific attacker ports
  (12684), reducing false positives from legitimate cloud services.
blind_spots:
- id: missing-network-visibility
  question: Are processes connecting directly to hardcoded IPs or non-standard ports
    without a preceding DNS resolution?
  requires: Endpoint telemetry capturing process-to-IP and SNI details
  risk: NJRAT and DCRAT often bypass DNS. If network telemetry only includes DNS logs,
    the command-and-control activity to AWS IPs will be invisible.
  stage: command-and-control-and-exfiltration
- id: tls-blind-spot
  question: What specifically is being sent to the Discord webhooks?
  requires: TLS inspection or detailed HTTP activity logs
  risk: We can see the target (Discord API) but not the content (tokens, screenshots).
    Without inspection, we can only infer exfiltration based on traffic rarity.
  stage: command-and-control-and-exfiltration
coverage:
- stage: command-and-control-and-exfiltration
  status: covered
  steps:
  - c2-infrastructure-connections
  - dns-resolutions-c2
  - rare-discord-webhooks
- reason: Covered in hunt 1 of 2 focused on ISO mounting and script execution.
  stage: initial-access-and-bootstrap
  status: out_of_scope
- reason: Covered in hunt 1 of 2 focused on Chaos ransomware behavior.
  stage: impact-wiper-operations
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: payload-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: defense-evasion-sinkholing
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: credential-and-data-collection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: This malware campaign targets high-interest themes with destructive
    payloads (wipers and persistent RATs). Detecting the network C2 and exfiltration
    phase is the most effective way to identify compromised hosts regardless of changes
    in the initial installer's file hash.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a combination of direct-IP C2 connections to AWS,
  protocol tunneling via ngrok, and Discord webhooks to control endpoints and exfiltrate
  data following a fake game installation.
labels:
- hunt
- attack.t1572
- attack.t1090.003
- attack.t1567
- attack.t1105
name: Multi-Protocol C2 and Webhook Exfiltration
parameters:
  c2_domains:
    default:
    - 7.tcp.eu.ngrok.io
    - a0700877.xsph.ru
    - clck.ru
    - discord.com
    description: C2 domains, tunneling endpoints, and exfiltration targets.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6-malware
    type: list[domain]
  c2_ips:
    default:
    - 35.157.111.131
    - 3.68.56.232
    - 3.67.15.169
    - 141.8.197.42
    description: C2 IP addresses observed in the report (AWS and Russian infrastructure).
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6-malware
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to these hostnames; leave empty to hunt across the
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-gta6-download-malware-analysis
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows endpoints. Prioritize user workstations where software
  installation or ISO mounting is common.
references:
- name: "Huntress \u2014 Grand Theft Auto VI hype leads to malware"
  url: https://www.huntress.com/blog/fake-gta6-download-malware-analysis
related:
- hunt: gta6-malware-local-persistence
  reason: This hunt focuses on network activity; the sibling hunt covers the registry,
    file, and task persistence components of the same malware bundle.
  relation: sibling
scenario:
  stages:
  - name: Fake Installer and Environment Check
    observables:
    - gta6installer.exe
    - checkinternetconnection.bat
    - find.vbs
    - https://clck.ru/34uJnp
    slug: initial-access-and-bootstrap
    tactic: initial-access
    techniques:
    - T1190
  - name: Multi-Malware Drop and Execution
    observables:
    - '%TEMP%\licensechecker.exe'
    - '%TEMP%\rockstar.exe'
    - '%TEMP%\steam.exe'
    - '%TEMP%\rockstargames.exe'
    - '%TEMP%\adminapp.exe'
    - '%TEMP%\any.ran.exe'
    - '%TEMP%\svchost.exe'
    - '%TEMP%\abc.exe'
    - '%TEMP%\P3usMXh1h4.bat'
    - C:\Users\Default\Local Settings\UserOOBEBroker.exe
    slug: payload-deployment
    tactic: execution
  - name: Telemetry and AV Sinkholing
    observables:
    - C:\Windows\System32\drivers\etc\hosts
    - v-s.mcafee.com
    - telemetry.microsoft.com
    - vortex-win.data.microsoft.com
    - r.office.microsoft.com
    slug: defense-evasion-sinkholing
    tactic: defense-evasion
  - name: Multi-Protocol C2 and Webhook Exfiltration
    observables:
    - 35.157.111.131
    - 3.68.56.232
    - 3.67.15.169
    - 141.8.197.42
    - 7.tcp.eu.ngrok.io:12684
    - a0700877.xsph.ru
    - discord.com/api/webhooks/995445114254139543/NmpxQmuBCD6sm3UkVvupGtx-Y0M_A86oJHp00O-l8F4jakfVhqFXzMBoy1uBDdj2rBLc
    slug: command-and-control-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  - name: Infostealing and Clipboard Access
    observables:
    - Chrome passwords
    - Discord tokens
    - Minecraft session data
    - Roblox Studio cookies
    - Clipboard data access
    slug: credential-and-data-collection
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  - name: Recovery Inhibition and Data Destruction
    observables:
    - vssadmin.exe delete shadows /all /quiet
    - bcdedit /set {default} recoveryenabled No
    - bcdedit /set {default} bootstatuspolicy ignoreallfailures
    - '%USERPROFILE%\AppData\Roaming\svchost.exe'
    - read_it.txt
    - AES encryption of files < 200MB
    - Overwriting of files > 200MB
    slug: impact-wiper-operations
    tactic: impact
    techniques:
    - T1486
    - T1490
  summary: Threat actors are exploiting Grand Theft Auto VI hype by distributing fake
    ISO installers via SEO poisoning and gaming forums. The installers deploy a variety
    of malware, including NJRAT, DCRAT, the Mercurial Grabber infostealer, and Chaos
    ransomware, which acts as a wiper to destroy system data after disabling recovery
    options.
series:
  index: 2
  slug: grand-theft-auto-vi-hype-leads-to-malware
  title: Grand Theft Auto VI hype leads to malware
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


# Multi-Protocol C2 and Webhook Exfiltration

This hunt focuses on the network footprint of the 'GTA6' malware bundle, including NJRAT, DCRAT, and Mercurial Grabber. We look for connections to hardcoded AWS infrastructure, the use of ngrok for protocol tunneling on non-standard ports (specifically port 12684), and the exfiltration of stolen credentials via Discord webhooks. By correlating rare network connections with DNS resolutions and HTTP traffic, we can identify compromised hosts even if the initial installer binaries have been renamed or removed.

## scope-active-windows
<!-- Scope to active Windows devices -->
Identify the active Windows estate where the malicious ISO is designed to execute.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Windows hostnames. Silence suggests no Windows endpoints are currently
  reporting inventory within the lookback window.
reads:
- hostname
- platform
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname FROM hb_devices WHERE LOWER(platform) = 'windows' AND lifecycle_state = 'active' AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-infrastructure-connections
<!-- Connections to C2 IPs and Tunneling Ports -->
Find connections to hardcoded C2 infrastructure or the specific ngrok port used by NJRAT.

```sqlite target=network role=detection-candidate params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hostnames and processes connecting to known-malicious IPs or specific ngrok
  tunnel ports. High fidelity for NJRAT and DCRAT activity.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- dst_endpoint_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, dst_endpoint_hostname, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR (LOWER(dst_endpoint_hostname) LIKE '%ngrok.io' AND dst_endpoint_port = 12684)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with DNS and Webhook Activity -->
parallel:
- → dns-resolutions-c2
- → rare-discord-webhooks
join: → triage-network-verdict

## dns-resolutions-c2
<!-- DNS lookups for suspicious C2 domains -->
Identify resolutions of the Russian C2 domain or the ngrok subdomains used for command and control.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes resolving domains named in the research. Silence suggests the
  actor may be using direct IP communication (bypassing DNS) or rotating subdomains.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.xsph.ru') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-discord-webhooks
<!-- Rare Discord Webhook exfiltration -->
Identify rare use of Discord webhooks, characteristic of Mercurial Grabber and similar infostealers.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A Discord webhook URL unique to 1 or 2 hosts. High probability of an exfiltration
  channel.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 3
reads:
- url_hostname
- url_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, url_path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS total_hits, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_hostname) = 'discord.com' AND url_path LIKE '/api/webhooks/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path HAVING hosts <= 2
```

## triage-network-verdict
<!-- Triage Network Evidence -->
```agent target=hunter
cite: required
context:
- c2-infrastructure-connections
- dns-resolutions-c2
- rare-discord-webhooks
max_iterations: 4
objective: Determine if any host exhibits combined signals of NJRAT/DCRAT connectivity
  (C2 IPs or ngrok tunnels) and infostealer exfiltration (Discord webhooks).
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  network rows.
tools:
- endpoint
- network
- web
```

## decision-route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review-task
unavailable: → analyst-review-task (blind_spot: missing-network-visibility)
else: → close-out

## isolate-infected-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. This actor utilizes multiple RATs and infostealers; assume credentials have been compromised.
```
→ analyst-review-task

## analyst-review-task
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited network activity. Cross-reference with the sibling hunt for local persistence (registry keys and scheduled tasks). Verify if the initial infection was via ISO mounting.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the negative or mitigated result. If false positives were found for ngrok or Discord webhooks, update exclusion filters.
```
→ end
