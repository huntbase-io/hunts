---
analysis: This hunt combines behavioral path execution, stack-counted prevalence,
  and network indicator matching to find variants that a static hash-based rule would
  miss.
blind_spots:
- id: missing-network-telemetry
  question: whether the host communicated with the C2 servers
  requires: hb_network_connection from all endpoints
  risk: A host without network logging will only be flagged based on binary rarity,
    which is a lower confidence signal without network correlation.
  stage: rat-c2-and-tunneling
- id: tls-inspection-gap
  question: what specific credentials were sent to Discord webhooks
  requires: hb_http_activity with full URL/Payload inspection
  risk: Without TLS inspection, the analyst can see the connection to Discord but
    cannot confirm the nature of the exfiltrated data.
  stage: infostealer-credential-theft
coverage:
- stage: rat-c2-and-tunneling
  status: covered
  steps:
  - suspicious-path-execution
  - binary-rarity-baseline
  - c2-network-activity
- stage: infostealer-credential-theft
  status: covered
  steps:
  - suspicious-path-execution
  - c2-network-activity
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: initial-access-seo-poisoning
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: fake-installer-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: wiper-impact-and-recovery-inhibition
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The use of 'leaked' software hype to distribute multifunctional malware
    is a persistent threat to corporate identity; confirming the absence of these
    RATs protects the enterprise fleet.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging Grand Theft Auto VI hype to deploy RATs and
  infostealers that use ngrok tunnels for command and control and Discord for credential
  exfiltration.
labels:
- hunt
- attack.t1090.003
- attack.t1572
- attack.t1555
- attack.t1115
- attack.t1071.001
name: 'GTA 6 Hype: RAT C2 and Data Theft'
parameters:
  c2_domains:
    default:
    - 7.tcp.eu.ngrok.io
    - a0700877.xsph.ru
    - discord.com
    description: C2 domains and hostnames observed in the malware traffic.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6
    type: list[domain]
  c2_ips:
    default:
    - 35.157.111.131
    - 3.68.56.232
    - 3.67.15.169
    - 141.8.197.42
    description: C2 IP addresses for NJRAT and DCRAT identified in the report.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-09'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-09-09'
      ref: analyst-scoping
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with end-user workstations where users are most likely to search
  for game leaks. Focus on the last 14 days following any high-profile game announcements.
references:
- name: "Huntress \u2014 Grand Theft Auto VI hype leads to malware"
  url: https://www.huntress.com/blog/fake-gta6-download-malware-analysis
related:
- hunt: gta6-hype-wiper-logic
  reason: This hunt focuses on C2 and exfiltration; the wiper functionality (encryption
    and Shadow Copy deletion) is a distinct behavioral phase.
  relation: out-of-scope-alternative
- hunt: gta6-malicious-installer-wiper-activity
  relation: follows
scenario:
  stages:
  - name: Initial Access via SEO Poisoning
    observables:
    - gta6installer.exe
    - https://clck.ru/34uJnp
    - Large ISO files masquerading as GTA6
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1190
  - name: Fake Installer Execution and Staging
    observables:
    - '%TEMP%\checkinternetconnection.bat'
    - '%TEMP%\find.vbs'
    - '%TEMP%\licensechecker.exe'
    - '%TEMP%\rockstar.exe'
    - '%TEMP%\steam.exe'
    - '%TEMP%\rockstargames.exe'
    - '%TEMP%\YandexPackLoader.exe'
    - C:\Windows\System32\drivers\etc\hosts
    - WScript.exe find.vbs
    slug: fake-installer-deployment
    tactic: execution
  - name: RAT Command and Control with Tunneling
    observables:
    - 7.tcp.eu.ngrok.io:12684
    - 35.157.111.131
    - 3.68.56.232
    - 3.67.15.169
    - a0700877.xsph.ru
    - 141.8.197.42
    - any.ran.exe
    - UserOOBEBroker.exe
    slug: rat-c2-and-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: Infostealer Collection and Exfiltration
    observables:
    - adminapp.exe
    - Mercurial Grabber
    - https://discord.com/api/webhooks/995445114254139543/NmpxQmuBCD6sm3UkVvupGtx-Y0M_A86oJHp00O-l8F4jakfVhqFXzMBoy1uBDdj2rBLc
    slug: infostealer-credential-theft
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  - name: Wiper Impact and Recovery Inhibition
    observables:
    - gta6.exe
    - '%USERPROFILE%\AppData\Roaming\svchost.exe'
    - vssadmin.exe delete shadows /all /quiet
    - bcdedit /set {default} recoveryenabled No
    - read_it.txt
    - YOU HAVE BEEN HACKED BY THE ASHA HACKER TEAM!
    slug: wiper-impact-and-recovery-inhibition
    tactic: impact
    techniques:
    - T1486
    - T1490
  summary: Threat actors are exploiting Grand Theft Auto VI hype by distributing malicious
    ISO files via SEO poisoning and gaming forums. The infection chain uses a fake
    installer to deploy a variety of malware including NJRAT, DCRAT, Mercurial Grabber,
    and Chaos ransomware, which acts as a wiper to destroy user data while inhibiting
    system recovery.
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
tlp: clear
type: investigation
---


# GTA 6 Hype: RAT C2 and Data Theft

This hunt identifies post-infection activity from fake GTA 6 installers by targeting the C2 and exfiltration phases. It looks for processes running from temporary paths that communicate with known malicious infrastructure or Discord webhooks. The hunt uses fleet-wide prevalence to isolate unique malware binaries from legitimate installer noise.

## suspicious-path-execution
<!-- Execution from temporary and default user paths -->
Identify processes launching from %TEMP% or C:\Users\Default which are the primary execution stages for this malware bundle.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of processes running from user-writable paths. Most will be legitimate
  installers, which the prevalence step will filter.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\users\default\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-behavior
<!-- Corroborate with rarity and network signals -->
parallel:
- → binary-rarity-baseline
- → c2-network-activity
join: → triage-evidence

## binary-rarity-baseline
<!-- Prevalence of binaries in temporary paths -->
Filter the lead results by identifying binaries that are rare across the fleet, suggesting they are malware variants rather than enterprise software.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-counted list of binaries; paths seen on 3 or fewer hosts are the
  primary indicators of opportunistic malware.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\users\default\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING host_count <= 3
```

## c2-network-activity
<!-- Malicious C2 and ngrok network activity -->
Match host connections to the reported RAT infrastructure and identify potential Discord data exfiltration.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_ips=c2_ips, c2_domains=c2_domains)
~~~yaml
expected: Outbound connections to AWS, ngrok, or Discord hosts. Silence proves absence
  only for the specified indicators.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_hostname, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage binary and network evidence -->
```agent target=hunter
cite: required
context:
- suspicious-path-execution
- binary-rarity-baseline
- c2-network-activity
max_iterations: 5
objective: Identify high-confidence compromises by finding rare binaries in temporary
  directories that are responsible for the detected C2 or Discord traffic.
success_criteria: A verdict of malicious or suspicious per host, citing specific rare
  binaries and their associated network activity.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict confirms a rare binary is communicating with malicious infrastructure" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-network-telemetry)
else: → close-out

## contain-host
<!-- Isolate host and preserve evidence -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to prevent further exfiltration. Preserve the identified rare binary for reverse engineering and forensic analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst review and exfiltration check -->
```manual target=analyst
Review the host's activity leading up to the infection. Check hb_http_activity for specific Discord webhook paths used and confirm whether tokens or passwords were exfiltrated. Update the c2_domains parameter if new infrastructure is discovered.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the absence of the GTA 6 malware bundle. Record any benign temporary installers that were stack-counted for future exclusion lists.
```
→ end
