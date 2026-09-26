---
analysis: Simple rules for Cloudflare traffic are often suppressed. This hunt correlates
  DNS leads with fallback IP connections and a specific PHP execution pattern across
  three telemetry surfaces, providing the context an analyst needs to differentiate
  a RAT from legitimate tunneling.
blind_spots:
- id: limited-rdp-visibility
  question: Did the attacker move between systems using local accounts or sessions
    not captured by the central provider?
  requires: hb_auth_signin with logon type and local session tracking
  risk: Lateral movement between servers using local accounts would not appear in
    centralized authentication logs.
  stage: lateral-movement-rdp
- id: cloudflare-legitimate-usage
  question: Is the Cloudflare Tunnel traffic malicious or legitimate administrative
    usage?
  requires: Proxy logs with SNI and HTTP header inspection
  risk: Legitimate use of Cloudflare Tunnels can create false positives, requiring
    correlation with PHP behavioral artifacts to confirm the RAT.
  stage: c2-cloudflare-tunneling
coverage:
- stage: c2-cloudflare-tunneling
  status: covered
  steps:
  - dns-c2-leads
  - fallback-network-connections
- stage: lateral-movement-rdp
  status: covered
  steps:
  - anomalous-rdp-logons
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: initial-access-web-inject
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: powershell-stager-execution
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: php-rat-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: automated-and-manual-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: persistence-registry-run
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Interlock RAT is a precursor to ransomware. Detecting its C2 and
    movement early prevents wide-scale encryption and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established a PHP-based RAT beachhead and is using Cloudflare
  Tunnels for C2 before moving laterally via RDP.
labels:
- hunt
- attack.t1071.001
- attack.t1572
- attack.t1021.001
name: Interlock RAT C2 and RDP Lateral Movement
parameters:
  c2_domains:
    default:
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - evidence-deleted-procedure-bringing.trycloudflare.com
    - nowhere-locked-manor-hs.trycloudflare.com
    - ranked-accordingly-ab-hired.trycloudflare.com
    description: Known TryCloudflare subdomains used by Interlock RAT.
    from:
      kind: article
      observed: '2025-07-14'
      ref: dfir-report-2025-07-14
    type: list[domain]
  fallback_ips:
    default:
    - 64.95.12.71
    - 184.95.51.165
    description: Hardcoded fallback IP addresses for Interlock RAT C2.
    from:
      kind: article
      observed: '2025-07-14'
      ref: dfir-report-2025-07-14
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts resolving trycloudflare subdomains. The hunt dynamically
  pivots by having the agent correlate these hosts with network and process telemetry.
references:
- name: The DFIR Report - KongTuke FileFix Leads to New Interlock RAT Variant
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-rat-persistence-and-discovery
  reason: Persistence via Run keys and automated discovery are handled in a separate
    hunt focused on local endpoint artifacts.
  relation: out-of-scope-alternative
- hunt: interlock-rat-endpoint-execution-recon
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Web-Inject
    observables:
    - captcha verification prompt
    - human verification steps
    - clipboard paste into run command
    slug: initial-access-web-inject
    tactic: initial-access
    techniques:
    - T1189
    - T1204.002
  - name: PowerShell Stager Execution
    observables:
    - schtasks /delete /tn Updater /f
    - New-Object System.Net.WebClient
    - DownloadString
    - deadly-programming-attorneys-our.trycloudflare.com
    - 'User-Agent: PowerShell'
    slug: powershell-stager-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1105
  - name: Interlock RAT (PHP) Deployment
    observables:
    - AppData\Roaming\php\php.exe
    - wefs.cfg
    - php.exe -d extension=zip -d extension_dir=ext
    - 28a9982cf2b4fc53a1545b6ed0d0c1788ca9369a847750f5652ffa0ca7f7b7d3
    - 8afd6c0636c5d70ac0622396268786190a428635e9cf28ab23add939377727b0
    slug: php-rat-deployment
    tactic: execution
    techniques:
    - T1059
  - name: Automated and Manual Discovery
    observables:
    - Get-NetNeighbor -AddressFamily IPv4
    - systeminfo /FO CSV
    - tasklist /svc
    - Get-Service
    - Get-PSDrive
    - '[Security.Principal.WindowsIdentity]::GetCurrent()'
    - '[adsiSearcher]"(ObjectClass=computer)"'
    - 'nltest /dclist:'
    - net user %USERNAME% /domain
    slug: automated-and-manual-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1057
    - T1018
    - T1087
    - T1069
    - T1016
  - name: Registry Run Key Persistence
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - php.exe AppData\Roaming\php\wefs.cfg
    slug: persistence-registry-run
    tactic: persistence
    techniques:
    - T1547.001
  - name: Cloudflare Tunnel C2
    observables:
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - evidence-deleted-procedure-bringing.trycloudflare.com
    - nowhere-locked-manor-hs.trycloudflare.com
    - ranked-accordingly-ab-hired.trycloudflare.com
    - 64.95.12.71
    - 184.95.51.165
    slug: c2-cloudflare-tunneling
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1572
  - name: Lateral Movement via RDP
    observables:
    - Remote Desktop Protocol usage
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: The Interlock ransomware group utilizes KongTuke web-injects to deliver
    a PHP-based RAT through a multi-stage PowerShell stager executed via social engineering.
    The malware conducts extensive automated and manual reconnaissance of system profiles
    and Active Directory, maintains persistence through registry Run keys, and leverages
    Cloudflare Tunnels for resilient C2 before facilitating lateral movement via RDP.
series:
  index: 2
  slug: kongtuke-filefix-leads-to-new-interlock-rat-variant
  title: KongTuke FileFix Leads to New Interlock RAT Variant
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Interlock RAT C2 and RDP Lateral Movement

This hunt identifies the post-exploitation phases of the Interlock RAT campaign, specifically targeting command-and-control communication through Cloudflare Tunnel subdomains and hardcoded fallback IP addresses. It correlates these network indicators with behavioral evidence of PHP execution from user-writable paths and subsequent RDP lateral movement originating from the beachhead hosts. The hunt provides a holistic view of the intrusion lifecycle from the first beacon to internal spread.

## dns-c2-leads
<!-- DNS leads to Cloudflare Tunnels -->
Identify potential beachheads by resolution of known C2 domains.

```sqlite target=endpoint role=triage params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving attacker subdomains indicate a likely beachhead. Silence
  proves no resolution attempts to these specific subdomains occurred.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS resolution_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## investigate-activity
<!-- Gather multi-surface evidence -->
parallel:
- → fallback-network-connections
- → php-execution-indicators
- → anomalous-rdp-logons
join: → agent-triage

## fallback-network-connections
<!-- Connections to fallback C2 IPs -->
Check for direct IP connections to hardcoded fallback C2 infrastructure.

```sqlite target=network role=triage params=(fallback_ips=fallback_ips, lookback_days=lookback_days)
~~~yaml
expected: Network connections to hardcoded IPs correlate with the report's fallback
  mechanism.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{fallback_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## php-execution-indicators
<!-- PHP execution with config files -->
Find behavioral signs of the PHP Interlock variant executing from roaming profiles.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: PHP executing with .cfg files from a user profile is highly suspicious in
  this context.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\roaming\php\php.exe' OR LOWER(process_name) = 'php.exe') AND (LOWER(process_cmd_line) LIKE '%.cfg%' OR LOWER(process_cmd_line) LIKE '%extension=zip%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## anomalous-rdp-logons
<!-- Anomalous RDP logon prevalence -->
Identify rare RDP logons; the agent will filter these for movement originating from beachheads.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare RDP logons reveal lateral movement. The agent will compare these source
  IPs to the identified C2 beachheads.
prevalence:
  by: dst_endpoint_name
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- activity_id
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, actor_user_name, src_endpoint_ip, MIN(time) AS first_seen, COUNT(*) AS logon_count FROM hb_auth_signin WHERE (LOWER(auth_protocol) = 'rdp' OR activity_id = 1) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name, actor_user_name, src_endpoint_ip HAVING logon_count < 5
```

## agent-triage
<!-- Correlate C2 and movement -->
```agent target=hunter
cite: required
context:
- dns-c2-leads
- fallback-network-connections
- php-execution-indicators
- anomalous-rdp-logons
max_iterations: 4
objective: Determine if any host exhibits Cloudflare C2 traffic or fallback IP connections,
  and whether those hosts coincide with the Interlock RAT PHP execution pattern or
  initiate RDP lateral movement.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows from all four queries.
tools:
- endpoint
- identity
- network
```

## route-infection
<!-- Route on infection verdict -->
if~: "The triage verdict is malicious for at least one host, indicating confirmed C2 traffic and suspicious lateral movement." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-investigation
unavailable: → manual-investigation (blind_spot: limited-rdp-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host using the endpoint agent and revoke active user sessions.
```
→ manual-investigation

## manual-investigation
<!-- Manual investigation -->
```manual target=analyst
Review the process logs on isolated hosts for evidence of NodeSnake (Node.js variant) deployment. Map all accounts used for RDP from the beachheads.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document impacted systems and recommend blocks for the identified subdomains. Promote the PHP behavioral query to a standing rule.
```
→ end
