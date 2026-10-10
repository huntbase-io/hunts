---
analysis: A single rule for reconnaissance commands might be noisy, but this hunt
  correlates those commands with the arrival of a rare PHP binary in a user-writable
  path and DNS callbacks, reducing false positives in varied environments.
blind_spots:
- id: no-process-audit
  question: Which hosts are not currently reporting process command lines?
  requires: hb_process_activity with command lines
  risk: A host that does not audit process creation or command lines will not show
    the reconnaissance behavior or the PHP arguments.
  stage: php-rat-deployment
- id: ephemeral-trycloudflare-domains
  question: Did the actor rotate domains before the hunt began?
  requires: hb_dns_activity
  risk: TryCloudflare subdomains are ephemeral; if the actor has rotated to new ones
    not listed in the parameters, the DNS step will return zero rows.
  stage: powershell-stager-execution
coverage:
- stage: powershell-stager-execution
  status: covered
  steps:
  - enrichment-dns-c2
  - agent-early-triage
- stage: php-rat-deployment
  status: covered
  steps:
  - scoping-php-in-appdata
  - baseline-rare-php-paths
  - enrichment-config-hashes
- stage: automated-and-manual-discovery
  status: covered
  steps:
  - detection-recon-commands
- stage: persistence-registry-run
  status: covered
  steps:
  - triage-registry-persistence
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: initial-access-web-inject
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: c2-cloudflare-tunneling
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
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
  justification: Interlock RAT is a gateway to ransomware; confirming its absence
    across the estate is a priority for business continuity and risk mitigation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed a PHP-based RAT into user-writable directories
  via a PowerShell stager and is conducting automated system reconnaissance to map
  the environment.
labels:
- hunt
- attack.t1059.001
- attack.t1105
- attack.t1082
- attack.t1057
- attack.t1018
- attack.t1087
- attack.t1069
- attack.t1016
- attack.t1547.001
name: Interlock RAT Endpoint Execution and Reconnaissance
parameters:
  c2_domains:
    default:
    - deadly-programming-attorneys-our.trycloudflare.com
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - evidence-deleted-procedure-bringing.trycloudflare.com
    - nowhere-locked-manor-hs.trycloudflare.com
    - ranked-accordingly-ab-hired.trycloudflare.com
    description: C2 domains observed in Interlock RAT campaigns.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rat_config_hashes:
    default:
    - 28a9982cf2b4fc53a1545b6ed0d0c1788ca9369a847750f5652ffa0ca7f7b7d3
    - 8afd6c0636c5d70ac0622396268786190a428635e9cf28ab23add939377727b0
    description: SHA256 hashes of the Interlock RAT configuration files.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[hash]
  scope_hosts:
    default: []
    description: Optional list of hosts to restrict the hunt to.
    type: list[host]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Exclude developer workstations where PHP may be legitimately running from
  user-specific paths (e.g., via Composer). Focus on general user workstations.
references:
- name: "The DFIR Report \u2014 KongTuke FileFix Leads to New Interlock RAT Variant"
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-rat-c2-tunnel-analysis
  reason: Cloudflare Tunnel traffic analysis requires high-fidelity network or proxy
    logs which are handled in a separate hunt.
  relation: out-of-scope-alternative
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
  index: 1
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
tlp: clear
type: investigation
---


# Interlock RAT Endpoint Execution and Reconnaissance

This hunt identifies the Interlock RAT PHP variant, a tool used by the Interlock ransomware group as a successor to NodeSnake. We look for the arrival of the PowerShell stager, the deployment of PHP binaries into Roaming AppData, the subsequent reconnaissance commands used to profile the host, and the persistence mechanisms used to survive reboots. The hunt uses a phased approach: first identifying the initial execution and rare interpreter paths, then pivoting to follow-on discovery and persistence behaviors seen in the June 2025 campaign.

## scoping-php-in-appdata
<!-- Scope hosts with PHP in AppData -->
Identify hosts running PHP executables from the user Roaming profile, which is the hallmark of the Interlock RAT delivery method.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts where PHP was executed from a non-standard, user-writable
  path. Silence suggests this specific delivery hasn't occurred.
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\roaming\php\php.exe' OR LOWER(process_name) LIKE '%\appdata\roaming\php\php.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early
<!-- Analyze early stage arrival -->
parallel:
- → baseline-rare-php-paths
- → enrichment-dns-c2
join: → agent-early-triage

## baseline-rare-php-paths
<!-- Baseline rare PHP binary paths -->
Stack-count PHP binary paths across the fleet to identify outliers running from user-writable directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: PHP executables seen on very few hosts, particularly those under user profile
  paths. Normal installations under Program Files will be common.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 5
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\php.exe' OR LOWER(process_name) = 'php.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING host_count < 5
```

## enrichment-dns-c2
<!-- DNS callbacks to stager C2 -->
Match host DNS activity against the Cloudflare Tunnel domains associated with the Interlock campaign.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: DNS lookups for known C2 domains or generic Cloudflare Tunnel patterns that
  coincide with rare PHP execution.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.trycloudflare.com') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage early infection stage -->
```agent target=hunter
cite: required
context:
- baseline-rare-php-paths
- enrichment-dns-c2
max_iterations: 3
objective: Identify hosts where PHP.exe arrived in a user path and immediately communicated
  with Cloudflare Tunnel domains.
success_criteria: A verdict citing specific process paths and domain lookups.
tools:
- endpoint
```

## parallel-follow-on
<!-- Search for discovery and persistence -->
parallel:
- → detection-recon-commands
- → triage-registry-persistence
- → enrichment-config-hashes
join: → agent-follow-on-synthesis

## detection-recon-commands
<!-- Post-infection reconnaissance commands -->
Identify the automated system profiling commands typically run by the Interlock RAT upon successful deployment.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A sequence of PowerShell or CMD commands profiling the network, system,
  and user context, often spawned from the PHP process.
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%get-netneighbor%' OR LOWER(process_cmd_line) LIKE '%systeminfo /fo csv%' OR LOWER(process_cmd_line) LIKE '%tasklist /svc%' OR LOWER(process_cmd_line) LIKE '%[security.principal.windowsidentity]%' OR LOWER(process_cmd_line) LIKE '%[adsisearcher]%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-registry-persistence
<!-- RAT Run key persistence -->
Locate the Registry Run keys used by the RAT to ensure persistence across reboots, specifically pointing to the PHP interpreter and a config file.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry values in the Run key pointing to the PHP executable in AppData,
  which confirms a persistent installation.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(reg_target) LIKE '%\currentversion\run%' AND LOWER(reg_value_data) LIKE '%php.exe%' AND LOWER(reg_value_data) LIKE '%.cfg%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## enrichment-config-hashes
<!-- Interlock config file matches -->
Corroborate the findings by matching SHA256 hashes of known Interlock RAT configuration files on disk.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rat_config_hashes=rat_config_hashes)
~~~yaml
expected: File creation or access events for .cfg files with matching hashes from
  the report.
reads:
- device_hostname
- file_hash_sha256
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, file_hash_sha256, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{rat_config_hashes}}' || ',', ',' || file_hash_sha256 || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-follow-on-synthesis
<!-- Synthesize final verdict -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- detection-recon-commands
- triage-registry-persistence
- enrichment-config-hashes
max_iterations: 4
objective: Confirm Interlock RAT presence by weighing the rare PHP paths from the
  first phase against the reconnaissance commands and Registry Run keys in the second
  phase.
success_criteria: A per-host verdict of malicious | suspicious | benign citing all
  relevant rows.
tools:
- endpoint
```

## decision-route
<!-- Route on final verdict -->
if~: "the agent-follow-on-synthesis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → action-isolate
indeterminate: → task-analyst-verify
unavailable: → task-analyst-verify (blind_spot: no-process-audit)
else: → task-close-out

## action-isolate
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately through the console and alert the IR team for follow-up.
```
→ task-analyst-verify

## task-analyst-verify
<!-- Analyst verification -->
```manual target=analyst
Collect the php.exe binary and .cfg configuration files from AppData\Roaming\php. Verify the parent process of the PHP execution to find the initial stager origin.
```
→ task-close-out

## task-close-out
<!-- Close out -->
```manual target=analyst
Record all confirmed findings. Propose a new detection rule for PHP.exe running from AppData Roaming with specific extension arguments as identified in this hunt.
```
→ end
