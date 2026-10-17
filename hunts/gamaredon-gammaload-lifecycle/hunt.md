---
analysis: This hunt uses a phased approach to link registry configuration caching
  with persistent ADS-based tasks and insecure PowerShell execution. A single rule
  cannot easily correlate these events across multiple surfaces over a persistent
  11-minute execution cycle.
blind_spots:
- id: no-registry-visibility
  question: whether C2 configuration was cached in the user's registry hive
  requires: logging for HKCU registry hive modifications
  risk: Registry writes to user hives are often missed by default telemetry, hiding
    the persistent configuration mechanism.
  stage: vbs-c2-discovery-registry
- id: no-ads-telemetry
  question: whether the dropper wrote the payload to an ADS under %TEMP%
  requires: hb_file_activity tracking of NTFS Alternate Data Streams
  risk: Without NTFS stream visibility, the presence of the hidden dropper payload
    cannot be confirmed through file events alone.
  stage: persistence-ads-task
coverage:
- stage: vbs-c2-discovery-registry
  status: covered
  steps:
  - registry-c2-caching
  - ddr-http-discovery
- stage: persistence-ads-task
  status: covered
  steps:
  - ads-scheduled-tasks
- stage: powershell-memory-loader
  status: covered
  steps:
  - powershell-memory-loaders
- stage: c2-exfiltration-anomalies
  status: covered
  steps:
  - ddr-http-discovery
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: GammaLoad is the persistent gateway for Gamaredon's stealers and
    wipers. Identifying it prevents long-term espionage and potentially destructive
    actions.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-stage VBScript loaders to maintain persistent
  access by caching C2 configuration in HKCU registry keys and executing payloads
  from Alternate Data Streams via scheduled tasks.
labels:
- hunt
- attack.t1059.001
- attack.t1053.005
- attack.t1041
- attack.t1555
name: Gamaredon GammaLoad Intrusion Lifecycle
parameters:
  ddr_domains:
    default:
    - te.legra.ph
    - telegram.me
    - check-host.net
    - huaweicloud.com
    - workers.dev
    - trycloudflare.com
    description: Known Dead Drop Resolvers and staging domains used by GammaLoad.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  path_keywords:
    default:
    - follow
    - sat
    - component
    - misfortune
    - endanger
    - menace
    - reproof
    - artistic
    - list
    - mosquito
    description: Keywords typically found in the randomized URL paths of Gammaload.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia
    type: list[string]
  scope_hosts:
    default: []
    description: Target hosts for the hunt; leave empty to scan the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with general Windows workstations. Focus on hosts showing unusual
  registry activity in the HKCU\Console path.
references:
- name: "FSB\u2019s matryoshka #2/3: Gamaredon's Gammaload Malware"
  url: https://www.sekoia.com/blog/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload
related:
- hunt: gamaredon-gammaphish-initial-access
  reason: GammaPhish is the initial delivery mechanism for GammaLoad.
  relation: precedes
- hunt: gamaredon-gammasteel-data-theft
  reason: GammaLoad is used to deploy the final GammaSteel data stealer.
  relation: follows
scenario:
  stages:
  - name: VBScript C2 Discovery and Registry Caching
    observables:
    - 'Registry keys: HKCU\Console\HistoryURL, HKCU\Console\WindowsResponby, HKCU\Console\CloudURL,
      HKCU\Console\IpURL'
    - Fingerprinting via %COMPUTERNAME% and drive serial number
    - 'Hardcoded DDR URLs: te.legra.ph/fxpppscdlw-12-27, telegram.me/s/akatachi, check-host.net/ip-info?host=snterval.selltosell.ru'
    - 'User-Agent separators: ##, !!, ??, ==, ::'
    slug: vbs-c2-discovery-registry
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via ADS and Scheduled Task
    observables:
    - 'File path using ADS: %TEMP%\:divedz0f'
    - 'Scheduled task name: \Windows\ApplicationData\DsSvcCleanup'
    - 'Task frequency: every 11 minutes'
    - 'Hardcoded C2s written to registry: vids-road-christina-guards.trycloudflare.com,
      172.86.72.243'
    slug: persistence-ads-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: In-Memory PowerShell Execution
    observables:
    - 'Command line: powershell.exe -nol -nop -encodedcommand'
    - 'Script content: [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}'
    - 'Script content: $webClient.DownloadString'
    - Use of ROT13 de-obfuscation in parent VBScript
    slug: powershell-memory-loader
    tactic: execution
    techniques:
    - T1059.001
  - name: C2 Communication and Fingerprint Exfiltration
    observables:
    - 'HTTP GET requests with Content-Length: 2114'
    - 'URL path keywords: sat, component, misfortune, endanger, menace, reproof, artistic,
      mosquito'
    - 'Randomized file extensions: .ato, .spl, .rmvb, .gtp, .dbc, .kfx, .brk'
    - Fingerprint data embedded in User-Agent header
    slug: c2-exfiltration-anomalies
    tactic: exfiltration
    techniques:
    - T1041
  summary: Gamaredon (UAC-0010) uses GammaLoad, a modular series of VBScript loaders,
    to maintain persistence and deploy follow-on stealers. The infection chain utilizes
    registry-based configuration caching, Dead Drop Resolvers on legitimate platforms,
    and Alternate Data Streams paired with scheduled tasks to execute obfuscated PowerShell
    payloads.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Gamaredon GammaLoad Intrusion Lifecycle

This hunt targets the GammaLoad malware used by Gamaredon (UAC-0010). The malware is characterized by a multi-stage execution chain that fingerprints hosts and uses Dead Drop Resolvers (DDR) to update C2 configuration stored in the HKCU\Console registry hive. It establishes persistence by writing payloads to Alternate Data Streams (ADS) and creating scheduled tasks to execute them. The hunt follows this lifecycle from initial C2 discovery through to the regular execution of obfuscated PowerShell memory loaders.

## scope-windows-software
<!-- Scope Windows endpoints -->
Identify Windows assets where the VBScript and PowerShell lifecycle is expected to run.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of Windows hostnames. Silence indicates no Windows systems are in
  the inventory.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%windows%' OR LOWER(vendor_name) LIKE '%microsoft%')
```

## early-staging-fan-out
<!-- Investigate initial staging -->
parallel:
- → registry-c2-caching
- → ddr-http-discovery
join: → early-stage-agent

## registry-c2-caching
<!-- Registry configuration caching -->
Detect VBScripts storing C2 URLs in HKCU\Console registry keys, a signature Gammaload behavior.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific registry keys in the Console hive being updated with URL data.
  Prevalence highlights rare C2 infrastructure.
prevalence:
  by: device_hostname
  key:
  - reg_target
  - reg_value_data
  rare_below: 5
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, reg_target, reg_value_data, COUNT(*) AS write_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\console\%' AND (instr(LOWER(reg_target), 'historyurl') > 0 OR instr(LOWER(reg_target), 'windowsresponby') > 0 OR instr(LOWER(reg_target), 'cloudurl') > 0 OR instr(LOWER(reg_target), 'ipurl') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, reg_target, reg_value_data HAVING COUNT(DISTINCT device_hostname) <= 5
```

## ddr-http-discovery
<!-- DDR lookups and path anomalies -->
Identify HTTP requests targeting DDR domains or using GammaLoad randomized path keywords.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ddr_domains=ddr_domains, path_keywords=path_keywords)
~~~yaml
expected: Requests to Telegram/Telegraph services or paths using report-matched keywords.
  Large 200 responses may indicate payload delivery.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- status_code
- response_bytes
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, status_code, response_bytes, time FROM hb_http_activity WHERE (instr(',' || '{{ddr_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR instr(',' || '{{path_keywords}}' || ',', ',' || LOWER(REPLACE(url_path, '/', '')) || ',') > 0 OR (status_code = 200 AND response_bytes > 1000) OR (status_code = 404 AND LOWER(url_path) LIKE '%.php%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-agent
<!-- Evaluate early staging -->
```agent target=hunter
cite: required
context:
- registry-c2-caching
- ddr-http-discovery
max_iterations: 4
objective: Determine if any host shows both registry configuration caching in HKCU\Console
  and matching HTTP traffic to DDR domains or path keywords.
success_criteria: A verdict citing specific hosts and their correlated registry/HTTP
  rows.
tools:
- endpoint
- web
```

## persistence-and-scripting-fan-out
<!-- Investigate persistence and payload execution -->
parallel:
- → ads-scheduled-tasks
- → powershell-memory-loaders
join: → full-chain-agent

## ads-scheduled-tasks
<!-- ADS-based persistence -->
Detect scheduled tasks configured to execute Alternate Data Streams, which GammaLoad uses for persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A task named DsSvcCleanup or a command line executing a file containing
  a colon (indicating an ADS).
reads:
- device_hostname
- job_name
- job_cmd_line
- job_definition_path
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_definition_path, time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%dssvccleanup%' OR job_cmd_line LIKE '%:%' OR LOWER(job_cmd_line) LIKE '%\temp\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-memory-loaders
<!-- PowerShell memory loaders -->
Identify PowerShell scripts that disable certificate validation and download strings, typical of GammaLoad's third stage.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks performing insecure HTTPS downloads for in-memory execution.
reads:
- device_hostname
- script_content
- process_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, script_content, process_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%servercertificatevalidationcallback%' AND LOWER(script_content) LIKE '%downloadstring%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## full-chain-agent
<!-- Synthesize full GammaLoad chain -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- ads-scheduled-tasks
- powershell-memory-loaders
max_iterations: 5
objective: Analyze the early staging results alongside the persistent task and PowerShell
  activity to confirm a persistent GammaLoad infection.
success_criteria: A final verdict of malicious | suspicious | benign per host citing
  the full chain of evidence.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent confirms malicious activity involving persistent tasks and C2 caching on a host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-registry-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate suspicious PowerShell processes, and remove the DsSvcCleanup task. Collect the ADS payload from %TEMP% for analysis.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review registry data in HKCU\Console. Verify the presence of the ADS in %TEMP%. Check for follow-on stealer activity (GammaSteel).
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the outcome for each host. Record any blind spots encountered.
```
→ end
