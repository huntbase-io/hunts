---
analysis: A simple detection rule might fire on encoded PowerShell. This hunt is superior
  because it correlates those behaviors with unique registry failover logic and DDR
  network patterns, providing a multi-surface view that identifies the persistent
  configuration used by the actor that static rules often miss.
blind_spots:
- id: visibility-gap
  question: whether GammaLoad has established persistence on hosts that do not report
    registry telemetry
  requires: endpoint agent reporting on the registry surface
  risk: A host with registry persistence but no active agent reporting will not be
    identified, leaving a persistent foothold for the adversary.
  stage: gammaload-vbs-discovery-c2
- id: ads-telemetry-truncation
  question: whether the execution of an Alternate Data Stream is correctly logged
    by the endpoint telemetry provider
  requires: hb_scheduled_job reporting full ADS paths
  risk: If the agent truncates the colon in the path or fails to report ADS execution
    within the task command line, the primary persistence mechanism remains invisible.
  stage: gammaload-persistence-ads
coverage:
- stage: gammaload-vbs-discovery-c2
  status: covered
  steps:
  - gammaload-registry-c2
  - gammaload-dns-ddr
- stage: gammaload-persistence-ads
  status: covered
  steps:
  - gammaload-persistence-task
- stage: gammaload-powershell-loader
  status: covered
  steps:
  - gammaload-persistence-task
  - triage-agent
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: GammaLoad is the bridge between initial access and final payload
    delivery for Gamaredon. Detecting this stage allows for containment before espionage
    tools like GammaSteel are deployed. A negative result provides confidence that
    the environment is not staged for FSB-backed espionage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established persistent access using GammaLoad VBScripts
  that manage C2 configuration via registry keys in HKCU\Console and execute via a
  high-frequency task invoking an Alternate Data Stream.
labels:
- hunt
- attack.t1059.001
- attack.t1090.003
- attack.t1053.005
- attack.t1041
name: Gamaredon GammaLoad Multi-stage Persistence and Execution
parameters:
  ddr_domains:
    default:
    - te.legra.ph
    - telegram.me
    - check-host.net
    - www.huaweicloud.com
    - yggjf81487.workers.dev
    - selltosell.ru
    - trycloudflare.com
    - csxvl00328.workers.dev
    - dayobtvoyu.ru
    description: Dead Drop Resolver and staging domains identified in the report.
    from:
      kind: article
      observed: '2026-01-23'
      ref: Sekoia GammaLoad
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-01-23'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-01-23'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: This hunt targets the Windows fleet, where GammaLoad registry and task
  mechanisms operate. Focus first on workstations with direct internet access, as
  they are the primary targets for initial access and DDR-based C2 discovery.
references:
- name: "Sekoia.io \u2014 FSB Matryoshka: Gamaredon GammaLoad"
  url: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
related:
- hunt: gamaredon-gammasteel-stealer-detection
  reason: GammaLoad is the delivery mechanism for the GammaSteel stealer analyzed
    in the next stage of the attack chain.
  relation: follows
scenario:
  stages:
  - name: VBScript Host Fingerprinting and C2 Discovery
    observables:
    - 'Registry keys: HKCU\Console\HistoryURL, HKCU\Console\WindowsResponby, HKCU\Console\CloudURL,
      HKCU\Console\IpURL'
    - 'Domains: te.legra.ph, telegram.me, check-host.net'
    - 'User-Agent separators: ##, !!, ??, ==, ::'
    - 'Anomalous HTTP GET request with Content-Length: 2114'
    - VBScript ExecuteGlobal() function
    - Fingerprinting of %COMPUTERNAME% and system drive serial number
    slug: gammaload-vbs-discovery-c2
    tactic: discovery
    techniques:
    - T1059.001
    - T1090.003
    - T1041
  - name: Persistence via Scheduled Task and ADS
    observables:
    - 'File path: %TEMP%\:divedz0f (Alternate Data Stream)'
    - 'Scheduled task name: \Windows\ApplicationData\DsSvcCleanup'
    - 'Task frequency: every 11 minutes'
    - 'Domain: dayobtvoyu.ru'
    slug: gammaload-persistence-ads
    tactic: persistence
    techniques:
    - T1053.005
  - name: Encoded PowerShell In-Memory Loader
    observables:
    - 'Process command: powershell.exe -nol -nop -encodedcommand'
    - 'Script method: [System.Net.ServicePointManager]::ServerCertificateValidationCallback'
    - 'Script method: $webClient.DownloadString'
    - XOR-decryption of downloaded payload
    - Execution of payload in-memory
    slug: gammaload-powershell-loader
    tactic: execution
    techniques:
    - T1059.001
  summary: Gamaredon (UAC-0010) uses the GammaLoad toolset, a multi-stage infection
    chain consisting of VBScript and PowerShell loaders. The malware fingerprints
    hosts, resolves C2 infrastructure via legitimate dead-drop services like Telegram
    and Telegraph, and maintains persistence using scheduled tasks that execute code
    stored in NTFS Alternate Data Streams.
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


# Gamaredon GammaLoad Multi-stage Persistence and Execution

GammaLoad is a modular VBScript loader used by Gamaredon (UAC-0010) for persistence and staging. It uses a failover mechanism for C2 discovery, storing active URLs in the Windows registry under HKCU\Console and using Dead Drop Resolvers (DDR) such as Telegraph and Telegram. This hunt identifies specific registry artifacts, correlates them with DNS requests to staging domains, and detects the 11-minute scheduled task used to launch a third-stage PowerShell loader from an Alternate Data Stream. By fanning out across registry, persistence, and network surfaces, the hunt provides a complete view of the GammaLoad infection chain that evades simple detection rules.

## scope-windows-hosts
<!-- Scope Windows Hosts -->
Identify active Windows assets in the environment as the primary targets for GammaLoad.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Windows hostnames active within the window. Silence indicates
  no Windows hosts are enrolled or active, limiting the scope of this hunt.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE LOWER(platform) = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## fan-out-corroboration
<!-- Parallel Evidence Gathering -->
parallel:
- → gammaload-registry-c2
- → gammaload-persistence-task
- → gammaload-dns-ddr
join: → triage-agent

## gammaload-registry-c2
<!-- GammaLoad Registry C2 Configuration -->
Identify hosts where GammaLoad has cached its active C2 infrastructure in HKCU\Console keys.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts with URL or IP address strings stored in the Console registry keys.
  Silence suggests no registry-based C2 caching occurred in the window.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\console\%' AND (LOWER(reg_value_data) LIKE 'http%' OR reg_value_data GLOB '*[0-9].[0-9]*') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gammaload-persistence-task
<!-- Persistence via Task and ADS -->
Detect the high-frequency scheduled task used to execute the GammaLoad payload from an Alternate Data Stream.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A scheduled task executing from a Temp path ADS or a script interpreter
  targeting the Temp directory. Silence provides evidence of absence for this specific
  persistence mechanism.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_cmd_line
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, job_cmd_line, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%\temp\:%' OR ((LOWER(job_cmd_line) LIKE '%cscript%' OR LOWER(job_cmd_line) LIKE '%wscript%') AND LOWER(job_cmd_line) LIKE '%\temp\%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gammaload-dns-ddr
<!-- Staging and DDR DNS Activity -->
Identify network resolution of the legitimate services abused by GammaLoad for C2 discovery.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, ddr_domains=ddr_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS requests to Telegraph, Telegram, or Check-Host on the same hosts exhibiting
  registry or task persistence. Silence suggests no resolution of known DDR domains.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{ddr_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-agent
<!-- Triage GammaLoad Infection -->
```agent target=hunter
cite: required
context:
- gammaload-registry-c2
- gammaload-persistence-task
- gammaload-dns-ddr
max_iterations: 5
objective: Correlate registry C2 storage, high-frequency scheduled tasks using Alternate
  Data Streams, and DNS resolution of Dead Drop domains to confirm active GammaLoad
  infection.
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  specific registry values and task command lines.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and prepare for forensic evidence collection.
```
→ forensic-review

## forensic-review
<!-- Forensic Review -->
```manual target=analyst
Collect the ADS content from %TEMP%\:divedz0f and extract the C2 URLs from the HKCU\Console keys. Inspect script logs for any XOR-decrypted final payloads.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record which hosts were impacted and the specific C2 indicators observed. Recommend promoting the HKCU\Console URL storage query to a standing detection rule.
```
→ end
