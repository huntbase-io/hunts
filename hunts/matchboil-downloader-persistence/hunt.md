---
analysis: A simple Run-key rule might fire on many benign updaters; this hunt correlates
  folder creation, script-based delivery, WMI discovery, and rare HTTP metadata to
  reduce false positives and identify the full attack lifecycle.
blind_spots:
- id: internal-wmi-recon
  question: whether the downloader performed WMI recon without spawning wmic.exe
  requires: EDR introspection into .NET ManagementObjectSearcher calls
  risk: C# processes can call WMI directly via APIs, which bypasses command-line monitoring
    for wmic.exe, making the discovery phase invisible.
  stage: discovery-wmi-recon
- id: encrypted-c2-payload
  question: whether the hex-encoded payload was delivered in the HTTP response body
  requires: TLS inspection or endpoint memory analysis
  risk: HTTPS encryption prevents the identification of the payload inside the HTML
    script tags during transit.
  stage: c2-payload-delivery
coverage:
- stage: initial-access-phishing-script
  status: covered
  steps:
  - script-loaders
- stage: discovery-wmi-recon
  status: covered
  steps:
  - wmi-recon
- stage: c2-payload-delivery
  status: covered
  steps:
  - scoping-installation
  - c2-http-metadata
- stage: persistence-registry-task
  status: covered
  steps:
  - registry-run-persistence
  - scheduled-task-persistence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAC-0099 is a known threat to critical infrastructure and governmental
    sectors in Ukraine. The MATCHBOIL downloader is a persistent entry point that
    requires cross-surface correlation to identify definitively.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed a MATCHBOIL downloader that establishes persistence
  through Registry Run keys or scheduled tasks after performing WMI-based system discovery
  to uniquely identify the victim host.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1047
- attack.t1547.001
- attack.t1053.005
- attack.t1071.001
- command and control
- discovery
- initial access
- persistence
name: MATCHBOIL Downloader Activity and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
  target_folder_pattern:
    default: '%\\appdata\\local\\devicemonitor\\%'
    description: Path pattern for the MATCHBOIL installation directory.
    from:
      kind: article
      observed: '2026-10-08'
      ref: https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/
    type: string
  ua_length:
    default: '25'
    description: User-Agent string length observed in 2024 variants.
    from:
      kind: article
      observed: '2026-10-08'
      ref: https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize workstations and servers in the transportation
  and energy sectors. Start with a broad lookback window as MATCHBOIL has been active
  for several years.
references:
- name: "ESET Research \u2014 MATCHBOIL: New tricks, same old evil intentions"
  url: https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/
related:
- hunt: lonepage-powershell-downloader
  reason: LONEPAGE is another UAC-0099 downloader that focuses on PowerShell and specific
    C&C URL patterns.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spearphishing and VBScript Loader
    observables:
    - VBScript file manual execution
    - Archive file download from spearphishing link
    - Execution of MATCHBOIL binary
    slug: initial-access-phishing-script
    tactic: initial-access
    techniques:
    - T1566
    - T1059.001
  - name: System Discovery via WMI
    observables:
    - ManagementObjectSearcher C# class usage
    - WMI queries for CPUID
    - WMI queries for BIOS serial number
    - WMI queries for username and MAC address
    slug: discovery-wmi-recon
    tactic: discovery
    techniques:
    - T1047
  - name: C2 Communication and Payload Retrieval
    observables:
    - HTTPS requests with custom HTTP header 'SN'
    - HTTPS requests with custom HTTP header 'Count'
    - 25-character User-Agent string
    - Hex-encoded payload extracted from HTML <script> tags
    - Creation of config.ini in payload directory
    - Payload installation in %LOCALAPPDATA%\DeviceMonitor
    slug: c2-payload-delivery
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Registry and Task Persistence
    observables:
    - Registry value 'DeviceMonitor' in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - Scheduled task named 'Updates\CheckTask'
    - Two-minute execution timer (later variants)
    slug: persistence-registry-task
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  summary: The Russia-aligned UAC-0099 group uses spearphishing links to deliver an
    archive containing a VBScript loader, which subsequently installs the MATCHBOIL
    C# downloader. MATCHBOIL performs system discovery via WMI and establishes persistence
    through both registry Run keys and scheduled tasks before communicating with a
    C2 server to deploy the MATCHWOK backdoor.
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


# MATCHBOIL Downloader Activity and Persistence

This hunt targets the MATCHBOIL C# downloader, a tool used by the UAC-0099 group. The malware follows a distinct lifecycle: it is typically introduced via VBScript loaders, performs hardware-based fingerprinting using WMI, and establishes persistence in user-writable directories. The hunt uses a phased flow to first identify initial execution and discovery leads, then validates them against established persistence mechanisms and anomalous C2 HTTP metadata such as specific User-Agent lengths and configuration file drops.

## scoping-installation
<!-- Scope for installation artifacts -->
Identify hosts where the downloader's directory structure or configuration files have been created.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, target_folder_pattern=target_folder_pattern)
~~~yaml
expected: Hosts showing the creation of the DeviceMonitor folder or config.ini files
  in AppData.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE LOWER('{{target_folder_pattern}}') OR LOWER(file_name) = 'config.ini') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early
<!-- Examine early-stage leads -->
parallel:
- → script-loaders
- → wmi-recon
join: → triage-early

## script-loaders
<!-- Script-based loaders -->
Identify VBScript or PowerShell activity used to download and execute the primary MATCHBOIL binary.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing web requests or stream-to-file logic. Silence indicates
  no script-based delivery was captured.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%xmlhttp%' OR LOWER(script_content) LIKE '%adodb.stream%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## wmi-recon
<!-- WMI hardware discovery -->
Find hardware fingerprinting commands used for victim identification during C2 check-in.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: WMIC commands querying CPUID or Serial Numbers. Silence may mean discovery
  was handled via internal .NET APIs.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%wmic%' AND (LOWER(process_cmd_line) LIKE '%cpu%' OR LOWER(process_cmd_line) LIKE '%bios%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early
<!-- Triage early indicators -->
```agent target=hunter
cite: required
context:
- scoping-installation
- script-loaders
- wmi-recon
max_iterations: 3
objective: Identify hosts where file installation aligns with suspicious script activity
  or hardware discovery.
success_criteria: A list of hosts showing evidence of multiple early-stage indicators.
tools:
- endpoint
- web
```

## parallel-follow
<!-- Validate established infection -->
parallel:
- → registry-run-persistence
- → scheduled-task-persistence
- → c2-http-metadata
join: → triage-full

## registry-run-persistence
<!-- Registry Run-key persistence -->
Identify registry keys pointing to the downloader binary for persistence across reboots.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry values in HKCU Run keys pointing to user-profile paths. Silence
  means persistence may be task-based.
reads:
- device_hostname
- reg_target
- reg_value_data
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, reg_target, reg_value_name, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\currentversion\run%' AND (LOWER(reg_value_name) = 'devicemonitor' OR LOWER(reg_value_data) LIKE '%devicemonitor%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## scheduled-task-persistence
<!-- Scheduled task persistence -->
Find scheduled tasks used to maintain execution or provide periodic payload updates.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Scheduled tasks named CheckTask or pointing to the DeviceMonitor folder.
  Silence indicates no such task persistence.
reads:
- device_hostname
- job_cmd_line
- job_definition_path
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_definition_path, time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%checktask%' OR LOWER(job_definition_path) LIKE '%checktask%' OR LOWER(job_cmd_line) LIKE '%devicemonitor%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-http-metadata
<!-- C2 HTTP metadata patterns -->
Baseline User-Agent lengths to find the anomalous 25-character strings documented in MATCHBOIL C2 traffic.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, ua_length=ua_length, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare HTTP requests with 25-character User-Agents. Silence means C2 metadata
  has likely rotated.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - user_agent
  rare_below: 3
reads:
- device_hostname
- time
- url_hostname
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT url_hostname, user_agent, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_http_activity WHERE length(user_agent) = {{ua_length}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, user_agent HAVING hosts <= 3
```

## triage-full
<!-- Analyze full infection state -->
```agent target=hunter
cite: required
context:
- triage-early
- registry-run-persistence
- scheduled-task-persistence
- c2-http-metadata
max_iterations: 4
objective: Determine if any host exhibits a complete MATCHBOIL lifecycle from initial
  script execution to established persistence.
success_criteria: A final verdict citing specific rows for script, discovery, persistence,
  and network metadata.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-full verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: internal-wmi-recon)
else: → close-out

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the DeviceMonitor directory contents and the config.ini file for forensic analysis before removing the Registry Run keys or scheduled tasks.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Review the script content fragments for VBS downloader logic. Verify if the 25-character User-Agent matches the identified hosts. Document the BIOS serial numbers or CPUIDs retrieved via WMI for further threat intelligence mapping.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Record the findings. If the Registry Run-key query yielded high-confidence results with low noise, promote it to a standing detection rule.
```
→ end
