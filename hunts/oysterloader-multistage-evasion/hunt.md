---
analysis: 'A simple detection rule might flag on_disk=0 or specific lures, but this
  hunt correlates the entire lifecycle: from the MSI lure to the rare in-memory execution
  and the resulting HTTP C2 patterns, reducing false positives from legitimate JIT
  processes.'
blind_spots:
- id: no-endpoint-visibility
  question: Can we see if a process is running without a backing file?
  requires: EDR process reporting with on_disk status
  risk: Without hb_process_activity.on_disk, we cannot reliably detect the shellcode
    injection and LZMA unpacking stages.
  stage: shellcode-lzma-decompression
- id: encrypted-http-traffic
  question: Are we missing HTTP metadata due to encryption?
  requires: TLS inspection or endpoint HTTP logging
  risk: If C2 traffic is purely over TLS without inspection, the url_path analysis
    in hb_http_activity will be empty.
  stage: downloader-environment-verification-c2
coverage:
- stage: initial-execution-msi
  status: covered
  steps:
  - suspicious-software-installations
- stage: textshell-packer-obfuscation
  status: covered
  steps:
  - in-memory-execution-leads
- stage: shellcode-lzma-decompression
  status: covered
  steps:
  - in-memory-execution-leads
  - rare-in-memory-processes
- stage: downloader-environment-verification-c2
  status: covered
  steps:
  - suspicious-http-checkins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: OysterLoader is an active threat used by Rhysida ransomware affiliates.
    It uses advanced evasive techniques (API hammering, custom LZMA) that bypass traditional
    signature-based AV, making behavioral hunting for in-memory execution essential.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trojanized MSI installers (impersonating tools like
  PuTTY or WinSCP) to execute a multi-stage loader that performs API hammering and
  custom LZMA decompression in-memory before checking in to a C2 server.
labels:
- hunt
- attack.t1566.002
- attack.t1204.002
- attack.t1027
- attack.t1129
- attack.t1055
- attack.t1071.001
- attack.t1090.003
name: OysterLoader Multi-Stage Evasive Infection
parameters:
  impersonated_apps:
    default:
    - PuTTY
    - WinSCP
    - Google Authenticator
    - ChatGPT
    - Ai software
    description: Common software names used as lures for OysterLoader MSIs.
    from:
      kind: article
      observed: '2024-06-01'
      ref: sekoia-oysterloader-2024
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts if needed.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially target all Windows workstations. If the software
  lures list is broad, focus on hosts with recent software installations via msiexec.
references:
- name: 'OysterLoader unmasked: the multi-stage evasion loader'
  url: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
related:
- hunt: gootloader-powershell-behavior
  reason: Gootloader is a known distribution vector for OysterLoader; a sibling hunt
    for Gootloader's PowerShell patterns provides earlier detection.
  relation: precedes
scenario:
  stages:
  - name: Trojanized MSI Installer Execution
    observables:
    - MSI installers impersonating PuTTy
    - MSI installers impersonating WinSCP
    - MSI installers impersonating Google Authenticator
    - MSI installers impersonating AI software
    slug: initial-execution-msi
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.002
  - name: TextShell Packer Evasion
    observables:
    - API hammering using hundreds of legitimate GDI calls
    - IsDebuggerPresent check for infinite loop trap
    - Dynamic API resolution using custom 32-bit hashing (h * 0x2001 + ord(ch))
    - NtAllocateVirtualMemory with RWX permissions
    slug: textshell-packer-obfuscation
    tactic: defense-evasion
    techniques:
    - T1027
    - T1129
    - T1497.001
  - name: Custom Shellcode and LZMA Decompression
    observables:
    - Custom LZMA range decoder implementation
    - Relocation fixups for E8 and E9 opcodes
    - VirtualProtect transition of memory regions to executable state
    slug: shellcode-lzma-decompression
    tactic: execution
    techniques:
    - T1140
    - T1055
  - name: Environmental Profiling and C2 Check-in
    observables:
    - Language verification checks
    - Keyboard layout identification
    - C2 communication check-in over HTTP
    - Bespoke LZMA-encoded downloader payload
    slug: downloader-environment-verification-c2
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
    - T1614.001
  summary: OysterLoader (also known as CleanUp or Broomstick) is a multi-stage C++
    loader used by the Rhysida ransomware group, typically distributed via fake software
    websites and trojanized MSI installers. The infection chain utilizes the TextShell
    packer for heavy API hammering and a custom LZMA decompression routine to deploy
    an intermediate downloader that profiles the environment before establishing C2.
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


# OysterLoader Multi-Stage Evasive Infection

This hunt targets the behavior of OysterLoader (aka CleanUp or Broomstick), a stealthy C2 loader associated with Rhysida ransomware. It begins by identifying hosts with suspicious software installations via MSI, then pivots to detect in-memory execution signatures (processes not on disk) following an installer launch. It corroborates this with prevalence analysis of injected processes and outbound network traffic patterns characteristic of an initial downloader check-in.

## suspicious-software-installations
<!-- Suspicious MSI software installations -->
Identify hosts that have recently installed software commonly used as lures for OysterLoader.

```sqlite target=endpoint role=scoping params=(impersonated_apps=impersonated_apps)
~~~yaml
expected: A list of hosts and the specific software lures found. Benign installs of
  these tools are expected; the next steps filter for malicious activity.
reads:
- device_hostname
- install_path
- package_name
- package_version
- provider
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (instr(',' || '{{impersonated_apps}}' || ',', ',' || package_name || ',') > 0 OR LOWER(package_name) LIKE '%authenticator%' OR LOWER(package_name) LIKE '%ai%') AND provider = 'osquery'
```

## in-memory-execution-leads
<!-- In-memory execution following MSI or user launch -->
Find processes that are no longer on disk (on_disk = 0), which is a high-fidelity indicator of shellcode injection used by OysterLoader stages.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes executing from memory without a corresponding file on disk. This
  indicates successful injection (Stage 2/3).
reads:
- device_hostname
- on_disk
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE on_disk = 0 AND (LOWER(parent_process_name) LIKE '%msiexec.exe' OR LOWER(parent_process_name) LIKE '%explorer.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Analyze Prevalence and Network Activity -->
parallel:
- → rare-in-memory-processes
- → suspicious-http-checkins
join: → triage-agent

## rare-in-memory-processes
<!-- Fleet-wide prevalence of in-memory code -->
Stack-count the combination of process and user for in-memory execution to find anomalies.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Malicious injection typically occurs on a small subset of hosts compared
  to legitimate browser-related JIT or update processes.
prevalence:
  by: device_hostname
  key:
  - process_name
  - user_name
  rare_below: 4
reads:
- device_hostname
- on_disk
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, user_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE on_disk = 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, user_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## suspicious-http-checkins
<!-- Suspicious HTTP downloader check-ins -->
Look for HTTP requests that follow the OysterLoader check-in pattern, often using rare paths or non-standard user agents.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests from suspected hosts to PHP endpoints or short random paths,
  which matches the Stage 4 downloader behavior.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND http_method = 'GET' AND (url_path LIKE '%.php' OR url_path LIKE '%.dat' OR length(url_path) < 10) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze OysterLoader infection chain -->
```agent target=hunter
cite: required
context:
- suspicious-software-installations
- in-memory-execution-leads
- rare-in-memory-processes
- suspicious-http-checkins
max_iterations: 4
objective: Determine if any host shows evidence of trojanized software installation
  followed by in-memory process execution and suspicious HTTP traffic.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  relevant rows from software, process, and network surfaces.
tools:
- endpoint
- web
```

## logic-route
<!-- Route on Triage Result -->
if~: "The triage verdict is malicious for at least one host, citing on_disk=0 processes and HTTP check-ins." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-visibility)
else: → close-out

## isolate-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke credentials for the user active during the MSI installation. Collect the MSI file and memory dumps for the identified PIDs.
```
→ analyst-review

## analyst-review
<!-- Manual Verification and Tuning -->
```manual target=analyst
Verify the MSI source and the in-memory process. Determine if the software lure is a new legitimate tool or part of an campaign. Document findings for the detection engineering team.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Report negative findings. Confirm that no suspicious on_disk=0 processes following MSI activity were found in the lookback window.
```
→ end
