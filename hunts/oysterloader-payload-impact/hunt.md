---
analysis: A rule might catch Tor.exe; this hunt correlates the presence of rare, unsigned
  processes with bulk file encryption and credential theft behaviors on hosts with
  suspected trojanized software, providing high-confidence context.
blind_spots:
- id: incomplete-host-coverage
  question: whether infection occurred on an unmanaged or BYOD device
  requires: Endpoint agent coverage across all business units
  risk: A host without telemetry could be undergoing encryption invisibly.
  stage: final-payload-deployment
- id: variable-extension
  question: whether Rhysida used a different extension other than .rhysida
  requires: hb_file_activity with entropy or multi-extension pattern detection
  risk: If the ransomware config is changed, the extension filter will fail.
  stage: final-payload-deployment
coverage:
- stage: final-payload-deployment
  status: covered
  steps:
  - vidar-credential-theft
  - rare-process-anomalies
  - rhysida-encryption-burst
  - proxy-c2-activity
- reason: Handled in the first hunt of the series.
  stage: initial-access-trojanized-installer
  status: out_of_scope
- reason: Handled in the second hunt of the series.
  stage: downloader-c2-beaconing
  status: out_of_scope
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: textshell-packer-obfuscation
  status: out_of_scope
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: in-memory-lzma-decompression
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt prevents permanent data loss from Rhysida ransomware and
    mass credential exposure from Vidar following an OysterLoader breach.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used OysterLoader to deploy Vidar for credential harvesting
  or Rhysida for ransomware, evidenced by unauthorized access to browser data, .rhysida
  file creation, or proxy-based C2 traffic.
labels:
- hunt
- attack.t1486
- attack.t1555
- attack.t1090.003
name: 'OysterLoader Impact: Vidar and Rhysida'
parameters:
  encryption_threshold:
    default: '20'
    description: Minimum count of .rhysida files created by a single process to indicate
      a burst.
    type: number
  impersonated_packages:
    default:
    - putty
    - winscp
    - google authenticator
    - anydesk
    description: Software names OysterLoader is known to impersonate as entry vectors.
    from:
      kind: article
      observed: '2024-06-01'
      ref: sekoia-oysterloader
    type: list[string]
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
    from: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hosts with 'IT Tool' lures like PuTTy or WinSCP. Widen to the
  whole fleet if any branch returns malicious hits.
references:
- name: 'OysterLoader unmasked: the multi-stage evasion loader'
  url: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
related:
- hunt: oysterloader-initial-access
  reason: Initial access is handled by the first hunt in this series.
  relation: out-of-scope-alternative
- hunt: oysterloader-in-memory-c2
  relation: follows
scenario:
  stages:
  - name: Trojanized MSI Installer
    observables:
    - MSI files impersonating PuTTy, WinSCP, Google Authenticator
    - Fake software download websites
    - Digitally signed MSI files to appear benign
    slug: initial-access-trojanized-installer
    tactic: initial-access
    techniques:
    - T1204.002
  - name: TextShell Packer Execution
    observables:
    - API hammering using irrelevant GDI calls (RevokeDragDrop, GetDC, CreateSolidBrush,
      SetMapMode)
    - IsDebuggerPresent() check leading to infinite loop 'while(1);'
    - 'Custom hashing formula for API resolution: h = (h * 0x2001 + ord(ch))'
    - Allocation of RWX memory using NtAllocateVirtualMemory
    - Data copied in 8-byte chunks to allocated memory
    slug: textshell-packer-obfuscation
    tactic: defense-evasion
    techniques:
    - T1027
    - T1497.003
    - T1140
  - name: Shellcode LZMA Decompression
    observables:
    - Custom LZMA range decoder with parameters lc=3, lp=0, pb=2
    - Relocation fixups for relative CALL (E8) and JMP (E9) opcodes
    - VirtualProtect calls to change memory regions to executable
    - Process injection behavior (on_disk = false)
    slug: in-memory-lzma-decompression
    tactic: defense-evasion
    techniques:
    - T1055
    - T1140
  - name: Downloader Intermediate Stage
    observables:
    - HTTP communication to retrieve OysterLoader core
    - Environment verification (language check, keyboard layout identification)
    - Dynamic loading of InternetOpenW
    - Custom hashing for server communication parameters
    slug: downloader-c2-beaconing
    tactic: command-and-control
    techniques:
    - T1105
    - T1090.003
  - name: Payload Deployment (Vidar/Rhysida)
    observables:
    - Deployment of Vidar infostealer for credential theft
    - Execution of Rhysida ransomware for file encryption
    - Credential harvesting from password stores
    slug: final-payload-deployment
    tactic: impact
    techniques:
    - T1486
    - T1555
  summary: OysterLoader (Broomstick) is a multi-stage C++ loader distributed via trojanized
    installers for software like PuTTy and WinSCP. It utilizes the TextShell packer,
    custom LZMA decompression, and in-memory shellcode to eventually deliver Rhysida
    ransomware or Vidar infostealers.
series:
  index: 3
  slug: oysterloader-unmasked-the-multi-stage-evasion-loader
  title: 'OysterLoader unmasked: the multi-stage evasion loader'
  total: 3
severity: critical
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


# OysterLoader Impact: Vidar and Rhysida

This hunt isolates the final payload stage of the OysterLoader infection chain. It focuses on the behavioral signatures of Vidar (infostealer) and Rhysida (ransomware) once they have been unpacked and executed. The hunt identifies hosts at risk due to the presence of software OysterLoader typically impersonates (e.g., PuTTy, WinSCP) and then gathers parallel evidence of credential theft, anomalous processes, encryption activity, and multi-hop proxy connections (Tor).

## scoping-impersonated-apps
<!-- Scope hosts with potentially trojanized software -->
Identify hosts running software OysterLoader frequently impersonates, narrowing the hunt to potential beachheads.

```sqlite target=endpoint role=scoping params=(impersonated_packages=impersonated_packages)
~~~yaml
expected: A list of hosts with IT tools that may have been installed from trojanized
  sources. Silence means the specific impersonated tools are not present.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE instr(',' || '{{impersonated_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## analyze-payload-behavior
<!-- Analyze Payload Behavior -->
parallel:
- → vidar-credential-theft
- → rare-process-anomalies
- → rhysida-encryption-burst
- → proxy-c2-activity
join: → triage-payloads

## vidar-credential-theft
<!-- Vidar: Non-browser access to browser credentials -->
Detect processes reading browser profile data, which is characteristic of Vidar credential harvesting (T1555).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A non-browser process reading 'Login Data'. Silence suggests no such credential
  theft occurred via file access.
reads:
- activity_id
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, COUNT(*) AS access_count FROM hb_file_activity WHERE activity_id = 2 AND (LOWER(file_path) LIKE '%\\google\\chrome\\user data\\default\\login data%' OR LOWER(file_path) LIKE '%\\microsoft\\edge\\user data\\default\\login data%') AND LOWER(process_name) NOT LIKE '%chrome.exe' AND LOWER(process_name) NOT LIKE '%msedge.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path
```

## rare-process-anomalies
<!-- Rare processes without valid signatures -->
Stack-count rare processes that are either fileless (injected) or lack standard company metadata, suggesting unpacked malware.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process seen on very few hosts without proper metadata. Silence may indicate
  all processes are signed and on-disk.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- on_disk
- process_file_company
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_name) AS process, process_file_company, on_disk, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (on_disk = 0 OR process_file_company IS NULL OR process_file_company = '') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING hosts <= 3 ORDER BY hosts ASC
```

## rhysida-encryption-burst
<!-- Rhysida: Bulk encryption markers -->
Identify the sudden creation of .rhysida files or ransom notes (T1486).

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, encryption_threshold=encryption_threshold)
~~~yaml
expected: A single process creating many files with the .rhysida extension. Silence
  means no mass encryption was observed.
reads:
- activity_id
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, COUNT(*) AS file_count FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.rhysida' OR LOWER(file_name) = 'criticalid.txt') AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_count >= {{encryption_threshold}}
```

## proxy-c2-activity
<!-- C2 Analysis: Tor and multi-hop proxy ports -->
Detect multi-hop proxy connections (T1090.003) commonly used by Rhysida/Vidar for C2.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Non-standard processes using local proxy ports or launching Tor. Silence
  suggests no proxy-based C2 within the window.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction FROM hb_network_connection WHERE (dst_endpoint_ip = '127.0.0.1' AND dst_endpoint_port IN (9050, 9051, 1080)) OR (dst_endpoint_port IN (9001, 443) AND LOWER(process_name) LIKE '%tor%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-payloads
<!-- Triage Payload Evidence -->
```agent target=hunter
cite: required
context:
- scoping-impersonated-apps
- vidar-credential-theft
- rare-process-anomalies
- rhysida-encryption-burst
- proxy-c2-activity
max_iterations: 4
objective: Determine if a host is currently infected with Vidar or Rhysida by correlating
  process signature status with file system impact and proxy behavior.
success_criteria: A host-by-host verdict (malicious | suspicious | benign) citing
  specific process and file rows.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-host-coverage)
else: → close-out

## isolate-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Dump memory of the suspicious process if possible before cleanup.
```
→ analyst-review

## analyst-review
<!-- Analyst review and forensic confirm -->
```manual target=analyst
Review the cited evidence of credential access and encryption. Verify if the 'impersonated software' was the source of the infection.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Log that no Vidar or Rhysida indicators were found on scoped hosts.
```
→ end
