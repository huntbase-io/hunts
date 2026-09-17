---
analysis: While a rule can alert on on_disk = 0, it is prone to noise. This hunt adds
  the critical context of downloader-specific network patterns (impersonation snippets
  and null UA prevalence) that a single-surface rule cannot easily weigh.
blind_spots:
- id: no-endpoint-telemetry
  owner: IT Security
  question: Is the decompression happening on hosts without visibility into on_disk
    state?
  remediation: Ensure agent coverage matches the full workstation fleet.
  requires: Endpoint agent reporting hb_process_activity (osquery/sysmon)
  risk: A host without an agent will not report processes running from memory, leaving
    a total gap in detection for the loading phase.
  stage: in-memory-lzma-decompression
- id: tls-visibility-path
  owner: Network Engineering
  question: Can we see the specific URL path for core retrieval if it is encrypted?
  remediation: Implement TLS inspection for workstation egress to identify core malware
    retrieval.
  requires: hb_http_activity with decrypted URL paths
  risk: If the C2 uses HTTPS and there is no proxy decryption, we lose visibility
    into the url_path and user_agent, relying only on the url_hostname.
  stage: downloader-c2-beaconing
coverage:
- stage: in-memory-lzma-decompression
  status: covered
  steps:
  - fileless-process-execution
- stage: downloader-c2-beaconing
  status: covered
  steps:
  - downloader-http-beacons
  - rare-dns-lookups
  - null-ua-prevalence
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: initial-access-trojanized-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: textshell-packer-obfuscation
  status: out_of_scope
- reason: 'Belongs to another part of the ''OysterLoader unmasked: the multi-stage
    evasion loader'' series.'
  stage: final-payload-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: OysterLoader is a precursor to Rhysida ransomware. Catching it at
    the shellcode or downloader stage allows for containment before the final payload
    (final-payload-deployment) can encrypt data or exfiltrate credentials.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is executing fileless code decompressed in memory using a
  custom LZMA routine, evidenced by processes without backing files that are beaconing
  to domain fragments used for payload retrieval.
labels:
- hunt
- attack.t1055
- attack.t1140
- attack.t1105
- attack.t1090.003
name: OysterLoader In-Memory Loading and Downloader C2
parameters:
  domain_snippets:
    default:
    - pefile.pe
    - exp.name
    - exports.append
    description: Substrings found in OysterLoader C2 domains used for stage retrieval.
    from:
      kind: article
      observed: '2024-06-01'
      ref: sekoia-oysterloader
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for fileless execution and network beacons.
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
rationale: Focus on workstations where MSI software was recently installed. Initial
  access typically involves spoofed IT software (WinSCP, PuTTy).
references:
- name: "Sekoia \u2014 OysterLoader unmasked: the multi-stage evasion loader"
  url: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
related:
- hunt: oysterloader-initial-access-msi
  reason: OysterLoader is distributed as an MSI; this hunt starts after that file
    has executed and begun its loading sequence.
  relation: precedes
- hunt: rhysida-impact-containment
  reason: If OysterLoader successfully loads its core, the next stage is typically
    Rhysida ransomware deployment.
  relation: follows
- hunt: oysterloader-stage-1-installer-packer
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
  index: 2
  slug: oysterloader-unmasked-the-multi-stage-evasion-loader
  title: 'OysterLoader unmasked: the multi-stage evasion loader'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# OysterLoader In-Memory Loading and Downloader C2

OysterLoader (Broomstick) uses a multi-stage loading process designed to evade static analysis. After the initial TextShell packer executes, it uses a custom shellcode to decompress the downloader stage into memory using a custom LZMA range decoder. This hunt looks for processes running without a backing file (on_disk = false)—a direct artifact of the LZMA decompression and memory allocation routine—and correlates them with subsequent HTTP/DNS activity. Specifically, we look for HTTP traffic to domains matching known OysterLoader naming patterns and identify rare instances of null user-agents that often accompany its InternetOpenW calls.

## fileless-process-execution
<!-- Detect fileless code execution -->
Identify processes running without a backing file on disk, excluding common system false positives, to find the decompressed shellcode stage.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Processes like svchost.exe or explorer.exe reporting on_disk=0. Silence
  suggests the shellcode phase has not occurred on managed endpoints.
reads:
- on_disk
- process_name
- pid
- device_hostname
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, pid, user_name, parent_process_name, time FROM hb_process_activity WHERE on_disk = 0 AND pid > 4 AND LOWER(process_name) NOT IN ('system', 'registry', 'idle') AND time >= datetime('now', '-{{lookback_days}} days')
```

## correlate-activity
<!-- Correlate with Network and DNS Beacons -->
parallel:
- → downloader-http-beacons
- → rare-dns-lookups
- → null-ua-prevalence
join: → triage-agent

## downloader-http-beacons
<!-- HTTP beacons with OysterLoader snippets -->
Capture the downloader communicating with C2 servers using partial matches for identified domain fragments.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Requests to domains incorporating these fragments. Presence of these indicates
  likely OysterLoader core retrieval.
reads:
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE (LOWER(url_hostname) LIKE '%pefile.pe%' OR LOWER(url_hostname) LIKE '%exp.name%' OR LOWER(url_hostname) LIKE '%exports.append%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-dns-lookups
<!-- Rare DNS lookups for software impersonation -->
Identify low-prevalence DNS queries that may indicate targeted downloader infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Domains seen on only one or two hosts, potentially matching software impersonation
  patterns (e.g., putty, winscp).
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT query_hostname, device_hostname, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## null-ua-prevalence
<!-- Prevalence filter for NULL User-Agents -->
Identify hosts where requests with NULL user-agents are rare, avoiding the noise of constant system telemetry.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hosts with occasional NULL user-agent requests. High event counts usually
  indicate legitimate automated system services.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 20
reads:
- user_agent
- device_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, user_agent, COUNT(*) as event_count, MIN(time) as first_seen FROM hb_http_activity WHERE user_agent IS NULL AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING event_count < 20
```

## triage-agent
<!-- Evaluate Multi-Stage Infection -->
```agent target=hunter
cite: required
context:
- fileless-process-execution
- downloader-http-beacons
- rare-dns-lookups
- null-ua-prevalence
max_iterations: 3
objective: Determine if 'on_disk = 0' processes are accompanied by downloader C2 fragments
  or suspicious NULL user-agent activity.
success_criteria: A verdict for every host found in Step 1, citing matching network
  rows.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## contain-host
<!-- Isolate Host and Preserve Memory -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Perform a full memory dump to capture the Stage 3 downloader and any unpacked OysterLoader core components. Retrieve the MSI that initiated the chain.
```
→ analyst-review

## analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the fileless processes. Confirm if they correspond to legitimate injected code (e.g., security agents, browser processes) or align with the OysterLoader profile of rare domains and null user-agents.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Record the baseline of fileless activity for future tuning. No malicious loading confirmed.
```
→ end
