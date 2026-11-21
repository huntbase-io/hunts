---
analysis: The hunt synthesizes staging behavior (chmod, fetch commands) with persistent
  state (ELF modification, Docker mounts) and infrastructure signals (rare LoongArch64
  architecture) into one decision. A single detection rule would struggle to correlate
  these temporally separated events without high noise.
blind_spots:
- id: incomplete-process-auditing
  question: whether the initial fetch or chmod commands were executed
  requires: EDR process logging on every endpoint
  risk: A host without process auditing will never trigger the lead query, allowing
    the intrusion to proceed unseen.
  stage: execution-fetch-payload-delivery
- id: restricted-telemetry-retention
  question: whether the follow-on staging activity occurred on hosts without deep
    auditing
  requires: Full network and file auditing across the estate
  risk: The fan-out queries depend on file and network surfaces; missing telemetry
    here prevents corroboration of the lead.
- id: disk-direct-write-visibility
  question: whether an ELF binary was modified via direct disk access bypassing standard
    syscalls
  requires: Kernel-level file integrity monitoring
  risk: Sophisticated persistence that writes directly to disk blocks may not appear
    in hb_file_activity.
  stage: persistence-linux-elf-injection
coverage:
- stage: execution-fetch-payload-delivery
  status: covered
  steps:
  - execution-leads
  - network-fetch-audit
- stage: persistence-linux-elf-injection
  status: covered
  steps:
  - file-integrity-audit
- stage: persistence-privileged-container-mount
  status: covered
  steps:
  - execution-leads
- reason: 'Belongs to another part of the ''Metasploit Wrapup: Unauth RCE modules
    in Network Perimeter Devices and much more'' series.'
  stage: initial-access-perimeter-vulnerabilities
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrapup: Unauth RCE modules
    in Network Perimeter Devices and much more'' series.'
  stage: credential-access-ntlm-disclosure
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are increasingly using non-standard architectures and
    native platform features like Docker mounts to evade traditional detections. This
    hunt provides a systematic audit of these advanced persistence techniques across
    multiple telemetry surfaces.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is staging non-standard architecture payloads using multi-protocol
  fetch adapters and establishing persistence via Linux ELF binary injection or privileged
  Docker containers with host root mounts.
labels:
- hunt
- attack.t1105
- attack.t1059.003
- attack.t1574
- attack.t1610
- attack.t1543.003
- credential access
- execution
- initial access
- persistence
name: Advanced Persistence and Payload Staging
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
  suspicious_paths:
    default:
    - /tmp
    - /var/tmp
    - /dev/shm
    - c:\users\public
    - c:\windows\temp
    description: Lowercase directory paths where payload staging is common.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: common-attack-patterns
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrapup-unauth-rce-modules-in-network-perimeter-devices-and-much-more
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux servers, Docker hosts, and systems with direct internet
  egress. Use the scope_hosts parameter if focusing on specific segments containing
  perimeter appliances.
references:
- name: 'Metasploit Wrapup: Unauth RCE modules in Network Perimeter Devices and much
    more'
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrapup-unauth-rce-modules-in-network-perimeter-devices-and-much-more
related:
- hunt: initial-access-perimeter-vulnerabilities
  reason: The initial exploitation of Citrix or Cisco devices is handled in a separate
    hunt focused on web and perimeter appliance logs.
  relation: out-of-scope-alternative
- hunt: perimeter-exploitation-ntlm-redirection
  relation: follows
scenario:
  stages:
  - name: Exploitation of Perimeter and Developer Tools
    observables:
    - HTTP POST to /forgot-password in Flowise
    - Unauthenticated CI lint API calls to GitLab
    - PHP file uploads to /wp-content/plugins/bug-library/
    - Command injection patterns in Citrix NetScaler login logs
    - SQL injection patterns in Cisco Secure Email Gateway S/MIME handling
    - CVE-2025-58434
    - CVE-2026-88771
    - CVE-2026-97229
    - CVE-2026-76443
    - CVE-2024-5450
    slug: initial-access-perimeter-vulnerabilities
    tactic: initial-access
    techniques:
    - T1190
  - name: NTLMv2 Hash Disclosure via UNC Path
    observables:
    - OpenBullet2 forced SMB authentication via UNC path proxy source
    - Outbound SMB (port 445) connections to attacker-controlled infrastructure
    - CVE-2026-39908
    slug: credential-access-ntlm-disclosure
    tactic: credential-access
    techniques:
    - T1557.001
  - name: Multi-Protocol Fetch Payload Execution
    observables:
    - Fetch commands using FTP, HTTP, HTTPS, or TFTP to download LoongArch64 payloads
    - Execution of chmod on downloaded files
    - Reverse shell or bind shell activity (e.g., shell_reverse_tcp)
    slug: execution-fetch-payload-delivery
    tactic: execution
    techniques:
    - T1105
    - T1059.003
  - name: Linux ELF Executable Payload Injection
    observables:
    - Code cave and segment injection in Linux ELF files
    - Architecture-specific trampolines for x86, x64, or AArch64
    - Modified ELF binaries on disk
    slug: persistence-linux-elf-injection
    tactic: persistence
    techniques:
    - T1574
  - name: Docker Container Persistence and Host Access
    observables:
    - Creation of privileged Docker containers
    - 'Bind-mounting host filesystem (e.g., C: drive on Windows or root on Linux)
      to a container'
    - Docker Desktop creating persistent Alpine containers on Windows
    - Portainer API activity to create containers with host access
    slug: persistence-privileged-container-mount
    tactic: persistence
    techniques:
    - T1610
    - T1543.003
  summary: This campaign involves the use of newly released Metasploit modules targeting
    unauthenticated RCE and authentication bypass vulnerabilities in perimeter devices
    and developer tools like Citrix NetScaler, Cisco Secure Email Gateway, Flowise,
    and GitLab. After initial access, attackers leverage specialized Linux ELF injection
    techniques and privileged Docker container creation for persistent access and
    payload execution.
series:
  index: 2
  slug: metasploit-wrapup-unauth-rce-modules-in-network-perimeter-devices-and-much-more
  title: 'Metasploit Wrapup: Unauth RCE modules in Network Perimeter Devices and much
    more'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Advanced Persistence and Payload Staging

This hunt examines tradecraft associated with recent Metasploit releases, focusing on post-exploitation staging and persistence. It targets the delivery of LoongArch64 payloads via FTP, TFTP, and HTTP, the modification of system-critical ELF binaries on Linux, and the use of Docker containers to mount host filesystems for high-privilege persistence. The hunt uses a gated flow, starting with a cheap lead query for suspicious process behavior before opening detailed network and file-level audits for corroboration.

## execution-leads
<!-- Suspicious execution and staging leads -->
Identify initial signs of payload staging, rare architecture references, or dangerous Docker configurations in process command lines.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_paths=suspicious_paths)
~~~yaml
expected: Process rows showing chmod commands in temporary directories, mentions of
  LoongArch64, or Docker commands with host filesystem mounts. Silence proves no common
  CLI staging patterns occurred.
reads:
- device_hostname
- process_name
- process_cmd_line
- current_directory
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, current_directory, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%loongarch64%' OR (LOWER(process_cmd_line) LIKE '%chmod%' AND (instr(process_cmd_line, ' +x') > 0 OR instr(process_cmd_line, ' 777') > 0)) OR (LOWER(process_cmd_line) LIKE '%docker%' AND (instr(process_cmd_line, '--privileged') > 0 OR instr(process_cmd_line, '-v /') > 0))) AND ('{{suspicious_paths}}' = '' OR instr(',' || '{{suspicious_paths}}' || ',', ',' || LOWER(current_directory) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-leads
<!-- Evaluate execution leads -->
```agent target=hunter
cite: required
context:
- execution-leads
max_iterations: 3
objective: Decide if the processes in execution-leads represent unauthorized payload
  delivery, arch-specific binary execution, or dangerous container persistence.
success_criteria: A clear verdict for every host found in the lead query.
tools:
- endpoint
- network
```

## gate-on-leads
<!-- Gate on leads -->
if~: "the evaluate-leads verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → deep-dive
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: incomplete-process-auditing)
else: → hunt-close-out

## deep-dive
<!-- Fan-out to network and file audits -->
parallel:
- → network-fetch-audit
- → file-integrity-audit
join: → triage-persistence

## network-fetch-audit
<!-- Audit fetch protocol activity -->
Corroborate staging leads with rare outbound connections on FTP, TFTP, or HTTP from fetch-related binaries.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to external IPs on unusual staging ports or from utilities used
  by the fetch payloads. Rare destinations indicate targeted staging infrastructure.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_network_connection WHERE (dst_endpoint_port IN (21, 69) OR (dst_endpoint_port IN (80, 443) AND (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%' OR LOWER(process_name) LIKE '%fetch%'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name HAVING host_count <= 3
```

## file-integrity-audit
<!-- Audit system binary integrity -->
Identify modification of core Linux binaries or new files in suspicious staging paths consistent with ELF injection.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_paths=suspicious_paths)
~~~yaml
expected: File updates or creations in system binary paths or designated staging directories.
  Silence means no direct disk modification occurred in these paths.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, activity_name, time FROM hb_file_activity WHERE (activity_id IN (1, 3, 5)) AND (file_path LIKE '/bin/%' OR file_path LIKE '/usr/bin/%' OR file_path LIKE '/sbin/%' OR file_path LIKE '/usr/sbin/%' OR instr(',' || '{{suspicious_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-persistence
<!-- Triage staging and persistence -->
```agent target=hunter
cite: required
context:
- evaluate-leads
- network-fetch-audit
- file-integrity-audit
max_iterations: 6
objective: Determine if the combined evidence confirms a persistent foothold established
  via binary injection, fetch payloads, or Docker container abuse.
success_criteria: A malicious | suspicious | benign verdict per host with supporting
  row citations.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-persistence verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: restricted-telemetry-retention)
else: → hunt-close-out

## isolate-endpoint
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate collection of modified ELF binaries or Docker container configuration files for forensic analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the cited rows from all stages. For Linux binary modifications, check package manager integrity (rpm -V or debsums). For Docker containers, inspect the mount configuration and check for root access to the host.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Document the findings, identifying any legitimate use of LoongArch64 or privileged Docker containers to tune future detections. Record which hosts were inaccessible due to missing telemetry.
```
→ end
