---
analysis: This hunt correlates the presence of a vulnerability with specific URI patterns
  and stack-counted rare fetch behavior, providing the necessary context to confirm
  an intrusion that a single rule would miss.
blind_spots:
- id: http-body-blindness
  owner: Network Engineering
  question: whether the exploit payload was delivered in a POST body
  remediation: Deploy a WAF with body inspection for sensitive LLM endpoints.
  requires: hb_http_activity with full request body
  risk: Many exploits, including Langflow's exec_globals, pass parameters in the JSON
    body, which the HTTP surface does not capture, leading to misses on URI-only inspection.
  stage: unauthenticated-rce-web-services
- id: architecture-context
  owner: Endpoint Security
  question: whether the host is specifically AArch64
  remediation: Include host architecture in the endpoint inventory or process telemetry.
  requires: hb_process_activity with CPU architecture
  risk: The hunt targets fetch utilities common to all Windows hosts; without architecture
    context, we cannot confirm if the host matches the specific platform for the new
    Metasploit payloads.
  stage: windows-aarch64-payload-fetch
coverage:
- stage: unauthenticated-rce-web-services
  status: covered
  steps:
  - vulnerable-hosts-scoping
  - http-exploit-indicators
- stage: windows-aarch64-payload-fetch
  status: covered
  steps:
  - rare-fetch-utility-baseline
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: A Collection of What
    Can Only Be Called Eclectic Modules'' series.'
  stage: linux-local-privilege-escalation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: A Collection of What
    Can Only Be Called Eclectic Modules'' series.'
  stage: persistence-via-auth-and-config
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: A Collection of What
    Can Only Be Called Eclectic Modules'' series.'
  stage: security-software-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Metasploit modules for unauthenticated RCE in emerging LLM stacks
    pose an immediate risk. A negative result verifies that internet-facing services
    are not being used for initial access via these specific vectors.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting unauthenticated RCE vulnerabilities in LLM
  or IPTV web services to run fetch utilities that download AArch64-specific payloads
  onto Windows systems.
labels:
- hunt
- attack.t1190
- attack.t1105
- attack.t1059
- discovery
- execution
- initial access
- persistence
- privilege escalation
name: Metasploit RCE and AArch64 Payload Delivery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-09'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus behavioral queries; leave empty
      for fleet-wide.
    from:
      kind: manual
      ref: analyst-defined
    type: list[host]
  target_cves:
    default:
    - CVE-2026-0770
    - CVE-2024-58286
    - CVE-2026-42271
    - CVE-2026-86218
    description: CVE identifiers for the targeted web and LLM vulnerabilities.
    from:
      kind: article
      observed: '2026-10-09'
      ref: rapid7-metasploit-wrapup
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-a-collection-of-what-can-only-be-called-eclectic-modules
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target systems with external exposure running Python or Node.js services,
  particularly those categorized as LLM proxies or media streaming servers.
references:
- name: 'Metasploit Wrap Up: A Collection of What Can Only Be Called Eclectic Modules'
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-a-collection-of-what-can-only-be-called-eclectic-modules
related:
- hunt: metasploit-privesc-and-persistence
  reason: This hunt focuses on the foothold; a sibling hunt addresses the Linux privilege
    escalation (snapd) and Windows persistence (Ollama) modules.
  relation: follows
scenario:
  stages:
  - name: Unauthenticated RCE in Web and LLM Services
    observables:
    - POST requests to /validate endpoint with exec_globals parameter (Langflow)
    - Modification of FFMPEG Executable Path settings in dizqueTV
    - Requests to MCP test REST endpoints in LiteLLM proxy
    - Struts BeanUtils exploitation against N-able N-central
    slug: unauthenticated-rce-web-services
    tactic: initial-access
    techniques:
    - T1190
  - name: Windows AArch64 Payload Fetching
    observables:
    - Execution of cmd/windows/http/aarch64/exec
    - Execution of cmd/windows/tftp/aarch64/shell_reverse_tcp
    - Command-line file transfers via FTP, HTTP, HTTPS, or TFTP on AArch64 Windows
      systems
    slug: windows-aarch64-payload-fetch
    tactic: execution
    techniques:
    - T1105
    - T1059
  - name: Linux Local Privilege Escalation
    observables:
    - Exploitation of snap-confine TOCTOU race condition (CVE-2026-3888)
    - DirtyClone exploit execution (CVE-2026-43503)
    - Execution as root inside OpenCTI API containers via safeEjs sandbox escape
    slug: linux-local-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Persistence via PAM and Config Tampering
    observables:
    - Upload of malicious .so files into the Linux PAM authentication chain
    - Path traversal exploitation in Ollama auto-update mechanism (CVE-2026-42249)
    slug: persistence-via-auth-and-config
    tactic: persistence
    techniques:
    - T1556
    - T1574.002
  - name: Security Software Discovery
    observables:
    - Execution of post/linux/gather/enum_protections
    - Automated enumeration of AV/EDR protections on the target system
    slug: security-software-discovery
    tactic: discovery
    techniques:
    - T1518.001
  summary: This campaign involves the exploitation of unauthenticated remote code
    execution vulnerabilities in LLM-related services and IPTV servers, followed by
    the delivery of fetch-based payloads to Windows AArch64 systems. Attackers then
    perform local privilege escalation on Linux systems and establish persistence
    through configuration tampering or malicious authentication modules.
series:
  index: 1
  slug: metasploit-wrap-up-a-collection-of-what-can-only-be-called-eclectic-modules
  title: 'Metasploit Wrap Up: A Collection of What Can Only Be Called Eclectic Modules'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Metasploit RCE and AArch64 Payload Delivery

This hunt identifies initial access and execution attempts matching new Metasploit modules. The hunt first identifies vulnerable Langflow, vLLM, and dizqueTV instances via vulnerability findings. It then correlates HTTP traffic matching known exploit URIs with rare process behavior involving Windows fetch utilities like FTP, TFTP, and Certutil. An agent weighs the vulnerability context against the observed behavior to identify successful compromises.

## vulnerable-hosts-scoping
<!-- Scope vulnerable LLM and Web services -->
The hunt identifies hosts with reported vulnerabilities corresponding to the new Metasploit modules to prioritize behavioral analysis.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of device UIDs that are vulnerable to the targeted exploits. A negative
  result verifies that internet-facing services are not being used for initial access
  via these specific vectors.
reads:
- device_uid
- cve_uid
- affected_package_name
- severity
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_uid, cve_uid, affected_package_name, severity, title FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0 OR LOWER(title) LIKE '%langflow%' OR LOWER(affected_package_name) LIKE '%dizquetv%'
```

## correlate-exploit-and-fetch
<!-- Parallel behavioral analysis -->
parallel:
- → http-exploit-indicators
- → rare-fetch-utility-baseline
join: → triage-intrusion

## http-exploit-indicators
<!-- HTTP exploit patterns for LLM services -->
The hunt detects exploit attempts in URL paths and queries targeting Langflow, LiteLLM, and dizqueTV endpoints.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests targeting specific vulnerable URIs. Silence suggests no URI-based
  exploitation occurred within the lookback window.
reads:
- device_hostname
- url_path
- url_query
- src_endpoint_ip
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, url_path, url_query, src_endpoint_ip, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/validate%' OR LOWER(url_path) LIKE '%/mcp/%' OR LOWER(url_path) LIKE '%ffmpeg%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-fetch-utility-baseline
<!-- Rare fetch utility command lines -->
The hunt baselines the use of Windows fetch utilities to find rare download commands that deliver payloads.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare command lines using FTP, TFTP, or Certutil on Windows. Commands involving
  external IPs or suspicious paths indicate potential payload delivery.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT process_cmd_line, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\ftp.exe' OR LOWER(process_name) LIKE '%\tftp.exe' OR LOWER(process_name) LIKE '%\certutil.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, device_hostname HAVING host_count <= 5
```

## triage-intrusion
<!-- Assess intrusion markers -->
```agent target=hunter
cite: required
context:
- vulnerable-hosts-scoping
- http-exploit-indicators
- rare-fetch-utility-baseline
max_iterations: 4
objective: Correlate vulnerability scoping, HTTP exploit traffic, and rare fetch commands
  to determine if a host was successfully compromised.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  evidence from all three sources.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route based on intrusion verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: http-body-blindness)
else: → remediation-and-closeout

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Review the command line from the rare-fetch-utility-baseline step to identify the downloaded payload.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation -->
```manual target=analyst
Review the process_cmd_line and url_path. Confirm if the fetch utility was directed at the same source IP seen in the HTTP exploit logs. Retrieve the downloaded file for forensic analysis.
```
→ remediation-and-closeout

## remediation-and-closeout
<!-- Remediation and closeout -->
```manual target=analyst
Update Langflow, vLLM, and dizqueTV to the latest versions. Audit any LiteLLM or N-central exposures. Record the findings and consider promoting the HTTP URI patterns to a standing detection rule.
```
→ end
