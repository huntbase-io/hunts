---
analysis: A single rule might flag the exploit name, but this hunt combines vulnerability
  state, stack-counted module prevalence, and process behavioral analysis (like on_disk
  = 0) to provide a complete picture of the post-exploitation phase.
blind_spots:
- id: no-file-telemetry
  question: Was a malicious PAM module uploaded but not yet loaded into a process?
  requires: hb_file_activity with deep scan
  risk: A module on disk that hasn't been loaded yet will be missed by the prevalence
    check on hb_module_activity.
  stage: persistence-via-auth-and-config
- id: no-script-content
  question: Is the enumeration module running entirely in memory without spawning
    new processes?
  requires: hb_script_activity with full block capture
  risk: If the Metasploit module discovery logic is executed via an existing interpreter
    without unique command line arguments, hb_process_activity might miss it.
  stage: security-software-discovery
coverage:
- stage: linux-local-privilege-escalation
  status: covered
  steps:
  - exploit-behavior
- stage: persistence-via-auth-and-config
  status: covered
  steps:
  - rare-pam-modules
  - exploit-behavior
- stage: security-software-discovery
  status: covered
  steps:
  - exploit-behavior
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: A Collection of What
    Can Only Be Called Eclectic Modules'' series.'
  stage: unauthenticated-rce-web-services
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: A Collection of What
    Can Only Be Called Eclectic Modules'' series.'
  stage: windows-aarch64-payload-fetch
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The release of new Metasploit modules lowers the bar for exploiting
    these specific vulnerabilities. Proactively hunting for these behaviors ensures
    detection of intrusions that bypass static signatures.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary escalates Linux privileges via snap-confine or DirtyClone
  and establishes persistence through PAM backdoors or Ollama auto-update tampering.
labels:
- hunt
- attack.t1068
- attack.t1556
- attack.t1574.002
- attack.t1518.001
- discovery
- execution
- initial access
- persistence
- privilege escalation
name: Local Escalation and Persistence via Metasploit Modules
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for all
      hosts.
    type: list[host]
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
rationale: Focus on Linux servers running snapd and Windows machines running Ollama.
  Use the vulnerability scoping step to identify high-priority targets first.
references:
- name: "Rapid7 \u2014 Metasploit Wrap Up: A Collection of What Can Only Be Called\
    \ Eclectic Modules"
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-a-collection-of-what-can-only-be-called-eclectic-modules
related:
- hunt: unauthenticated-rce-web-services
  reason: This hunt focuses on post-exploitation local activity; initial access via
    web service exploits is covered in a sibling hunt.
  relation: out-of-scope-alternative
- hunt: metasploit-rce-aarch64-payload-delivery
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
  index: 2
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
tlp: clear
type: investigation
---


# Local Escalation and Persistence via Metasploit Modules

The adversary uses Metasploit modules to move from a beachhead to full control. This hunt identifies vulnerable systems using vulnerability discovery data and then looks for behavioral signals: the query identifies rare PAM modules loaded into the authentication chain and process activity associated with Linux privilege escalation. An agent weighs the evidence to identify compromised hosts where an attacker transitioned to root or established persistent access.

## scope-vulnerable-hosts
<!-- Scope vulnerable hosts -->
Identify hosts with known vulnerabilities targeted by the new Metasploit modules to focus the behavioral queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows identify hosts running vulnerable versions of snapd, Ollama, or relevant
  Linux kernels. Silence means no known vulnerable systems were reported.
reads:
- device_uid
- cve_uid
- affected_package_name
- severity_id
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_uid, cve_uid, affected_package_name, severity_id, title FROM hb_vulnerability_finding WHERE cve_uid IN ('CVE-2026-3888', 'CVE-2026-43503', 'CVE-2026-42249')
```

## parallel-hunt
<!-- Gather behavioral evidence -->
parallel:
- → rare-pam-modules
- → exploit-behavior
join: → triage-findings

## rare-pam-modules
<!-- Identify rare PAM modules -->
Find potentially malicious .so files loaded into the Linux authentication chain that indicate a PAM backdoor.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A module path seen on only one or two hosts. Genuine PAM modules should
  be present across the fleet; a backdoor will appear unique to the target.
prevalence:
  by: device_hostname
  key:
  - module_path
  rare_below: 2
reads:
- module_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT module_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_module_activity WHERE (LOWER(module_path) LIKE '/lib/security/%.so' OR LOWER(module_path) LIKE '/usr/lib/security/%.so') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY module_path HAVING hosts <= 2 ORDER BY hosts ASC
```

## exploit-behavior
<!-- Hunt for exploit execution and discovery -->
Detect the execution of LPE exploits, security software discovery, and Ollama configuration changes.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes mentioning exploit names or the Metasploit discovery module. Transition
  of these processes to root or processes with on_disk = 0 are high-confidence indicators.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, on_disk, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%snap-confine%' OR LOWER(process_cmd_line) LIKE '%dirtyclone%' OR LOWER(process_cmd_line) LIKE '%enum_protections%' OR LOWER(process_cmd_line) LIKE '%ollama%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-findings
<!-- Triage results -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-hosts
- rare-pam-modules
- exploit-behavior
max_iterations: 5
objective: Determine if any host shows a combination of vulnerability exposure, rare
  PAM modules, and exploit-related process activity indicative of privilege escalation
  or persistence.
success_criteria: A verdict of malicious, suspicious, or benign per host with cited
  evidence from the process and module logs.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on agent verdict -->
if~: "the triage verdict is malicious for at least one host based on exploit execution or unauthorized PAM modules" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: no-file-telemetry)
else: → close-out

## isolate-endpoint
<!-- Isolate the host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host from the network to prevent lateral movement or further persistence installation.
```
→ forensic-investigation

## forensic-investigation
<!-- Conduct manual forensics -->
```manual target=analyst
Perform a deep dive on the isolated host. Collect the rare PAM module if present, analyze the process tree leading to root transition, and check for any additional persistence mechanisms like cron jobs.
```
→ close-out

## close-out
<!-- Finalize hunt -->
```manual target=analyst
Document the findings, update vulnerability management records, and determine if the detection-candidate process query should be promoted to a standing alert.
```
→ end
