---
analysis: While a rule can fire on a specific binary name, this hunt provides the
  context of machine-speed network scanning and LSASS module interaction, allowing
  an analyst to identify automated coordination rather than a manual pentest.
blind_spots:
- id: limited-network-visibility
  question: whether fscan is scanning segments not captured by endpoint sensors
  requires: hb_network_connection for all internal segments
  risk: An automated agent could perform reconnaissance on unmonitored subnets without
    triggering the prevalence baseline.
  stage: internal-discovery-automation
- id: in-memory-tool-execution
  question: whether tools like Mimikatz were loaded directly into memory via shellcode
  requires: hb_process_activity (on_disk = 0) and hb_module_activity
  risk: Tools executed entirely in memory bypass the file-name lead query and are
    only visible if the module load or process tampering is successfully audited.
  stage: automated-credential-harvesting
coverage:
- stage: orchestrated-c2-and-tunneling
  status: covered
  steps:
  - offensive-tool-lead
  - network-discovery-prevalence
- stage: internal-discovery-automation
  status: covered
  steps:
  - network-discovery-prevalence
- stage: automated-credential-harvesting
  status: covered
  steps:
  - credential-harvesting-triage
- reason: 'Belongs to another part of the ''ARTEX and beyond: AI-enabled penetration
    testing platforms'' series.'
  stage: automated-vulnerability-probing
  status: out_of_scope
- reason: 'Belongs to another part of the ''ARTEX and beyond: AI-enabled penetration
    testing platforms'' series.'
  stage: high-velocity-credential-spraying
  status: out_of_scope
- reason: 'Belongs to another part of the ''ARTEX and beyond: AI-enabled penetration
    testing platforms'' series.'
  stage: cloud-privilege-manipulation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI-enabled frameworks like ARTEX can move from entry to credential
    theft in minutes; a negative result over the estate confirms no machine-speed
    maneuvering occurred within the retention window.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated attacker is coordinating dual-use offensive tools like VShell,
  Chisel, or fscan to perform high-velocity internal discovery and credential harvesting.
labels:
- hunt
- attack.t1572
- attack.t1046
- attack.t1003.001
- attack.t1555
- attack.t1105
- command and control
- credential access
- discovery
- initial access
- persistence
name: ARTEX Automated Endpoint and Network Maneuvering
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  offensive_tools:
    default:
    - fscan.exe
    - vshell.exe
    - chisel.exe
    - nps.exe
    - mimikatz.exe
    - adaptix.exe
    - gophish.exe
    description: Names of offensive or dual-use binaries identified in ARTEX worker
      agent workflows.
    from:
      kind: article
      observed: '2026-11-13'
      ref: https://blog.talosintelligence.com/artex-and-beyond/
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames from the scoping step to narrow the behavioral
      queries; leave empty to hunt across the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/artex-and-beyond/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and high-value workstation segments. If the lead query
  is empty, consider widening the offensive_tools list to include generic names like
  'scan.exe' or 'tunnel.exe'.
references:
- name: "Cisco Talos \u2014 ARTEX and beyond: AI-enabled penetration testing platforms"
  url: https://blog.talosintelligence.com/artex-and-beyond/
related:
- hunt: automated-vulnerability-probing
  reason: The initial stage of vulnerability probing and web shell deployment is a
    separate hunt focused on web server logs and public-facing exposures.
  relation: out-of-scope-alternative
- hunt: ai-driven-identity-cloud-exploitation
  relation: follows
scenario:
  stages:
  - name: Automated Vulnerability Probing
    observables:
    - Acunetix web scanner
    - Nessus vulnerability scanner
    - Interactsh out-of-band detection
    - Inbound scanning traffic from ARTEX-associated C2 IPs
    slug: automated-vulnerability-probing
    tactic: initial-access
    techniques:
    - T1190
  - name: High-Velocity Credential Spraying
    observables:
    - Accelerated sign-in attempts against downstream Microsoft 365 tenants
    - Compromised ConnectWise application credentials used for multi-tenant access
    slug: high-velocity-credential-spraying
    tactic: credential-access
    techniques:
    - T1110.003
  - name: Orchestrated C2 and Tunneling
    observables:
    - VShell C2 framework
    - AdaptixC2 framework
    - Chisel TCP/UDP tunneling
    - Net Proxy Server (NPS) tunneling
    - multios.trojan.adaptixc2 signature
    slug: orchestrated-c2-and-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: Internal Discovery Automation
    observables:
    - fscan internal network scanner
    - multios.tool.fscan signature
    slug: internal-discovery-automation
    tactic: discovery
    techniques:
    - T1046
  - name: Automated Credential Harvesting
    observables:
    - Mimikatz execution
    - LSASS memory access
    - Credential leak management services integration
    slug: automated-credential-harvesting
    tactic: credential-access
    techniques:
    - T1003.001
    - T1555
  - name: Cloud Privilege Manipulation
    observables:
    - Microsoft Graph API activity
    - Entra ID application credential changes
    - Role assignment and privilege modifications
    slug: cloud-privilege-manipulation
    tactic: persistence
    techniques:
    - T1098
  summary: Threat actors are leveraging AI-driven penetration testing frameworks like
    ARTEX and PentAGI to automate reconnaissance, credential spraying, and post-exploitation
    at machine speed. These frameworks orchestrate a variety of offensive tools including
    C2 frameworks (VShell, AdaptixC2), tunneling utilities (Chisel, NPS), and internal
    scanners (fscan) to rapidly compromise targets across both endpoint and cloud
    environments.
series:
  index: 2
  slug: artex-and-beyond-ai-enabled-penetration-testing-platforms
  title: 'ARTEX and beyond: AI-enabled penetration testing platforms'
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


# ARTEX Automated Endpoint and Network Maneuvering

ARTEX and similar agentic frameworks coordinate worker agents to deploy offensive toolsets at machine speed. This hunt identifies the execution of common binaries used by these agents—including VShell, Chisel, and fscan—and correlates them with behavioral indicators of automated network scanning and unauthorized module loads into LSASS. By examining these signals across process, network, and module telemetry, an analyst can distinguish between a human operator and an objective-driven automated framework.

## offensive-tool-lead
<!-- Offensive Tool Execution Lead -->
Identify hosts executing binaries associated with ARTEX worker agents to narrow the search space.

```sqlite target=endpoint role=scoping params=(offensive_tools=offensive_tools, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating the execution of known offensive tools. Silence suggests
  no direct matches for the named binaries occurred.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_original_file_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_original_file_name, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{offensive_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{offensive_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## maneuver-fan-out
<!-- Maneuver Fan-out -->
parallel:
- → network-discovery-prevalence
- → credential-harvesting-triage
join: → triage-orchestration

## network-discovery-prevalence
<!-- Network Discovery Prevalence -->
Detect automated internal scanning by finding processes that contact a high volume of unique internal destination IPs.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Processes (like fscan or vshell) that target dozens of internal hosts in
  a short window. Genuine admin tools may show this, but rare process names should
  stand out.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT dst_endpoint_ip) AS unique_targets, COUNT(*) AS total_conns FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_targets > 15 ORDER BY unique_targets DESC
```

## credential-harvesting-triage
<!-- Credential Harvesting Triage -->
Corroborate tool execution by finding module loads related to LSASS or SAM access from non-system directories.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any row where a user-space binary is interacting with the credential databases.
  Silence proves the tools did not attempt LSASS memory access within the window.
reads:
- device_hostname
- process_name
- module_path
- module_signature_subject
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_name, module_path, module_signature_subject, time FROM hb_module_activity WHERE (LOWER(module_path) LIKE '%\lsasrv.dll' OR LOWER(module_path) LIKE '%\samlib.dll') AND NOT (LOWER(process_name) LIKE 'c:\windows\system32\%' OR LOWER(process_name) LIKE 'c:\windows\syswow64\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-orchestration
<!-- Triage Orchestration -->
```agent target=hunter
cite: required
context:
- offensive-tool-lead
- network-discovery-prevalence
- credential-harvesting-triage
max_iterations: 5
objective: Determine if the execution of offensive tools, the high-velocity network
  connections, and the LSASS module loads together indicate an automated AI-enabled
  framework like ARTEX on any single host.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing the
  offensive binary name and connection volume.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host involving an offensive tool binary" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: limited-network-visibility)
else: → hunt-closeout

## isolate-endpoint
<!-- Isolate Affected Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate any processes identified by the triage agent as malicious.
```
→ analyst-validation

## analyst-validation
<!-- Analyst Validation -->
```manual target=analyst
Review the process ancestry for the offensive binaries; search for unusual Python or Node.js processes that may be acting as the ARTEX agent harness coordinating the tools.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt Close-out -->
```manual target=analyst
Record the outcome and verify that all hosts in the affected segment have reporting EDR agents, as ARTEX frameworks often include bypass capabilities.
```
→ end
