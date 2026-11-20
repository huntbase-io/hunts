---
analysis: This hunt uses a phased flow to pivot from module sideloading and RMM child
  processes into high-frequency command analysis; no single detection rule can baseline
  normal developer AI assistant behavior against automated abuse.
blind_spots:
- id: no-agent-telemetry
  question: Are we seeing sideloading on hosts that do not report telemetry?
  requires: an endpoint agent on every host
  risk: Attackers may target unmanaged hosts where module loads are not visible.
  stage: execution-msi-dll-sideloading
- id: ai-traffic-encryption
  question: Is the protocol tunneling hidden within standard encrypted AI traffic?
  requires: TLS inspection or proxy logs
  risk: Network connection counts can identify outliers, but the actual payload content
    is invisible without decryption.
  stage: c2-proxy-tunneling
coverage:
- stage: execution-msi-dll-sideloading
  status: covered
  steps:
  - sideloading-check
- stage: persistence-rmm-abuse
  status: covered
  steps:
  - rmm-child-check
- stage: c2-proxy-tunneling
  status: covered
  steps:
  - tunneling-check
- stage: execution-ai-agent-automation
  status: covered
  steps:
  - ai-velocity-check
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: initial-access-aitm-phishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: identity-consent-mfa-bypass
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are actively weaponizing trusted software like ScreenConnect
    and AI assistants, which are often excluded from aggressive detection; a negative
    result over the estate is essential to ensure trust is not being abused.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are weaponizing trusted remote management tools and AI assistants
  to execute code via MSI sideloading and high-frequency automated commands, bypassing
  traditional detection by operating within signed processes.
labels:
- hunt
- attack.t1195
- attack.t1574.002
- attack.t1572
- attack.t1190
- command and control
- credential access
- execution
- initial access
- persistence
name: Abuse of Trusted RMM and AI Agent Software
parameters:
  ai_process_names:
    default:
    - cursor.exe
    - github-copilot-agent.exe
    - windsurf.exe
    - code.exe
    description: Common AI assistant process names.
    from:
      kind: article
      observed: '2026-11-04'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_process_names:
    default:
    - screenconnect.exe
    - screenconnect.client.exe
    - anydesk.exe
    description: Process names for RMM software to monitor.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: common-rmm-list
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to focus on; leave empty for fleet-wide.
    type: list[host]
  shell_names:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - bash
    - sh
    description: Common shell processes to find as children of RMM.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: shell-list
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target developer workstations and IT servers first. Ensure the lookback
  covers the 4-day automation window mentioned in the research.
references:
- name: "Elastic Security Labs \u2014 November 2026 threats, etc Report"
  url: https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust
related:
- hunt: initial-access-aitm-phishing
  reason: Phishing-based initial access is handled by a separate identity-focused
    hunt.
  relation: out-of-scope-alternative
- hunt: saas-identity-consent-loophole-abuse
  relation: follows
scenario:
  stages:
  - name: Adversary-in-the-Middle Phishing
    observables:
    - Adversary-in-the-Middle (AiTM) phishing kits
    - Credential theft targeting cloud/SaaS tenants
    slug: initial-access-aitm-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Consent Loophole and Rapid Login
    observables:
    - Abuse of first-party application consent
    - 8-minute delay between infostealer infection and login
    - Bypassing MFA hurdles via session theft
    slug: identity-consent-mfa-bypass
    tactic: credential-access
    techniques:
    - T1190
    - T1555
  - name: Signed MSI and DLL Sideloading
    observables:
    - Microsoft Software Installer (MSI) delivery
    - Dynamic link library (DLL) sideloading
    - 16-second execution window from lure to sideload
    slug: execution-msi-dll-sideloading
    tactic: execution
    techniques:
    - T1574.002
  - name: RMM Persistence via ScreenConnect
    observables:
    - ScreenConnect
    - Signed remote monitoring and management (RMM) agents
    - Interactive access on endpoints
    slug: persistence-rmm-abuse
    tactic: persistence
    techniques:
    - T1195
  - name: Network Proxy Tunneling
    observables:
    - Proxy tunneling
    - Memory tampering outcomes
    slug: c2-proxy-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: AI Agent-Driven Attack Actions
    observables:
    - AI coding assistants
    - 17,600 reconstructed actions over four days
    - High-frequency automated activity from AI application processes
    slug: execution-ai-agent-automation
    tactic: execution
    techniques:
    - T1195
  summary: Adversaries are weaponizing trust across the enterprise stack by abusing
    legitimate tools like ScreenConnect, AI coding assistants, and Microsoft first-party
    clients. Intrusions leverage AiTM phishing to bypass MFA and deploy signed payloads
    via DLL sideloading, often achieving full compromise from infection to cloud login
    in just eight minutes.
series:
  index: 2
  slug: when-trust-becomes-the-payload-inside-the-threats-etc-quarterly-report
  title: 'When trust becomes the payload: Inside the threats, etc quarterly report'
  total: 2
severity: medium
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


# Abuse of Trusted RMM and AI Agent Software

This hunt examines the weaponization of legitimate, signed software in the enterprise stack. It follows a phased flow: first identifying hosts with ScreenConnect or AI assistants, then searching for rapid MSI sideloading and suspicious RMM child processes. Finally, it correlates this with high-frequency automated actions and protocol tunneling to distinguish between administrative use and adversary abuse.

## identify-trusted-hosts
<!-- Identify hosts with RMM or AI software -->
Find the subset of the estate where trusted software (RMM or AI) has actually run in the window to scope the hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_process_names=ai_process_names, rmm_process_names=rmm_process_names)
~~~yaml
expected: A list of hostnames. Silence means no such software is active in the environment.
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (instr(',' || '{{ai_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{rmm_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Examine execution and persistence stages -->
parallel:
- → sideloading-check
- → rmm-child-check
join: → early-triage-agent

## sideloading-check
<!-- MSIexec loading modules from user-writable paths -->
Identify potential DLL sideloading matching the report's MSI-delivery pattern.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: MSIexec loading a module from a user profile is the core observable for
  the 16-second attack window described in the report.
reads:
- device_hostname
- module_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT device_hostname, process_name, module_path, time FROM hb_module_activity WHERE LOWER(process_name) LIKE '%msiexec.exe' AND (LOWER(module_path) LIKE '%\users\public\%' OR LOWER(module_path) LIKE '%\appdata\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rmm-child-check
<!-- Shell spawns from trusted RMM tools -->
Identify when an attacker or technician spawns a shell from an RMM tool.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rmm_process_names=rmm_process_names, shell_names=shell_names)
~~~yaml
expected: A shell spawned by RMM indicates a technician (or attacker) is running commands;
  this provides the persistence context.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE instr(',' || '{{rmm_process_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage-agent
<!-- Early-stage read -->
```agent target=hunter
cite: required
context:
- sideloading-check
- rmm-child-check
max_iterations: 3
objective: Identify hosts where signed software is performing unexpected execution
  or spawning shells.
success_criteria: A list of hosts with suspicious early-stage activity.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Investigate AI automation and tunneling -->
parallel:
- → ai-velocity-check
- → tunneling-check
join: → comprehensive-triage-agent

## ai-velocity-check
<!-- High-velocity AI assistant command activity -->
Detect the 17,600-action pattern by counting unique commands from AI processes with a high threshold.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_process_names=ai_process_names)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: High counts (e.g., >1000 commands) suggest automated abuse of an AI coding
  agent rather than normal developer work.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 2
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT device_hostname, process_name, COUNT(*) as action_count, MIN(time) as first_action, MAX(time) as last_action FROM hb_process_activity WHERE instr(',' || '{{ai_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING action_count > 1000
```

## tunneling-check
<!-- Outbound tunneling from trusted processes -->
Identify protocol tunneling by finding rare outbound destinations from RMM or AI tools.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_process_names=ai_process_names, rmm_process_names=rmm_process_names)
~~~yaml
expected: Outbound traffic to rare IP addresses from trusted apps is an indicator
  of C2 tunneling.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) as host_count FROM hb_network_connection WHERE (instr(',' || '{{ai_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{rmm_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING host_count <= 2
```

## comprehensive-triage-agent
<!-- Comprehensive triage -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- ai-velocity-check
- tunneling-check
max_iterations: 6
objective: Confirm whether the sequence of trust abuse, high-velocity automation,
  and protocol tunneling constitutes a malicious intrusion.
success_criteria: A detailed intrusion verdict per host.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route on verdict -->
if~: "the comprehensive-triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: no-agent-telemetry)
else: → analyst-validation

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR to sever C2 and halt automated commands.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation -->
```manual target=analyst
Review the command lists from ai-velocity-check. Confirm if they match known development workflows or automated credential theft.
```
→ close-hunt

## close-hunt
<!-- Close hunt -->
```manual target=analyst
Document findings and identify any trusted applications that require tuning in the baseline.
```
→ end
