---
analysis: A simple detection rule might flag sc.msi, but this hunt uses a gated flow
  to correlate behavioral markers (c=Exploited) with script block analysis and fleet-wide
  prevalence. This context allows an analyst to distinguish targeted SCKit intrusions
  from legitimate MSP software maintenance.
blind_spots:
- id: unmanaged-endpoints
  owner: IT Operations
  question: Are unauthorized clients installed on unmanaged endpoints?
  remediation: Audit agent coverage against network-discovered ScreenConnect clients.
  requires: comprehensive hb_software_inventory coverage
  risk: Intruders targeting hosts without an agent will leave no traces in this hunt,
    creating a blind beachhead.
  stage: initial-access-screenconnect-abuse
- id: no-script-block-logging
  owner: Security Engineering
  question: What did the decoded SCKit scripts execute in memory?
  remediation: Enable PowerShell Script Block Logging via GPO for all managed endpoints.
  requires: hb_script_activity with full PowerShell Script Block Logging (Event ID
    4104)
  risk: Without block-level logging, the hunt identifies the loader but not the actual
    commands SCKit ran after decryption.
  stage: sckit-powershell-deployment
coverage:
- stage: initial-access-screenconnect-abuse
  status: covered
  steps:
  - lead-unauthorized-msi-install
  - msi-cmd-prevalence
- stage: unauthorized-client-installation
  status: covered
  steps:
  - lead-unauthorized-msi-install
- stage: sckit-powershell-deployment
  status: covered
  steps:
  - script-block-activity
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: persistence-establishment
  status: out_of_scope
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: c2-and-infrastructure-communication
  status: out_of_scope
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: relay-trap-technician-targeting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ScreenConnect is a high-trust administrative tool; unauthorized clients
    provide persistent, unmonitored access that bypasses firewall and identity perimeters.
    Verifying the integrity of the support infrastructure is critical for MSP-managed
    estates.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has abused ScreenConnect management consoles or extension
  vulnerabilities to silently deploy unauthorized remote-access clients and the SCKit
  loader toolkit to managed endpoints.
labels:
- hunt
- attack.t1190
- attack.t1059
- attack.t1059.001
- command and control
- execution
- initial access
- lateral movement
- persistence
name: Unauthorized ScreenConnect Client Deployment
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: hunt-standard
    type: number
  sckit_scripts:
    default:
    - stage0loader.ps1
    - panel-lateral.ps1
    - panel-lateral-free.ps1
    - labconfig.ps1
    - lite-alert.ps1
    - trapwatch.ps1
    - install.ps1
    description: Filenames of the SCKit loader scripts identified in threat research.
    from:
      kind: article
      observed: '2026-11-13'
      ref: msrc-blog-sckit
    type: list[string]
  scope_hosts:
    default: []
    description: Hostnames to focus the behavioral search on; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with endpoints identified in the scoping query as having ScreenConnect
  or ConnectWise software. Focus initial behavioral analysis on hosts showing curl
  activity or silent msiexec parameters.
references:
- name: "MSRC Blog \u2014 SCKit abuses ScreenConnect to deploy remote access and target\
    \ technician sessions"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
related:
- hunt: sckit-persistence-mechanisms
  reason: This hunt focuses on initial deployment; persistence via scheduled tasks
    and run keys is handled by a sibling hunt in the series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ScreenConnect Management Abuse
    observables:
    - Unauthorized commands issued via RMM+ extension APIs
    - ScreenConnect.ClientSetup.msi requested with c=Exploited parameters
    - Abuse of ConnectWise Automate/LabTech extensions
    slug: initial-access-screenconnect-abuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious MSI Deployment
    observables:
    - curl.exe -o C:\Windows\Temp\sc.msi
    - msiexec.exe /i C:\Windows\Temp\sc.msi /qn /norestart
    - Silent installation of unauthorized ScreenConnect guest clients
    slug: unauthorized-client-installation
    tactic: execution
    techniques:
    - T1059
  - name: SCKit Payload Extraction
    observables:
    - Stage0Loader.ps1
    - Panel-Lateral.ps1
    - Panel-Lateral-free.ps1
    - LabConfig.ps1
    - PowerShell decoder extracting toolkit using device-specific material
    slug: sckit-powershell-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via Tasks and Registry
    observables:
    - schtasks.exe creating malicious maintenance tasks
    - Registry Run keys for SCKit launchers
    - trapkit\install.ps1
    - Stop-LabTrap.bat
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
    - T1562.001
  - name: Command and Control Infrastructure
    observables:
    - 185.99.255.28
    - 155.94.150.39
    - ns.mo7sen.dev
    - sc.payproofkit.com
    - cdn007-digitaldownloads.com
    - relaytrap.cs
    - newnewnew.gotdns.org
    - soxnewwork.homedns.org
    slug: c2-and-infrastructure-communication
    tactic: command-and-control
    techniques:
    - T1071
  - name: Technician Session Hijacking
    observables:
    - CVE-2026-84869
    - RelayTrap component delivery to connecting technicians
    - TrapWatch.ps1
    - ToolboxRelayUploader.exe
    - Lite-Alert.ps1
    slug: relay-trap-technician-targeting
    tactic: lateral-movement
    techniques:
    - T1059.001
  summary: Threat actors abuse vulnerabilities in ScreenConnect server extensions
    or hijacked management consoles to deploy unauthorized remote-access clients and
    the SCKit malware toolkit. The campaign establishes long-term persistence on customer
    endpoints to host RelayTrap, a component that targets IT technicians' workstations
    with malicious payloads during support sessions.
series:
  index: 1
  slug: sckit-abuses-screenconnect-to-deploy-remote-access-and-target-technician-sessions
  title: SCKit abuses ScreenConnect to deploy remote access and target technician
    sessions
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


# Unauthorized ScreenConnect Client Deployment

This hunt identifies the initial entry and deployment phase of the SCKit campaign. It first scopes the estate for hosts with ScreenConnect software, then focuses on a lead query identifying silent installations (sc.msi) with session markers (c=Exploited) common in reported attacks. The hunt follows a gated flow: it only performs expensive PowerShell script analysis and fleet-wide command-line prevalence counting if the initial MSI lead is suspicious. This ensures high-fidelity triage of unauthorized support software without manual review of every legitimate installation.

## identify-screenconnect-hosts
<!-- Scope ScreenConnect installations -->
Find the hosts that currently have ScreenConnect or ConnectWise software to narrow the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with ScreenConnect installed. Presence of the software is
  expected; silence means the software is not inventoried or is missing from the estate.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%connectwise%')
```

## lead-unauthorized-msi-install
<!-- Lead: Silent MSI deployment with exploited markers -->
Identify suspicious MSI installations involving sc.msi or session markers like c=Exploited initiated via curl or msiexec.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines showing curl downloading sc.msi or msiexec installing it silently.
  The presence of session markers in the URL is a high-confidence lead.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%sc.msi%' OR LOWER(process_cmd_line) LIKE '%c=exploited%') AND (LOWER(process_cmd_line) LIKE '%msiexec%' OR LOWER(process_cmd_line) LIKE '%curl%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate MSI installation lead -->
```agent target=hunter
cite: required
context:
- lead-unauthorized-msi-install
max_iterations: 3
objective: Determine if the command lines in lead-unauthorized-msi-install match the
  research for SCKit deployment, specifically focusing on unauthorized download sources
  or c=Exploited markers.
success_criteria: A per-host verdict of suspicious or benign, citing specific command
  strings.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on lead verdict -->
if~: "the evaluate-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → gather-sckit-evidence
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review (blind_spot: unmanaged-endpoints)
else: → close-out-hunt

## gather-sckit-evidence
<!-- Gather SCKit evidence -->
parallel:
- → script-block-activity
- → msi-cmd-prevalence
join: → triage-deployment

## script-block-activity
<!-- SCKit toolkit script execution -->
Identify the execution of the PowerShell-based decoders and loaders that extract the SCKit toolkit.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, sckit_scripts=sckit_scripts, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks matching the toolkit logic. Finding these on the same hosts
  as the MSI lead strongly corroborates a compromise.
reads:
- device_hostname
- script_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, script_name, script_content, time FROM hb_script_activity WHERE (instr(',' || '{{sckit_scripts}}' || ',', ',' || LOWER(script_name) || ',') > 0 OR LOWER(script_content) LIKE '%panel-lateral%' OR LOWER(script_content) LIKE '%relaytrap%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## msi-cmd-prevalence
<!-- Prevalence of MSI installation commands -->
Stack-count the installation commands to separate legitimate fleet-wide management activity from unique, attacker-controlled outliers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines seen on only one or two hosts. Genuine MSP maintenance will
  typically have high host counts.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%sc.msi%' OR LOWER(process_cmd_line) LIKE '%c=exploited%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## triage-deployment
<!-- Triage deployment activity -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- script-block-activity
- msi-cmd-prevalence
max_iterations: 6
objective: Determine if the host was targeted by SCKit by weighing the rarity of its
  MSI installation command line against the presence of known toolkit PowerShell script
  blocks.
success_criteria: A per-host verdict citing specific rows from process and script
  surfaces.
tools:
- endpoint
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage-deployment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review (blind_spot: unmanaged-endpoints)
else: → analyst-remediation-review

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately. Capture a forensic image and the unauthorized sc.msi installer for analysis.
```
→ analyst-remediation-review

## analyst-remediation-review
<!-- Analyst remediation review -->
```manual target=analyst
Review the triage evidence. Identify the origin of the management commands (e.g., vulnerable RMM+ extension). Audit the registry and scheduled tasks for follow-on SCKit persistence components.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Log the number of affected hosts and the specific command line markers identified. If markers like c=Exploited are confirmed malicious, promote them to a standing detection rule.
```
→ end
