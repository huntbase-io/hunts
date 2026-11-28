---
analysis: A single rule might alert on any MSP360 installation. This hunt uses a gated
  flow to evaluate phishing-specific filenames and paths, corroborates them with persistent
  service creation, and uses stack-counting to differentiate a targeted attack from
  legitimate IT updates.
blind_spots:
- id: no-process-events
  owner: Endpoint Security
  question: Which masqueraded binaries were executed by the user?
  remediation: Deploy endpoint sensors to all workstations and ensure process creation
    auditing is enabled.
  requires: hb_process_activity with process command line
  risk: A host without endpoint telemetry contributes no process rows, allowing execution
    from a user profile to go unobserved.
  stage: initial-access-phishing-lures
- id: no-service-telemetry
  owner: Infrastructure Ops
  question: Was the persistence service successfully installed on the host?
  remediation: Enable and centralize Security log collection for service installation
    events (Event ID 4697/7045).
  requires: hb_service_activity with service installation events
  risk: The hunt cannot confirm a successful foothold without service installation
    logs, leading to missed compromises.
  stage: persistence-rmm-foothold
coverage:
- stage: initial-access-phishing-lures
  status: covered
  steps:
  - masqueraded-installer-lead
- stage: execution-installer-elevation
  status: covered
  steps:
  - masqueraded-installer-lead
  - service-persistence
- stage: persistence-rmm-foothold
  status: covered
  steps:
  - service-persistence
- reason: Belongs to another part of the 'Phishing Abuses RMM Tools for Persistent
    Access' series.
  stage: c2-redundant-rmm-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Phishing Abuses RMM Tools for Persistent
    Access' series.
  stage: post-compromise-tooling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The abuse of signed administrative software like MSP360 bypasses
    traditional reputation-based security controls. A negative result provides assurance
    that masqueraded installers have not established persistence via service-based
    footholds.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is distributing a legitimate but masqueraded MSP360 RMM installer
  via phishing lures to establish persistent, service-based administrative access
  on endpoints.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1543.003
- attack.t1547.001
- attack.t1106
- attack.t1190
- collection
- command and control
- execution
- initial access
- persistence
name: Masqueraded MSP360 RMM Installer and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rare_threshold:
    default: '5'
    description: Maximum number of hosts a binary can appear on to be considered rare.
    type: number
  rmm_hashes:
    default:
    - 108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc
    - f34330d4c6e0aa978dc3af40360c14b31ad51127
    description: Known hashes for the MSP360 RMM installer version 2.5.0.67.
    from:
      kind: article
      observed: '2026-09-29'
      ref: msrc-blog-2026-09-29
    type: list[hash]
  scope_hosts:
    default: []
    description: Optional host list to narrow the hunt; leave empty to scan the full
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints where users are likely to encounter phishing lures.
  Legitimate IT deployments of MSP360 usually occur on servers; a user-profile execution
  on a workstation is a high-fidelity trigger for this campaign.
references:
- name: "Microsoft Security Blog \u2014 Phishing Abuses RMM Tools for Persistent Access"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/
related:
- hunt: redundant-rmm-screenconnect-deployment
  reason: This hunt focuses on the initial MSP360 foothold; the follow-on ScreenConnect
    deployment and post-compromise tooling are covered in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing via Masqueraded RMM Installer
    observables:
    - VIP_ECARD_INVITATION_rmm_v2.5.0.67_oid.exe
    - ZoomSetup_Installation_v2.5.0.67_oid.exe
    - PDF Reader & Editor the Adobe Acrobatte_rmm_v2.5.0.67_oid.exe
    - RSVP_INVITATION_E_CARD_rmm_v2.5.0.67_oid.exe
    - SSA.GOV_STATEMENT_rmm_v2.5.0.67_oid.exe
    - 108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc
    - f34330d4c6e0aa978dc3af40360c14b31ad51127
    - gitlab.com
    - dropbox.com
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Installer Execution and UAC Elevation
    observables:
    - System.dll
    - nsExec.dll
    - UAC.dll
    - eventcreate.exe
    - dotnet --list-runtimes
    - MSP360 RMM Agent installer
    - Begin installation
    - End installation. MSP360 de Success.
    slug: execution-installer-elevation
    tactic: execution
    techniques:
    - T1059.001
    - T1106
  - name: RMM Agent Persistence and Configuration
    observables:
    - RMM.Agent.exe
    - RMM.Agent.Launcher.exe
    - C:\Program Files\RMM Agent\
    - UDP port 48678
    slug: persistence-rmm-foothold
    tactic: persistence
    techniques:
    - T1543.003
    - T1547.001
  - name: PowerShell Deployment of Secondary RMM
    observables:
    - Invoke-WebRequest
    - ClientSetup.msi
    - msiexec.exe /qn
    - ScreenConnect.ClientService.exe
    - ScreenConnect.WindowsClient.exe
    slug: c2-redundant-rmm-deployment
    tactic: command-and-control
    techniques:
    - T1059.001
    - T1105
  - name: Deployment of Information Collection Tools
    observables:
    - C:\Users\%user%\Documents\ScreenConnect\Temp\
    - WebBrowserPassView.exe
    - WindowsSecurity_PIN.exe
    - DefenderControl.exe
    - WebBrowserBookmarksView.exe
    - WindVerify.exe
    - Passwords.EXE
    slug: post-compromise-tooling
    tactic: collection
    techniques:
    - T1555
    - T1005
  summary: Threat actors use phishing lures themed as meeting invites and software
    updates to deliver masqueraded MSP360 RMM installers. Once established, the RMM
    agent executes PowerShell to deploy a redundant ScreenConnect client, which serves
    as a platform for transferring and executing various credential theft and information
    collection utilities.
series:
  index: 1
  slug: phishing-abuses-rmm-tools-for-persistent-access
  title: Phishing Abuses RMM Tools for Persistent Access
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


# Masqueraded MSP360 RMM Installer and Persistence

This hunt identifies the abuse of legitimate Remote Monitoring and Management (RMM) software, specifically MSP360 (v2.5.0.67), used to establish an initial foothold. The adversary distributes the signed installer through social-engineering lures themed around Zoom, PDF updates, or meeting invitations. Once executed from a user profile, the installer elevates and installs persistent Windows services. We open by scoping existing RMM footprints, then use a gated lead query to identify suspicious execution patterns. If the lead is judged suspicious, the hunt fanned out to investigate service persistence and the rarity of the installer across the estate to distinguish a targeted attack from legitimate IT activity.

## identify-rmm-scope
<!-- Identify RMM software footprint -->
Find hosts where MSP360 or RMM agent software is already installed to focus the investigation.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running or with MSP360 installed. This provides
  context for where legitimate RMM activity is expected.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%msp360%' OR LOWER(package_name) LIKE '%rmm agent%' OR LOWER(vendor_name) LIKE '%msp360%'
```

## masqueraded-installer-lead
<!-- Masqueraded RMM installer execution -->
Find RMM installer execution from user-writable paths using filenames designed to masquerade as common software or documents.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, rmm_hashes=rmm_hashes, scope_hosts=scope_hosts)
~~~yaml
expected: A process launch matching the RMM version or hash from a user directory.
  Silence suggests no such masqueraded installers were executed in the window.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_hash_sha256
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_hash_sha256, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%_rmm_v2.5.0.67_%' OR instr(',' || '{{rmm_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\downloads\%' OR LOWER(process_path) LIKE '%\temp\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## gate-read
<!-- Evaluate lead suspicion -->
```agent target=hunter
cite: required
context:
- masqueraded-installer-lead
max_iterations: 3
objective: Review the process executions in masqueraded-installer-lead. Determine
  if the filenames (e.g. including 'Zoom', 'PDF', 'ECARD', 'INVITATION') combined
  with the RMM version string 'v2.5.0.67' indicate a social-engineering lure.
success_criteria: A verdict of suspicious for any host showing masqueraded RMM execution
  from a user profile.
tools:
- endpoint
```

## gate-decision
<!-- Gate on suspicion -->
if~: "the gate-read verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-fanout
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-events)
else: → close-out

## parallel-fanout
<!-- Corroborate persistence and rarity -->
parallel:
- → service-persistence
- → installer-rarity
join: → final-triage

## service-persistence
<!-- RMM service persistence -->
Find evidence of successful RMM service installation following the lead execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of RMM.Agent or RMM.Agent.Launcher services. Silence suggests elevation
  or installation failed.
reads:
- device_hostname
- service_name
- service_cmd_line
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, service_name, service_cmd_line, actor_user_name, time FROM hb_service_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(service_name) LIKE 'rmm.agent%' OR LOWER(service_cmd_line) LIKE '%rmm agent%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## installer-rarity
<!-- Installer rarity stack-count -->
Determine if the suspicious binary name or hash is rare across the fleet, which distinguishes targeted lures from wide software updates.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rmm_hashes=rmm_hashes, rare_threshold=rare_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count showing the binary is unique or extremely rare. Silence on
  rarity suggests a broader, potentially legitimate deployment.
prevalence:
  by: device_hostname
  key:
  - name
  rare_below: 5
reads:
- process_name
- device_hostname
- process_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT LOWER(process_name) AS name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%_rmm_v2.5.0.67_%' OR instr(',' || '{{rmm_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING hosts <= {{rare_threshold}}
```

## final-triage
<!-- Triage foothold and rarity -->
```agent target=hunter
cite: required
context:
- gate-read
- service-persistence
- installer-rarity
max_iterations: 5
objective: Determine if any host has been successfully compromised via a masqueraded
  MSP360 installer. Correlate the suspicious execution identified in gate-read with
  the service creation and installer rarity.
success_criteria: A verdict of malicious for hosts showing the phishing lure followed
  by service persistence and binary rarity.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-service-telemetry)
else: → close-out

## contain-host
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Stop and delete the RMM.Agent and RMM.Agent.Launcher services. Collect the installer binary from the user's profile for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Forensic review -->
```manual target=analyst
Review the lead and service rows. Specifically check if RMM.Agent.exe spawned PowerShell to download ClientSetup.msi, which indicates the second remote access channel has been deployed.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the examined hosts and findings. Document any legitimate MSP360 use cases to update the excluded scope for future periodic runs.
```
→ end
