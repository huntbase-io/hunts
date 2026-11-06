---
analysis: A simple rule may fire on taskkill, but this hunt correlates termination
  attempts with driver load counts (BYOVD) and application installations, providing
  a complete picture of the attack chain that individual rules miss.
blind_spots:
- id: endpoint-visibility-gap
  question: Was Windows Defender disabled before telemetry could be forwarded?
  requires: hb_device_config_state with tamper protection status
  risk: If an actor disables the security agent and its logging before BYOVD begins,
    the later stages remain invisible.
  stage: defense-evasion-edr-impairment
- id: event-log-clearing
  question: Were local event logs cleared to hinder analysis?
  requires: off-device log forwarding (SIEM)
  risk: Interlock actors are known to clear logs; if logs are not centralized, the
    lead query will return zero rows even if an intrusion occurred.
  stage: defense-evasion-edr-impairment
coverage:
- stage: rmm-dropper-execution
  status: covered
  steps:
  - rmm-msi-deployment
- stage: defense-evasion-edr-impairment
  status: covered
  steps:
  - edr-termination-lead
  - driver-load-stacking
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: vishing-rmm-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: edge-vulnerability-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: persistence-web-shell-accounts
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: lateral-movement-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: credential-access-ai-secrets
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: exfiltration-over-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''IR trends Q3 2026: Actors impersonate
    IT help desks in vishing attacks as ransomware activity increases'' series.'
  stage: data-encryption-for-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ransomware operators are increasingly prioritizing the systematic
    impairment of EDR to evade detection. A negative result provides the business
    with confidence that security agents remain operational across the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a foothold and is systematically disabling
  security controls via process termination and Bring Your Own Vulnerable Driver (BYOVD)
  techniques to facilitate ransomware execution via RMM tools.
labels:
- hunt
- attack.t1562.001
- attack.t1059.001
- attack.t1070.001
- attack.t1195.002
- attack.t1486
- credential access
- defense evasion
- execution
- exfiltration
- impact
- initial access
- lateral movement
- persistence
name: EDR Impairment and RMM-Driven Ransomware Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_tools:
    default:
    - meshagent
    - rclone
    - psexec
    - quickassist
    description: Keywords for remote monitoring and administrative tools used in ransomware
      campaigns.
    from:
      kind: article
      observed: '2026-10-29'
      ref: https://blog.talosintelligence.com/ir-trends-q3-2026/
    type: list[string]
  scope_hosts:
    default: []
    description: The list of hosts discovered in the lead query to scope the parallel
      queries.
    type: list[host]
  security_processes:
    default:
    - cscm.exe
    - sfc.exe
    - msmpeng.exe
    - msascuil.exe
    description: Process names of security agents and system integrity tools targeted
      for termination.
    from:
      kind: article
      observed: '2026-10-29'
      ref: https://blog.talosintelligence.com/ir-trends-q3-2026/
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/ir-trends-q3-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The analyst focuses on high-value endpoints where the adversary might have
  cleared security logs. Prioritize servers and workstations showing recent administrative
  tool usage or PowerShell activity.
references:
- name: "Cisco Talos \u2014 IR trends Q3 2026: Actors impersonate IT help desks"
  url: https://blog.talosintelligence.com/ir-trends-q3-2026/
related:
- hunt: vishing-rmm-initial-access
  reason: The initial social engineering via vishing belongs to a hunt focused on
    identity and RMM session initiation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: IT help desk vishing and remote assistance
    observables:
    - Microsoft Quick Assist
    - IT help desk impersonation
    - vishing calls
    slug: vishing-rmm-access
    tactic: initial-access
    techniques:
    - T1566
    - T1133
  - name: Exploitation of Cisco IOS XE management interface
    observables:
    - CVE-2023-20198
    - web-based management interface access
    slug: edge-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Web shell implant and privileged account creation
    observables:
    - BadCandy web shell
    - privilege 15 command
    - local user creation on network device
    slug: persistence-web-shell-accounts
    tactic: persistence
    techniques:
    - T1505.003
    - T1133
  - name: RMM deployment and MSI installation
    observables:
    - MeshAgent
    - PowerShell
    - MSI package
    - remote IP download
    slug: rmm-dropper-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: EDR killing via BYOVD and task termination
    observables:
    - taskkill.exe
    - cscm.exe
    - sfc.exe
    - BYOVD
    - vulnerable drivers
    - Windows Defender real-time protection disabled
    - event logs cleared
    slug: defense-evasion-edr-impairment
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1070.001
  - name: Network discovery and lateral movement
    observables:
    - PsExec.exe
    - MSTSC
    - IP scan
    - Microsoft Terminal Services Client
    slug: lateral-movement-discovery
    tactic: lateral-movement
    techniques:
    - T1021.002
    - T1021.001
  - name: macOS keychain scraping for AI credentials
    observables:
    - macOS keychain
    - Anthropic Claude Code secrets
    - credential scraping scripts
    slug: credential-access-ai-secrets
    tactic: credential-access
    techniques:
    - T1003
  - name: Data exfiltration via Rclone
    observables:
    - Rclone
    - multi-day exfiltration
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1041
  - name: Ransomware encryption
    observables:
    - VYPR
    - Interlock
    - ransom note
    slug: data-encryption-for-impact
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors utilized vishing to impersonate IT help desks and establish
    remote sessions via Microsoft Quick Assist, or exploited CVE-2023-20198 on Cisco
    IOS XE edge devices to gain entry. Post-compromise, they deployed RMM tools and
    vulnerable drivers to terminate EDR systems (BYOVD) before conducting multi-day
    data exfiltration via Rclone and deploying ransomware variants like VYPR and Interlock.
series:
  index: 2
  slug: ir-trends-q3-2026-actors-impersonate-it-help-desks-in-vishing-attacks-as-ransomware-activity-inc
  title: 'IR trends Q3 2026: Actors impersonate IT help desks in vishing attacks as
    ransomware activity increases'
  total: 3
severity: critical
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


# EDR Impairment and RMM-Driven Ransomware Execution

This hunt targets the execution and defense evasion stages observed in Q3 2026 ransomware campaigns, such as VYPR and Interlock. It identifies the direct impairment of security agents like Cisco Secure Endpoint and the Windows System File Checker (sfc.exe). The hunt corroborates these leads by detecting kernel driver stacking—a signature of BYOVD experimentation—and the deployment of RMM tools used for PowerShell-based MSI installations. An agent weighs the combined evidence of control disruption and suspicious deployment to identify hosts at immediate risk of impact.

## edr-termination-lead
<!-- Security process termination attempts -->
The query identifies where the adversary terminated security agents or system integrity tools, a primary indicator of defense evasion.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, security_processes=security_processes)
~~~yaml
expected: Rows showing the termination of Cisco Secure Endpoint (cscm.exe) or the
  Windows Defender process. Silence suggests no direct process-level impairment of
  these targets occurred.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE ((activity_id = 2 AND (instr(',' || '{{security_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE '%\\cscm.exe' OR LOWER(process_name) LIKE '%\\sfc.exe' OR LOWER(process_name) LIKE '%\\msmpeng.exe' OR LOWER(process_name) LIKE '%\\msascuil.exe')) OR (LOWER(process_name) LIKE '%\\taskkill.exe' AND (LOWER(process_cmd_line) LIKE '%/f%' OR LOWER(process_cmd_line) LIKE '%/im%'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with drivers and RMM -->
parallel:
- → driver-load-stacking
- → rmm-msi-deployment
join: → triage-impairment

## driver-load-stacking
<!-- Kernel driver load stacking -->
The hunt identifies hosts where the adversary loaded an unusually high number of drivers, indicating a BYOVD attack.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single host with more than 3 unique driver loads in a short window, particularly
  with non-standard signers. This aligns with VYPR BYOVD tactics.
prevalence:
  by: device_hostname
  key:
  - driver_path
  rare_below: 3
reads:
- device_hostname
- driver_path
- driver_signature_subject
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, driver_path, driver_signature_subject, COUNT(*) OVER (PARTITION BY device_hostname) AS load_count, time FROM hb_kernel_extension_activity WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY load_count DESC
```

## rmm-msi-deployment
<!-- RMM and MSI activity via PowerShell -->
The query detects the adversary installing RMM packages or MSI files via PowerShell, as seen in the VYPR campaign.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, rmm_tools=rmm_tools, scope_hosts=scope_hosts)
~~~yaml
expected: The query finds evidence of the adversary installing MeshAgent or similar
  RMM tools via PowerShell commands. Silence proves only that no MSI lifecycle events
  matched the keywords.
reads:
- device_hostname
- message
- package_calling_process
- time
silence: not_evidence_of_absence
source: hb_application_lifecycle
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, message, package_calling_process, time FROM hb_application_lifecycle WHERE (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(message) || ',') > 0 OR LOWER(message) LIKE '%.msi%') AND (LOWER(package_calling_process) LIKE '%\\powershell.exe' OR LOWER(package_calling_process) LIKE '%\\pwsh.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-impairment
<!-- Weigh impairment and deployment -->
```agent target=hunter
cite: required
context:
- edr-termination-lead
- driver-load-stacking
- rmm-msi-deployment
max_iterations: 5
objective: Identify hosts where the adversary impaired security controls immediately
  prior to or alongside the deployment of RMM tools or multiple kernel drivers.
success_criteria: A per-host verdict citing the specific process terminated and the
  count of unique drivers loaded.
tools:
- endpoint
```

## route-verdict
<!-- Route on impairment verdict -->
if~: "the triage verdict is malicious for at least one host based on EDR termination and RMM deployment" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: endpoint-visibility-gap)
else: → forensic-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to prevent the adversary from moving laterally or executing ransomware. Do not reboot, as this may trigger automated ransomware encryption routines.
```
→ forensic-review

## forensic-review
<!-- Forensic review of drivers and RMM -->
```manual target=analyst
Examine the hashes of the loaded drivers. Cross-reference them with databases of known vulnerable drivers (e.g., loldrivers.io). Review the source of any MeshAgent or MSI packages found.
```
→ close-out

## close-out
<!-- Close-out and reporting -->
```manual target=analyst
Record all identified malicious files and driver hashes. Ensure any service gaps identified are reported for policy review.
```
→ end
