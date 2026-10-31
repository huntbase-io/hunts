---
analysis: While a rule might fire on Set-MpPreference, this hunt correlates registry
  writes across both Policy and local hives, applies a fleet-wide prevalence count
  to find rare paths, and specifically checks for the stealth registry flag.
blind_spots:
- id: registry-visibility-gap
  question: Did the exclusion occur on a host where the endpoint agent lacks permissions
    to read MDAV-protected registry keys?
  requires: hb_registry_activity logging with sufficient permissions
  risk: The registry is the most reliable source for the final state of exclusions;
    if it is unreadable, the hunt relies solely on process logs which may be incomplete.
  stage: modify-defender-exclusions
- id: gpo-actor-attribution
  question: Was the exclusion set via a GPO modification on the domain controller
    rather than a local command?
  requires: Domain Controller GPO audit logs
  risk: Local registry activity will show the result, but the actor_user_name may
    reflect the SYSTEM account applying the GPO rather than the attacker account used
    on the DC.
  stage: modify-defender-exclusions
coverage:
- stage: modify-defender-exclusions
  status: covered
  steps:
  - registry-defender-modifications
  - rare-exclusion-paths
  - suspicious-exclusion-commands
- stage: stealth-defender-exclusions
  status: covered
  steps:
  - registry-defender-modifications
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries use Defender exclusions as a highly effective way to
    bypass real-time protection; identifying broad or hidden exclusions is a high-fidelity
    indicator of persistent compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has modified Microsoft Defender exclusions to shield malicious
  paths from scanning and enabled stealth settings to hide these changes from local
  administrators.
labels:
- hunt
- attack.t1047
- attack.t1059.001
- attack.t1562.001
- defense evasion
name: Microsoft Defender Antivirus Exclusion Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search; leave empty for all.
    type: list[host]
  suspicious_paths:
    default:
    - c:\
    - c:\temp
    - c:\users\public
    - c:\windows\temp
    - c:\downloads
    description: Common paths attackers exclude from MDAV scanning.
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/you-can-run-but-you-cant-hide-defender-exclusions
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and workstations that have broad internet access or
  those hosting legacy applications often excluded by IT as these provide the most
  noise for an attacker to blend in.
references:
- name: "Huntress \u2014 You Can Run, But You Can't Hide: Defender Exclusions"
  url: https://www.huntress.com/blog/you-can-run-but-you-cant-hide-defender-exclusions
related:
- hunt: defender-tampering-service-disablement
  reason: This hunt focuses on exclusions; a different hunt would be needed to detect
    the total disablement of the WinDefend service.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Defender Exclusion Modification
    observables:
    - Set-MpPreference -ExclusionPath
    - Add-MpPreference -ExclusionPath
    - Set-MpPreference -ExclusionExtension
    - Invoke-CimMethod -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference
      -MethodName Add
    - reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
    - reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions"
    - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions
    - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions
    - 'Excluded paths: C:\Temp, C:\, Downloads'
    slug: modify-defender-exclusions
    tactic: defense-evasion
    techniques:
    - T1059.001
    - T1047
    - T1562.001
  - name: Hide Defender Exclusions
    observables:
    - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\HideExclusionsFromLocalAdmins
    - reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v HideExclusionsFromLocalAdmins
      /t REG_DWORD /d 1
    slug: stealth-defender-exclusions
    tactic: defense-evasion
    techniques:
    - T1562.001
  summary: Attackers leverage Windows Defender Antivirus (MDAV) exclusion settings
    to hide malicious binaries from real-time and scheduled scans. By using PowerShell,
    WMI, or direct registry modifications, adversaries can exclude entire directories
    (e.g., C:\Temp or the whole C:\ drive) and hide these exclusions from administrators
    by setting the HideExclusionsFromLocalAdmins registry value.
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


# Microsoft Defender Antivirus Exclusion Abuse

Adversaries like GootKit and WhisperGate abuse Microsoft Defender Antivirus (MDAV) exclusions to hide malicious binaries from real-time and scheduled scans. By adding file paths such as the root drive or temporary folders to the exclusion list, they ensure their payloads remain undetected. This hunt identifies these modifications by correlating registry changes with PowerShell and WMI execution, specifically looking for rare exclusion paths and the HideExclusionsFromLocalAdmins setting which blinds administrators and the SYSTEM user from viewing the current policy.

## registry-defender-modifications
<!-- Defender exclusion and stealth registry changes -->
Identify every host where Defender exclusions were modified or the local admin hiding policy was set.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_paths=suspicious_paths)
~~~yaml
expected: Rows indicating a target exclusion path or the HideExclusionsFromLocalAdmins
  toggle. Silence means no readable registry modifications occurred on the enrolled
  estate.
reads:
- actor_user_name
- device_hostname
- reg_target
- reg_value_data
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, actor_user_name, reg_target, reg_value_name, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\microsoft\windows defender\exclusions\%' OR LOWER(reg_target) LIKE '%\hideexclusionsfromlocaladmins%' OR instr(',' || '{{suspicious_paths}}' || ',', ',' || LOWER(reg_value_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## correlate-evidence
<!-- Correlate with execution and prevalence -->
parallel:
- → rare-exclusion-paths
- → suspicious-exclusion-commands
join: → triage-exclusion-behavior

## rare-exclusion-paths
<!-- Which exclusion paths are rare -->
Stack-count the paths found in registry values so that one-off attacker paths stand out from common corporate IT exclusions.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of exclusion paths seen on only a few hosts; corporate-wide software
  paths can be ignored.
prevalence:
  by: device_hostname
  key:
  - reg_value_name
  rare_below: 5
reads:
- device_hostname
- reg_target
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT reg_value_name AS excluded_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\windows defender\exclusions\paths%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY reg_value_name HAVING host_count < 5 ORDER BY host_count ASC
```

## suspicious-exclusion-commands
<!-- Defender preference commands in process logs -->
Find process launches using Set-MpPreference or Add-MpPreference which are the primary vectors for MDAV modification.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines explicitly setting exclusions. Silence suggests WMI or direct
  registry manipulation was used instead.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%set-mppreference%' OR LOWER(process_cmd_line) LIKE '%add-mppreference%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-exclusion-behavior
<!-- Evaluate exclusion legitimacy -->
```agent target=hunter
cite: required
context:
- registry-defender-modifications
- rare-exclusion-paths
- suspicious-exclusion-commands
max_iterations: 6
objective: Decide whether the combined registry modifications, prevalence of excluded
  paths, and process commands indicate an attempt to hide malicious activity, citing
  the specific rows.
success_criteria: A per-host verdict citing paths and command lines that match known
  abuse patterns.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving suspicious exclusion paths or the hidden exclusions setting" (confidence: high, judge=hunter)
then: → contain-and-remediate
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: registry-visibility-gap)
else: → close-out-hunt

## contain-and-remediate
<!-- Isolate host and remediate exclusions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host to stop lateral movement. Run Remove-MpPreference -ExclusionPath <path> or Remove-MpPreference -ExclusionExtension <extension> via an administrative PowerShell session to remove the unauthorized exclusions. Set the HideExclusionsFromLocalAdmins registry value to 0 if it was enabled.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Verify remediation -->
```manual target=analyst
Review the isolation and remediation logs. Confirm that MDAV is now scanning the previously excluded paths and investigate the process or actor responsible for the initial configuration change.
```
→ close-out-hunt

## close-out-hunt
<!-- Hunt close-out -->
```manual target=analyst
Record the number of hosts with suspicious exclusions. If specific paths found were common among attackers, recommend promoting the registry monitoring query to a standing detection rule.
```
→ end
