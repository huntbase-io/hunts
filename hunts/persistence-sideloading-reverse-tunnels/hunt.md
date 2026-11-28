---
analysis: A simple detection rule may find a specific Run key name, but this hunt
  pivots between the persistence artifact, the prevalence of module loads (detecting
  sideloading behaviors), and network-level SSH tunnel infrastructure to identify
  compromised hosts even as IOCs rotate.
blind_spots:
- id: endpoint-visibility-gap
  question: whether persistence was established on hosts without agent coverage
  requires: hb_module_activity and hb_registry_activity coverage on all hosts
  risk: A host without EDR or Sysmon will not report the registry or module load artifacts,
    even if it is participating in a reverse tunnel.
- id: script-block-logging-disabled
  question: the content of r.ps1 if the file is deleted before collection
  requires: hb_script_activity (PowerShell Script Block Logging)
  risk: If script block logging is off, we cannot see the parameters of the reverse
    tunnel if the on-disk script is ephemeral.
  stage: c2-reverse-tunneling
coverage:
- stage: persistence-staging-scripts
  status: covered
  steps:
  - run-key-persistence
- stage: evasion-dll-sideloading
  status: covered
  steps:
  - rare-programdata-modules
- stage: c2-reverse-tunneling
  status: covered
  steps:
  - c2-tunnel-ips
- reason: 'Belongs to another part of the ''Beyond the clipboard: The evolving tradecraft
    of ClickFix'' series.'
  stage: initial-access-clickfix-lure
  status: out_of_scope
- reason: 'Belongs to another part of the ''Beyond the clipboard: The evolving tradecraft
    of ClickFix'' series.'
  stage: execution-clipboard-powershell
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: ClickFix is a high-volume initial access technique leading directly
    to long-term persistence via DLL sideloading and reverse tunnels. Detecting these
    footholds is essential to stopping lateral movement and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has established persistence using ClickFix-dropped batch scripts
  that install DLL sideloading implants and reverse SSH tunnels to maintain long-term
  access.
labels:
- hunt
- attack.t1547.001
- attack.t1053.005
- attack.t1574.002
- attack.t1572
- command and control
- defense evasion
- execution
- initial access
- persistence
name: Persistence via Sideloading and Reverse Tunnels
parameters:
  c2_ips:
    default:
    - 167.148.201.104
    - 23.227.199.41
    - 151.240.151.76
    description: Known C2 or tunnel exit IPs from the research.
    from:
      kind: article
      observed: '2026-11-10'
      ref: huntress-clickfix-beyond-clipboard
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  target_run_paths:
    default:
    - CertEnrollCtrl_Y0db6oZq9
    - LockScreenContentServer_qQrRrJiHX
    - DuskDesk
    description: Specific Run key value names observed in ClickFix campaigns.
    from:
      kind: article
      observed: '2026-11-10'
      ref: huntress-clickfix-beyond-clipboard
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Look for endpoints with recent software installation errors or those reporting
  high PowerShell script block volume. Prioritize hosts where ProgramData contains
  new, single-character or random-character subdirectories.
references:
- name: "The evolving tradecraft of ClickFix \u2014 Huntress"
  url: https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
related:
- hunt: initial-access-clickfix-clipboard
  reason: This hunt focuses on the post-compromise persistence; a separate hunt is
    needed to target the initial clipboard-based social engineering.
  relation: out-of-scope-alternative
- hunt: clickfix-redirection-script-execution
  relation: follows
scenario:
  stages:
  - name: ClickFix Web Redirection
    observables:
    - vvestalw.ghost.io
    - westlaw-signon.com
    - apirequestaccess.com
    - moziw.com
    - http://apirequestaccess.com/cfirm.php?token=
    slug: initial-access-clickfix-lure
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Clipboard-based PowerShell Execution
    observables:
    - powershell.exe
    - Get-Clipboard
    - 6341434163416441.txt
    - cf_verify.zip
    slug: execution-clipboard-powershell
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Persistence via Tasks and Run Keys
    observables:
    - 1.bat
    - C:\ProgramData\f8f33b09aed97a47\
    - C:\ProgramData\7168f7f870a45fbb\
    - CertEnrollCtrl_Y0db6oZq9
    - LockScreenContentServer_qQrRrJiHX
    - DuskDesk
    - SysyService
    slug: persistence-staging-scripts
    tactic: persistence
    techniques:
    - T1053.005
    - T1547.001
  - name: DLL Sideloading
    observables:
    - CertEnrollCtrl.exe
    - CertEnroll.dll
    - LockScreenContentServer.exe
    - dui70.dll
    slug: evasion-dll-sideloading
    tactic: defence-evasion
    techniques:
    - T1574.002
  - name: Reverse Tunnel and C2
    observables:
    - C:\ProgramData\ShService\r.ps1
    - 23.227.199.41
    - 167.148.201.104
    - node.exe
    - LimeMint.js
    - launch.js
    slug: c2-reverse-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  summary: Threat actors use SEO poisoning and malvertising to lure users to fake
    verification pages (ClickFix) that trick them into executing malicious PowerShell
    commands from their clipboard. These commands download multi-stage payloads that
    establish persistence through scheduled tasks and Run keys, eventually deploying
    DLL sideloading chains for reverse SSH tunnels or Node.js-based RATs.
series:
  index: 2
  slug: beyond-the-clipboard-the-evolving-tradecraft-of-clickfix
  title: 'Beyond the clipboard: The evolving tradecraft of ClickFix'
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


# Persistence via Sideloading and Reverse Tunnels

This hunt targets the persistent phase of ClickFix campaigns where initial script execution leads to established footholds. It focuses on non-standard Registry Run keys pointing to ProgramData staging paths, identifies rare module loads that indicate DLL sideloading, and corroborates these findings with network connections to known reverse-tunnel infrastructure. An agent weighs the persistence, module prevalence, and network telemetry to identify compromised hosts.

## run-key-persistence
<!-- ProgramData Run key persistence -->
Find Run keys that point to scripts or binaries staged in ProgramData, matching specific campaign patterns.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, target_run_paths=target_run_paths)
~~~yaml
expected: A Run key pointing to a ProgramData path or using a known campaign value
  name. Silence means no such persistence was identified via Registry.
reads:
- device_hostname
- reg_target
- reg_value_data
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, reg_target, reg_value_data, reg_value_name, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\currentversion\run%' OR LOWER(reg_target) LIKE '%\currentversion\runonce%') AND (LOWER(reg_value_data) LIKE '%c:\programdata\%' OR instr(',' || '{{target_run_paths}}' || ',', ',' || reg_value_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with modules and network -->
parallel:
- → rare-programdata-modules
- → c2-tunnel-ips
join: → triage-implants

## rare-programdata-modules
<!-- Rare modules loaded from ProgramData -->
Stack-count module loads from ProgramData to identify rare DLLs that may be sideloaded.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A module load from a ProgramData subdirectory occurring on only a few hosts
  across the fleet.
prevalence:
  by: device_hostname
  key:
  - module_name
  - module_path
  rare_below: 3
reads:
- device_hostname
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT module_name, module_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_load FROM hb_module_activity WHERE LOWER(module_path) LIKE 'c:\programdata\%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY module_name, module_path HAVING host_count <= 3 ORDER BY host_count ASC
```

## c2-tunnel-ips
<!-- Network connections to tunnel infrastructure -->
Match network connections to known ClickFix and reverse SSH tunnel infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: A host connecting to a known tunnel IP, especially via processes like node.exe
  or powershell.exe.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-implants
<!-- Triage implants and tunnels -->
```agent target=hunter
cite: required
context:
- run-key-persistence
- rare-programdata-modules
- c2-tunnel-ips
max_iterations: 3
objective: Determine if a host has been successfully compromised with a persistent
  ClickFix implant. Correlate the Run key entry with rare DLL loads from the same
  staging path and any network connections to known tunnel IPs.
success_criteria: A clear verdict per host citing the intersection of persistence
  and behavior.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: endpoint-visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the endpoint agent. Revoke any active sessions for the user logged into the host.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the registry values and module paths cited by the agent. Collect any scripts or DLLs found in the C:\ProgramData subfolders for reverse engineering. Check for reverse SSH tunnel processes (e.g., node.exe or powershell.exe) and their command lines.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the hunt results. If any new IOCs were found in the forensic review (new IPs or DLL names), update the global watchlist and the parameters of this hunt.
```
→ end
