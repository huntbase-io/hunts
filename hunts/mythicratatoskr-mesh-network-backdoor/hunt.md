---
analysis: A single detection rule cannot correlate the two-month progression from
  a phishing-driven scheduled task to a decentralized Go-based mesh backdoor. This
  hunt baseline-counts the unique IPv6 range and pivots through the earlier MATCHWOK
  infection markers to verify a complex, multi-actor intrusion.
blind_spots:
- id: limited-mesh-visibility
  question: Whether the mesh-network traffic was visible to the network sensors
  requires: Comprehensive IPv6 logging including deprecated 200::/7 ranges
  risk: Adversaries could maintain C2 via encrypted IPv6 mesh routing that bypasses
    legacy IPv4-centric network filters.
  stage: yggdrasil-mesh-and-lateral-movement
coverage:
- stage: initial-access-scheduled-task
  status: covered
  steps:
  - scoping-pdfopentask
  - phishing-script-blocks
- stage: matchwok-backdoor-persistence
  status: covered
  steps:
  - matchwok-registry-persistence
- stage: mythicratatoskr-service-installation
  status: covered
  steps:
  - mythic-binary-execution
- stage: yggdrasil-mesh-and-lateral-movement
  status: covered
  steps:
  - yggdrasil-traffic-baseline
  - manual-incident-review
- reason: 'Belongs to another part of the ''MythicRatatoskr: An Yggdrasil-enabled
    backdoor deployed in a UAC-0099-Sandworm collaboration'' series.'
  stage: gpo-coordinated-data-wipe
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The UAC-0099 to Sandworm handover is a documented precursor to destructive
    attacks; verifying the absence of the MythicRatatoskr backdoor is an essential
    preventive measure for high-risk estates.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established initial access via a scheduled task to deploy
  the MATCHWOK backdoor and subsequently installed the MythicRatatoskr backdoor, which
  uses the Yggdrasil mesh network for stealthy C2 communication.
labels:
- hunt
- attack.t1566
- attack.t1053.005
- attack.t1059.001
- attack.t1071
- attack.t1041
- command and control
- impact
- initial access
- persistence
name: MythicRatatoskr Mesh-Network Backdoor and Sandworm Handover
parameters:
  lookback_days:
    default: '60'
    description: Days of history to examine, covering the window from initial access
      to the reported data-wiping attacks.
    type: number
  mythic_binaries:
    default:
    - updater.exe
    - krbtman.exe
    - windowsdefendersvc.exe
    - onedriveliveupdater.exe
    - applicationasphost.exe
    - act64.exe
    - ieupdate.exe
    - ie.exe
    description: Binary filenames associated with MythicRatatoskr and its proxy components.
    from:
      kind: article
      observed: '2026-10-22'
      ref: eset-mythicratatoskr
    type: list[path]
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step to focus the follow-on binary
      search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on the pdfopentask scheduled task; hosts identified here
  should be used to seed the scope_hosts parameter for the binary execution phase.
references:
- name: "ESET Research \u2014 MythicRatatoskr: An Yggdrasil-enabled backdoor deployed\
    \ in a UAC-0099-Sandworm collaboration"
  url: https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/
related:
- hunt: gpo-coordinated-data-wipe
  reason: This hunt focuses on the persistent backdoor phase; the final wiping phase
    via GPO is a distinct follow-on activity.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access and Scheduled Task Execution
    observables:
    - scheduled task named pdfopentask
    - PowerShell payload executed from %temp%\temporarydoc.txt
    - MATCHBOIL downloader execution
    slug: initial-access-scheduled-task
    tactic: initial-access
    techniques:
    - T1566
    - T1053.005
    - T1059.001
  - name: MATCHWOK Backdoor Persistence
    observables:
    - registry value UpdateMonitor in HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
    - C&C domain uztickets.com
    - Download URL egyptanimals.com/animals/photoalbum
    slug: matchwok-backdoor-persistence
    tactic: persistence
    techniques:
    - T1071
  - name: MythicRatatoskr Service Installation
    observables:
    - Windows service named ieupdate
    - Binary paths including C:\windows\system32\updater.exe, windowsdefendersvc.exe,
      and krbtman.exe
    - Configuration files named .updatecache in C:\Windows\system32 or C:\Windows\Temp
    - Configuration file .crond in %LocalAppData%/Temp
    slug: mythicratatoskr-service-installation
    tactic: persistence
    techniques:
    - T1053.005
  - name: Yggdrasil Mesh Network C2 and Lateral Movement
    observables:
    - IPv6 overlay traffic in the 200::/7 range
    - 10-minute startup delay for backdoor execution
    - SOCKS5 server deployment (krbtman.exe)
    - OpenSSH SFTP server used for internal sample distribution
    slug: yggdrasil-mesh-and-lateral-movement
    tactic: command-and-control
    techniques:
    - T1071
    - T1041
  - name: GPO Coordinated Data Wipe
    observables:
    - Active Directory Group Policy (GPO) deployment of wiping tools
    - Execution of SDelete utility across the organization
    slug: gpo-coordinated-data-wipe
    tactic: impact
    techniques:
    - T1059.001
  summary: UAC-0099 initiated access to a Ukrainian firm via spearphishing and deployed
    the MATCHWOK backdoor before handing off access to Sandworm. The campaign featured
    a novel Go-based backdoor named MythicRatatoskr that utilizes the Yggdrasil mesh
    network for command and control, ultimately concluding with a destructive data-wiping
    attack via Active Directory Group Policy.
series:
  index: 1
  slug: mythicratatoskr-an-yggdrasil-enabled-backdoor-deployed-in-a-uac-0099-sandworm-collaboration
  title: 'MythicRatatoskr: An Yggdrasil-enabled backdoor deployed in a UAC-0099-Sandworm
    collaboration'
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


# MythicRatatoskr Mesh-Network Backdoor and Sandworm Handover

The adversary gains initial access via phishing and persists using scheduled tasks and registry keys. The hunt identifies these early access markers and then pivots to find specialized mesh-network C2 telemetry. The phased flow ensures that the hunt weighs early access markers alongside specialized mesh C2 telemetry to confirm a high-confidence intrusion before the adversary transitions to data-wiping activity.

## scoping-pdfopentask
<!-- Scoping the pdfopentask beachhead -->
Identify the initial set of hosts where the UAC-0099 execution chain likely began.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts that executed the reported initial-access task name. Silence
  implies the beachhead was not established or the task name was rotated.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE LOWER(job_name) = 'pdfopentask' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early-corroboration
<!-- Corroborate early stage indicators -->
parallel:
- → phishing-script-blocks
- → matchwok-registry-persistence
join: → triage-early-access

## phishing-script-blocks
<!-- PowerShell blocks for temporarydoc.txt -->
Identify the execution of the PowerShell payload from the temporary directory.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Script content showing the download or execution of the MATCHBOIL payload.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, script_content, script_path, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%temporarydoc.txt%' OR LOWER(script_content) LIKE '%egyptanimals.com%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## matchwok-registry-persistence
<!-- MATCHWOK Run-key persistence -->
Find the specific registry key used to persist the MATCHWOK backdoor.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A registry value named UpdateMonitor pointing to a suspicious binary.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\currentversion\\run\\updatemonitor' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-access
<!-- Triage early access markers -->
```agent target=hunter
cite: required
context:
- scoping-pdfopentask
- phishing-script-blocks
- matchwok-registry-persistence
max_iterations: 3
objective: Determine which hosts show confirmed signs of the UAC-0099 initial access
  chain (pdfopentask, temporarydoc, or UpdateMonitor).
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows
  from the scoped results.
tools:
- endpoint
- network
```

## parallel-mythic-ratatoskr
<!-- Hunt for MythicRatatoskr and Mesh C2 -->
parallel:
- → mythic-binary-execution
- → yggdrasil-traffic-baseline
join: → full-chain-assessment

## mythic-binary-execution
<!-- MythicRatatoskr binary execution -->
Identify the execution of specific filenames and service names associated with the MythicRatatoskr backdoor.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, mythic_binaries=mythic_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of updater.exe, krbtman.exe, or other reported binaries, particularly
  on hosts from the scoping phase. Suffix matching identifies binaries even when installed
  in unusual paths.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\updater.exe' OR LOWER(process_name) LIKE '%\\krbtman.exe' OR LOWER(process_name) LIKE '%\\windowsdefendersvc.exe' OR LOWER(process_name) LIKE '%\\onedriveliveupdater.exe' OR LOWER(process_name) LIKE '%\\applicationasphost.exe' OR LOWER(process_name) LIKE '%\\act64.exe' OR LOWER(process_name) LIKE '%\\ieupdate.exe' OR LOWER(process_name) LIKE '%\\ie.exe' OR LOWER(process_cmd_line) LIKE '%ieupdate%' OR instr(',' || '{{mythic_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## yggdrasil-traffic-baseline
<!-- Baseline rare Yggdrasil mesh traffic -->
Find rare IPv6 traffic in the 200::/7 range indicating mesh-network C2.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: 'Connections to IPv6 addresses in the deprecated mesh range (0200:: to 03ff::),
  appearing on a small number of hosts.'
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_ip >= '0200:' AND dst_endpoint_ip < '0400:') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING host_count <= 3
```

## full-chain-assessment
<!-- Assess full intrusion chain -->
```agent target=hunter
cite: required
context:
- triage-early-access
- mythic-binary-execution
- yggdrasil-traffic-baseline
max_iterations: 6
objective: Confirm if any hosts showing early access markers also demonstrate MythicRatatoskr
  binary execution or Yggdrasil mesh network traffic.
success_criteria: A per-host verdict citing the transition from MATCHWOK to MythicRatatoskr.
tools:
- endpoint
- network
```

## compromise-decision
<!-- Route on compromise confidence -->
if~: "the full-chain-assessment verdict is malicious for at least one host showing Yggdrasil network connections or mythic binary execution" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-incident-review
unavailable: → manual-incident-review (blind_spot: limited-mesh-visibility)
else: → close-out-hunt

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate updater.exe and krbtman.exe processes, and capture the .updatecache configuration file for forensics.
```
→ manual-incident-review

## manual-incident-review
<!-- Forensic review of mesh config -->
```manual target=analyst
Decrypt and examine the .updatecache files from C:\Windows\system32 to find the Yggdrasil peer public keys and C2 endpoints; check SOCKS5 logs for internal lateral movement.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record whether Yggdrasil traffic was found, the binaries identified, and recommend the UpdateMonitor registry query for promotion to a permanent rule.
```
→ end
