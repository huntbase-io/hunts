---
analysis: A simple detection rule might fire on 'Speech Processing' metadata, but
  this hunt pivots between the metadata, the prevalence of the path across the fleet,
  and the existence of a corresponding scheduled task to reduce false positives from
  legitimate installations of that software (e.g., in medical environments).
blind_spots:
- id: no-process-metadata
  owner: Endpoint Security Team
  question: Are the processes truly masquerading or are they legitimate?
  remediation: Enable Sysmon Event ID 1 (Process Creation) with metadata capture or
    use EDR with enriched metadata.
  requires: Endpoint telemetry with PE version info (Company, Description, etc.)
  risk: Without metadata, randomized paths may just look like legitimate installers
    or temp files, leading to high false negatives.
  stage: defense-evasion-masquerading
- id: ephemeral-random-paths
  owner: IR Team
  question: Was the binary deleted immediately after execution?
  remediation: Ensure file deletion events (hb_file_activity) are captured for the
    same paths.
  requires: Real-time process activity with parent-child tracking
  risk: If the binary is deleted after running, registry or task-based hunting might
    point to a non-existent file, making forensics difficult.
  stage: persistence-scheduled-task-execution
coverage:
- stage: defense-evasion-masquerading
  status: covered
  steps:
  - masqueraded-processes
  - rare-path-processes
- stage: persistence-scheduled-task-execution
  status: covered
  steps:
  - suspicious-scheduled-jobs
  - trueupdate-artifacts
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: initial-access-spoofed-software-sites
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: execution-wrapped-installer-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: c2-cloud-storage-communication
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries are bypassing standard name-based filters by using randomized
    paths and high-fidelity metadata clones. This hunt proactively finds these persistence
    mechanisms before they transition to more damaging lateral movement or data exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using randomized file paths in world-writable directories
  and masqueraded PE metadata (e.g., Philips Speech Driver or Indigo Rose) to evade
  detection and maintain persistence via scheduled tasks.
labels:
- hunt
- attack.t1562.001
- attack.t1053.005
- attack.t1036.005
name: Persistent Masqueraded Payloads
parameters:
  known_malicious_hashes:
    default:
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    - 676a2a7b94ca5187790b411985392df3d4734563a3d5483a918f4a7c1b505886
    - c6100166e2d36329a7364653696517a6104c86927d31481b43d3b7643b9c7161
    description: Hashes identified in the report.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: default
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows systems with active user sessions, particularly in regions
  where the campaign is active. Start with Users\Public and ProgramData directories
  as primary hunting grounds.
references:
- name: "MSRC \u2014 Counterfeit installers to system compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: initial-access-spoofed-software-sites
  reason: The delivery of these payloads starts with the browser navigating to spoofed
    domains.
  relation: precedes
- hunt: c2-cloud-storage-communication
  reason: Once persistent, the payload communicates with Alibaba Cloud OSS for updates.
  relation: follows
- hunt: counterfeit-installer-delivery-execution
  relation: follows
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - app-microsoft-edge.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    slug: initial-access-spoofed-software-sites
    tactic: initial-access
    techniques:
    - T1071
  - name: Dynamic installer execution
    observables:
    - app_setup.6653004.zip
    - a_instapp83353001.exe
    - z_instapp83351010.exe
    - C:\Users\Public\sE94yD\aLcUaw.exe
    - msedge.exe
    - 7zFM.exe
    - 360zip.exe
    - WinRAR.exe
    slug: execution-wrapped-installer-delivery
    tactic: execution
    techniques:
    - T1071
  - name: Payload masquerading and randomization
    observables:
    - C:\Program Files (x86)\
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - D:\hellothere\svchost.exe
    - XPSPLOG.dll
    slug: defense-evasion-masquerading
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Scheduled task persistence
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\zsMmvukD\beuv4Mie.exe
    - Indigo Rose TrueUpdate Client
    - ProductVersion 3.8.0.0
    - tu_rt.exe
    - _ir_tu2_temp_
    slug: persistence-scheduled-task-execution
    tactic: persistence
    techniques:
    - T1053.005
  - name: Command and control via Cloud Storage
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - Port 443
    slug: c2-cloud-storage-communication
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  summary: The Silver Fox campaign uses a large-scale network of spoofed software
    download sites to trick users into downloading dynamically generated malicious
    archives. Once executed, a wrapper installer drops masqueraded payloads into randomized
    system directories, establishes persistence via Windows Task Scheduler, and communicates
    with Alibaba Cloud OSS for further payload delivery.
series:
  index: 2
  slug: counterfeit-installers-to-system-compromise-tracking-a-deceptive-software-download-campaign
  title: 'Counterfeit installers to system compromise: Tracking a deceptive software
    download campaign'
  total: 3
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Persistent Masqueraded Payloads

This hunt identifies components of the Silver Fox (Yinhu) campaign by focusing on behavioral anomalies in process metadata and persistence mechanisms. It targets processes that exhibit illegitimate metadata (mismatched company names and descriptions) running from unusual paths like C:\Users\Public or C:\ProgramData, and correlates these with scheduled tasks and specific file artifacts left by the Indigo Rose TrueUpdate runtime.

## masqueraded-processes
<!-- Processes with masqueraded metadata -->
Identify processes using specific vendor metadata (Speech Processing or Indigo Rose) running from suspicious or randomized paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process with legitimate-looking company names but running from a world-writable
  path or with a randomized filename.
reads:
- device_hostname
- process_cmd_line
- process_file_company
- process_file_description
- process_hash_sha256
- process_name
- process_original_file_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_file_company, process_file_description, process_original_file_name, process_hash_sha256, time FROM hb_process_activity WHERE (LOWER(process_file_company) LIKE '%speech processing solutions%' OR LOWER(process_file_company) LIKE '%indigo rose%' OR LOWER(process_file_description) LIKE '%philips speech driver%') AND (LOWER(process_path) LIKE 'c:\\users\\public\\%' OR LOWER(process_path) LIKE 'c:\\programdata\\%' OR LOWER(process_path) LIKE 'c:\\program files (x86)\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-correlation-parallel
<!-- Correlate persistence and artifacts -->
parallel:
- → suspicious-scheduled-jobs
- → trueupdate-artifacts
- → rare-path-processes
join: → triage-agent

## suspicious-scheduled-jobs
<!-- Scheduled jobs in randomized paths -->
Find scheduled tasks that execute binaries from User or ProgramData directories.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Tasks pointing to randomized subdirectories in Public or ProgramData. These
  are often used by the Silver Fox loaders.
reads:
- device_hostname
- job_cmd_line
- job_name
- job_path
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_path, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%\\users\\public\\%' OR LOWER(job_cmd_line) LIKE '%\\programdata\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## trueupdate-artifacts
<!-- TrueUpdate temporary artifacts -->
Detect the presence of specific temporary files created by the Indigo Rose TrueUpdate runtime used in this campaign.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: File creation events with the '_ir_tu2_temp_' prefix, which corroborates
  the execution of the Indigo Rose-masqueraded payload.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) LIKE '%_ir_tu2_temp_%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-path-processes
<!-- Rare processes in writable paths -->
Identify binaries in Users\Public or ProgramData that are unique to a few hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries running from randomized paths seen on 3 or fewer hosts.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_path) as path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE 'c:\\users\\public\\%' OR LOWER(process_path) LIKE 'c:\\programdata\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## triage-agent
<!-- Triage combined evidence -->
```agent target=hunter
cite: required
context:
- masqueraded-processes
- suspicious-scheduled-jobs
- trueupdate-artifacts
- rare-path-processes
max_iterations: 4
objective: Identify malicious persistence using masqueraded binaries.
success_criteria: A per-host verdict of malicious, suspicious, or benign.
tools:
- endpoint
```

## decide-route
<!-- Decision on triage results -->
if~: "The triage verdict is malicious for one or more hosts" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-task
unavailable: → analyst-task (blind_spot: no-process-metadata)
else: → close-out

## contain-host
<!-- Isolate affected hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately and capture the suspicious binary from the randomized path for forensic analysis.
```
→ analyst-task

## analyst-task
<!-- Analyze and document -->
```manual target=analyst
Review the masqueraded metadata and scheduled tasks. Verify if the binary name matches its OriginalFileName and if the path is genuinely randomized. Ensure all related binaries are removed.
```
→ end

## close-out
<!-- Close hunt -->
```manual target=analyst
No malicious activity found. Document the negative result and the coverage provided.
```
→ end
