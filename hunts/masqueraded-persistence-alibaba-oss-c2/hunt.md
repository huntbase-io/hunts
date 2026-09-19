---
analysis: A simple detection rule might catch the creation of a scheduled task, but
  this hunt pivots between task configuration, binary metadata masquerading, specific
  file system artifacts (TrueUpdate temp files), and cloud C2 destinations to distinguish
  malicious activity from legitimate updates.
blind_spots:
- id: missing-process-metadata
  question: Can we reliably see the 'TODO' metadata string or fabricated company names
    in process telemetry?
  requires: hb_process_activity with extended PE metadata (Company, Description, Product)
  risk: If the endpoint source only reports the image path and not extended metadata,
    the primary masquerading signal is lost.
  stage: defense-evasion-masquerading
- id: dns-retention
  question: Did the initial beaconing to Alibaba OSS occur before the current log
    window?
  requires: hb_dns_activity with 30+ days retention
  risk: Short lookback windows will miss the early 'update' beacons that indicate
    initial persistence setup.
  stage: c2-alibaba-oss
coverage:
- stage: defense-evasion-masquerading
  status: covered
  steps:
  - masqueraded-process-activity
- stage: persistence-scheduled-task
  status: covered
  steps:
  - suspicious-scheduled-tasks
  - trueupdate-file-artifacts
- stage: c2-alibaba-oss
  status: covered
  steps:
  - c2-dns-activity
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: initial-access-spoofed-downloads
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: execution-wrapper-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: execution-randomized-stage-one
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Silver Fox campaign utilizes high-fidelity impersonation and
    randomized paths to bypass signature-based AV. Identifying this persistent implant
    is critical because it serves as a long-term staging point for follow-on payloads
    via cloud infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is maintaining persistence via scheduled tasks that launch
  masqueraded binaries mimicking legitimate driver software or update clients to communicate
  with Alibaba Cloud infrastructure.
labels:
- hunt
- attack.t1562.001
- attack.t1036.005
- attack.t1053.005
- attack.t1071
- attack.t1090.003
name: Masqueraded Persistence and Alibaba OSS C2
parameters:
  c2_domains:
    default:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    description: Alibaba OSS bucket domains used for C2.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-2026-09-01
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-lookback
    type: number
  masquerade_companies:
    default:
    - Speech Processing Solutions GmbH
    - Indigo Rose Corporation
    description: Company names used in malicious binary metadata.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-2026-09-01
    type: list[string]
  scope_hosts:
    default: []
    description: Paste the device_hostname results from 'suspicious-scheduled-tasks'
      here to focus the subsequent parallel queries.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-pivot
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with Windows endpoints in regions with China-based operations. Focus
  specifically on tasks in ProgramData and Public profiles.
references:
- name: "MSRC \u2014 Counterfeit installers to system compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-initial-delivery
  reason: This hunt targets the activity after the initial installer has executed
    and the persistent payload is dropped.
  relation: follows
- hunt: counterfeit-installer-randomized-execution
  relation: follows
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - app-microsoft-edge.com.cn
    - kaspersky-lab.hl.cn
    - sejda.hl.cn
    - translate-youdao.hl.cn
    - zh-diskgenius.com.cn
    - baidu-pan.com.cn
    - ocam-pc.com.cn
    - cn-drawio.com.cn
    - steelseries-cn.com.cn
    - gw-sogou.com.cn
    - calibre-ebook.com.cn
    - mindmoster.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    slug: initial-access-spoofed-downloads
    tactic: initial-access
    techniques:
    - T1071
  - name: Wrapper installer execution
    observables:
    - a_instapp83353001.exe
    - z_instapp83351010.exe
    - ainstaller-86533003.exe
    - ainst8663586104.exe
    - app_setup.6653004.zip
    slug: execution-wrapper-installer
    tactic: execution
    techniques:
    - T1204.002
  - name: Randomized stage-one payload
    observables:
    - C:\Users\Public\sE94yD\aLcUaw.exe
    - C:\Users\Public\nvdPX5\2b3L5i.exe
    - C:\Users\Public\yZ6A88\9bEELI.exe
    - C:\Users\Public\Y93eny\Ge86Zr.exe
    - C:\Users\Public\Mmzm0e\Lrrhwp.exe
    - C:\Users\Public\YJMvsB\BcQVw7.exe
    - 'sha256: 676a2a7b94ca54e19597793a388053c892850931f6e076735e5d122283083e9d'
    slug: execution-randomized-stage-one
    tactic: execution
    techniques:
    - T1059
  - name: Binary masquerading
    observables:
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - tu_rt.exe
    - Indigo Rose TrueUpdate Client
    - 'TODO: <Product name>'
    - D:\hellothere\svchost.exe
    - XPSPLOG.dll
    slug: defense-evasion-masquerading
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1036.005
  - name: Persistence via Task Scheduler
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\zsMmvukD\beuv4Mie.exe
    - C:\ProgramData\uwMUCYBN\SaYC4Mga.exe
    - Temp\_ir_tu2_temp_
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: C2 via Alibaba Cloud OSS
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - port 443
    slug: c2-alibaba-oss
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  summary: Attackers impersonate legitimate software brands via look-alike domains
    to distribute server-side regenerated installer archives. These installers drop
    stage-one payloads in randomized paths and establish persistence through scheduled
    tasks, masquerading as legitimate drivers and update utilities to facilitate C2
    communications.
series:
  index: 2
  slug: counterfeit-installers-to-system-compromise-tracking-a-deceptive-software-download-campaign
  title: 'Counterfeit installers to system compromise: Tracking a deceptive software
    download campaign'
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


# Masqueraded Persistence and Alibaba OSS C2

This hunt targets the long-term persistence and defense evasion phases of the Silver Fox (Yinhu) campaign. It identifies scheduled tasks running from non-standard directories (ProgramData, Public) and corroborates them using binary metadata masquerading (mimicking Philips Speech or Indigo Rose software) and network activity to Alibaba OSS buckets. By looking for the 'TODO: <Product name>' placeholder in PE headers and the specific TrueUpdate temp file pattern, the hunt isolates persistent implants from genuine software.

## suspicious-scheduled-tasks
<!-- Scheduled tasks in user-writable paths -->
Identify persistence mechanisms where tasks point to binaries in ProgramData, Public, or PerfLogs, excluding system-standard paths.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Tasks targeting randomized subfolders in world-writable paths. These are
  common in this campaign for persistent staging. Silence suggests no such tasks are
  currently active.
reads:
- device_hostname
- job_cmd_line
- job_name
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%\\programdata\\%' OR LOWER(job_cmd_line) LIKE '%\\users\\public\\%' OR LOWER(job_cmd_line) LIKE '%\\perflogs\\%') AND (LOWER(job_cmd_line) LIKE '%.exe%' OR LOWER(job_cmd_line) LIKE '%.dll%') AND LOWER(job_cmd_line) NOT LIKE '%\\windows\\system32\\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-persistence
<!-- Corroborate on metadata, networking, and files -->
parallel:
- → masqueraded-process-activity
- → c2-dns-activity
- → trueupdate-file-artifacts
join: → triage-persistence

## masqueraded-process-activity
<!-- Masqueraded metadata in running processes -->
Find processes using fake Philips or Indigo Rose metadata running from non-standard paths on the identified hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, masquerade_companies=masquerade_companies, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes with fabricated metadata (especially the TODO string) running
  from randomized subdirectories. Hits are strong indicators of the Silver Fox implant.
prevalence:
  by: device_hostname
  key:
  - process_file_description
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_file_company
- process_file_description
- process_file_product
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_file_company, process_file_description, process_file_product, time FROM hb_process_activity WHERE (instr(',' || '{{masquerade_companies}}' || ',', ',' || process_file_company || ',') > 0 OR LOWER(process_file_description) LIKE '%philips speech%' OR LOWER(process_file_description) LIKE '%trueupdate%' OR process_file_product LIKE '%TODO:%') AND (LOWER(process_path) NOT LIKE '%\\program files%' AND LOWER(process_path) NOT LIKE '%\\windows\\system32%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-activity
<!-- DNS lookups to Alibaba OSS -->
Confirm C2 communication to the observed campaign infrastructure specifically for the scoped hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS requests for the Alibaba OSS C2 domain from hosts identified in the
  scoping step.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## trueupdate-file-artifacts
<!-- TrueUpdate runtime artifacts -->
Detect the specific file artifacts left by the Indigo Rose TrueUpdate runtime used in the campaign, restricted to candidate hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of '_ir_tu2_temp_' files by processes running on hosts that also
  possess suspicious scheduled tasks.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\\temp\\_ir_tu2_temp_%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-persistence
<!-- Weigh persistence evidence -->
```agent target=hunter
cite: required
context:
- suspicious-scheduled-tasks
- masqueraded-process-activity
- c2-dns-activity
- trueupdate-file-artifacts
max_iterations: 5
objective: Determine if a host has the Silver Fox persistent implant by weighing the
  presence of suspicious scheduled tasks, masqueraded process metadata (especially
  the TODO string), and Alibaba OSS network traffic.
success_criteria: A verdict of malicious or suspicious per host with citations to
  the task and process rows.
tools:
- endpoint
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on the TODO metadata or C2 traffic" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-metadata)
else: → analyst-review

## isolate-host
<!-- Isolate host and collect binary -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Prior to full remediation, collect the binary identified in the scheduled task and the contents of the randomized folder in ProgramData.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage agent's citations. Confirm metadata masquerading on a non-standard path. Document the source of the installer and look for lateral movement from the confirmed host using authentication logs.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record results, what was examined, and whether any new indicators should be added to the parameter lists.
```
→ end
