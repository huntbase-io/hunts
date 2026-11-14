---
analysis: A single rule on schtasks.exe would be too noisy. This hunt pivots between
  HTTP lures, hidden-window conhost scripts, and unique SSH command arguments to confirm
  the specific Star Blizzard infection chain.
blind_spots:
- id: vhdx-mount-visibility
  question: Which specific VHDX file was mounted by the user?
  requires: Windows Event ID 12 (VHD Mount) or endpoint volume telemetry
  risk: The hunt sees the aftermath (script execution), but linking it directly to
    the specific VHDX file requires telemetry that may not be present on standard
    configurations.
  stage: vhdx-payload-execution
- id: msi-payload-blindness
  question: What was the hash of the MSI installer downloaded via SSH?
  requires: Endpoint file write events with SHA256 of the MSI
  risk: If the MSI is deleted immediately after creating the task, forensic identification
    of the loader relies solely on memory or registry remnants.
  stage: ssh-msi-delivery
coverage:
- stage: phishing-initial-contact
  status: covered
  steps:
  - phishing-contact
- stage: vhdx-payload-execution
  status: covered
  steps:
  - conhost-script-execution
- stage: ssh-msi-delivery
  status: covered
  steps:
  - ssh-delivery-mechanism
- stage: scheduled-task-persistence
  status: covered
  steps:
  - cpl-scheduled-tasks
- stage: redflick-cpl-loading
  status: covered
  steps:
  - cpl-scheduled-tasks
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Star Blizzard (FSB Centre 18) is a sophisticated actor targeting
    critical policy-making institutions. The RedFlick technique is designed specifically
    to bypass interactive detections, making a cross-surface behavioral hunt a business
    necessity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via phishing and is using the RedFlick
  technique to deliver a backdoor through VHDX-mounted scripts, SSH-based MSI downloads,
  and CPL-driven scheduled tasks.
labels:
- hunt
- attack.t1566.001
- attack.t1566.002
- attack.t1204.002
- attack.t1059.003
- attack.t1105
- attack.t1218
- attack.t1053.005
- attack.t1218.002
- defense evasion
- execution
- initial access
- persistence
name: Star Blizzard RedFlick VHDX and SSH-based Malware Delivery
parameters:
  campaign_domains:
    default:
    - ukr.net
    description: Domains associated with the initial phishing contact and compromised
      accounts.
    from:
      kind: article
      observed: '2026-09-29'
      ref: msrc-blog-star-blizzard-2026
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow follow-on stages based on initial
      leads.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations of researchers, diplomatic staff, and NGOs. Broaden
  the query if initial HTTP hits are missing, as the actor rotates compromised domains
  frequently.
references:
- name: Star Blizzard refines phishing and malware delivery with the RedFlick technique
  url: https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
related:
- hunt: cosmicpulse-behavioral-backdoor
  reason: This hunt focuses on delivery and persistence; a subsequent hunt should
    examine the operational behavior of the CosmicPulse backdoor.
  relation: follows
scenario:
  stages:
  - name: Large-scale Phishing via Compromised Infrastructure
    observables:
    - ukr.net
    - Password-protected RAR/ZIP archives
    - "Subject: \u041F\u043E\u0432\u0456\u0434\u043E\u043C\u043B\u0435\u043D\u043D\
      \u044F \u043F\u0440\u043E \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442\
      \u0438 \u043F\u043E\u0434\u0430\u0442\u043A\u043E\u0432\u043E\u0457 \u043F\u0435\
      \u0440\u0435\u0432\u0456\u0440\u043A\u0438"
    - 'Subject: Invitation to an IISS Private Roundtable'
    - 'Subject: Payment Advice Note'
    - WordPress/cPanel compromised sender accounts
    slug: phishing-initial-contact
    tactic: initial-access
    techniques:
    - T1566.001
    - T1566.002
  - name: Malicious VHDX and LNK Execution
    observables:
    - VHDX virtual disk file
    - LNK file masquerading as PDF
    - conhost.exe (hidden window)
    - cmd.exe spawning BAT script
    slug: vhdx-payload-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1059.003
  - name: Malware Download via SSH PermitLocalCommand
    observables:
    - ssh.exe
    - -o PermitLocalCommand=yes
    - Execution of remote MSI installer
    slug: ssh-msi-delivery
    tactic: execution
    techniques:
    - T1105
    - T1218
  - name: Persistence via MSI Installed Task
    observables:
    - schtasks.exe /create
    - msiexec.exe execution
    slug: scheduled-task-persistence
    tactic: persistence
    techniques:
    - T1053.005
  - name: RedFlick Loader Execution via Control Panel Applet
    observables:
    - control.exe
    - .cpl file extension
    - Remote URL for CPL download
    - CosmicPulse backdoor
    slug: redflick-cpl-loading
    tactic: defense-evasion
    techniques:
    - T1218.002
  summary: Russian state actor Star Blizzard conducts large-scale phishing campaigns
    using compromised WordPress and cPanel sites to deliver password-protected archives
    containing malicious VHDX files. These files initiate an execution chain involving
    BAT scripts and ssh.exe to download an MSI, which then establishes persistence
    via a scheduled task that leverages control.exe to execute the RedFlick loader
    and CosmicPulse backdoor disguised as a Control Panel applet.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Star Blizzard RedFlick VHDX and SSH-based Malware Delivery

Star Blizzard (FSB Centre 18) has shifted to RedFlick, a multi-stage infection chain. It begins with password-protected archives containing VHDX files which mount to execute BAT scripts. These scripts use ssh.exe with the PermitLocalCommand option to download MSI installers, which then create scheduled tasks that use control.exe to load remote CPL files. This hunt identifies the progression from phishing contact and initial payload execution to persistent backdoor loading.

## software-scoping
<!-- Identify hosts with relevant software -->
Find workstations that have the software required to interact with the campaign's password-protected archives and decoy PDF lures. This generates context for the agent triage.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts and their installed archive/PDF software. Silence is expected
  if the estate uses different or unmanaged software.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%winrar%' OR LOWER(package_name) LIKE '%7-zip%' OR LOWER(package_name) LIKE '%acrobat%' OR LOWER(package_name) LIKE '%reader%')
```

## early-stage-leads
<!-- Gather early infection evidence -->
parallel:
- → phishing-contact
- → conhost-script-execution
join: → early-stage-triage

## phishing-contact
<!-- Phishing contact HTTP activity -->
Find HTTP requests to the Ukr.net mail provider or URLs containing campaign-themed keywords.

```sqlite target=web role=baseline params=(campaign_domains=campaign_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts that have accessed the specified mail provider or clicked on lure
  themes. Silence means no web-based interaction was caught.
reads:
- device_hostname
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE (instr(',' || '{{campaign_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_path) LIKE '%tax audit%' OR LOWER(url_path) LIKE '%payment advice%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## conhost-script-execution
<!-- Rare conhost-initiated script execution -->
Identify rare BAT or LNK scripts launched by conhost, which indicates execution from a mounted VHDX in a hidden window.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare scripts running under conhost. Silence suggests standard environment-wide
  login scripts or no such activity.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT process_cmd_line, GROUP_CONCAT(DISTINCT device_hostname) AS affected_hosts, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%conhost.exe%' AND (LOWER(process_cmd_line) LIKE '%.bat%' OR LOWER(process_cmd_line) LIKE '%.lnk%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 3
```

## early-stage-triage
<!-- Triage early infection stages -->
```agent target=hunter
cite: required
context:
- software-scoping
- phishing-contact
- conhost-script-execution
max_iterations: 4
objective: Evaluate whether the phishing contact leads and conhost script rows indicate
  a VHDX-based execution chain on any host.
success_criteria: A verdict citing specific hosts and rows that bridge the network
  and process telemetry.
tools:
- endpoint
- web
```

## follow-on-leads
<!-- Hunt follow-on delivery and persistence -->
parallel:
- → ssh-delivery-mechanism
- → cpl-scheduled-tasks
join: → full-chain-analysis

## ssh-delivery-mechanism
<!-- SSH PermitLocalCommand delivery -->
Detect the use of ssh.exe with the PermitLocalCommand option, a specific RedFlick indicator used to execute commands upon connection.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Instances of SSH being used as a downloader. Silence means this specific
  delivery variant was not used on the checked hosts.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%ssh.exe%' AND LOWER(process_cmd_line) LIKE '%permitlocalcommand=yes%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## cpl-scheduled-tasks
<!-- CPL persistence via scheduled tasks -->
Identify scheduled tasks that use control.exe to load .cpl files, representing the RedFlick persistence and downloader stage.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Scheduled tasks pointing to unusual Control Panel applets. Silence means
  the persistence mechanism differs or was not established.
reads:
- device_hostname
- job_cmd_line
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, job_cmd_line, job_name, time FROM hb_scheduled_job WHERE LOWER(job_cmd_line) LIKE '%control.exe%' AND LOWER(job_cmd_line) LIKE '%.cpl%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## full-chain-analysis
<!-- Analyze full infection chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- ssh-delivery-mechanism
- cpl-scheduled-tasks
max_iterations: 6
objective: Determine if any host exhibits the transition from phishing contact and
  hidden script execution to SSH-based delivery and CPL persistence.
success_criteria: A malicious verdict for hosts showing multiple correlated stages
  of the RedFlick technique.
tools:
- endpoint
- web
```

## judgement
<!-- Route based on compromise confidence -->
if~: "the full-chain-analysis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → containment
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: vhdx-mount-visibility)
else: → analyst-validation

## containment
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host at the network level, revoke all active Entra/M365 and SaaS sessions for the local users, and delete the malicious scheduled task and associated .cpl file.
```
→ analyst-validation

## analyst-validation
<!-- Manual evidence review -->
```manual target=analyst
Review the conhost command lines to locate where the VHDX was mounted. Search the user's temp directory for .rar or .zip files matching the campaign dates. Inspect the MSI logs to confirm which binary was dropped.
```
→ close-out

## close-out
<!-- Hunt closure and detection handoff -->
```manual target=analyst
Document the Star Blizzard TTPs observed, list the compromised hosts, and promote the SSH PermitLocalCommand query to a production detection rule.
```
→ end
