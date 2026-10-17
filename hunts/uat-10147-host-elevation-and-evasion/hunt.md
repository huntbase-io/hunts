---
analysis: A single rule cannot connect the drop of a batch script to a subsequent
  Defender exclusion and a deceptive scheduled task. This hunt uses a phased approach
  to pivot across file, process, registry, and job surfaces to weigh the entire chain.
blind_spots:
- id: no-process-telemetry
  question: whether elevation tools were executed on unmanaged servers
  requires: EDR agent coverage (hb_process_activity) on every web server
  risk: A compromised host without EDR coverage can execute the elevation chain without
    generating process logs, leaving only the registry or file aftermath.
  stage: privilege-escalation-exploits
- id: obfuscated-script-content
  question: what instructions were executed if batch scripts use environment variable
    expansion
  requires: hb_script_activity content de-obfuscation
  risk: If the adversary renames scripts and obfuscates command strings, simple filename
    matching will fail to identify the foothold.
  stage: automated-foothold-execution
coverage:
- stage: automated-foothold-execution
  status: covered
  steps:
  - staged-script-drops
- stage: privilege-escalation-exploits
  status: covered
  steps:
  - rare-elevation-commands
- stage: antivirus-exclusion-evasion
  status: covered
  steps:
  - evasion-registry-activity
- stage: iis-server-discovery
  status: covered
  steps:
  - persistence-scheduled-jobs
- stage: persistence-mechanisms
  status: covered
  steps:
  - persistence-scheduled-jobs
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: web-application-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: c2-implant-communication
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: system-telemetry-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-10147 is a financially motivated actor using AI to automate complex
    post-compromise tasks. Detecting the elevation and evasion chain stops the actor
    before they deploy persistent web shells or exfiltrate data.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing automated staging scripts to deploy privilege
  escalation tools and blind security software on compromised web servers.
labels:
- hunt
- attack.t1059.001
- attack.t1068
- attack.t1562.001
- attack.t1053.005
- attack.t1505.003
- attack.t1021.001
name: 'UAT-10147: Host Elevation and Evasion'
parameters:
  exclusion_paths:
    default:
    - c:\windows\syswow64\inetsrv
    - c:\windows\system32\inetsrv
    description: Directories the adversary excludes from Windows Defender.
    from:
      kind: article
      observed: '2026-01-20'
      ref: UAT-10147 blog
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional hostnames to narrow the search.
    type: list[host]
  staged_scripts:
    default:
    - back.bat
    - back.txt
    - user.bat
    - bai.bat
    description: Reported filenames of the staging batch scripts.
    from:
      kind: article
      observed: '2026-01-20'
      ref: UAT-10147 blog
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed web servers. Narrow the hunt by prioritizing
  servers where hb_software_inventory shows IIS, Nacos, or ASP.NET components.
references:
- name: "Cisco Talos \u2014 UAT-10147 integrates agentic AI into post-compromise operations"
  url: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
related:
- hunt: uat-10147-initial-access
  reason: Initial web-level exploitation occurs before these host-centric scripts
    run.
  relation: precedes
- hunt: uat-10147-c2-and-exfiltration
  reason: Exfiltration over the Nacos C2 channel happens after the host foothold is
    secured.
  relation: follows
- hunt: web-exploit-telemetry-theft-uat-10147
  relation: follows
scenario:
  stages:
  - name: Web Application Exploitation
    observables:
    - CVE-2022-27925
    - CVE-2021-23758
    - CVE-2019-18935
    - adminapi.tippusoni.in
    - exploitation of Zimbra Collaboration Suite
    - exploitation of AjaxPro
    - exploitation of Telerik UI for ASP.NET AJAX
    slug: web-application-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Automated Foothold Execution
    observables:
    - back.bat
    - back.txt
    - user.bat
    - bai.bat
    - certutil -urlcache -split -f
    - Runtime.exec()
    - dll.zip
    - prcc1.rar
    slug: automated-foothold-execution
    tactic: execution
    techniques:
    - T1059
    - T1059.001
  - name: Privilege Escalation Exploits
    observables:
    - EfsPotato
    - CVE-2022-0995
    - CVE-2021-3156
    - CVE-2015-5287
    - CVE-2015-3246
    - CVE-2010-3904
    - CVE-2022-0847
    - Dirty Pipe exploitation
    slug: privilege-escalation-exploits
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Antivirus Exclusion Evasion
    observables:
    - Add-MpPreference -ExclusionPath C:\Windows\SysWOW64\inetsrv
    - Add-MpPreference -ExclusionPath C:\Windows\System32\inetsrv
    - reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    - powershell.exe Add-MpPreference
    slug: antivirus-exclusion-evasion
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: IIS Server Discovery
    observables:
    - appcmd list site /config /xml
    - C:\Windows\system32\inetsrv\appcmd
    slug: iis-server-discovery
    tactic: discovery
    techniques:
    - T1059
  - name: Persistence Mechanisms
    observables:
    - Google Chrome Start
    - BadIIS
    - addition of user to Remote Desktop Users group
    - rogue local user account creation
    - System32\inetsrv\BadIIS.dll
    slug: persistence-mechanisms
    tactic: persistence
    techniques:
    - T1053.005
    - T1505.003
    - T1021.001
  - name: C2 Implant Communication
    observables:
    - 139.180.197.150
    - svchosts.exe
    - QuasarRAT
    - NoodleRAT
    - SPECTRE
    - Gh0stCringe
    - Meterpreter
    slug: c2-implant-communication
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: System Telemetry Exfiltration
    observables:
    - HTTP POST to Nacos configuration server
    - exfiltration of id and hostname
    - exfiltration of %USERNAME% and %COMPUTERNAME%
    slug: system-telemetry-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: UAT-10147 targets Windows and Linux web servers globally, integrating agentic
    AI to optimize exploit development and post-compromise orchestration. The campaign
    leverages high-volume vulnerability exploitation followed by automated privilege
    escalation, defense evasion through antivirus exclusions, and persistence via
    rogue IIS modules and scheduled tasks.
series:
  index: 2
  slug: uat-10147-integrates-agentic-ai-into-post-compromise-operations
  title: UAT-10147 integrates agentic AI into post-compromise operations
  total: 3
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


# UAT-10147: Host Elevation and Evasion

This hunt targets the endpoint-centric phase of UAT-10147 operations, where an adversary uses semi-autonomous playbooks to operationalize offensive tradecraft. The actor deploys multi-stage batch scripts to download privilege escalation tools like EfsPotato, modifies the Windows Registry to exclude malicious IIS directories from Defender scans, and establishes persistence through deceptive scheduled tasks. The hunt follows a phased flow: it first identifies initial foothold scripts and rare elevation commands, then pivots to look for the subsequent defense evasion and persistence mechanisms that secure the intruder's presence.

## scope-web-servers
<!-- Identify web server scope -->
Focus the hunt on hosts running web server software or frameworks targeted by UAT-10147.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames acting as web servers. Silence indicates no managed
  web servers are visible in inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%iis%' OR LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%nacos%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-parallel
<!-- Search for foothold and elevation -->
parallel:
- → staged-script-drops
- → rare-elevation-commands
join: → early-stage-agent

## staged-script-drops
<!-- Staged script drops -->
Detect the creation of the reported staging batch scripts on scoped hosts.

```sqlite target=endpoint role=triage params=(staged_scripts=staged_scripts, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File creation events for scripts like back.bat or user.bat. Silence for
  these exact names over 14 days is evidence of absence.
reads:
- device_hostname
- file_name
- file_path
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE instr(',' || '{{staged_scripts}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-elevation-commands
<!-- Rare elevation tool execution -->
Identify rare process execution involving reported privilege escalation tools such as EfsPotato or Linux exploit strings.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Execution of known elevation tools seen on fewer than three hosts. A hit
  confirms an active exploitation attempt.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%prcc1.rar%' OR LOWER(process_cmd_line) LIKE '%efspotato%' OR LOWER(process_cmd_line) LIKE '%cve-2022-0995%' OR LOWER(process_cmd_line) LIKE '%cve-2021-3156%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY cmd HAVING hosts < 3
```

## early-stage-agent
<!-- Evaluate early intrusion signs -->
```agent target=hunter
cite: required
context:
- staged-script-drops
- rare-elevation-commands
max_iterations: 4
objective: Determine if any host shows evidence of staging script drops or privilege
  escalation execution consistent with UAT-10147 tradecraft.
success_criteria: A per-host verdict citing specific script names or elevation commands.
tools:
- endpoint
```

## follow-on-parallel
<!-- Search for evasion and persistence -->
parallel:
- → evasion-registry-activity
- → persistence-scheduled-jobs
join: → full-chain-agent

## evasion-registry-activity
<!-- Defender exclusion modifications -->
Identify Registry modifications that add the malicious IIS directories to Windows Defender exclusions.

```sqlite target=endpoint role=detection-candidate params=(exclusion_paths=exclusion_paths, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry writes that blind Defender for the exact paths where BadIIS modules
  are dropped. Single-host occurrences are critical findings.
reads:
- device_hostname
- reg_target
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, reg_target, reg_value_name, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%windows defender\exclusions\paths%' AND instr(',' || '{{exclusion_paths}}' || ',', ',' || LOWER(reg_value_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## persistence-scheduled-jobs
<!-- Persistence and discovery tasks -->
Detect the reported 'Google Chrome Start' scheduled task and use of appcmd for reconnaissance.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Deceptive scheduled jobs or IIS configuration enumeration. Hits indicate
  established persistence.
reads:
- device_hostname
- job_cmd_line
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'google chrome start' OR LOWER(job_cmd_line) LIKE '%appcmd%list%site%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## full-chain-agent
<!-- Full chain intrusion correlation -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- evasion-registry-activity
- persistence-scheduled-jobs
max_iterations: 6
objective: 'Identify hosts where the UAT-10147 chain is complete: early elevation
  combined with subsequent Defender blinding and deceptive scheduled jobs.'
success_criteria: A malicious verdict citing the linkage between early stage tools
  and follow-on persistence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the full-chain-agent verdict is malicious and identifies a link between privilege escalation and follow-on evasion" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-validation
unavailable: → forensic-validation (blind_spot: no-process-telemetry)
else: → forensic-validation

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate active cmd.exe or powershell.exe shells and prepare for forensic evidence collection.
```
→ forensic-validation

## forensic-validation
<!-- Forensic validation -->
```manual target=analyst
1. Inspect C:\Windows\System32\inetsrv and SysWOW64\inetsrv for unexpected DLLs. 2. Verify the 'Google Chrome Start' scheduled task. 3. Check for new local users in the Administrators and Remote Desktop Users groups.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout -->
```manual target=analyst
Document the identified compromised hosts and promote the Defender exclusion registry query to a permanent detection rule for unauthorized exclusion paths.
```
→ end
