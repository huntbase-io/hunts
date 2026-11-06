---
analysis: A standard rule for 'msimg32.dll' is too noisy for a production fleet. This
  hunt uses a gated flow to first identify rare MSI executions and then pivot to high-fidelity
  behavioral correlation, including a temporal check between the installer and the
  side-load in a system process.
blind_spots:
- id: msi-telemetry-gap
  question: whether the .msi path in the msiexec command line is visible or truncated
  requires: full process command line telemetry including temporary paths
  risk: The lead query depends on seeing the filename in the command line; truncation
    would hide the trojanized installer.
  stage: initial-access-seo-poisoning
- id: module-visibility-gap
  question: whether the side-loading of msimg32.dll into consent.exe was recorded
  requires: hb_module_activity with DLL load logging for system processes
  risk: Some EDRs ignore module loads into Microsoft-signed system processes, blinding
    the hunt to the execution stage.
  stage: execution-malware-loading
coverage:
- stage: initial-access-seo-poisoning
  status: covered
  steps:
  - scoping-affected-software
  - lead-msi-execution
  - c2-network-activity
- stage: execution-malware-loading
  status: covered
  steps:
  - module-sideload-behavior
- stage: command-and-control-bumblebee-adaptix
  status: covered
  steps:
  - c2-network-activity
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: discovery-host-and-domain
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: persistence-domain-account-creation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: lateral-movement-rdp
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: credential-access-ntds-dump
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: persistence-and-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: credential-access-postgre-lsass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: exfiltration-sftp
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: From Bing Search to Ransomware:
    Bumblebee and AdaptixC2 Deliver Akira'' series.'
  stage: impact-akira-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Bumblebee is a gateway to Akira ransomware. Detecting the initial
    infection at the DLL side-loading stage prevents the intrusion from escalating
    to full domain compromise and data exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder compromises privileged workstations by poisoning search results
  for IT tools, tricking users into running a trojanized MSI that side-loads Bumblebee
  malware via consent.exe.
labels:
- hunt
- attack.t1189
- attack.t1574.002
- attack.t1204.002
- attack.t1071.001
- attack.t1568.002
name: Bumblebee SEO Poisoning and DLL Sideloading
parameters:
  c2_domains:
    default:
    - opmanager.pro
    - angryipscanner.org
    - axiscamerastation.org
    - ip-scanner.org
    - ev2sirbd269o5j.org
    - 2rxyt9urhq0bgj.org
    description: Known C2 and redirect domains from the article.
    from:
      kind: article
      observed: '2025-08-05'
      ref: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    type: list[domain]
  lead_hosts:
    default: []
    description: Specific hosts identified in the lead query; the analyst must populate
      this to run the behavioral fan-out.
    type: list[host]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames from the scoping step to narrow the search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-privilege IT administrator workstations and servers where
  management software like ManageEngine is expected. Use the inventory query to find
  legitimate installations to establish a baseline.
references:
- name: "The DFIR Report \u2014 From Bing Search to Ransomware: Bumblebee and AdaptixC2\
    \ Deliver Akira"
  url: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
related:
- hunt: bumblebee-discovery-and-recon
  reason: This hunt targets initial access; the follow-on hunt identifies the subsequent
    internal reconnaissance commands.
  relation: follows
scenario:
  stages:
  - name: Initial Access via SEO Poisoning
    observables:
    - opmanager.pro
    - ManageEngine-OpManager.msi
    - angryipscanner.org
    - axiscamerastation.org
    - ip-scanner.org
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1189
  - name: Bumblebee Loading and Execution
    observables:
    - msiexec.exe
    - consent.exe
    - msimg32.dll
    - 186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da
    - a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331
    slug: execution-malware-loading
    tactic: execution
    techniques:
    - T1574.002
    - T1204.002
  - name: Bumblebee and Adaptix C2
    observables:
    - 109.205.195.211
    - 188.40.187.145
    - 172.96.137.160
    - ev2sirbd269o5j.org
    - 2rxyt9urhq0bgj.org
    - AdgNsy.exe
    slug: command-and-control-bumblebee-adaptix
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1568.002
  - name: Host and Domain Reconnaissance
    observables:
    - systeminfo
    - 'nltest /dclist:'
    - whoami /groups
    - net group "domain admins" /dom
    slug: discovery-host-and-domain
    tactic: discovery
    techniques:
    - T1082
    - T1087.002
    - T1069.002
  - name: Privileged Account Creation
    observables:
    - net user backup_DA
    - net user backup_EA
    - net group "Enterprise Administrators" backup_EA /add
    slug: persistence-domain-account-creation
    tactic: persistence
    techniques:
    - T1136.002
  - name: Lateral Movement via RDP
    observables:
    - backup_EA
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: NTDS.dit Extraction
    observables:
    - wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:"C:\windows\NTDS\ntds.dit"
    - ntds.dit
    slug: credential-access-ntds-dump
    tactic: credential-access
    techniques:
    - T1003.003
  - name: Persistence and External Tunneling
    observables:
    - RustDesk
    - ssh root@193.242.184.150 -R *:10400
    - 83.229.17.60
    slug: persistence-and-tunneling
    tactic: persistence
    techniques:
    - T1133
    - T1572
  - name: Database and Memory Credential Theft
    observables:
    - psql.exe -U postgres -d VeeamBackup -c "SELECT user_name,password FROM credentials"
    - 'rundll32.exe C:\windows\System32\comsvcs.dll, #+000024'
    slug: credential-access-postgre-lsass
    tactic: credential-access
    techniques:
    - T1003.001
    - T1555
  - name: Data Exfiltration via FileZilla
    observables:
    - FileZilla
    - 185.174.100.203
    slug: exfiltration-sftp
    tactic: exfiltration
    techniques:
    - T1048.003
  - name: Akira Ransomware Deployment
    observables:
    - locker.exe
    - win.exe
    - de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d
    slug: impact-akira-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors utilized SEO poisoning for 'ManageEngine OpManager' to deliver
    Bumblebee malware, which dropped AdaptixC2 for post-exploitation. The intrusion
    involved domain account creation, NTDS.dit dumping via wbadmin, and lateral movement
    to a backup server before exfiltrating data and deploying Akira ransomware.
series:
  index: 1
  slug: flash-alert-from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira
  title: 'Flash Alert: From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver
    Akira'
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


# Bumblebee SEO Poisoning and DLL Sideloading

This hunt targets the mid-2025 campaign where an adversary delivered Bumblebee through SEO-poisoned Bing search results for common IT tools like ManageEngine OpManager. The adversary tricks users into downloading trojanized MSI installers, which then side-load malware via the Windows consent process. The hunt identifies affected systems by inventory, evaluates rare installer execution in user-writable paths, and correlates those leads with behavioral and network indicators of Bumblebee and AdaptixC2. The analyst verifies the causal link between the installer and the subsequent high-integrity DLL side-loading to confirm the infection.

## scoping-affected-software
<!-- Scope hosts with targeted IT software -->
Identify hosts containing the impersonated IT management software to focus the hunt on likely victims.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running software often impersonated by this threat actor,
  such as OpManager or network scanners.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%opmanager%' OR LOWER(package_name) LIKE '%manageengine%' OR LOWER(package_name) LIKE '%angry ip%' OR LOWER(package_name) LIKE '%axis camera%' OR LOWER(package_name) LIKE '%advanced ip%')
```

## lead-msi-execution
<!-- Rare MSI executions from user paths -->
Locate the trojanized installer by finding rare MSI executions triggered from user-writable or temporary directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare command lines pointing at installers in Downloads or ProgramData. The
  process_path confirms whether msiexec.exe is running from System32.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, MIN(time) AS first_seen, COUNT(DISTINCT device_hostname) AS host_count FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%msiexec.exe' OR LOWER(process_cmd_line) LIKE '%msiexec %') AND (LOWER(process_cmd_line) LIKE '%\\users\\%' OR LOWER(process_cmd_line) LIKE '%\\downloads\\%' OR LOWER(process_cmd_line) LIKE '%\\desktop\\%' OR LOWER(process_cmd_line) LIKE '%\\programdata\\%') AND LOWER(process_cmd_line) LIKE '%.msi%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, process_path, device_hostname, user_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## evaluate-lead
<!-- Evaluate MSI installation lead -->
```agent target=hunter
cite: required
context:
- lead-msi-execution
max_iterations: 3
objective: Determine if any detected MSI executions resemble the trojanized IT tools
  named in the research, such as ManageEngine or Angry IP Scanner.
success_criteria: A list of hosts where the MSI leads are suspicious enough to warrant
  further behavioral analysis.
tools:
- endpoint
```

## gate-on-msi
<!-- Gate on MSI findings -->
if~: "the evaluation identified at least one suspicious MSI installer matching the campaign pattern" (confidence: high, judge=hunter)
then: → fan-out-investigation
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: msi-telemetry-gap)
else: → close-out-hunt

## fan-out-investigation
<!-- Investigate infection behavior -->
parallel:
- → module-sideload-behavior
- → c2-network-activity
join: → triage-infection

## module-sideload-behavior
<!-- Bumblebee side-loading by consent.exe -->
Detect the side-loading of msimg32.dll into the Windows UAC consent.exe process, a signature Bumblebee technique.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, lead_hosts=lead_hosts)
~~~yaml
expected: consent.exe loading msimg32.dll from an unexpected directory on a lead host.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE LOWER(process_name) LIKE '%\\consent.exe' AND LOWER(module_name) = 'msimg32.dll' AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-activity
<!-- Bumblebee DGA and C2 network activity -->
Verify the infection through DNS activity matching the Bumblebee DGA and redirect domains.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, lead_hosts=lead_hosts)
~~~yaml
expected: Lead hosts resolving known C2 redirectors or DGA domains like random .org
  addresses.
reads:
- device_hostname
- query_hostname
- answers
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, answers, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (length(query_hostname) BETWEEN 12 AND 18 AND query_hostname LIKE '%.org')) AND ('{{lead_hosts}}' = '' OR instr(',' || '{{lead_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infection
<!-- Triage Bumblebee infection -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- module-sideload-behavior
- c2-network-activity
max_iterations: 6
objective: Explicitly correlate the timestamp of the rare MSI execution found in evaluate-lead
  with the consent.exe module load in module-sideload-behavior to confirm the causal
  link. Determine if C2 traffic provides additional confirmation.
success_criteria: A malicious verdict for hosts where the trojanized installer triggered
  the side-loading behavior.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on infection verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: module-visibility-gap)
else: → manual-analyst-review

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the MSI installer and the msimg32.dll file from the temporary directories for further forensic analysis.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Audit browser history for searches on Bing related to the identified IT tools. Verify if subsequent discovery commands like 'systeminfo' or 'nltest' ran on the host.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Document confirmed malicious MSI packages. Consider promoting the consent.exe module-load logic to a persistent detection rule if false positive rates are low.
```
→ end
