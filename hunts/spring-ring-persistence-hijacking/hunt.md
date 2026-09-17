---
analysis: A single detection rule might alert on headless Edge, but this hunt combines
  file indicators, stack-counting of Temp directories, and behavioral browser anomalies
  to confirm the specific Spring Ring pattern, distinguishing it from legitimate developer
  tools or automated testing.
blind_spots:
- id: incomplete-telemetry
  owner: Endpoint Engineering
  question: Are there hosts not reporting process command lines or file creation events?
  remediation: Audit EDR coverage and ensure command-line auditing (e.g., Windows
    Event 4688 or Sysmon) is active.
  requires: hb_file_activity and hb_process_activity from all endpoints
  risk: Attackers may operate on unmanaged devices or those with crippled logging,
    leaving the headless Edge behavior invisible.
  stage: persistence-and-hijacking
- id: extension-content-visibility
  owner: Forensics Team
  question: What is the specific functionality of the sideloaded Edge extension?
  remediation: Establish a process for remote retrieval of the %LocalAppData%\Microsoft\Edge\User
    Data\Default\Extensions directory.
  requires: Browser extension manifest analysis
  risk: Telemetry shows the extension is loaded, but not what it does (e.g., credential
    scraping vs. session hijacking).
  stage: persistence-and-hijacking
coverage:
- stage: persistence-and-hijacking
  status: covered
  steps:
  - temp-file-indicators
  - headless-edge-hijacking
  - rare-temp-execution
- reason: Covered in the 'initial-access' sibling hunt.
  stage: initial-access-teams-vishing
  status: out_of_scope
- reason: Covered in the 'execution-and-delivery' sibling hunt focusing on AWS/S3
    links.
  stage: execution-and-delivery
  status: out_of_scope
- reason: Covered in the 'discovery-and-lateral-movement' sibling hunt focusing on
    PetitPotam.
  stage: discovery-and-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Spring Ring campaign leverages the 'Chat with Anyone' feature
    in Teams, which is often enabled by default. Identifying persistence and hijacking
    behaviors on the endpoint is critical because the initial voice call is rarely
    monitored or recorded.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a foothold by dropping duplicated executables
  into temporary directories and is using a headless browser with a sideloaded extension
  to hijack user sessions or facilitate persistence.
labels:
- hunt
- attack.t1574.002
- attack.t1176
- attack.t1547.001
- attack.t1059.001
name: 'Spring Ring: Temp Persistence and Browser Hijacking'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-31'
      ref: standard-lookback
    type: number
  rare_threshold:
    default: '3'
    description: The maximum number of hosts a binary can appear on to be considered
      rare.
    from:
      kind: manual
      observed: '2026-08-31'
      ref: prevalence-standard
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with general Windows workstations. The Spring Ring campaign targets
  various industries, so scope broadly unless specific vishing alerts are available.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: spring-ring-initial-access-teams
  reason: This hunt focuses on the vishing lures and initial contact via Teams.
  relation: precedes
- hunt: spring-ring-lateral-movement-dc
  reason: This hunt targets the subsequent NTLM relay and PetitPotam activity.
  relation: follows
- hunt: spring-ring-teams-vishing-delivery
  relation: follows
scenario:
  stages:
  - name: Teams Vishing Lure
    observables:
    - ithelp@InternalSystemsDaily.onmicrosoft.com
    - HelpDesk@ITProtectionDepartment.onmicrosoft.com
    - itadmin@MandatoryNetworkMonitoring.onmicrosoft.com
    - Internal@InternalUSAHelpDeskIT.onmicrosoft.com
    - ithelpdesk@CertifiedUpdateNetwork.onmicrosoft.com
    - patrick@infrastructureopsdesk.onmicrosoft.com
    - robert@systemdeploymentcenter.onmicrosoft.com
    - clara@systemsupportoperations.onmicrosoft.com
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.002
    - T1566.003
  - name: RMM and Malware Delivery
    observables:
    - Quick Assist
    - san-sid.com
    - .s3.us-west-2.amazonaws.com
    - -org-filters-update-
    - amsiInitFailed
    slug: execution-and-delivery
    tactic: execution
    techniques:
    - T1204.002
    - T1105
  - name: Persistence and Browser Hijacking
    observables:
    - \Temp\vhlp-*.exe
    - \Temp\scnr-*.exe
    - headless Microsoft Edge
    - Edge extension sideloading
    slug: persistence-and-hijacking
    tactic: persistence
    techniques:
    - T1574.002
    - T1176
    - T1547.001
  - name: Enumeration and PetitPotam Relay
    observables:
    - whoami /groups
    - net group /dom
    - C:\ProgramData\IntegrityData\python.exe
    - Port 445
    - PetitPotam
    slug: discovery-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1087.002
    - T1550.002
    - T1210
  summary: The Spring Ring campaign leverages external Microsoft Teams identities
    to conduct voice phishing (vishing) attacks, masquerading as IT support. Victims
    are coerced into executing RMM tools or custom malware, leading to host enumeration,
    browser hijacking, and NTLM relay attacks targeting domain controllers via PetitPotam.
series:
  index: 2
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
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


# Spring Ring: Temp Persistence and Browser Hijacking

This hunt targets the endpoint persistence and evasion tactics used in the Spring Ring campaign. After a successful voice phishing (vishing) call on Microsoft Teams, the attackers deploy malware that copies itself to temporary directories (using patterns like vhlp-*.exe and scnr-*.exe) and launches a headless instance of Microsoft Edge. The hunt identifies these specific file artifacts and uses behavioral signals—specifically the unusual combination of headless and extension-loading flags in the browser—to detect hijacking and sideloading attempts.

## temp-file-indicators
<!-- Search for Campaign-Specific Temp Files -->
Identify hosts where the specific persistence files (vhlp- or scnr-) were created in temporary directories.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicating the creation of executables with the specified prefixes
  in Temp folders. Silence suggests these specific campaign artifacts are absent,
  though the behavior might still exist under different names.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\temp\vhlp-%.exe' OR LOWER(file_path) LIKE '%\temp\scnr-%.exe') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-behavior
<!-- Corroborate with Evasion and Prevalence -->
parallel:
- → headless-edge-hijacking
- → rare-temp-execution
join: → triage-persistence

## headless-edge-hijacking
<!-- Headless Microsoft Edge with Sideloaded Extension -->
Detect the execution of Edge in a headless state while simultaneously loading an extension, a key evasion/hijacking behavior noted in the campaign.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process event for msedge.exe using both --headless and --load-extension.
  This is highly suspicious in an enterprise environment.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%msedge.exe' OR LOWER(process_path) LIKE '%msedge.exe') AND LOWER(process_cmd_line) LIKE '%--headless%' AND LOWER(process_cmd_line) LIKE '%--load-extension%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-temp-execution
<!-- Rare Binaries Executed from Temp Directories -->
Stack-count executables running from temporary directories to highlight rare payloads that may not match known campaign filenames.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rare_threshold=rare_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of binaries running from Temp folders seen on very few hosts. Legitimate
  installers might appear, but malware copies will stand out by their low host count
  and randomized paths.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS execution_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\appdata\local\temp\%') AND LOWER(process_path) LIKE '%.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= {{rare_threshold}} ORDER BY host_count ASC
```

## triage-persistence
<!-- Evaluate Persistence and Hijacking Evidence -->
```agent target=hunter
cite: required
context:
- temp-file-indicators
- headless-edge-hijacking
- rare-temp-execution
max_iterations: 4
objective: Determine if any host exhibits both the presence of temp-based staging
  files (vhlp/scnr) and behavioral evasion signs (headless Edge) that match the Spring
  Ring campaign profile.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  host, citing specific rows from the file and process results.
tools:
- endpoint
```

## verdict-decision
<!-- Route Based on Triage -->
if~: "the triage verdict identifies malicious activity consistent with Spring Ring on at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Prioritize memory forensic capture before rebooting to preserve the headless browser state and sideloaded extension details.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Forensic Review -->
```manual target=analyst
Review the identified Temp files and Edge extensions. Check for python.exe activity in C:\ProgramData as a precursor to lateral movement, which is characteristic of the next stage of this campaign.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
No campaign activity was found. Record the baseline of rare temp-folder executables for future tuning.
```
→ end
