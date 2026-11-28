---
analysis: 'A single rule for the EdgeUpdate key is easily bypassed by changing a string.
  This hunt identifies the structural behavior of the attack: staging a runtime in
  a user path, rare persistence mechanisms, and follow-on lateral movement that crosses
  network and process boundaries.'
blind_spots:
- id: no-network-telemetry
  question: Did the actor pivot to other hosts via WinRM?
  requires: hb_network_connection with destination port
  risk: Without outbound socket data, the hunt cannot track the movement from the
    beachhead to sensitive identity servers.
  stage: lateral-movement-winrm
- id: ephemeral-js-implants
  question: What specific tasks did the C2 provide?
  requires: hb_file_activity with content capture
  risk: Node.js implants often execute tasking in memory or temporary files that are
    immediately deleted, hiding the specific data stolen or tools used.
  stage: nodejs-implant-persistence
coverage:
- stage: nodejs-implant-persistence
  status: covered
  steps:
  - scope-node-in-localappdata
  - run-key-localappdata
  - nonstandard-file-prevalence
- stage: c2-recon-and-tasking
  status: covered
  steps:
  - recon-and-rundll32
- stage: lateral-movement-winrm
  status: covered
  steps:
  - winrm-lateral-movement
- stage: execution-rundll32-dlls
  status: covered
  steps:
  - recon-and-rundll32
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: initial-access-teams-vishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: remote-session-msi-delivery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The abuse of Microsoft Teams for social engineering bypasses many
    email-based controls; detecting the resulting Node.js implant and subsequent WinRM
    pivoting is critical to preventing enterprise-wide compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using a portable Node.js runtime and an obfuscated implant
  staged in LocalAppData to move laterally via WinRM after initial social engineering
  via Microsoft Teams.
labels:
- hunt
- attack.t1059.001
- attack.t1071
- attack.t1041
- attack.t1555
- attack.t1218.011
- attack.t1090.003
- attack.t1566.003
name: Node.js Backdoor and Lateral Movement
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  nonstandard_extensions:
    default:
    - .tmp
    - .ini
    - .dat
    - .bin
    - .cfg
    description: Extensions used for encrypted implants and loaders.
    type: list[string]
  scope_hosts:
    default: []
    description: Hostnames flagged in the early triage stage to narrow follow-on queries.
    type: list[host]
  scope_users:
    default: []
    description: Usernames flagged in the early triage stage to narrow follow-on queries.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations without developer roles first, as Node.js in LocalAppData
  is highly anomalous there. Use the early triage hosts and users to populate the
  scoping parameters for follow-on queries.
references:
- name: "Microsoft Security Blog \u2014 Impersonating IT support: how threat actors\
    \ turn a remote session into enterprise-wide access"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: initial-access-teams-vishing
  reason: That hunt covers the Teams ingress and social engineering; this hunt focuses
    on the post-access technical footprint.
  relation: out-of-scope-alternative
- hunt: it-support-impersonation-remote-access
  relation: follows
scenario:
  stages:
  - name: IT Support Impersonation via Teams
    observables:
    - Microsoft Teams external tenant collaboration
    - Accept/Block prompts in Teams
    - Quick Assist connection code usage
    - 'Lures: ''Microsoft Security Update'', ''Spam Filter Update'', ''Account Verification'''
    - Vishing (voice phishing) used to layer trust
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.003
  - name: Remote Session and MSI Delivery
    observables:
    - Quick Assist or remote support tool process tree
    - PowerShell downloading MSI from cloud storage
    - msiexec.exe /qn (silent installation)
    - 'MSI filenames: ''devfix.msi'', ''Hotfix.msi'''
    slug: remote-session-msi-delivery
    tactic: execution
    techniques:
    - T1059.001
  - name: Node.js Implant Staging and Persistence
    observables:
    - Portable Node.js runtime downloaded from official distribution
    - Files staged in LocalAppData randomly named directories
    - 'Nonstandard file extensions: .tmp, .ini, .dat, .bin, .cfg'
    - HKCU Run key 'EdgeUpdate'
    - Startup folder shortcut 'EdgeUpdate.lnk'
    - Renamed Node.js binaries with original metadata 'node.exe'
    slug: nodejs-implant-persistence
    tactic: persistence
    techniques:
    - T1059.001
  - name: C2 Communication and Reconnaissance
    observables:
    - Randomized HTTPS long-polling to C2 server
    - Discovery of antivirus products and virtualization
    - ADSI (Active Directory Service Interfaces) queries
    - Screen captures encoded in Base64 and saved to temporary files
    - Host hardware and locale enumeration
    slug: c2-recon-and-tasking
    tactic: command-and-control
    techniques:
    - T1071
    - T1041
    - T1555
  - name: Lateral Movement via WinRM
    observables:
    - WinRM connections over TCP port 5985
    - Pivoting toward Domain Controllers and Certificate Authorities
    - Native Windows Remote Management execution
    slug: lateral-movement-winrm
    tactic: lateral-movement
    techniques:
    - T1059.001
  - name: Follow-on Payload Execution
    observables:
    - rundll32.exe loading threat actor-supplied DLLs
    - Short-lived cmd.exe and PowerShell child processes of Node.js
    slug: execution-rundll32-dlls
    tactic: defense-evasion
    techniques:
    - T1218.011
  summary: A human-operated campaign impersonates IT support via Microsoft Teams to
    trick users into granting remote access through tools like Quick Assist. Once
    access is established, the attackers deploy a persistent Node.js-based implant
    to perform extensive reconnaissance and move laterally via WinRM toward high-value
    infrastructure like domain controllers.
series:
  index: 2
  slug: impersonating-it-support-how-threat-actors-turn-a-remote-session-into-enterprise-wide-access
  title: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
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


# Node.js Backdoor and Lateral Movement

This hunt targets the technical footprint of a human-operated intrusion campaign that deploys a Node.js-based implant. It identifies the staging of a portable Node.js runtime, non-standard file extensions for loaders, and per-user registry persistence. The hunt then pivots to investigate follow-on reconnaissance and lateral movement over WinRM (port 5985), focusing on activity originating from the compromised beachhead. By examining the process tree and network connections together, the hunt distinguishes legitimate administrative work from malicious interactive tasking.

## scope-node-in-localappdata
<!-- Scope Node.js in LocalAppData -->
Identify hosts running Node.js or renamed copies from a user-writable path, indicating the staging of a portable runtime.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts where Node.js is running from a user profile directory. Silence suggests
  no portable Node.js runtime has been launched in this way.
reads:
- device_hostname
- user_name
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, user_name, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\appdata\\local\\%' OR LOWER(process_cmd_line) LIKE '%\\appdata\\local\\%') AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_file_description) LIKE '%node.js%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## staging-and-persistence
<!-- Analyze staging and persistence -->
parallel:
- → run-key-localappdata
- → nonstandard-file-prevalence
join: → triage-early-footprint

## run-key-localappdata
<!-- Run key persistence in LocalAppData -->
Identify any registry Run key pointing to executable code within LocalAppData, which is a common persistence method for this implant.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A Run key pointing to a binary or script in a user's LocalAppData. This
  is a durable signal of staging.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\currentversion\\run%' AND LOWER(reg_value_data) LIKE '%\\appdata\\local\\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## nonstandard-file-prevalence
<!-- Rare files with non-standard extensions -->
Find rare files in user profiles matching the report's extension list to identify encrypted payloads using a suffix-based filter.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, nonstandard_extensions=nonstandard_extensions)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Files with extensions like .tmp or .cfg appearing in a LocalAppData folder
  that are rare across the fleet. Silence proves these specific extensions were not
  used.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 5
reads:
- device_hostname
- file_path
- file_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, file_path, file_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\\appdata\\local\\%' AND instr(',' || '{{nonstandard_extensions}}' || ',', ',' || substr(LOWER(file_name), instr(LOWER(file_name), '.')) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path, file_name HAVING hosts <= 5
```

## triage-early-footprint
<!-- Triage early implant staging -->
```agent target=hunter
cite: required
context:
- scope-node-in-localappdata
- run-key-localappdata
- nonstandard-file-prevalence
max_iterations: 4
objective: Determine which hosts show evidence of a Node.js implant staging, citing
  the process location, Run key values, and clusters of rare staging files.
success_criteria: A per-host verdict of malicious | suspicious | benign, naming the
  user and host.
tools:
- endpoint
- network
```

## follow-on-activity
<!-- Investigate follow-on intrusion -->
parallel:
- → winrm-lateral-movement
- → recon-and-rundll32
join: → triage-intrusion-scope

## winrm-lateral-movement
<!-- WinRM lateral movement (Port 5985) -->
Identify outbound WinRM connections from the beachheads. Populate scope_hosts with results from triage-early-footprint to automate the pivot.

```sqlite target=network role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound connections to 5985 originating from a suspected beachhead host.
  This indicates an attempt to move laterally.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE dst_endpoint_port = 5985 AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## recon-and-rundll32
<!-- Discovery and rundll32 payloads -->
Detect Active Directory discovery and follow-on rundll32 execution, scoped to the specific users and hosts flagged in the early triage to minimize administrative noise.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, scope_users=scope_users)
~~~yaml
expected: Process command lines performing domain enumeration or rundll32 loading
  actor-supplied DLLs, scoped to the flagged beachhead.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%adsi%' OR LOWER(process_cmd_line) LIKE '%get-ad%' OR LOWER(process_name) LIKE '%rundll32.exe%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-intrusion-scope
<!-- Triage enterprise intrusion -->
```agent target=hunter
cite: required
context:
- triage-early-footprint
- winrm-lateral-movement
- recon-and-rundll32
max_iterations: 4
objective: 'Weigh the evidence from both phases: does the host with the Node.js implant
  also show WinRM lateral movement or AD discovery? Determine the full scope of the
  intrusion.'
success_criteria: A final verdict naming beachheads, lateral targets, and users involved.
tools:
- endpoint
- network
```

## route-response
<!-- Route based on breach scope -->
if~: "the triage-intrusion-scope verdict is malicious for at least one host, indicating confirmed lateral movement or AD discovery" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the hosts identified as compromised beachheads. Revoke credentials for associated users and begin forensic collection of the LocalAppData artifacts.
```
→ analyst-review

## analyst-review
<!-- Analyze intrusion depth -->
```manual target=analyst
Examine the targets of the WinRM connections for follow-on payloads. Review the Teams chat history of affected users to identify the attacker's ingress method and the external tenant involved.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record that no evidence of the Node.js implant or associated WinRM pivoting was found. Archive the instances of legitimate Node.js usage observed in profile paths for future tuning.
```
→ end
