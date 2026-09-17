---
analysis: "A simple detection rule on 'EdgeUpdate' is trivial to bypass. This hunt\
  \ combines registry persistence, file-system artifacts, and network prevalence (stack-counting)\
  \ with an agent to weigh the overall context\u2014pivoting across three telemetry\
  \ surfaces to confirm the presence of a tool (Node.js) that is otherwise legitimate\
  \ in the enterprise."
blind_spots:
- id: no-https-inspection
  question: What specific JavaScript tasks were received by the implant?
  requires: hb_http_activity or TLS inspection
  risk: Without payload visibility, the exact reconnaissance and screen-capture commands
    are only visible via their follow-on process activity.
  stage: implant-c2-polling
- id: portable-binary-inventory
  question: Does the software inventory track 'portable' or user-profile installed
    binaries?
  requires: hb_software_inventory
  risk: If portable binaries aren't tracked, Query 1 may return false negatives, making
    the hunt purely dependent on activity logs.
coverage:
- stage: implant-persistence
  status: covered
  steps:
  - suspicious-run-keys
  - startup-shortcut-search
- stage: implant-c2-polling
  status: covered
  steps:
  - rare-user-path-connections
  - http-polling-activity
- reason: 'Handled in Hunt 1: Initial Access and MSI Delivery.'
  stage: teams-social-engineering
  status: out_of_scope
- reason: 'Handled in Hunt 1: Initial Access and MSI Delivery.'
  stage: msi-delivery-and-execution
  status: out_of_scope
- reason: 'Handled in Hunt 1: Initial Access and MSI Delivery.'
  stage: nodejs-implant-staging
  status: out_of_scope
- reason: 'Handled in Hunt 3: Post-Implant Discovery and Lateral Movement.'
  stage: discovery-and-screen-capture
  status: out_of_scope
- reason: 'Handled in Hunt 3: Post-Implant Discovery and Lateral Movement.'
  stage: lateral-movement-winrm
  status: out_of_scope
- reason: 'Handled in Hunt 3: Post-Implant Discovery and Lateral Movement.'
  stage: follow-on-payload-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: A negative result across the estate confirms the absence of this
    persistent, interactive command-and-control channel which is the critical gateway
    to lateral movement and ransomware.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence for a Node.js-based implant using
  user-writable paths (AppData\Local) and update-themed Run keys or Startup shortcuts,
  and is communicating via randomized HTTPS long-polling.
labels:
- hunt
- attack.t1547.001
- attack.t1071.001
- attack.t1059.007
- attack.t1036.003
name: 'IT Support Impersonation: Node.js Implant Persistence and C2'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: default
    type: number
  persistence_keyword:
    default: EdgeUpdate
    description: The keyword used in Run keys and Startup shortcuts.
    from:
      kind: article
      observed: '2026-09-02'
      ref: msrc-blog
    type: string
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on LocalAppData as the primary staging area for human-operated
  Node.js implants. It uses the specific lure 'EdgeUpdate' but prioritizes behavioral
  leads like any binary in LocalAppData having persistent run keys or rare network
  traffic.
references:
- name: "MSRC \u2014 Impersonating IT support: how threat actors turn a remote session\
    \ into enterprise-wide access"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: teams-vishing-initial-access
  reason: This hunt covers the post-infection stage after successful Teams-based social
    engineering.
  relation: precedes
- hunt: discovery-and-screen-capture
  reason: Once the implant is confirmed, the next stage is to hunt for its reconnaissance
    activity.
  relation: follows
- hunt: remote-initiated-implant-staging
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Microsoft Teams
    observables:
    - Microsoft Teams external contact prompts
    - Quick Assist remote sessions
    - Teams 'request control' prompts
    - Vishing calls instructing users to bypass security warnings
    slug: teams-social-engineering
    tactic: initial-access
    techniques:
    - T1566.003
  - name: Malicious MSI Delivery
    observables:
    - msiexec.exe /qn
    - PowerShell download of MSI from cloud storage
    - 'MSI filenames: devfix.msi, Hotfix.msi'
    slug: msi-delivery-and-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1218.007
  - name: Node.js Runtime and Implant Staging
    observables:
    - Portable Node.js runtime download from official distribution
    - Implant files in LocalAppData with extensions .tmp, .ini, .dat, .bin, .cfg
    - High-entropy encrypted data files staged under user-writable directories
    slug: nodejs-implant-staging
    tactic: execution
    techniques:
    - T1105
  - name: Per-User Persistence
    observables:
    - HKCU Run key 'EdgeUpdate'
    - Startup folder shortcut 'EdgeUpdate.lnk'
    - WScript launching Node.js loader
    slug: implant-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Node.js Command and Control
    observables:
    - Randomized HTTPS long-polling
    - Node.js process executing JavaScript from standard input
    - Renamed Node.js executable network traffic
    slug: implant-c2-polling
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Discovery and Desktop Monitoring
    observables:
    - ADSI queries for domain accounts and servers
    - Base64-encoded screenshots written to temporary files
    - Querying display adapter name and installed AV products
    slug: discovery-and-screen-capture
    tactic: discovery
    techniques:
    - T1082
    - T1113
    - T1018
  - name: Lateral Movement via WinRM
    observables:
    - TCP port 5985 connections to Domain Controllers and CAs
    - WinRM pivoting initiated from Node.js process
    slug: lateral-movement-winrm
    tactic: lateral-movement
    techniques:
    - T1021.006
  - name: Proxy Execution of DLLs
    observables:
    - rundll32.exe loading actor-supplied DLLs
    slug: follow-on-payload-execution
    tactic: defense-evasion
    techniques:
    - T1218.011
  summary: Threat actors impersonate IT support via Microsoft Teams to socially engineer
    users into granting remote access, which is then used to deploy a Node.js-based
    implant. The campaign leverages legitimate portable runtimes for persistent command-and-control,
    performing extensive Active Directory reconnaissance and lateral movement via
    WinRM toward high-value infrastructure.
series:
  index: 2
  slug: impersonating-it-support-how-threat-actors-turn-a-remote-session-into-enterprise-wide-access
  title: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# IT Support Impersonation: Node.js Implant Persistence and C2

This hunt targets the persistence and command-and-control (C2) infrastructure of the human-operated intrusion campaign that impersonates IT support. It looks for behavioral indicators of Node.js-based implants executing from non-standard, user-writable directories (LocalAppData) regardless of the binary name. The hunt correlates these execution events with persistence markers like the 'EdgeUpdate' registry key and Startup folder links, as well as network-level evidence of rare, repetitive HTTPS connections originating from those same user-path binaries. This multi-surface approach ensures the hunt remains effective even if the threat actor rotates indicator names like 'EdgeUpdate'.

## node-inventory-scoping
<!-- Scoping hosts with Node.js present -->
Identify hosts that have Node.js installed to understand the normal baseline of where Node-based activity is expected.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with Node.js installed. Silence suggests any Node.js execution
  found later is likely a 'portable' version brought by the attacker.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%node%'
```

## suspicious-run-keys
<!-- Behavioral Run-key persistence in LocalAppData -->
Find Run keys pointing to any binary or script in user-writable LocalAppData, which is the primary behavioral marker for this implant's persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Registry entries where software is set to start from a user profile. This
  would still fire if the 'EdgeUpdate' name is changed.
reads:
- device_hostname
- reg_target
- reg_value_name
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, reg_target, reg_value_name, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\\currentversion\\run%' OR LOWER(reg_target) LIKE '%\\currentversion\\runonce%') AND LOWER(reg_value_data) LIKE '%\\appdata\\local\\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Parallel investigation of persistence and network leads -->
parallel:
- → startup-shortcut-search
- → rare-user-path-connections
- → http-polling-activity
join: → triage-implants

## startup-shortcut-search
<!-- Specific Startup folder shortcut search -->
Look for the specific 'EdgeUpdate.lnk' file in the Startup folder as described in the report.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, persistence_keyword=persistence_keyword)
~~~yaml
expected: A hit on the specific file name used in the observed campaign.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\\microsoft\\windows\\start menu\\programs\\startup\\%' AND LOWER(file_name) LIKE '%{{persistence_keyword}}%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-user-path-connections
<!-- Rare connections from user-path binaries -->
Find processes running from AppData\Local that communicate with rare external destinations, a strong signal for C2.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections from LocalAppData binaries to IPs seen on only 1-3 hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT process_name, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%\\appdata\\local\\%' OR LOWER(process_name) LIKE '%\\appdata\\local\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_ip HAVING host_count <= 3 ORDER BY host_count ASC
```

## http-polling-activity
<!-- HTTP polling patterns to unknown domains -->
Identify the randomized polling behavior by looking for high-frequency HTTP requests to external domains from endpoint processes.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Repetitive requests indicating a long-polling C2 mechanism.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path, user_agent HAVING request_count > 20 ORDER BY request_count DESC
```

## triage-implants
<!-- Triage Node.js persistence and C2 evidence -->
```agent target=hunter
cite: required
context:
- node-inventory-scoping
- suspicious-run-keys
- startup-shortcut-search
- rare-user-path-connections
- http-polling-activity
max_iterations: 5
objective: 'Analyze the collected rows to determine if a host shows the specific IT-support
  impersonation campaign pattern: Node.js binaries in LocalAppData, ''EdgeUpdate''
  persistence, and rare external C2 polling.'
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign citing specific
  evidence.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route on triage results -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-https-inspection)
else: → close-out

## isolate-host
<!-- Isolate host and collect artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host. Collect the binaries and scripts located in the identified LocalAppData paths for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the triage results. Examine the Node.js scripts for C2 functionality. Check for evidence of 'discovery-and-screen-capture' or 'lateral-movement-winrm' hunts if the implant is confirmed.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the negative result or the outcome of the incident. If false positives were found for legitimate Node.js updaters, add them to an exclusion list for future runs.
```
→ end
