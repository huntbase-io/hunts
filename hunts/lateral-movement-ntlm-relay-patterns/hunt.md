---
analysis: A standard detection rule for 'net group /dom' is easily circumvented or
  generates high noise for admins. This hunt differentiates by correlating the enumeration
  with rare outbound SMB connections and the presence of an unauthorized Python execution
  environment in a user-writable path.
blind_spots:
- id: missing-auth-logs
  owner: Infrastructure Team
  question: Was an NTLM relay successful against a specific target?
  remediation: Enable and ingest Advanced Audit Policy logs (Logon/Logoff) from all
    Domain Controllers.
  requires: hb_auth_signin with NTLM protocol coverage
  risk: Without authentication logs from the Domain Controller, we can see the attempt
    (SMB traffic) but not the successful coercion or relay outcome.
  stage: discovery-and-lateral-movement
- id: rpc-visibility
  owner: Endpoint Security Team
  question: Was the PetitPotam EFSRPC call specifically used?
  remediation: Deploy Sysmon with Event ID 11/17/18 and RPC filter configurations.
  requires: Deep Packet Inspection or RPC-specific endpoint events
  risk: General SMB port 445 traffic indicates a connection, but not the specific
    API call. Attackers could use other coercion methods that blend in.
  stage: discovery-and-lateral-movement
coverage:
- stage: discovery-and-lateral-movement
  status: covered
  steps:
  - scoping-unusual-python-path
  - detection-enumeration-commands
  - rare-smb-outbound
  - ntlm-auth-anomalies
- reason: Covered in the first hunt of this series focusing on Teams activity.
  stage: initial-access-teams-vishing
  status: out_of_scope
- reason: Covered in the second hunt of this series focusing on tailored Amazon S3
    payloads.
  stage: execution-and-delivery
  status: out_of_scope
- reason: Focuses on the browser extension and Temp directory staging, handled in
    a dedicated persistence hunt.
  stage: persistence-and-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Lateral movement and NTLM relay attacks represent a high risk of
    total domain compromise. Detecting these patterns on the endpoint allows for isolation
    before an attacker can finalize a relay to a DC.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using a non-standard Python environment and native Windows
  utilities to enumerate domain groups and initiate NTLM relay attacks against internal
  servers.
labels:
- hunt
- attack.t1087.002
- attack.t1550.002
- attack.t1210
name: Lateral Movement and NTLM Relay Patterns
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-31'
      ref: standard-retention
    type: number
  python_path:
    default: c:\programdata\integritydata\python.exe
    description: Path to the unauthorized Python environment identified in the report.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
    type: path
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
rationale: Focus on endpoints that were targets of the previous 'Execution' hunt or
  those showing unusual software inventory hits in ProgramData.
references:
- name: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: initial-access-teams-vishing
  reason: The lateral movement follows the initial access and tool delivery via Teams
    vishing.
  relation: precedes
- hunt: spring-ring-persistence-hijacking
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
  index: 3
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
  total: 3
severity: critical
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Lateral Movement and NTLM Relay Patterns

This hunt focuses on the 'Spring Ring' lateral movement phase. It identifies unusual Python execution from ProgramData, detects standard domain enumeration commands, and baselines outbound SMB traffic to find rare processes attempting to coerce NTLM authentication. By correlating these behaviors, we can identify PetitPotam-style relay attacks that a single alert would miss.

## scoping-unusual-python-path
<!-- Unauthorized Python environment execution -->
Find instances of the specific Python binary used in Campaign B to initiate lateral movement.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, python_path=python_path)
~~~yaml
expected: A hit names the host and user running the malicious Python environment.
  Silence suggests this specific tool path is not currently active.
reads:
- device_hostname
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_path) = LOWER('{{python_path}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## detection-enumeration-commands
<!-- Domain and Group Enumeration -->
Identify manual discovery attempts using built-in utilities as seen in Campaign A.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Commands targeting domain groups or user group memberships. Hits from non-admin
  accounts or unusual parent processes (like Python or RMM tools) are high fidelity.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%whoami /groups%' OR (LOWER(process_cmd_line) LIKE '%net group%' AND LOWER(process_cmd_line) LIKE '%/dom%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-lateral-evidence
<!-- Corroborate Lateral Movement Activity -->
parallel:
- → rare-smb-outbound
- → ntlm-auth-anomalies
join: → triage-lateral-movement

## rare-smb-outbound
<!-- Rare processes initiating SMB traffic -->
Stack-count processes initiating outbound SMB (445) to identify potential scanning or relay tools.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of processes that are not standard system components (like svchost
  or explorer) but are initiating internal SMB connections.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- process_name
- device_hostname
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as connection_count FROM hb_network_connection WHERE dst_endpoint_port = 445 AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count < 5 ORDER BY host_count ASC
```

## ntlm-auth-anomalies
<!-- NTLM Authentication Failures -->
Identify potential relay or credential harvesting targets via NTLM logs.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: High counts of NTLM failures between internal hosts, potentially indicating
  an attacker attempting to coerce authentication.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- auth_protocol
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, COUNT(*) as attempts FROM hb_auth_signin WHERE LOWER(auth_protocol) LIKE '%ntlm%' AND activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name
```

## triage-lateral-movement
<!-- Correlate Lateral Evidence -->
```agent target=hunter
cite: required
context:
- scoping-unusual-python-path
- detection-enumeration-commands
- rare-smb-outbound
- ntlm-auth-anomalies
max_iterations: 3
objective: 'Determine if any host shows a cluster of activity: (1) running unauthorized
  Python, (2) executing AD enumeration commands, and (3) initiating rare SMB connections
  or NTLM failures.'
success_criteria: A verdict of malicious | suspicious | benign per host with cited
  rows for each evidence type.
tools:
- endpoint
- identity
- network
```

## route-verdict
<!-- Route based on Triage -->
if~: "The triage verdict is malicious for one or more hosts with correlated process and network evidence." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: missing-auth-logs)
else: → close-hunt

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host and revoke current sessions for the user account involved.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Investigation -->
```manual target=analyst
Review the SMB traffic targets from the 'rare-smb-outbound' step. Determine if a Domain Controller was the target and check DC logs for PetitPotam (EID 4624/4625 with unusual workstations).
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
Document the absence of Spring Ring lateral movement tools. If enumeration was found but was benign, add the parent process to a tuning list.
```
→ end
