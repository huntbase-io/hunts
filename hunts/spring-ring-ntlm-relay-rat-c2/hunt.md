---
analysis: A simple detection rule on the Python path can be evaded by renaming the
  binary. This hunt pivots to the behavioral impact (SMB scanning) and network indicators
  (DNS) to confirm the intrusion's intent.
blind_spots:
- id: no-smb-visibility
  question: whether the DC successfully authenticated back to the attacker
  requires: hb_network_connection with log visibility on domain controllers
  risk: We see the outbound scan from the beachhead but cannot confirm if the relay
    attack succeeded without server-side logs.
  stage: lateral-movement-ntlm-relay
- id: ephemeral-c2-infrastructure
  question: whether the PowerShell RAT received further payloads
  requires: TLS inspection of outbound web traffic
  risk: DNS lookups show intent but not the content of the payload delivery, which
    may use arithmetic obfuscation that automated tools miss.
  stage: command-and-control-rat
coverage:
- stage: lateral-movement-ntlm-relay
  status: covered
  steps:
  - find-custom-python
  - smb-scanning
- stage: command-and-control-rat
  status: covered
  steps:
  - c2-beaconing
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: initial-access-teams-vishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: execution-rmm-and-custom-payloads
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: persistence-staging-temp
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: defense-evasion-obfuscation-and-hijack
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: discovery-host-and-domain
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Spring Ring campaign targets domain controllers via NTLM relay
    after establishing a beachhead via vishing. A negative result confirms that the
    known technical execution phase has not occurred on the enrolled estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has deployed a custom Python environment to facilitate NTLM
  relay attacks and a PowerShell-based RAT that beacons to external command-and-control
  infrastructure.
labels:
- hunt
- attack.t1557.001
- attack.t1210
- attack.t1071.001
name: 'Spring Ring: NTLM Relay and RAT C2'
parameters:
  c2_domains:
    default:
    - san-sid.com
    description: C2 domains for the PowerShell RAT.
    from:
      kind: article
      observed: '2026-08-31'
      ref: Spring Ring
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  python_path:
    default: C:\ProgramData\IntegrityData\python.exe
    description: The specific Python path used for PetitPotam coercion.
    from:
      kind: article
      observed: '2026-08-31'
      ref: Spring Ring
    type: path
  scope_hosts:
    default: []
    description: Paste hosts from the scoping step here to narrow subsequent queries.
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with general endpoints. If the find-custom-python step identifies
  hits, use those hostnames in the scope_hosts parameter for the scanning and C2 steps.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: spring-ring-initial-access-vishing
  reason: This hunt focuses on technical execution after a potential vishing breach.
  relation: follows
- hunt: teams-vishing-payload-execution
  relation: follows
scenario:
  stages:
  - name: Teams Vishing and Impersonation
    observables:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.003
  - name: User Execution of RMM and Payloads
    observables:
    - Quick Assist
    - s3.us-west-2.amazonaws.com
    - '*-org-filters-update-*.exe'
    - san-sid.com
    slug: execution-rmm-and-custom-payloads
    tactic: execution
    techniques:
    - T1204.002
    - T1219
  - name: Staging and Persistence
    observables:
    - \Temp\vhlp-*.exe
    - \Temp\scnr-*.exe
    slug: persistence-staging-temp
    tactic: persistence
    techniques:
    - T1547
  - name: Bypassing AMSI and Browser Hijacking
    observables:
    - amsiInitFailed
    - Headless Microsoft Edge
    - Sideloaded Edge extension
    - Obfuscated PowerShell script
    slug: defense-evasion-obfuscation-and-hijack
    tactic: defense-evasion
    techniques:
    - T1027
    - T1562.001
    - T1176
  - name: Host and Domain Discovery
    observables:
    - whoami /groups
    - net group /dom
    slug: discovery-host-and-domain
    tactic: discovery
    techniques:
    - T1033
    - T1069.002
  - name: NTLM Relay and PetitPotam
    observables:
    - C:\ProgramData\IntegrityData\python.exe
    - Port 445 SMB scanning
    - PetitPotam coercion against Domain Controllers
    slug: lateral-movement-ntlm-relay
    tactic: lateral-movement
    techniques:
    - T1557.001
    - T1210
  - name: PowerShell RAT C2 Beaconing
    observables:
    - san-sid.com
    slug: command-and-control-rat
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Spring Ring is a social engineering campaign that leverages external Microsoft
    Teams accounts to impersonate IT help desks via vishing calls. Attackers coerce
    employees into running remote management tools or custom malware, leading to domain
    enumeration and NTLM relay attacks (PetitPotam) intended to compromise domain
    controllers.
series:
  index: 2
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
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


# Spring Ring: NTLM Relay and RAT C2

This hunt targets the lateral movement and command-and-control phases of the Spring Ring campaign. It identifies the execution of a tailored Python interpreter used for NTLM coercion (PetitPotam) and correlates it with outbound SMB scanning and DNS resolutions for known C2 domains. By pivoting from a specific process path to network-layer behaviors, the hunt detects attempts to escalate privileges to the domain level.

## find-custom-python
<!-- Find custom Python interpreter -->
Identify hosts running the tailored Python environment used to initiate NTLM relay attacks.

```sqlite target=endpoint role=scoping params=(python_path=python_path, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts and users executing the specific Python binary. Silence
  indicates the environment has not been deployed on any enrolled Windows endpoint.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) = LOWER('{{python_path}}') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4
```

## gather-evidence
<!-- Corroborate scanning and C2 -->
parallel:
- → smb-scanning
- → c2-beaconing
join: → triage-verdict

## smb-scanning
<!-- Outbound SMB scanning on port 445 -->
Identify potential PetitPotam coercion attempts by finding hosts contacting many internal targets over SMB.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A host connecting to multiple internal IP addresses on port 445. The presence
  of the suspicious python.exe as the originating process is a critical signal.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = 445 AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING connections > 5 ORDER BY connections DESC
```

## c2-beaconing
<!-- DNS lookups for Spring Ring C2 -->
Verify if hosts are beaconing to the PowerShell RAT command-and-control infrastructure.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Resolutions for the known C2 domains from the beachhead hosts. Silence means
  no DNS activity for these specific indicators was captured.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MAX(time) AS last_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## triage-verdict
<!-- Evaluate Spring Ring intrusion -->
```agent target=hunter
cite: required
context:
- find-custom-python
- smb-scanning
- c2-beaconing
max_iterations: 5
objective: Decide whether the combined evidence of custom python execution, SMB scanning,
  and C2 beaconing indicates an active Spring Ring campaign on any host.
success_criteria: A verdict of malicious for any host showing the custom python execution
  alongside scanning or C2 activity.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on malicious verdict -->
if~: "the triage-verdict identifies at least one host as malicious" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → investigate-lateral-movement
unavailable: → investigate-lateral-movement (blind_spot: no-smb-visibility)
else: → cleanup-and-report

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate any processes running from C:\ProgramData\IntegrityData\.
```
→ investigate-lateral-movement

## investigate-lateral-movement
<!-- Forensic review of SMB scanning -->
```manual target=analyst
Examine the destination IPs from the smb-scanning step. Check Domain Controller logs for NTLM authentication attempts or coercion errors around the same time.
```
→ cleanup-and-report

## cleanup-and-report
<!-- Cleanup and report -->
```manual target=analyst
Summarize the hosts identified and the specific behaviors observed. Note any gaps in SMB visibility on servers.
```
→ end
