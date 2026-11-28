---
analysis: A single detection rule for Registry Run keys or DNS lookups would be prone
  to false positives from legitimate support activity. This hunt uses the agent to
  weigh multiple independent signals (vulnerability status, rare persistence scripts,
  and named artifact execution) to confirm a sophisticated toolkit installation.
blind_spots:
- id: incomplete-telemetry
  question: Are there unmanaged hosts in the environment that SCKit has successfully
    compromised?
  requires: EDR agent coverage across all MSP-managed endpoints
  risk: A host without an agent will not appear in registry or process logs, leaving
    persistence unobserved and session hijacking possible.
  stage: persistence-establishment
- id: ephemeral-processes
  question: Did the RelayTrap component execute and terminate between sampling intervals?
  requires: High-frequency process sampling or full process log retention
  risk: If using snapshot-based process activity (hb_process_activity) without historical
    logs, short-lived toolkit components may be missed.
  stage: relay-trap-technician-targeting
coverage:
- stage: persistence-establishment
  status: covered
  steps:
  - rare-persistence-scripts
  - sckit-artifact-execution
- stage: c2-and-infrastructure-communication
  status: covered
  steps:
  - infrastructure-dns-lookups
- stage: relay-trap-technician-targeting
  status: covered
  steps:
  - vulnerable-screenconnect-hosts
  - sckit-artifact-execution
  - agent-triage
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: initial-access-screenconnect-abuse
  status: out_of_scope
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: unauthorized-client-installation
  status: out_of_scope
- reason: Belongs to another part of the 'SCKit abuses ScreenConnect to deploy remote
    access and target technician sessions' series.
  stage: sckit-powershell-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SCKit represents a direct threat to the trust relationship between
    MSPs and their customers. By abusing legitimate remote-access tools to hijack
    technician sessions, the threat actor can achieve broad lateral movement that
    bypasses standard perimeter controls.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder who has compromised a ScreenConnect client is maintaining
  access via script-based Registry persistence and is using the RelayTrap component
  to target connecting technician sessions.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1071
- attack.t1190
- attack.t1547.001
- attack.t1562.001
- command and control
- execution
- initial access
- lateral movement
- persistence
name: SCKit Persistence and RelayTrap Targeting
parameters:
  c2_domains:
    default:
    - ns.mo7sen.dev
    - sc.payproofkit.com
    - relaytrap.cs
    - cdn007-digitaldownloads.com
    - suspscreenconnectdownload.ea
    - tikise.ea
    - relaypersist.fc
    - screlaytrap.ec
    - screenconnect.sc
    - screenconnect.dc
    description: C2 and relay domains identified in the research.
    from:
      kind: article
      observed: '2026-11-13'
      ref: msrc-blog-sckit-screenconnect
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of activity to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to hunt the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The scoping query targets the vulnerability used for initial access. The
  hunt also checks all hosts for persistence regardless of patch status to identify
  infections that occurred before patching.
references:
- name: "Microsoft Security Blog \u2014 SCKit abuses ScreenConnect to deploy remote\
    \ access and target technician sessions"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/
related:
- hunt: unauthorized-screenconnect-client-deployment
  reason: This hunt focuses on the persistent toolkit and technician targeting, whereas
    deployment focuses on the initial MSI installer activity.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ScreenConnect Management Abuse
    observables:
    - Unauthorized commands issued via RMM+ extension APIs
    - ScreenConnect.ClientSetup.msi requested with c=Exploited parameters
    - Abuse of ConnectWise Automate/LabTech extensions
    slug: initial-access-screenconnect-abuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious MSI Deployment
    observables:
    - curl.exe -o C:\Windows\Temp\sc.msi
    - msiexec.exe /i C:\Windows\Temp\sc.msi /qn /norestart
    - Silent installation of unauthorized ScreenConnect guest clients
    slug: unauthorized-client-installation
    tactic: execution
    techniques:
    - T1059
  - name: SCKit Payload Extraction
    observables:
    - Stage0Loader.ps1
    - Panel-Lateral.ps1
    - Panel-Lateral-free.ps1
    - LabConfig.ps1
    - PowerShell decoder extracting toolkit using device-specific material
    slug: sckit-powershell-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via Tasks and Registry
    observables:
    - schtasks.exe creating malicious maintenance tasks
    - Registry Run keys for SCKit launchers
    - trapkit\install.ps1
    - Stop-LabTrap.bat
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
    - T1562.001
  - name: Command and Control Infrastructure
    observables:
    - 185.99.255.28
    - 155.94.150.39
    - ns.mo7sen.dev
    - sc.payproofkit.com
    - cdn007-digitaldownloads.com
    - relaytrap.cs
    - newnewnew.gotdns.org
    - soxnewwork.homedns.org
    slug: c2-and-infrastructure-communication
    tactic: command-and-control
    techniques:
    - T1071
  - name: Technician Session Hijacking
    observables:
    - CVE-2026-84869
    - RelayTrap component delivery to connecting technicians
    - TrapWatch.ps1
    - ToolboxRelayUploader.exe
    - Lite-Alert.ps1
    slug: relay-trap-technician-targeting
    tactic: lateral-movement
    techniques:
    - T1059.001
  summary: Threat actors abuse vulnerabilities in ScreenConnect server extensions
    or hijacked management consoles to deploy unauthorized remote-access clients and
    the SCKit malware toolkit. The campaign establishes long-term persistence on customer
    endpoints to host RelayTrap, a component that targets IT technicians' workstations
    with malicious payloads during support sessions.
series:
  index: 2
  slug: sckit-abuses-screenconnect-to-deploy-remote-access-and-target-technician-sessions
  title: SCKit abuses ScreenConnect to deploy remote access and target technician
    sessions
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


# SCKit Persistence and RelayTrap Targeting

This hunt identifies long-term SCKit infections following the abuse of ScreenConnect clients. It begins by scoping the estate to endpoints running unpatched or vulnerable ScreenConnect clients (CVE-2026-84869). It then executes a fan-out to find independent evidence of the toolkit's presence: rare batch or PowerShell scripts persisting in Registry Run keys, the execution of named SCKit artifacts like TrapWatch or Lite-Alert, and network communication with known malicious relay infrastructure. An agent triages these signals to identify compromised customer endpoints that may be attempting to hijack technician sessions.

## vulnerable-screenconnect-hosts
<!-- Identify vulnerable ScreenConnect clients -->
Find hosts susceptible to unauthorized file execution via ScreenConnect (CVE-2026-84869).

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows identify unpatched hosts. If none, the primary vector for SCKit deployment
  is mitigated, but the hunt continues for existing persistence.
reads:
- device_uid
- affected_package_version
- severity
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_uid, affected_package_version, severity, collected_at FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-84869' AND status != 'suppressed'
```

## corroborate-evidence
<!-- Fan-out for persistence and C2 signals -->
parallel:
- → rare-persistence-scripts
- → sckit-artifact-execution
- → infrastructure-dns-lookups
join: → agent-triage

## rare-persistence-scripts
<!-- Rare script persistence in Run keys -->
Identify hosts where SCKit launchers or cleanup scripts (Stop-LabTrap.bat) have been added to registry startup keys.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare scripts (batch or PowerShell) persisting in Run keys. Malicious launchers
  like Run-Lateral-Full.bat will appear as unique entries.
prevalence:
  by: device_hostname
  key:
  - reg_value_data
  rare_below: 3
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT LOWER(reg_value_data) AS script_data, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\currentversion\run%' OR LOWER(reg_target) LIKE '%\currentversion\runonce%') AND (LOWER(reg_value_data) LIKE '%.bat%' OR LOWER(reg_value_data) LIKE '%.ps1%' OR LOWER(reg_value_data) LIKE '%.cmd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## sckit-artifact-execution
<!-- Execution of SCKit toolkit artifacts -->
Detect the running components of the SCKit worm and RelayTrap payload.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes executing specific SCKit scripts or the RelayTrap uploader. This
  is a high-confidence indicator of active infection.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%trapwatch.ps1%' OR LOWER(process_cmd_line) LIKE '%lite-alert.ps1%' OR LOWER(process_cmd_line) LIKE '%stop-labtrap.bat%' OR LOWER(process_cmd_line) LIKE '%toolboxrelayuploader.exe%' OR LOWER(process_cmd_line) LIKE '%relaytrap%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## infrastructure-dns-lookups
<!-- DNS lookups to malicious relay infrastructure -->
Correlate host activity with the known domains used for toolkit retrieval and RelayTrap communication.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries for domains like ns.mo7sen.dev or sc.payproofkit.com. Any match
  indicates a host communicating with the threat actor's infrastructure.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage SCKit evidence per host -->
```agent target=hunter
cite: required
context:
- vulnerable-screenconnect-hosts
- rare-persistence-scripts
- sckit-artifact-execution
- infrastructure-dns-lookups
max_iterations: 6
objective: Determine which hosts are compromised by SCKit. A host is 'malicious' if
  it shows either artifact execution (TrapWatch/RelayTrap) or a combination of vulnerability
  (CVE-2026-84869) and rare script-based Run key persistence. Evaluate if the host
  process names suggest a technician workstation was the source of DNS lookups to
  the relays.
success_criteria: A verdict of malicious | suspicious | benign per host with citations.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on infection verdict -->
if~: "the agent-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active ScreenConnect sessions associated with the machine's client ID.
```
→ analyst-review

## analyst-review
<!-- Detailed analyst investigation -->
```manual target=analyst
Verify if the compromised host was used by a technician. Check for evidence of RelayTrap delivery (RelayTrap.cs or compiled variants) and audit any ScreenConnect commands issued during the infection window.
```
→ end

## close-out
<!-- Close hunt and record coverage -->
```manual target=analyst
Document the number of endpoints patched against CVE-2026-84869. If no malicious activity was found, record the negative results for persistence and C2 communication.
```
→ end
