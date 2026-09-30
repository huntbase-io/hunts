---
analysis: A standard rule might detect MeshAgent, but this hunt pivots between authentication
  logs to establish a beachhead and uses prevalence stack-counting to identify renamed
  RMM binaries that would otherwise blend in.
blind_spots:
- id: missing-network-logs
  question: Did the MeshAgent binary successfully establish a C2 channel?
  requires: hb_network_connection with state_kind = 'log'
  risk: If the endpoint agent or network fabric does not capture flow logs, we only
    see the process execution and not the confirmation of active C2.
  stage: persistence-rmm-meshagent
- id: vpn-auth-visibility
  question: Which VPN logins are tied to the intrusion?
  requires: hb_auth_signin with VPN provider integration
  risk: If the VPN provider is not integrated with the authentication surface, we
    cannot correlate the entry point with the internal persistence.
  stage: initial-access-remote-services
coverage:
- stage: initial-access-remote-services
  status: covered
  steps:
  - remote-access-signins
- stage: persistence-rmm-meshagent
  status: covered
  steps:
  - rare-rmm-processes
  - meshagent-c2-traffic
- reason: Covered in the following hunt in the Settra series.
  stage: defense-evasion-byovd
  status: out_of_scope
- reason: Covered in the following hunt in the Settra series.
  stage: execution-ransomware-launcher
  status: out_of_scope
- reason: Covered in the following hunt in the Settra series.
  stage: anti-recovery-and-evasion
  status: out_of_scope
- reason: Covered in the following hunt in the Settra series.
  stage: impact-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Settra ransomware uses legitimate RMM tools for persistence to survive
    standard security measures; detecting this channel before the launcher executes
    provides the best opportunity to prevent impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a beachhead via compromised external remote
  services and installed MeshAgent, potentially renamed, to maintain persistent command-and-control
  access.
labels:
- hunt
- attack.t1133
- attack.t1021.001
- attack.t1219
name: Settra Persistence via MeshAgent and Remote Access
parameters:
  c2_ips:
    default:
    - 45.13.122.7
    - 193.5.65.114
    description: C2 IP addresses associated with MeshAgent in Settra incidents; no
      spaces between entries.
    from:
      kind: article
      observed: '2026-09-17'
      ref: huntress-settra-ransomware
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  meshagent_metadata:
    default: MeshAgent
    description: The expected original filename or product name in the PE metadata.
    from:
      kind: article
      observed: '2026-09-17'
      ref: huntress-settra-ransomware
    type: string
  scope_hosts:
    default: []
    description: A list of hostnames to focus the hunt on, typically derived from
      the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/new-settra-ransomware-variant
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all successful RDP and VPN sign-ins. If you find high-volume
  access from unusual IPs, use those hostnames as the scope_hosts parameter to narrow
  the expensive process and network queries.
references:
- name: "Huntress \u2014 New Settra Ransomware Variant Deploys MeshAgent RMM"
  url: https://www.huntress.com/blog/new-settra-ransomware-variant
related:
- hunt: settra-ransomware-evasion-and-encryption
  reason: This hunt targets the persistence stage; the following hunt covers the BYOVD
    evasion and file encryption stages.
  relation: follows
scenario:
  stages:
  - name: External Remote Service Compromise
    observables:
    - VPN credential compromise
    - RDP session usage
    slug: initial-access-remote-services
    tactic: initial-access
    techniques:
    - T1133
    - T1021.001
  - name: Persistence via MeshAgent RMM
    observables:
    - mvtcs.exe
    - MeshAgent RMM installation
    - 45.13.122.7
    - 193.5.65.114
    - Workstation name WIN-LIVFRVQFMKO
    slug: persistence-rmm-meshagent
    tactic: persistence
  - name: BYOVD Security Tool Disabling
    observables:
    - gdrv.sys
    - Disable antivirus services
    slug: defense-evasion-byovd
    tactic: defense-evasion
  - name: Settra Ransomware Execution
    observables:
    - '*_win64.exe'
    - C:\Perflogs
    - \Documents\*_win64.exe
    slug: execution-ransomware-launcher
    tactic: execution
  - name: Inhibit Recovery and Clear Logs
    observables:
    - reagentc /disable
    - ipconfig /flushdns
    - diskpart.exe execution with recovery partition script
    - 'cipher /w:'
    - wevtutil log clearing (Application, Security, System, Setup, ForwardedEvents)
    - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    - Microsoft-Windows-TerminalServices-RDPClient/Operational
    - Microsoft-Windows-Sysmon/Operational
    - Microsoft-Windows-PowerShell/Operational
    - Microsoft-Windows-WinRM/Operational
    - Microsoft-Windows-TaskScheduler/Operational
    - Microsoft-Windows-Windows-Defender/Operational
    slug: anti-recovery-and-evasion
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Data Encrypted for Impact
    observables:
    - .locked extension
    - .locked_wip extension
    - RESTORE_FILES.txt
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Settra ransomware incidents involve initial persistence via MeshAgent RMM
    and the use of BYOVD (gdrv.sys) to disable security tools before executing a ransomware
    binary named after the victim domain. The threat actor employs extensive anti-recovery
    measures including clearing multiple event logs, disabling the Windows Recovery
    Environment, and overwriting free disk space using native Windows utilities.
series:
  index: 1
  slug: ready-settra-go-new-settra-ransomware-variant-deploys-meshagent-rmm
  title: 'Ready, Settra, Go: New Settra Ransomware Variant Deploys MeshAgent RMM'
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


# Settra Persistence via MeshAgent and Remote Access

This hunt identifies the early stages of a Settra ransomware intrusion by correlating remote access sign-ins with the subsequent deployment of the MeshAgent RMM tool. MeshAgent is a legitimate remote management utility that Settra operators use for persistence, often renaming the binary to mvtcs.exe. The hunt pivots from scoping successful RDP or VPN sessions to stack-counting rare binaries and identifying network telemetry reaching out to specific C2 infrastructure reported in recent Settra incidents.

## remote-access-signins
<!-- Remote access sign-ins -->
Identify successful logins via RDP or VPN that may represent the initial beachhead for the threat actor.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and users accessing the network remotely. Silence suggests
  either no remote access occurred or the activity is outside the logging visibility
  of the authentication surface.
reads:
- dst_endpoint_name
- actor_user_name
- src_endpoint_ip
- auth_protocol
- status_id
- activity_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT dst_endpoint_name AS device_hostname, actor_user_name, src_endpoint_ip, auth_protocol, MIN(time) AS first_signin, MAX(time) AS last_signin FROM hb_auth_signin WHERE status_id = 1 AND (LOWER(auth_protocol) LIKE '%rdp%' OR LOWER(auth_protocol) LIKE '%vpn%' OR LOWER(activity_name) LIKE '%remote%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name, actor_user_name, src_endpoint_ip, auth_protocol ORDER BY last_signin DESC
```

## persistence-corroboration
<!-- Corroborate persistence -->
parallel:
- → rare-rmm-processes
- → meshagent-c2-traffic
join: → triage-verdict

## rare-rmm-processes
<!-- Rare MeshAgent-related processes -->
Find rare processes associated with MeshAgent binaries by checking paths and original file name metadata across the estate.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, meshagent_metadata=meshagent_metadata, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The binary mvtcs.exe or meshagent.exe appearing on a very small number of
  hosts, or any process with MeshAgent original metadata. Silence proves no such processes
  ran on the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - path
  - process_original_file_name
  rare_below: 3
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT LOWER(process_name) AS path, process_original_file_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%\mvtcs.exe' OR LOWER(process_name) LIKE '%\meshagent.exe' OR LOWER(process_original_file_name) LIKE '%' || LOWER('{{meshagent_metadata}}') || '%' OR LOWER(process_cmd_line) LIKE '%meshagent%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING hosts <= 3 ORDER BY hosts, runs
```

## meshagent-c2-traffic
<!-- MeshAgent C2 traffic -->
Detect network connections from scoped hosts to the specific MeshAgent C2 IPs reported for Settra.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound connections to 45.13.122.7 or 193.5.65.114. Any matching connection
  is highly suspicious if paired with an unrecognized RMM binary.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-verdict
<!-- Triage verdict -->
```agent target=hunter
cite: required
context:
- remote-access-signins
- rare-rmm-processes
- meshagent-c2-traffic
max_iterations: 5
objective: Determine if the remote access session led to the installation of MeshAgent
  RMM and whether that RMM is communicating with known-malicious infrastructure.
success_criteria: A verdict of malicious if MeshAgent is found connecting to the report's
  IPs on the same host where a remote sign-in occurred.
tools:
- endpoint
- identity
- network
```

## routing-decision
<!-- Routing decision -->
if~: "the triage verdict is malicious for at least one host, citing the presence of a rare MeshAgent binary and connections to Settra C2 IPs" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-network-logs)
else: → close-out-report

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Kill any running instances of mvtcs.exe or meshagent.exe. Revoke active sessions for the user account identified in the sign-in step.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the full process tree for the rare binary. Check for scheduled tasks or registry run keys that might restart MeshAgent. Pivot to the next stage hunt (BYOVD and Ransomware Launcher) to check for further progression.
```
→ close-out-report

## close-out-report
<!-- Close-out report -->
```manual target=analyst
Record all confirmed IPs and filenames. If mvtcs.exe was found, promote the process query to a standing detection rule.
```
→ end
