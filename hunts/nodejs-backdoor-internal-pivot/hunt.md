---
analysis: A static detection for node.exe might fire on legitimate developers. This
  hunt uses stack-counting (prevalence) to isolate rare runtimes in user profiles
  and corroborates them with network pivots and script-based discovery that only occur
  during a live intrusion.
blind_spots:
- id: no-script-logging
  question: What specific Active Directory queries were performed?
  requires: hb_script_activity with full PowerShell logging
  risk: Without script block logging, operator-issued reconnaissance commands are
    invisible.
  stage: discovery-host-and-domain
- id: node-renaming
  question: Is the runtime renamed to a benign name?
  requires: hb_process_activity.process_original_file_name
  risk: If the attacker renames the Node.js binary and the EDR does not capture original
    file metadata, a simple name-based hunt will miss the execution.
  stage: c2-nodejs-implant
coverage:
- stage: c2-nodejs-implant
  status: covered
  steps:
  - suspicious-files-in-profile
  - nodejs-from-profile
  - rare-process-paths
- stage: discovery-host-and-domain
  status: covered
  steps:
  - discovery-script-activity
- stage: lateral-movement-winrm
  status: covered
  steps:
  - lateral-winrm-activity
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: initial-access-teams-vishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: execution-powershell-msi-loader
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: persistence-edgeupdate-run-key
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: defense-evasion-rundll32-proxy
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This intrusion campaign bypasses standard phishing filters by using
    legitimate Teams collaboration. Detecting the Node.js implant is critical because
    it represents the transition from social engineering to an interactive breach.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is maintaining command-and-control via a portable Node.js
  runtime hidden in a user profile and is performing internal discovery or lateral
  movement via WinRM.
labels:
- hunt
- attack.t1071
- attack.t1059.001
- attack.t1021.006
- attack.t1018
- attack.t1566.003
name: Node.js Backdoor and Internal Pivot
parameters:
  implant_extensions:
    default:
    - .tmp
    - .ini
    - .dat
    - .bin
    - .cfg
    description: Non-standard extensions used by the Node.js loader and implant.
    from:
      kind: article
      observed: '2026-09-02'
      ref: msrc-blog-2026-09-02
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; empty means the entire
      estate.
    type: list[host]
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
rationale: Focus on workstations and endpoints assigned to users with high privilege
  or domain-admin access. Servers should be monitored for WinRM incoming traffic on
  5985 from these workstations.
references:
- name: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: teams-vishing-initial-access
  reason: This hunt picks up after the remote session is established; the initial
    Teams vishing is a separate vector.
  relation: precedes
scenario:
  stages:
  - name: IT Support Impersonation via Teams
    observables:
    - Microsoft Teams external tenant chat
    - QuickAssist.exe execution
    - Remote control requests for screen-sharing
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.003
  - name: PowerShell MSI Delivery
    observables:
    - PowerShell download from cloud storage (Azure Blob, GitHub, Dropbox)
    - msiexec /qn /i
    - 'MSI filenames: devfix.msi, Hotfix.msi'
    slug: execution-powershell-msi-loader
    tactic: execution
    techniques:
    - T1059.001
  - name: EdgeUpdate Persistence
    observables:
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdate
    - 'Startup folder shortcut: EdgeUpdate.lnk'
    - LocalAppData directory staged with Node.js runtime
    slug: persistence-edgeupdate-run-key
    tactic: persistence
  - name: Node.js HTTPS Backdoor
    observables:
    - node.exe execution from LocalAppData
    - HTTPS long-polling to randomized C2 domains
    - 'JavaScript loaders with extensions: .tmp, .ini, .dat, .bin, .cfg'
    slug: c2-nodejs-implant
    tactic: command-and-control
    techniques:
    - T1071
  - name: Active Directory and Host Discovery
    observables:
    - ADSI queries for domain controllers and CAs
    - Discovery of AV products and virtualization environment
    - Screen capture exfiltration via Base64 encoded files
    slug: discovery-host-and-domain
    tactic: discovery
  - name: Execution via Rundll32
    observables:
    - rundll32.exe loading actor-supplied DLLs
    slug: defense-evasion-rundll32-proxy
    tactic: defense-evasion
    techniques:
    - T1218.011
  - name: WinRM Lateral Movement
    observables:
    - Outbound connections on TCP port 5985
    - Targeting of domain controllers and certificate authorities
    slug: lateral-movement-winrm
    tactic: lateral-movement
  summary: A human-operated campaign impersonates IT support via Microsoft Teams to
    trick users into granting remote access. Attackers then use PowerShell to deploy
    a malicious MSI that installs a Node.js-based implant for persistent command-and-control,
    environmental reconnaissance, and lateral movement via WinRM.
series:
  index: 2
  slug: impersonating-it-support-how-threat-actors-turn-a-remote-session-into-enterprise-wide-access
  title: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
  total: 2
severity: medium
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


# Node.js Backdoor and Internal Pivot

This hunt targets the post-compromise activity associated with IT-support impersonation campaigns. It focuses on identifying unusual Node.js runtime execution from user-writable paths (LocalAppData), which threat actors use to execute obfuscated JavaScript implants. The hunt corroborates this activity by looking for subsequent Active Directory discovery and lateral movement attempts via the WinRM protocol (TCP 5985) toward sensitive infrastructure.

## suspicious-files-in-profile
<!-- Suspicious implant files in LocalAppData -->
Identify hosts where files with the report's non-standard extensions were created in LocalAppData, a precursor to the Node.js implant execution.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts, implant_extensions=implant_extensions)
~~~yaml
expected: Creation of files with extensions like .tmp or .cfg in a user's LocalAppData
  folder. Legitimate apps use these, but they serve as a lead when combined with unusual
  process execution.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(file_path) LIKE '%\appdata\local\%' AND instr(',' || '{{implant_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, -4)) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## nodejs-corroboration
<!-- Corroborate Node.js activity across surfaces -->
parallel:
- → nodejs-from-profile
- → rare-process-paths
- → lateral-winrm-activity
- → discovery-script-activity
join: → triage-node-pivot

## nodejs-from-profile
<!-- Node.js execution from LocalAppData -->
Find instances where node.exe (or a renamed runtime) is running from a user profile rather than Program Files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any host running Node.js from a user's LocalAppData folder. This is a high-fidelity
  indicator for portable runtimes dropped by attackers.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_original_file_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_original_file_name, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\appdata\local\%') AND (LOWER(process_name) LIKE '%node.exe%' OR LOWER(process_original_file_name) = 'node.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-process-paths
<!-- Rare Node.js paths in profiles -->
Stack-count the Node.js paths to identify one-off portable runtimes used in specific attacks.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Paths seen on only one or two hosts are highly suspicious, whereas paths
  seen fleet-wide likely represent internal developer tools.
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
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\local\%') AND (LOWER(process_name) LIKE '%node.exe%' OR LOWER(process_original_file_name) = 'node.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts ASC
```

## lateral-winrm-activity
<!-- WinRM lateral movement on port 5985 -->
Detect outbound WinRM connections from suspicious endpoints, specifically targeting domain controllers or certificate authorities.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound TCP 5985 traffic from a host that also shows the Node.js implant
  is a near-certain indicator of lateral movement.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE dst_endpoint_port = 5985 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## discovery-script-activity
<!-- ADSI and AV discovery scripts -->
Examine script block telemetry for environment discovery commands issued by the operator via the Node.js C2 channel.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell or other scripts querying for Domain Controllers, installed AV,
  or virtualization tells indicate an active attacker mapping the host and network.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(script_content) LIKE '%adsisearcher%' OR LOWER(script_content) LIKE '%antivirusproduct%' OR LOWER(script_content) LIKE '%win32_videoadapter%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-node-pivot
<!-- Triage Node.js and Pivot evidence -->
```agent target=hunter
cite: required
context:
- suspicious-files-in-profile
- nodejs-from-profile
- rare-process-paths
- lateral-winrm-activity
- discovery-script-activity
max_iterations: 6
objective: Determine if any host shows evidence of a Node.js-based backdoor used for
  environment reconnaissance or lateral movement.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  Node.js path and network destination.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host running node.exe from LocalAppData" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-script-logging)
else: → close-out

## isolate-host
<!-- Isolate host and collect logs -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the Node.js runtime and all .tmp, .ini, .dat, .bin, .cfg files from the user's LocalAppData folder. Identify and revoke any leaked domain credentials.
```
→ manual-review

## manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the Node.js execution time against the user's Teams history. Look for legitimate remote-support apps (Quick Assist, ScreenConnect) launched just before the Node.js installation. Confirm if WinRM connections successfully hit Domain Controllers.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
If no intrusion was found, record the hosts examined and the lookback window. If developer noise was high, consider tuning the 'rare-process-paths' query.
```
→ end
