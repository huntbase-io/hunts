---
analysis: While a rule might alert on RMM installation, this hunt correlates that
  installation with the staging of portable runtimes and lateral movement attempts
  over WinRM, providing the full multi-stage context an analyst needs to confirm an
  active intrusion.
blind_spots:
- id: no-endpoint-telemetry
  question: Are unmanaged systems running Node.js runtimes?
  requires: Endpoint agent coverage on all systems
  risk: A negative result only covers the enrolled estate; unmanaged servers or BYOD
    devices could host the runtime invisibly.
- id: obfuscated-script-blocks
  question: What MSI was downloaded if the PowerShell script content was heavily obfuscated?
  requires: De-obfuscation or network traffic matching
  risk: The query for MSI delivery relies on cleartext strings; obfuscated downloaders
    may bypass this step.
  stage: powershell-payload-delivery
coverage:
- stage: social-engineering-rmm-access
  status: covered
  steps:
  - rmm-host-scoping
- stage: powershell-payload-delivery
  status: covered
  steps:
  - powershell-msi-delivery
- stage: portable-nodejs-c2
  status: covered
  steps:
  - rare-processes-in-user-paths
- stage: active-directory-discovery
  status: covered
  steps:
  - ad-discovery-activity
- stage: winrm-lateral-movement
  status: covered
  steps:
  - winrm-movement-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries are increasingly using legitimate RMM and administrative
    protocols to blend with IT operations. This hunt validates the security of these
    intersections by searching for the rare behavioral pivots (portable runtimes in
    user paths) that distinguish an intrusion from daily management.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used social engineering to gain access via Remote Monitoring
  and Management (RMM) software, followed by staging a portable Node.js runtime for
  C2 and attempting internal discovery and WinRM lateral movement.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1059
- attack.t1087
- attack.t1069
- attack.t1021.006
name: Impersonation-led Remote Support and Lateral Movement
parameters:
  discovery_binaries:
    default:
    - net.exe
    - nltest.exe
    - dsquery.exe
    - adfind.exe
    - net1.exe
    description: Native binaries used for Active Directory and domain discovery.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_tools:
    default:
    - anydesk
    - screenconnect
    - teamviewer
    - logmein
    - atera
    - splashtop
    - connectwise
    description: Common RMM tool names or substrings used for initial access.
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt; empty for entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints where RMM tools like AnyDesk or ScreenConnect are present
  but not part of standard IT policy. Narrowing to specific hosts via the `scope_hosts`
  parameter after the initial inventory query is recommended to reduce noise.
references:
- name: "MSRC \u2014 From guidance to action: Security fundamentals that materially\
    \ reduce risk"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/
related:
- hunt: external-teams-impersonation-detection
  reason: Teams-based social engineering is the initial vector before endpoint access.
  relation: precedes
scenario:
  stages:
  - name: Social Engineering via Remote Support
    observables:
    - Microsoft Teams impersonation
    - remote-support software (AnyDesk, ScreenConnect, TeamViewer)
    - legitimate IT support tools
    slug: social-engineering-rmm-access
    tactic: initial-access
    techniques:
    - T1566
  - name: PowerShell Payload Delivery
    observables:
    - powershell.exe
    - malicious Windows Installer (MSI) package
    - msiexec.exe
    - download of external artifacts
    slug: powershell-payload-delivery
    tactic: execution
    techniques:
    - T1059.001
  - name: Portable Node.js Persistence and C2
    observables:
    - portable node.exe runtime
    - outbound network connections from Node.js process
    - staged runtime in user-writable directories
    slug: portable-nodejs-c2
    tactic: c2
    techniques:
    - T1059
  - name: Active Directory Mapping
    observables:
    - Active Directory mapping
    - net.exe
    - nltest.exe
    - enumeration of domain controllers
    - enumeration of certificate authorities
    slug: active-directory-discovery
    tactic: discovery
    techniques:
    - T1087
    - T1069
  - name: Lateral Movement via WinRM
    observables:
    - WinRM (Windows Remote Management)
    - wsmprovhost.exe
    - winrshost.exe
    - connections to port 5985
    - connections to port 5986
    slug: winrm-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1021.006
  summary: Attackers impersonate IT support via Microsoft Teams to deploy remote support
    software, using it as a bridge to execute PowerShell scripts that install a portable
    Node.js runtime for persistent C2. The operator then maps Active Directory and
    attempts lateral movement via WinRM to reach high-value targets including Domain
    Controllers and Certificate Authorities.
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


# Impersonation-led Remote Support and Lateral Movement

This hunt targets tradecraft observed in the CaptiveCrunch and Storm-2945 campaigns, where attackers impersonate support staff to deploy RMM tools. It follows the attack chain from RMM installation to the staging of portable Node.js runtimes in user-writable paths and subsequent lateral movement attempts using WinRM. By correlating software inventory, rare process behavior in user profiles, and native protocol activity, we identify intrusions that blend with legitimate administrative operations.

## rmm-host-scoping
<!-- Identify Hosts with RMM Software -->
Scope the hunt to hosts that have Remote Monitoring and Management (RMM) software installed, which may have been the initial entry point via impersonation.

```sqlite target=endpoint role=scoping params=(rmm_tools=rmm_tools)
~~~yaml
expected: A list of hosts with RMM tools. This helps focus behavioral queries on high-probability
  beachheads.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## rare-processes-in-user-paths
<!-- Rare Binaries Running from User Profile Paths -->
Find rare processes, specifically targeting Node.js runtimes or MSI installers, running from user-writable directories which are typical for portable/staged runtimes.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries (like node.exe) running from non-standard user-profile paths
  across very few hosts.
prevalence:
  by: device_hostname
  key:
  - process_path
  - process_name
  rare_below: 5
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\users\public\%') AND (LOWER(process_name) = 'node.exe' OR LOWER(process_name) = 'msiexec.exe' OR LOWER(process_name) LIKE '%.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count < 5 ORDER BY host_count ASC
```

## powershell-msi-delivery
<!-- PowerShell Downloads of MSI Packages -->
Corroborate the presence of rare installers by identifying PowerShell script activity that downloads and installs MSI packages.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing download logic paired with MSI file extensions.
  Silence may indicate obfuscation or the use of other download methods.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%webclient%' OR LOWER(script_content) LIKE '%downloadstring%' OR LOWER(script_content) LIKE '%curl%' OR LOWER(script_content) LIKE '%wget%') AND LOWER(script_content) LIKE '%.msi%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## discovery-lateral-parallel
<!-- Discovery and Lateral Movement Search -->
parallel:
- → ad-discovery-activity
- → winrm-movement-activity
join: → triage-adversary-path

## ad-discovery-activity
<!-- Active Directory Infrastructure Discovery -->
Identify the use of discovery tools to map domain controllers or certificate authorities following the initial breach.

```sqlite target=endpoint role=triage params=(discovery_binaries=discovery_binaries, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Native discovery tools executed with domain-specific arguments on hosts
  that also show rare profile-path binaries.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{discovery_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%domain%' OR LOWER(process_cmd_line) LIKE '%trust%' OR LOWER(process_cmd_line) LIKE '%dclist%' OR LOWER(process_cmd_line) LIKE '%group%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## winrm-movement-activity
<!-- Lateral Movement via WinRM -->
Search for network connections and processes associated with WinRM lateral movement attempts.

```sqlite target=network role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to WinRM ports or execution of WinRM host processes, particularly
  from systems already identified as suspicious in earlier steps.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (dst_endpoint_port IN (5985, 5986) OR LOWER(process_name) IN ('wsmprovhost.exe', 'winrshost.exe')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-adversary-path
<!-- Triage Incident Path -->
```agent target=hunter
cite: required
context:
- rmm-host-scoping
- rare-processes-in-user-paths
- powershell-msi-delivery
- ad-discovery-activity
- winrm-movement-activity
max_iterations: 5
objective: Determine whether the combination of RMM tool presence, rare node.exe/portable
  binaries in user paths, MSI download activity, and WinRM network attempts indicates
  a coordinated impersonation-led intrusion.
success_criteria: A verdict of malicious | suspicious | benign per host with citations
  to the specific process, script, and network rows.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Triage Verdict -->
if~: "The triage verdict is malicious for at least one host involving rare runtimes and WinRM attempts." (confidence: high, judge=hunter)
then: → isolate-hosts
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → analyst-review

## isolate-hosts
<!-- Isolate Compromised Hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the hosts identified as malicious and revoke active sessions for the involved users. Preserve the binaries found in user profile paths for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the agent's triage report and host isolation status. Verify the origin of the RMM tools and portable binaries. Document any new C2 IP addresses found in network telemetry and promote the Node.js path query to a permanent detection rule if appropriate.
```
→ end
