---
analysis: A single rule on Node.js execution might be too noisy in developer environments;
  this hunt correlates the rare runtime with preceding remote-support takeover and
  following lateral movement, providing the full context an analyst needs to act.
blind_spots:
- id: no-winrm-command-logging
  owner: Infrastructure Team
  question: Which specific administrative commands were executed on the Domain Controller?
  remediation: Enable WinRM auditing and Process Command Line logging on all Domain
    Controllers and Certificate Authorities.
  requires: WinRM Operational logging or deep packet inspection
  risk: While the connection is visible, the impact (e.g., AD mapping, account creation)
    remains hidden without detailed host logs on the destination.
  stage: lateral-movement-winrm-dc
- id: node-runtime-renaming
  owner: Endpoint Security Team
  question: Did the attacker rename the portable Node.js runtime to masquerade as
    a system process?
  remediation: Deploy hash-based monitoring for known portable runtimes or utilize
    original_file_name columns in process activity queries.
  requires: hb_process_activity with original file name or hash-based detection
  risk: If node.exe is renamed to svchost.exe or similar, the current process_name
    filter will miss it.
  stage: command-and-control-node-js
coverage:
- stage: execution-remote-support-takeover
  status: covered
  steps:
  - remote-support-spawning-shells
- stage: execution-powershell-msi-download
  status: covered
  steps:
  - powershell-msi-scripting
- stage: command-and-control-node-js
  status: covered
  steps:
  - portable-node-prevalence
- reason: AD mapping via WinRM typically uses internal API calls or LDAP traffic not
    captured in standard process or network activity surfaces.
  stage: discovery-active-directory-mapping
  status: not_visible
- stage: lateral-movement-winrm-dc
  status: covered
  steps:
  - winrm-lateral-expansion
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: initial-access-teams-impersonation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are using legitimate remote-support tools to bypass security
    boundaries and expand laterally using native protocols like WinRM. This hunt protects
    the critical internal infrastructure that these multi-stage paths target.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked a remote-support session to execute PowerShell,
  use a portable Node.js runtime for C2, and expand laterally via WinRM to domain
  controllers.
labels:
- hunt
- attack.t1219
- attack.t1059.001
- attack.t1105
- attack.t1071.001
- attack.t1087.002
- attack.t1021.006
name: IT Support Impersonation and WinRM Lateral Expansion
parameters:
  admin_shell_binaries:
    default:
    - powershell.exe
    - cmd.exe
    - msiexec.exe
    description: Shells and installers typically used after takeover.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  remote_support_tool_names:
    default:
    - anydesk.exe
    - teamviewer.exe
    - teamviewer_desktop.exe
    - screenconnect.client.exe
    - quickassist.exe
    - remoteassistant.exe
    description: Common remote support process names.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: common-remote-support-processes
    type: list[string]
  scope_hosts:
    default: []
    description: Optional hostnames to narrow the scope.
    type: list[host]
  sensitive_ip_targets:
    default: []
    description: IPs of Domain Controllers or Certificate Authorities to monitor for
      WinRM.
    from:
      kind: article
      observed: '2026-09-17'
      ref: https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/
    type: list[ip]
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
rationale: Focus on endpoints where remote-support software is prevalent but restricted
  to IT use. Provide known Domain Controller and CA IP addresses to refine the lateral
  movement detection.
references:
- name: "MSRC \u2014 From guidance to action: Security fundamentals that materially\
    \ reduce risk"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/
related:
- hunt: teams-guest-account-takeover
  reason: The initial impersonation via Teams is an identity-focused hunt that precedes
    the endpoint activities covered here.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: IT Support Impersonation via Teams
    observables:
    - Microsoft Teams conversation
    - IT support impersonation
    slug: initial-access-teams-impersonation
    tactic: initial-access
    techniques:
    - T1566.002
    - T1566.003
  - name: Remote Support Software Execution
    observables:
    - Legitimate remote-support software
    - User-granted session control
    slug: execution-remote-support-takeover
    tactic: execution
    techniques:
    - T1219
  - name: PowerShell MSI Deployment
    observables:
    - powershell.exe
    - Windows Installer (MSI) package download
    - msiexec.exe
    slug: execution-powershell-msi-download
    tactic: execution
    techniques:
    - T1059.001
    - T1105
  - name: Node.js Portable Runtime C2
    observables:
    - Portable Node.js runtime
    - node.exe
    - Outbound C2 connection
    slug: command-and-control-node-js
    tactic: command-and-control
    techniques:
    - T1105
    - T1071.001
  - name: Active Directory Mapping
    observables:
    - Active Directory mapping commands
    - Queries against domain controllers
    slug: discovery-active-directory-mapping
    tactic: discovery
    techniques:
    - T1087.002
    - T1482
  - name: Lateral Movement via WinRM
    observables:
    - WinRM protocol usage
    - Connections to domain controllers
    - Connections to certificate authorities
    slug: lateral-movement-winrm-dc
    tactic: lateral-movement
    techniques:
    - T1021.006
  summary: Attackers impersonate IT support via Microsoft Teams to trick users into
    granting control via legitimate remote-support software, followed by the deployment
    of a portable Node.js runtime for command-and-control. Once established, the operators
    map Active Directory and move laterally to critical infrastructure like domain
    controllers and certificate authorities using WinRM.
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


# IT Support Impersonation and WinRM Lateral Expansion

This hunt identifies the multi-stage progression of the CaptiveCrunch campaign. It first isolates hosts where legitimate remote-support tools are used as a launchpad for PowerShell-based MSI downloads. It then pivots to find the deployment of rare Node.js runtimes in user-writable paths and subsequent WinRM connections to sensitive internal infrastructure like Domain Controllers and Certificate Authorities.

## identify-remote-support-hosts
<!-- Inventory of hosts with remote support software -->
Find the subset of the estate where remote support tools are installed to focus behavioral analysis.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts with known remote-support packages. Silence is expected
  if these tools are not in the official inventory.
reads:
- device_hostname
- install_path
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%anydesk%' OR LOWER(package_name) LIKE '%teamviewer%' OR LOWER(package_name) LIKE '%connectwise%' OR LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%quick assist%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-early-execution
<!-- Examine early takeover behavior -->
parallel:
- → remote-support-spawning-shells
- → powershell-msi-scripting
join: → agent-early-takeover-triage

## remote-support-spawning-shells
<!-- Remote support tools spawning administrative shells -->
Identify process patterns where a support tool acts as a parent to a shell or installer.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, remote_support_tool_names=remote_support_tool_names, admin_shell_binaries=admin_shell_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: A support tool launching PowerShell, CMD, or MSIExec. Legitimate admin use
  may occur but will be weighed by the agent.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, time, process_name, process_cmd_line, parent_process_name, user_name FROM hb_process_activity WHERE instr(',' || '{{remote_support_tool_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{admin_shell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## powershell-msi-scripting
<!-- PowerShell script blocks downloading MSI files -->
Detect the specific scripting commands used to retrieve malicious installer packages.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script contents showing network-based retrieval of MSI files. This is a
  behavioral indicator of staging.
reads:
- actor_user_name
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, time, script_content, actor_user_name FROM hb_script_activity WHERE LOWER(script_content) LIKE '%.msi%' AND (LOWER(script_content) LIKE '%download%' OR LOWER(script_content) LIKE '%iwr%' OR LOWER(script_content) LIKE '%http%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## agent-early-takeover-triage
<!-- Triaging remote-support takeover -->
```agent target=hunter
cite: required
context:
- identify-remote-support-hosts
- remote-support-spawning-shells
- powershell-msi-scripting
max_iterations: 3
objective: Identify hosts where remote support software spawned PowerShell or MSIExec
  to download external packages.
success_criteria: A per-host verdict citing the specific process and script rows that
  indicate malicious staging.
tools:
- endpoint
- network
```

## parallel-follow-on-activity
<!-- Analyze C2 staging and lateral expansion -->
parallel:
- → portable-node-prevalence
- → winrm-lateral-expansion
join: → agent-full-chain-triage

## portable-node-prevalence
<!-- Prevalence of Node.js runtimes in user paths -->
Stack-count Node.js executions from user-writable paths to isolate the portable C2 runtime from official installations.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A Node.js binary seen on only a few hosts, running from a non-standard directory.
  Common developer installs will appear across more hosts.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 5
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) = 'node.exe' AND (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\public\%' OR LOWER(process_path) LIKE '%\temp\%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY 1 HAVING hosts <= 5 ORDER BY hosts ASC
```

## winrm-lateral-expansion
<!-- WinRM connections to sensitive internal targets -->
Identify lateral movement attempts targeting high-value infrastructure like Domain Controllers.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, sensitive_ip_targets=sensitive_ip_targets, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from the suspected beachhead to sensitive IPs over WinRM ports.
  Silence means no such connections were logged.
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
SELECT device_hostname, time, process_name, dst_endpoint_ip, dst_endpoint_port, direction FROM hb_network_connection WHERE (dst_endpoint_port IN (5985, 5986) OR LOWER(process_name) = 'wsmprovhost.exe') AND (instr(',' || '{{sensitive_ip_targets}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR '{{sensitive_ip_targets}}' = '') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## agent-full-chain-triage
<!-- Final multi-stage chain correlation -->
```agent target=hunter
cite: required
context:
- agent-early-takeover-triage
- portable-node-prevalence
- winrm-lateral-expansion
max_iterations: 5
objective: Determine if any host identified as suspicious in the early triage also
  displays rare Node.js runtimes and WinRM lateral movement.
success_criteria: A final verdict of malicious for hosts matching the CaptiveCrunch
  behavioral pattern.
tools:
- endpoint
- network
```

## route-on-full-verdict
<!-- Route on attack chain confirmation -->
if~: "the final triage verdict is malicious for at least one host, linking remote-support takeover to lateral movement" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-forensic-task
unavailable: → analyst-forensic-task (blind_spot: no-winrm-command-logging)
else: → close-out-hunt

## isolate-endpoint
<!-- Isolate compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the triage verdict. Revoke any active sessions for the user(s) associated with the remote-support takeover.
```
→ analyst-forensic-task

## analyst-forensic-task
<!-- Analyst forensic and AD review -->
```manual target=analyst
Review WinRM logs (Event ID 91) on the targeted Domain Controllers to identify executed commands. Search for any new MSI installations or portable node.exe binaries on those systems.
```
→ close-out-hunt

## close-out-hunt
<!-- Hunt closure and documentation -->
```manual target=analyst
Record the hosts examined and the final verdicts. If legitimate remote support was found but used as a vector, recommend tighter ASR rules.
```
→ end
