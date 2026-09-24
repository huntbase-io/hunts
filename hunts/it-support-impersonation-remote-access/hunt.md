---
analysis: A static rule for RMM tools triggers too many false positives. This hunt
  uses external collaboration as a lead and applies a prevalence baseline across the
  estate to find the specific tool instance an attacker selected, which a single rule
  cannot do.
blind_spots:
- id: vishing-audio-blindspot
  owner: Collaboration Engineering
  question: whether the lure was delivered entirely via voice rather than chat
  remediation: Enable recording for external tenant calls if corporate policy allows,
    or rely on user reporting.
  requires: Teams voice call recording or transcripts
  risk: Lures delivered through voice leave no text-based log of the impersonation
    attempt, making the initial link to the RMM session harder to prove.
  stage: initial-access-teams-vishing
- id: ephemeral-rmm-session
  owner: Network Engineering
  question: whether an RMM tool successfully contacted a controller
  remediation: Ensure egress logs for RMM ports are retained and correctly attributed
    to process owners.
  requires: hb_network_connection with process mapping
  risk: A process that starts and fails to connect may look identical to a successful
    session in process logs; network telemetry confirms if hands-on activity actually
    occurred.
coverage:
- stage: initial-access-teams-vishing
  status: covered
  steps:
  - teams-external-auth
  - rare-rmm-execution
  - rmm-shell-spawns
- reason: Belongs to the follow-on hunt focusing on MSI loaders and Node.js execution.
  stage: remote-session-msi-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: nodejs-implant-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: c2-recon-and-tasking
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: lateral-movement-winrm
  status: out_of_scope
- reason: 'Belongs to another part of the ''Impersonating IT support: how threat actors
    turn a remote session into enterprise-wide access'' series.'
  stage: execution-rundll32-dlls
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are bypassing email security by using trusted collaboration
    platforms to bridge into interactive endpoint access. A negative result validates
    current external collaboration controls and user awareness.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has gained interactive access by impersonating IT support
  via Microsoft Teams, coaxing a user into initiating an RMM session that bypasses
  standard perimeter controls.
labels:
- hunt
- attack.t1566.003
- attack.t1059.001
- attack.t1071
- attack.t1218.011
name: IT Support Impersonation and Remote Access
parameters:
  internal_domains:
    default:
    - example.com
    description: The organization's own domains; used to exclude internal collaboration
      from scoping.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-lookback
    type: number
  rmm_processes:
    default:
    - quickassist.exe
    - remotehelp.exe
    - anydesk.exe
    - teamviewer.exe
    - connectwise.exe
    - screenconnect.exe
    - logmein.exe
    - aeroadmin.exe
    description: Legitimate remote management tool process names to monitor.
    from:
      kind: article
      observed: '2026-09-02'
      ref: msrc-blog
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames to narrow the search; empty searches the whole
      estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-pivoting
    type: list[host]
  shell_processes:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - wscript.exe
    - cscript.exe
    description: Interpreters used by attackers for hands-on activity.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: general-threat-intelligence
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with successful external Teams authentications (hb_auth_signin).
  Focus on users who do not normally collaborate with external technical tenants.
  Use identified hostnames to narrow the rmm_processes search.
references:
- name: "Microsoft Threat Intelligence \u2014 Impersonating IT support: how threat\
    \ actors turn a remote session into enterprise-wide access"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: nodejs-implant-persistence
  reason: Once an interactive session is established, attackers deploy a Node.js implant
    for persistence; that behavior is out of scope here.
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
  index: 1
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# IT Support Impersonation and Remote Access

This hunt identifies the early stages of a social engineering campaign where threat actors abuse Microsoft Teams external collaboration to impersonate helpdesk personnel. The attack relies on the user voluntarily granting remote access through tools like Quick Assist or AnyDesk. The hunt begins by identifying anomalous external authentication events in Teams, then forks to identify rare RMM tool usage across the fleet and behavioral leads such as shells spawning directly from those support tools. An agent weighs the timing and prevalence of these events per host to identify the human-interactive bridge before persistent implants are deployed.

## teams-external-auth
<!-- External Teams authentication leads -->
Identify successful sign-ins to Microsoft Teams from external domains which may indicate the point of first contact from an impersonator.

```sqlite target=identity role=scoping params=(internal_domains=internal_domains, lookback_days=lookback_days)
~~~yaml
expected: Auth events from external domains. While many are legitimate guests, an
  event followed by RMM activity for that same user profile is a high-fidelity lead.
reads:
- actor_user_name
- actor_user_domain
- src_endpoint_ip
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT actor_user_name, actor_user_domain, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE provider = 'm365' AND status_id = 1 AND (LOWER(dst_endpoint_name) LIKE '%teams%' OR LOWER(activity_name) LIKE '%teams%') AND NOT instr(',' || '{{internal_domains}}' || ',', ',' || LOWER(actor_user_domain) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-session-investigation
<!-- Parallel session investigation -->
parallel:
- → rare-rmm-execution
- → rmm-shell-spawns
join: → triage-agent

## rare-rmm-execution
<!-- Rare RMM tool execution -->
Stack-count RMM tools to find specific instances that are anomalous for the environment or scoped hosts.

```sqlite target=endpoint role=baseline params=(rmm_processes=rmm_processes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare RMM tools. Common corporate support tools will show many hosts; attacker-favored
  tools like Quick Assist on non-standard hosts will stand out.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT LOWER(process_name) AS rmm_tool, COUNT(DISTINCT device_hostname) AS host_count, GROUP_CONCAT(DISTINCT device_hostname) AS hosts FROM hb_process_activity WHERE instr(',' || '{{rmm_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING host_count <= 5 ORDER BY host_count ASC
```

## rmm-shell-spawns
<!-- Shell spawns from RMM tools -->
Identify administrative shells originating from RMM processes, signifying hands-on-keyboard activity.

```sqlite target=endpoint role=detection-candidate params=(shell_processes=shell_processes, rmm_processes=rmm_processes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Shell processes whose parent is a legitimate RMM tool. This indicates an
  external operator is actively running commands on the endpoint.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE instr(',' || '{{shell_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND instr(',' || '{{rmm_processes}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage session evidence -->
```agent target=hunter
cite: required
context:
- teams-external-auth
- rare-rmm-execution
- rmm-shell-spawns
max_iterations: 6
objective: Determine if any host shows a sequence of external Teams authentication
  followed by the execution of a rare RMM tool and subsequent shell activity within
  the same hour. Cite specific rows for all three steps.
success_criteria: A per-host verdict of malicious | suspicious | benign with cited
  times and command lines.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on the auth-to-RMM-to-shell chain" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → review-teams-logs
unavailable: → review-teams-logs (blind_spot: vishing-audio-blindspot)
else: → review-teams-logs

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke the user's M365/Teams session to prevent further external chat interaction.
```
→ review-teams-logs

## review-teams-logs
<!-- Review Teams chat and lure logs -->
```manual target=analyst
Examine Teams chat logs for messages from the identified external domain. Look for requests to run Quick Assist or instructions to read back codes. If vishing is suspected, interview the user to confirm if they received a voice call alongside the chat.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt summary and close-out -->
```manual target=analyst
Record the outcome. If a new RMM tool was used, update the rmm_processes parameter for future runs. Report any lack of Teams external-call logging to the platform team.
```
→ end
