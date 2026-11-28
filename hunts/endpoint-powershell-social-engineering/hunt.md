---
analysis: A simple detection rule for PowerShell launched from Explorer is extremely
  noisy due to administrative activity. This hunt provides context by stack-counting
  command lines for rarity, inspecting full script blocks, and correlating with DNS
  lookups to phishing domains within a tight temporal window.
blind_spots:
- id: missing-registry-telemetry
  question: Did the PowerShell process interact with the clipboard to receive the
    command?
  requires: Registry value-set events for the user's Explorer RunMRU key in hb_registry_activity (for example Sysmon event 13 or an EDR registry feed)
  risk: Without this audit, the 'pasting' aspect cannot be verified, leaving only
    the process parent and script content for analysis.
  stage: clickfix-powershell-execution
- id: obfuscated-script-blocks
  question: What was the intent of the executed PowerShell script?
  requires: PowerShell Script Block Logging (Event 4104)
  risk: If the command line is obfuscated and script block logging is disabled, the
    specific exfiltration logic remains invisible.
  stage: clickfix-powershell-execution
coverage:
- stage: phishing-social-engineering
  status: covered
  steps:
  - phishing-dns-activity
- stage: clickfix-powershell-execution
  status: covered
  steps:
  - powershell-via-run-dialog
  - script-block-content
  - run-dialog-history
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: token-theft-session-impersonation
  status: out_of_scope
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: mfa-registration-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: app-registration-secret-creation
  status: out_of_scope
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: cloud-role-privilege-escalation
  status: out_of_scope
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: device-code-flow-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Social engineering attacks like ClickFix bypass technical MFA controls
    by tricking the user into running local commands. This hunt identifies the execution
    of those commands on the endpoint, providing a critical lead before the stolen
    tokens are used to compromise cloud environments.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has tricked a user into running a malicious PowerShell command
  via the Windows Run dialog by mimicking a CAPTCHA on a look-alike SharePoint site
  to exfiltrate session tokens.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1204.004
- defense evasion
- execution
- initial access
- persistence
- privilege escalation
name: Endpoint PowerShell Execution via Social Engineering
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default: []
    description: Look-alike SharePoint and Microsoft 365 domains you have seen, for example from your mail gateway. The source research names none; the step also flags SharePoint look-alikes on its own.
    type: list[domain]
  scope_hosts:
    default: []
    description: Filter results to these hostnames; leave empty to examine the whole
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/three-attacks-zero-exploits-microsoft-365
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The lead query is focused on standard user workstations where Explorer-to-PowerShell
  execution is most likely to be a result of social engineering rather than administrative
  work.
references:
- name: "Huntress \u2014 Three Attacks, Zero Exploits in Microsoft 365"
  url: https://www.huntress.com/blog/three-attacks-zero-exploits-microsoft-365
related:
- hunt: token-theft-session-impersonation
  reason: This hunt focuses on the initial endpoint execution; monitoring the subsequent
    use of stolen tokens requires analyzing cloud API logs separately.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering Phishing
    observables:
    - Email subjects regarding holiday policy updates
    - Look-alike SharePoint domains
    - Short codes (Netflix-style) for device login
    slug: phishing-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: ClickFix PowerShell Execution
    observables:
    - powershell.exe
    - Windows key + R (Run dialog) instructions
    - Clipboard manipulation via fake CAPTCHA 'prove you are not a robot'
    - PowerShell commands designed to export session cookies
    slug: clickfix-powershell-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1204.004
  - name: Session Hijacking via Token Theft
    observables:
    - Cookie Editor browser extension
    - Access to Outlook from unexpected IP addresses with existing session cookies
    - Successful sign-ins bypassing MFA using stolen tokens
    slug: token-theft-session-impersonation
    tactic: defense-evasion
    techniques:
    - T1539
  - name: Attacker MFA Registration
    observables:
    - Registration of new MFA methods (phone numbers or authenticators) by a recently
      compromised account
    - Entra ID audit events for MFA device changes
    slug: mfa-registration-persistence
    tactic: persistence
    techniques:
    - T1098
  - name: App Registration Secret Manipulation
    observables:
    - New secrets created for existing App Registrations
    - Secrets with long lifespans (e.g., 2 years)
    - Standard user accounts interacting with the Azure management portal/Entra app
      registrations
    slug: app-registration-secret-creation
    tactic: persistence
    techniques:
    - T1098
  - name: Privilege Escalation via Over-Permissioned Apps
    observables:
    - Apps with 'RoleManagement.ReadWrite.Directory' permissions
    - n8n workflow automation tool usage
    - Assignment of Global Administrator role to a compromised user via an application
      principal
    slug: cloud-role-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1078.004
  - name: Device Code Flow Hijacking
    observables:
    - Logins via microsoft.com/devicelogin
    - Device code flow used for browser-based session capture
    - Unusual UserAgents or client applications requesting device codes
    slug: device-code-flow-hijacking
    tactic: initial-access
    techniques:
    - T1566
  summary: Attackers target Microsoft 365 environments using social engineering tactics
    like ClickFix and Device Code phishing to bypass MFA or capture session tokens.
    Once inside, they exploit over-permissioned applications and register new MFA
    methods to persist and escalate privileges to Global Administrator.
series:
  index: 1
  slug: three-attacks-zero-exploits-in-microsoft-365
  title: Three Attacks, Zero Exploits in Microsoft 365
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


# Endpoint PowerShell Execution via Social Engineering

This hunt identifies ClickFix tradecraft where social engineering bypasses technical controls by convincing users to manually execute code. It identifies rare PowerShell commands launched directly from Windows Explorer (the parent of the Run dialog), retrieves the full script block content to inspect for obfuscation, and correlates these events with DNS lookups to phishing domains within a tight temporal window. An agent weighs the combined evidence of rarity, phishing navigation, and Run dialog history to identify successful session hijacking.

## powershell-via-run-dialog
<!-- Rare PowerShell launched via Run dialog -->
Find rare instances of PowerShell starting from Windows Explorer, which is the parent process for commands launched via the Win+R Run dialog. This step performs prevalence counting to filter out common administrative noise.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique command lines launched from the Run dialog. Legitimate admin activity
  typically clusters across several hosts, whereas ClickFix payloads are often host-specific
  or rare.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- parent_process_name
- process_name
- user_name
- pid
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT process_cmd_line, device_hostname, user_name, pid, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\\explorer.exe' AND LOWER(process_name) LIKE '%\\powershell.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING COUNT(DISTINCT device_hostname) <= 3
```

## corroborate-execution
<!-- Corroborate script content and phishing activity -->
parallel:
- → script-block-content
- → phishing-dns-activity
- → run-dialog-history
join: → triage-agent

## script-block-content
<!-- PowerShell script block content -->
Retrieve full PowerShell script block text to identify obfuscation or session cookie extraction logic that may not be visible in truncated process command lines.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell script blocks containing session or cookie keywords, web client
  calls, or encoded payloads.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT device_hostname, script_content, script_path, time FROM hb_script_activity WHERE script_type = 'PowerShell' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## phishing-dns-activity
<!-- DNS activity for phishing domains -->
Find DNS lookups to look-alike domains. The results allow the agent to verify if these occurred within a 10-minute window prior to the PowerShell execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Any resolution of look-alike domains around the time of the lead execution.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LOWER(query_hostname) LIKE '%sharepoint%' AND LOWER(query_hostname) NOT LIKE '%.sharepoint.com')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## run-dialog-history
<!-- Run dialog command history -->
Read what was pasted into the Windows Run dialog. Windows keeps each Run command in the user's RunMRU registry key, so a PowerShell, mshta or curl one-liner there is the ClickFix delivery itself, even after the process has exited.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing PowerShell processes interacting with the clipboard. While
  common for some utilities, in the context of ClickFix it confirms the delivery mechanism.
reads:
- device_hostname
- actor_user_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT device_hostname, actor_user_name, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\explorer\\runmru%' AND (LOWER(reg_value_data) LIKE '%powershell%' OR LOWER(reg_value_data) LIKE '%pwsh%' OR LOWER(reg_value_data) LIKE '%mshta%' OR LOWER(reg_value_data) LIKE '%curl%' OR LOWER(reg_value_data) LIKE '%-enc%' OR LOWER(reg_value_data) LIKE '%iex%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh ClickFix evidence -->
```agent target=hunter
cite: required
context:
- powershell-via-run-dialog
- script-block-content
- phishing-dns-activity
- run-dialog-history
max_iterations: 6
objective: Determine if the rare PowerShell activity on each host is a result of a
  ClickFix attack. Specifically, check if a DNS lookup to a phishing domain occurred
  within 10 minutes prior to the PowerShell execution on the same host, and if the
  script content contains session theft or obfuscated commands.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  rows and temporal correlation notes.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on temporal matching of phishing navigation and rare script execution" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-registry-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Revoke all active Microsoft 365 sessions and Entra ID tokens for the affected user immediately.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage verdict. Examine the script content for exfiltration destinations. Check cloud audit logs (hb_cloud_api_activity) for logins using the stolen tokens from the time of the PowerShell execution.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Log the result. If new phishing domains were found, add them to the phishing_domains parameter for future runs.
```
→ end
