---
analysis: A simple rule might alert on PowerShell launching from Chrome, but this
  hunt pivots to script content and uses stack-counting on HTTP traffic to identify
  rare domains that likely represent C2 or squatting infrastructure invented by LLMs.
blind_spots:
- id: no-script-logging
  question: What specific code was executed when a user pasted a command into the
    terminal?
  requires: hb_script_activity (PowerShell Script Block Logging / Windows Event ID
    4104)
  risk: Without script logging, the hunt can identify that a terminal was launched,
    but cannot see the deobfuscated commands used for persistence or exfiltration.
  stage: execution-indirect-prompt-injection
- id: ual-retention
  question: When was the malicious skill first consented to?
  requires: hb_cloud_api_activity (Unified Audit Log)
  risk: If the consent happened outside the retention window (typically 90 days),
    the initial access event will be invisible.
  stage: initial-access-malicious-ai-skills
coverage:
- stage: phishing-ai-enhanced-social-engineering
  status: covered
  steps:
  - clickfix-terminal-activity
- stage: initial-access-malicious-ai-skills
  status: covered
  steps:
  - m365-ai-app-consents
- stage: exploit-public-facing-rapid-cve
  status: covered
  steps:
  - scoping-vulnerable-hosts
- stage: execution-indirect-prompt-injection
  status: covered
  steps:
  - script-execution-content
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: credential-access-password-stores
  status: out_of_scope
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: evasion-vulnerable-driver-edr-killer
  status: out_of_scope
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: impact-ransomware-data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI-enhanced phishing and social engineering (ClickFix) are reaching
    high click-through rates. Detecting these before they result in full ransomware
    deployment or data theft is a critical operational need for resource-strapped
    SMBs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access by using AI-generated phishing
  lures, malicious AI skills, or ClickFix social engineering where users paste malicious
  terminal commands.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1190
- attack.t1203
- credential access
- defense evasion
- execution
- impact
- initial access
- m365
name: AI Agent and Social Engineering Initial Access
parameters:
  browser_parents:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    description: Browser process names that should not typically be direct parents
      of terminals.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt; leave empty for fleet-wide.
    type: list[host]
  terminal_processes:
    default:
    - powershell.exe
    - pwsh.exe
    - cmd.exe
    - bash
    - sh
    description: Process names for terminal environments commonly abused in ClickFix.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/smb-cybersecurity-squeeze-ai-agents-work-old-attacks-overdrive/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing web servers and hosts identified with critical
  vulnerabilities. Monitor users with high-privilege access to M365 who may be targeted
  for AI skill rug pull attacks.
references:
- name: 'The SMB cybersecurity squeeze: AI agents at work, old attacks in overdrive'
  url: https://www.welivesecurity.com/en/business-security/smb-cybersecurity-squeeze-ai-agents-work-old-attacks-overdrive/
related:
- hunt: credential-access-password-stores
  reason: Password storage theft is a post-compromise activity that follows the initial
    access hunted here.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Enhanced Phishing and ClickFix
    observables:
    - QR codes in phishing emails
    - Fake AI troubleshooting error messages
    - AI-generated lures with high click-through rates
    - ClickFix prompts asking users to paste commands
    slug: phishing-ai-enhanced-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: AI Agent Supply Chain Compromise
    observables:
    - Installation of malicious 'skills' from public repositories
    - Malicious MCP (Model Context Protocol) server connections
    - AI agent 'rug pull' behavior where a tool morphs into an infostealer
    slug: initial-access-malicious-ai-skills
    tactic: initial-access
    techniques:
    - T1195
  - name: Rapid Vulnerability Exploitation
    observables:
    - Exploitation of known vulnerabilities on or before disclosure day
    - Scanning for vulnerable software libraries invented by LLM hallucinations
    slug: exploit-public-facing-rapid-cve
    tactic: initial-access
    techniques:
    - T1190
  - name: Indirect Prompt Injection and Terminal Execution
    observables:
    - EchoLeak-style data exposure in Microsoft 365 Copilot
    - Users pasting commands into terminals following ClickFix lures
    - Malicious instructions retrieved by agents from webpages or emails
    slug: execution-indirect-prompt-injection
    tactic: execution
    techniques:
    - T1203
  - name: Credential Theft via Infostealer
    observables:
    - Access to browser password databases
    - Phishing-as-a-service kits capturing login credentials
    - Infostealer malware execution
    slug: credential-access-password-stores
    tactic: credential-access
    techniques:
    - T1555
  - name: EDR Impairment via Vulnerable Drivers
    observables:
    - Loading of known vulnerable drivers (BYOVD)
    - Tools designed to kill EDR processes
    - Abuse of legitimate drivers to gain kernel-level access
    slug: evasion-vulnerable-driver-edr-killer
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Data Encryption and Exfiltration
    observables:
    - PromptLock ransomware execution
    - Encryption of files on local or shared drives
    - Exfiltration of sensitive data via AI agent tools
    - C2 traffic to attacker-controlled domains
    slug: impact-ransomware-data-exfiltration
    tactic: impact
    techniques:
    - T1486
    - T1041
  summary: AI agents are being compromised via malicious supply chain skills and indirect
    prompt injection, while traditional threats like phishing and vulnerability exploitation
    are accelerated by AI-driven automation. Adversaries are increasingly using 'Bring
    Your Own Vulnerable Driver' (BYOVD) techniques to disable EDR tools before deploying
    ransomware or exfiltrating credentials.
series:
  index: 1
  slug: the-smb-cybersecurity-squeeze-ai-agents-at-work-old-attacks-in-overdrive
  title: 'The SMB cybersecurity squeeze: AI agents at work, old attacks in overdrive'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI Agent and Social Engineering Initial Access

This hunt follows a phased flow to detect AI-enhanced initial access. It first identifies vulnerable hosts and monitors for signs of user-driven command execution (ClickFix) or unauthorized AI agent registrations in M365. An early-stage agent weighs these indicators before fanning out to examine the specific script content and outbound network traffic for signs of successful exploitation and command-and-control. This approach targets the lethal trifecta of agentic security: data access, external exposure, and communication permissions.

## scoping-vulnerable-hosts
<!-- Identify hosts with critical vulnerabilities -->
Scope the hunt by identifying hosts with high-severity vulnerabilities that are candidates for rapid exploitation, joining with hb_devices to provide hostnames for filtering.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames and their high-severity vulnerabilities. Silence implies
  no critical unpatched vulnerabilities are known to the scanner.
reads:
- device_uid
- cve_uid
- affected_package_name
- affected_package_version
- severity_id
- status
- provider
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT d.hostname AS device_hostname, v.cve_uid, v.affected_package_name, v.affected_package_version, v.severity_id FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE v.severity_id >= 4 AND v.status != 'suppressed' AND d.provider = v.provider
```

## early-access-leads
<!-- Monitor for terminal execution and AI agent registration -->
parallel:
- → clickfix-terminal-activity
- → m365-ai-app-consents
join: → early-stage-read

## clickfix-terminal-activity
<!-- Detect terminals launched with browser parents -->
Identify ClickFix social engineering where a user pastes a command following a browser prompt.

```sqlite target=endpoint role=detection-candidate params=(terminal_processes=terminal_processes, browser_parents=browser_parents, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A terminal process spawned directly by a web browser. Silence is expected
  in a healthy environment.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE instr(',' || '{{terminal_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND instr(',' || '{{browser_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## m365-ai-app-consents
<!-- Identify new M365 AI application and skill consents -->
Find M365 Unified Audit Log events for application consents that may represent malicious AI skills.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Users granting permissions to AI-related applications or skills. This can
  identify the rug pull supply chain compromise.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
- provider
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (api_operation = 'ConsentToApplication' OR api_operation = 'Add app role assignment') AND (LOWER(resource_name) LIKE '%ai%' OR LOWER(resource_name) LIKE '%bot%' OR LOWER(resource_name) LIKE '%copilot%' OR LOWER(resource_name) LIKE '%skill%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-read
<!-- Weigh early-stage evidence -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-hosts
- clickfix-terminal-activity
- m365-ai-app-consents
max_iterations: 3
objective: Determine if the process and cloud activities indicate a credible initial
  access attempt via social engineering or AI supply chain compromise.
success_criteria: Verdicts (malicious | suspicious | benign) for each host and user
  identified in the leads.
tools:
- endpoint
- web
```

## follow-on-activity
<!-- Hunt for script execution and outbound C2 -->
parallel:
- → script-execution-content
- → outbound-http-prevalence
join: → follow-on-read

## script-execution-content
<!-- Examine script block content for malicious indicators -->
Review the actual commands executed in terminal sessions, looking for ClickFix commands or data retrieval script blocks.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Scripts that interact with the clipboard or perform remote downloads, typical
  of ClickFix lures.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (script_content LIKE '%Get-Clipboard%' OR script_content LIKE '%IEX%' OR script_content LIKE '%Invoke-Expression%' OR script_content LIKE '%curl%' OR script_content LIKE '%wget%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## outbound-http-prevalence
<!-- Identify rare outbound HTTP domains -->
Stack-count outbound domain resolutions to find rare C2 domains or squatting domains invented by LLM hallucinations, focusing on suspect hosts.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare domains contacted by a small number of hosts. These often represent
  attacker-controlled infrastructure.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- url_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT url_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## follow-on-read
<!-- Final compromise assessment -->
```agent target=hunter
cite: required
context:
- early-stage-read
- script-execution-content
- outbound-http-prevalence
max_iterations: 5
objective: Confirm whether the early-stage leads resulted in successful execution
  or data exfiltration based on the script and HTTP activity.
success_criteria: A final verdict citing specific script commands and rare domain
  connections.
tools:
- endpoint
- web
```

## compromise-decision
<!-- Route on compromise verdict -->
if~: "The final compromise assessment indicates a malicious verdict with evidence of terminal execution or data exfiltration." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-script-logging)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke any M365 session tokens associated with users identified in the cloud audit logs.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Examine the script_content from hb_script_activity for the confirmed hosts. Verify the legitimacy of the rare domains identified. Check for signs of lateral movement originating from the beachhead.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings. If suspicious ClickFix patterns were found but not confirmed, consider a user awareness training session. Tune detection rules if any benign browser-to-terminal patterns were seen.
```
→ end
