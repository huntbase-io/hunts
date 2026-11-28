---
analysis: A simple rule for unsigned drivers would fire too often on development tools.
  This hunt combines that signal with the lead (credential theft) and the aftermath
  (mass file activity) to provide the necessary context for high-confidence host isolation.
blind_spots:
- id: kernel-visibility-gap
  question: Was every driver load event captured and signature verified?
  requires: hb_kernel_extension_activity with consistent cross-platform signature
    status
  risk: Some EDR versions may fail to report kernel loads once they are actively being
    impaired, leading to a silent failure in the hunt.
  stage: evasion-vulnerable-driver-edr-killer
- id: process-on-disk-evasion
  question: Was the infostealer running purely in memory?
  requires: hb_process_activity with on_disk = 0 tracking
  risk: If an infostealer is injected into a legitimate process, the file activity
    lead might only attribute the access to the legitimate process name.
  stage: credential-access-password-stores
coverage:
- stage: credential-access-password-stores
  status: covered
  steps:
  - credential-store-access
- stage: evasion-vulnerable-driver-edr-killer
  status: covered
  steps:
  - driver-load-check
- stage: impact-ransomware-data-exfiltration
  status: covered
  steps:
  - high-volume-file-activity
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: phishing-ai-enhanced-social-engineering
  status: out_of_scope
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: initial-access-malicious-ai-skills
  status: out_of_scope
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: exploit-public-facing-rapid-cve
  status: out_of_scope
- reason: 'Belongs to another part of the ''The SMB cybersecurity squeeze: AI agents
    at work, old attacks in overdrive'' series.'
  stage: execution-indirect-prompt-injection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ransomware remains the highest risk to SMBs, and 'BYOVD' (Bring Your
    Own Vulnerable Driver) is a primary method used to disable the protection these
    companies rely on. This hunt catches the transition from theft to impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is stealing credentials from browser stores and attempting
  to disable security controls using vulnerable drivers before launching a high-volume
  ransomware or exfiltration attack.
labels:
- hunt
- attack.t1555
- attack.t1562.001
- attack.t1486
- attack.t1041
- credential access
- defense evasion
- execution
- impact
- initial access
name: EDR Impairment and Ransomware Impact
parameters:
  credential_files:
    default:
    - login data
    - cookies
    - logins.json
    - key4.db
    description: Browser credential and session filenames targeted by infostealers.
    from:
      kind: article
      observed: '2026-09-21'
      ref: eset-smb-2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-hunt-period
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the lead query to narrow subsequent
      searches.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-pivot
    type: list[host]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The lead query identifies hosts where non-browser processes access browser
  credential stores. These hosts should be provided in the scope_hosts parameter for
  the parallel checks to focus on likely compromised endpoints.
references:
- name: 'The SMB cybersecurity squeeze: AI agents at work, old attacks in overdrive'
  url: https://www.welivesecurity.com/en/business-security/smb-cybersecurity-squeeze-ai-agents-work-old-attacks-overdrive/
related:
- hunt: phishing-ai-enhanced-social-engineering
  reason: The initial access via AI-enhanced phishing is handled in a separate hunt
    in this series.
  relation: out-of-scope-alternative
- hunt: ai-agent-social-engineering-access
  relation: follows
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
  index: 2
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
tlp: clear
type: investigation
---


# EDR Impairment and Ransomware Impact

This hunt targets the late-stage progression of an intrusion in an SMB environment. It starts by identifying suspicious access to browser credential stores, then fans out to detect the loading of unsigned or revoked kernel drivers used for EDR impairment. Simultaneously, it baselines file activity to find rare processes performing mass encryption or renaming. An agent weighs these signals to identify coordinated impact attempts.

## credential-store-access
<!-- Suspicious access to browser credential stores -->
Identify potential infostealer activity by finding non-browser processes reading password files.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, credential_files=credential_files)
~~~yaml
expected: Rows show processes like cmd.exe or unknown binaries reading browser databases.
  Silence suggests no such direct access was recorded.
reads:
- activity_id
- actor_user_name
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, process_name, file_name, file_path, time FROM hb_file_activity WHERE instr(',' || '{{credential_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND activity_id = 2 AND (LOWER(process_name) NOT LIKE '%\\chrome.exe' AND LOWER(process_name) NOT LIKE '%\\msedge.exe' AND LOWER(process_name) NOT LIKE '%\\firefox.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-check
<!-- Check for EDR killer drivers and mass file impact -->
parallel:
- → driver-load-check
- → high-volume-file-activity
join: → triage-impact

## driver-load-check
<!-- Unsigned or suspicious driver loading -->
Detect the BYOVD technique used to kill security software by loading vulnerable drivers.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of unsigned or untrusted drivers. Silence is a strong indicator that
  no standard BYOVD tool was loaded.
reads:
- device_hostname
- driver_path
- driver_signature_status
- driver_signature_subject
- driver_signed
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, driver_path, driver_signature_subject, driver_signed, time FROM hb_kernel_extension_activity WHERE (driver_signed = 'false' OR LOWER(driver_signature_status) != 'valid') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## high-volume-file-activity
<!-- Rare processes with high modification volume -->
Identify the final ransomware or exfiltration stage where a rare process touches many files.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process rare across the fleet modifying a large number of files on a single
  host. Silence means no mass modification occurred during the window.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 4
reads:
- activity_id
- device_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS total_events, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id IN (3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING hosts <= 3 AND total_events > 50 ORDER BY hosts ASC
```

## triage-impact
<!-- Weigh evidence of impairment and impact -->
```agent target=hunter
cite: required
context:
- credential-store-access
- driver-load-check
- high-volume-file-activity
max_iterations: 4
objective: Determine if any host shows a sequence of credential theft followed by
  suspicious driver loading and finally high-volume file modifications. Cite the specific
  process names and driver paths found in all three steps.
success_criteria: A malicious | suspicious | benign verdict per host with supporting
  row citations.
tools:
- endpoint
```

## route-verdict
<!-- Route based on agent verdict -->
if~: "the triage verdict is malicious for at least one host involving driver loading and mass file activity" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: kernel-visibility-gap)
else: → forensic-review

## isolate-endpoint
<!-- Isolate impacted endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR console. Preserve the endpoint state for forensic memory collection, focusing on the malicious driver.
```
→ forensic-review

## forensic-review
<!-- Manual forensic review -->
```manual target=analyst
Review the cited driver paths and file activities. Check the process_cmd_line for the processes touching credential stores to find where they were launched from.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout and documentation -->
```manual target=analyst
Record the findings. If driver loading was not visible on some OS versions, document this as a telemetry gap for the platform team.
```
→ end
