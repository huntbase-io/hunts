---
analysis: A simple rule on 'curl | sh' is often too noisy for developer environments.
  This hunt uses a gated flow to correlate DNS-based redirection with rare persistence
  and specific sensitive file access, providing the context needed for high-confidence
  triage.
blind_spots:
- id: no-agent-coverage
  question: Are there hosts missing telemetry for DNS or process activity?
  requires: endpoint agent on all systems
  risk: A host without an agent resolves the domain but remains invisible to forensics.
- id: clipboard-content-visibility
  question: What was the exact text the user copied from the AI platform?
  requires: clipboard monitoring logs
  risk: The hunt sees the execution but not the specific 'Apple Support' or 'Claude
    Cowork' lure that prompted it.
  stage: clipboard-command-execution
- id: encrypted-dns
  question: Was the redirect domain resolved via DoH (DNS over HTTPS)?
  requires: TLS inspection or proxy logs
  risk: If the agent cannot intercept encrypted DNS, the initial lead may be missed.
coverage:
- stage: clipboard-command-execution
  status: covered
  steps:
  - clipboard-execution
- stage: stealer-persistence
  status: covered
  steps:
  - rare-scheduled-persistence
- stage: sensitive-data-access
  status: covered
  steps:
  - credential-theft-evidence
- reason: This stage occurs on the search engine and browser before endpoint behavior
    begins.
  stage: initial-access-seo-redirection
  status: out_of_scope
- reason: Payload delivery is observed as the redirect DNS and resulting terminal
    command.
  stage: malicious-payload-delivery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are weaponizing the trust inherent in AI platforms
    to deliver malware. Confirming that users have not executed commands from these
    emerging impersonation vectors is a high-priority exposure check.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses a trusted AI platform to trick a user into executing
  a terminal command from the clipboard, establishing persistence and stealing credentials.
labels:
- hunt
- attack.t1059.001
- attack.t1059.004
- attack.t1053.005
- attack.t1555
- attack.t1539
- attack.t1552
name: AI-Impersonation Driven Script Execution and Data Theft
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  redirect_domains:
    default:
    - downloading-api.it.com
    description: Malicious redirect domains observed in AI-lure campaigns.
    from:
      kind: article
      observed: '2026-08-27'
      ref: huntress-ai-attack-surface
    type: list[domain]
  scope_hosts:
    default: []
    description: Limit forensics to these hosts; usually the output of the DNS lead
      step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ai-attack-surface
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The lead query identifies users interacting with known redirect infrastructure.
  Forensics are then narrowed to those hosts to reduce noise from developers using
  similar terminal patterns.
references:
- name: 'The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms'
  url: https://www.huntress.com/blog/ai-attack-surface
related:
- hunt: ai-platform-mediated-malvertising-redirection
  relation: follows
scenario:
  stages:
  - name: AI Platform SEO Redirection
    observables:
    - claude.ai
    - chatgpt.com
    - grok.com
    - claude.ai/share
    - sponsored search results
    - Bing
    - Google Search
    slug: initial-access-seo-redirection
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.001
  - name: AI-Themed Payload Delivery
    observables:
    - downloading-api.it.com
    - ClaudeDesktop.exe
    slug: malicious-payload-delivery
    tactic: execution
    techniques:
    - T1204.001
  - name: Terminal and PowerShell Execution
    observables:
    - curl
    - powershell
    - zsh
    - bash
    - Terminal
    - Apple Support install guide lure
    - Clear disk space lure
    slug: clipboard-command-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1059.004
  - name: Malware Persistence
    observables:
    - new scheduled tasks
    - SectopRAT
    - AMOS
    - MacSync
    slug: stealer-persistence
    tactic: persistence
    techniques:
    - T1053.005
  - name: Credential and Secret Theft
    observables:
    - ~/.ssh
    - ~/.aws
    - ~/Library/Keychains
    - browser cookies
    - Telegram sessions
    slug: sensitive-data-access
    tactic: credential-access
    techniques:
    - T1555
    - T1539
    - T1552
  summary: Threat actors are utilizing SEO poisoning to lure victims into interacting
    with malicious artifacts and shared conversations on trusted AI platforms like
    Claude, ChatGPT, and Grok. These interactions lead to either the download of fake
    installers from malicious redirect domains or the execution of commands via Terminal
    and PowerShell that deploy credential stealers. The resulting malware, such as
    AMOS and MacSync, establishes persistence via scheduled tasks and exfiltrates
    sensitive credentials, cloud keys, and browser data.
series:
  index: 2
  slug: the-ai-attack-surface-how-threat-actors-abuse-trusted-ai-platforms
  title: 'The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms'
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


# AI-Impersonation Driven Script Execution and Data Theft

This hunt identifies 'ClickFix' attacks where victims follow malicious instructions from shared AI conversations or artifacts. The attacker uses the inherent trust in platforms like Claude and ChatGPT to bypass search safety, delivering commands that download stealers like AMOS or MacSync. The flow uses a gated approach: a cheap lead query identifies interaction with known redirect domains before opening forensic queries that examine terminal execution, rare scheduled jobs, and sensitive file access.

## dns-to-redirect
<!-- DNS to AI-lure redirect domains -->
Find any host resolving known malicious domains used as redirects from legitimate AI artifacts.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, redirect_domains=redirect_domains)
~~~yaml
expected: A hit indicates a user clicked a link within an AI platform; silence suggests
  no interaction with known indicators in this window.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{redirect_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-dns-lead
<!-- Evaluate DNS lead -->
```agent target=hunter
cite: required
context:
- dns-to-redirect
max_iterations: 3
objective: Determine if the DNS activity indicates a suspicious redirect from an AI
  platform.
success_criteria: A suspicious or benign verdict per host citing the resolution event.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate forensics on DNS lead -->
if~: "the evaluate-dns-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-forensics
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: no-agent-coverage)
else: → close-out

## parallel-forensics
<!-- Gather forensics side by side -->
parallel:
- → clipboard-execution
- → rare-scheduled-persistence
- → credential-theft-evidence
join: → kill-chain-triage

## clipboard-execution
<!-- Suspicious shell execution patterns -->
Identify command execution matching the AI-lure pattern, such as shell downloads or encoded PowerShell commands.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process rows showing an interpreter downloading and executing content directly
  from the command line.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) IN ('curl', 'wget', 'bash', 'zsh', 'powershell.exe', 'pwsh', 'cmd.exe')) AND (LOWER(process_cmd_line) LIKE '%|%sh%' OR LOWER(process_cmd_line) LIKE '%iex%' OR LOWER(process_cmd_line) LIKE '%-enc%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-scheduled-persistence
<!-- Rare scheduled persistence -->
Find new scheduled tasks that are unique to the scoped hosts, indicating persistence established by the malware.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A job seen on one or two hosts shortly after the lead interaction.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(job_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3 ORDER BY hosts ASC
```

## credential-theft-evidence
<!-- Credential and sensitive file access -->
Detect access to SSH keys, cloud credentials, and browser keychains targeted by stealers.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File activity indicating a shell or unknown process reading sensitive directories.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%/.ssh/%' OR LOWER(file_path) LIKE '%/.aws/%' OR LOWER(file_path) LIKE '%/library/keychains/%' OR LOWER(file_path) LIKE '%/telegram%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## kill-chain-triage
<!-- Kill chain triage -->
```agent target=hunter
cite: required
context:
- evaluate-dns-lead
- clipboard-execution
- rare-scheduled-persistence
- credential-theft-evidence
max_iterations: 6
objective: Determine if the host shows a complete attack lifecycle following the AI
  redirect.
success_criteria: A malicious verdict citing matching timestamps across DNS, process,
  and file surfaces.
tools:
- endpoint
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the kill-chain-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: no-agent-coverage)
else: → close-out

## contain-host
<!-- Contain compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the user to rotate all cloud and SSH keys from a different device.
```
→ remediation-review

## remediation-review
<!-- Remediation and key rotation review -->
```manual target=analyst
Review the file paths in credential-theft-evidence. Verify that the user has rotated SSH keys, AWS credentials, and browser-stored secrets accessed during the incident window.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts examined. If benign results were numerous, consider tuning the shell execution query to exclude known internal admin utilities.
```
→ end
