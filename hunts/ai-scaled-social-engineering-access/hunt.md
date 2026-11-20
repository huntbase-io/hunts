---
analysis: A single rule might detect a tool name, but this hunt correlates the automated
  creation of dozens of PDFs with subsequent high-speed discovery command bursts,
  providing the context of an AI-scaled operation.
blind_spots:
- id: limited-endpoint-visibility
  question: Whether lures were delivered to machines not enrolled in the monitoring
    platform.
  requires: Full agent coverage across recruitment and engineering teams
  risk: An attacker compromises a personal machine or shadow-IT host that lacks telemetry,
    bypassing the lure-burst detection.
  stage: initial-access-ai-tailored-phishing
- id: git-repository-audit-gap
  question: Which specific private repository was accessed or modified via trojanized
    lures.
  requires: hb_cloud_api_activity for GitHub or GitLab
  risk: Without repository audit logs, we can see the 'clone' but cannot verify if
    the actor exfiltrated source code or committed malicious changes back to the origin.
  stage: initial-access-trojanized-repositories
coverage:
- stage: initial-access-ai-tailored-phishing
  status: covered
  steps:
  - automated-lure-bursts
  - early-stage-triage
- stage: initial-access-trojanized-repositories
  status: covered
  steps:
  - trojan-repo-clones
  - early-stage-triage
- stage: execution-agentic-framework-artex
  status: covered
  steps:
  - artex-agentic-recon
  - follow-on-triage
- stage: persistence-and-evasion-ai-tooling
  status: covered
  steps:
  - cursor-persistence-check
  - follow-on-triage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: North Korean actors have operationalized AI to scale attacks. This
    hunt provides the correlation needed to find automated lure delivery and 'agentic'
    post-exploitation frameworks that individual rules miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses generative AI to produce high-volume tailored lures and
  trojanized repositories, subsequently deploying agentic frameworks like ARTEX for
  automated reconnaissance and persistence.
labels:
- hunt
- attack.t1566.001
- attack.t1195.002
- attack.t1059
- attack.t1543
- attack.t1027
- execution
- initial access
- persistence
name: AI-Scaled Social Engineering and Access
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-29'
      ref: default-retention
    type: number
  lure_keywords:
    default:
    - resume.pdf
    - interview_prep.pdf
    - blockchain_intelligence.pdf
    - software_engineer_jd.pdf
    - salary_details.pdf
    description: Exact filenames of suspected AI-generated lures to filter for in
      the file activity query.
    from:
      kind: article
      observed: '2026-10-29'
      ref: msrc-blog-2026-10-29
    type: list[string]
  recon_tools:
    default:
    - whoami
    - net
    - tasklist
    - systeminfo
    - ipconfig
    - sc
    - quser
    - query
    description: Common reconnaissance tools executed by agentic frameworks like ARTEX.
    from:
      kind: article
      observed: '2026-10-29'
      ref: msrc-blog-2026-10-29
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the entire
      estate.
    from:
      kind: manual
      observed: '2026-10-29'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/29/tracking-ai-adoption-in-north-korean-threat-actor-tradecraft/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hosts belonging to software engineers, blockchain researchers,
  and recruitment staff. Machines without development tools like git or VS Code are
  lower priority but should still be scanned for PDF bursts.
references:
- name: Tracking AI adoption in North Korean threat actor tradecraft
  url: https://www.microsoft.com/en-us/security/blog/2026/10/29/tracking-ai-adoption-in-north-korean-threat-actor-tradecraft/
related:
- hunt: ai-mcp-server-remote-source
  reason: Existing rules target MCP server exploitation; this hunt looks for broader
    agentic frameworks like ARTEX.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Tailored Phishing Lures
    observables:
    - PDF lure files created in rapid succession (dozens in minutes)
    - Job-themed filenames and content (software engineer, recruitment)
    - Email or outreach referencing spoofed AI-powered blockchain intelligence companies
    - Tailored recruiter or investor domains used for contact
    slug: initial-access-ai-tailored-phishing
    tactic: initial-access
    techniques:
    - T1566.001
  - name: Trojanized Private Repository Lures
    observables:
    - Cloned private source code repositories containing trojanized logic
    - Git activity involving malicious repository lures
    - Malicious code refactored or generated using AI dev platforms
    slug: initial-access-trojanized-repositories
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Agentic AI Framework Execution
    observables:
    - Process launches for 'ARTEX' agentic AI penetration testing framework
    - Automated penetration testing commands and scripts launched via AI agents
    - Execution of commands generated via agentic workflows for reconnaissance and
      exploitation
    slug: execution-agentic-framework-artex
    tactic: execution
    techniques:
    - T1059
  - name: AI-Assisted Tooling and Persistence
    observables:
    - Usage of Cursor AI-assisted development platform for script modification
    - AI-generated persistence mechanisms (services, scheduled tasks)
    - AI-refactored obfuscation layers in scripts and malware
    - Commands and scripts troubleshooting errors as observed in command line logs
    slug: persistence-and-evasion-ai-tooling
    tactic: persistence
    techniques:
    - T1543
    - T1027
  summary: North Korean threat actors are leveraging generative and agentic AI to
    scale reconnaissance, social engineering, and malware development, including the
    rapid generation of tailored PDF lures and the use of the ARTEX framework for
    automated penetration testing. These campaigns frequently use fake job-themed
    personas and front companies to deliver trojanized code via private repositories
    or initiate malicious interview workflows.
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


# AI-Scaled Social Engineering and Access

This hunt identifies North Korean threat actor tradecraft that incorporates AI as a force multiplier. It begins by identifying automated lure generation (dozens of PDFs created in minutes) and suspicious repository interaction. The hunt then pivots to find evidence of agentic AI frameworks—detecting the automated command bursts typical of ARTEX—and AI-assisted development tools used for persistence.

## scoping-dev-tools
<!-- Scope development and AI tools -->
Identify hosts with development environments or AI assistants as these are the primary targets for North Korean supply chain and remote-worker operations.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hostnames belonging to developers, researchers, or recruiters. Silence indicates
  no development software is present in the inventory.
reads:
- package_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%git%' OR LOWER(package_name) LIKE '%cursor%' OR LOWER(package_name) LIKE '%vscode%' OR LOWER(package_name) LIKE '%python%')
```

## early-intrusion-parallel
<!-- Search for early intrusion evidence -->
parallel:
- → automated-lure-bursts
- → trojan-repo-clones
join: → early-stage-triage

## automated-lure-bursts
<!-- Automated PDF lure creation bursts -->
Detect the rapid creation of multiple PDF files in user-writable paths, characteristic of AI-scaled phishing lures.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lure_keywords=lure_keywords)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A single host creating 10 or more PDFs in a short window. Silence suggests
  no automated lure bursts occurred in monitored paths.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 2
reads:
- file_name
- file_path
- device_hostname
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, COUNT(*) as pdf_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_file_activity WHERE LOWER(file_name) LIKE '%.pdf' AND (LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%\\desktop\\%' OR LOWER(file_path) LIKE '%/downloads/%' OR LOWER(file_path) LIKE '%/desktop/%') AND (instr(',' || '{{lure_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR '{{lure_keywords}}' = '') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING pdf_count >= 10
```

## trojan-repo-clones
<!-- Suspicious git repository cloning -->
Identify git clones from external sources, which may deliver AI-refactored trojanized logic.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Users cloning repositories from unusual domains. Silence means no git network
  activity was recorded on these hosts.
reads:
- process_name
- process_cmd_line
- device_hostname
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%git%' AND LOWER(process_cmd_line) LIKE '%clone%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early intrusion signals -->
```agent target=hunter
cite: required
context:
- automated-lure-bursts
- trojan-repo-clones
max_iterations: 3
objective: Evaluate if the PDF creation patterns or git clone commands match the automated,
  AI-enabled profiles of North Korean lures.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows and timing.
tools:
- endpoint
```

## post-access-parallel
<!-- Search for agentic follow-on activity -->
parallel:
- → artex-agentic-recon
- → cursor-persistence-check
join: → follow-on-triage

## artex-agentic-recon
<!-- ARTEX agentic command bursts -->
Identify the agentic footprint of ARTEX by searching for bursts of unique discovery commands from a single parent.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, recon_tools=recon_tools)
~~~yaml
expected: A parent process executing 3+ distinct recon tools in 60 seconds. Silence
  indicates no automated recon bursts were detected.
reads:
- process_name
- parent_pid
- device_hostname
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, parent_pid, parent_process_name, COUNT(DISTINCT REPLACE(LOWER(process_name), '.exe', '')) as unique_recon_cmds, MIN(time) as start_time, MAX(time) as end_time FROM hb_process_activity WHERE instr(',' || '{{recon_tools}}' || ',', ',' || REPLACE(LOWER(process_name), '.exe', '') || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, parent_pid HAVING unique_recon_cmds >= 3 AND (strftime('%s', MAX(time)) - strftime('%s', MIN(time))) <= 60
```

## cursor-persistence-check
<!-- AI-assisted persistence mechanisms -->
Identify services in user-writable paths, potentially refactored or generated using AI dev tools like Cursor.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: New services pointing to profile-based binaries that are not known developer
  workers.
reads:
- service_cmd_line
- service_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, service_name, service_cmd_line, time FROM hb_service_activity WHERE (LOWER(service_cmd_line) LIKE '%appdata%' OR LOWER(service_cmd_line) LIKE '%public%' OR LOWER(service_cmd_line) LIKE '%/tmp/%') AND activity_id = 1 AND LOWER(service_cmd_line) NOT LIKE '%code%' AND LOWER(service_cmd_line) NOT LIKE '%cursor%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Analyze full intrusion chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- artex-agentic-recon
- cursor-persistence-check
max_iterations: 5
objective: Correlate early signals from the first triage with the follow-on ARTEX
  bursts or service persistence found on the same hosts.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the sequential chain of events.
tools:
- endpoint
```

## intrusion-decision
<!-- Intrusion decision -->
if~: "the follow-on triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-endpoint-visibility)
else: → close-out

## contain-host
<!-- Isolate impacted host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke any credentials used by the target account in the lookback window.
```
→ analyst-review

## analyst-review
<!-- Deep analyst review -->
```manual target=analyst
Review the command bursts identified as ARTEX and any AI-refactored scripts found in user profiles. Document the lure filenames and the timing of the automated reconnaissance.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record what was examined. If no activity was found, update the 'baseline' prevalence for PDF bursts to ensure legitimate automated tool updates are documented.
```
→ end
