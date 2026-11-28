---
analysis: A standard detection rule might trigger on 'sqlmap.exe', but ARTEX's durability
  comes from rotating tools and techniques at speed. This hunt pivots between tool
  discovery, a baseline for execution frequency (the 'machine-speed' signature in
  1-hour windows), sensitive file access, and DNS exfiltration signals, providing
  the context an analyst needs to identify autonomous automation rather than a single
  tool hit.
blind_spots:
- id: missing-linux-audit-data
  question: Whether /etc/shadow was successfully read by a non-privileged user
  requires: hb_linux_audit or properly configured hb_file_activity for root-level
    files
  risk: Standard endpoint monitoring may not capture access to restricted files unless
    specifically audited, leading to a missed harvesting step.
  stage: host-and-domain-credential-harvesting
- id: truncated-script-logging
  question: The exact logic within the worker agent scripts used to pivot
  requires: hb_script_activity with full block logging
  risk: ARTEX agents use dynamically generated scripts; without full script block
    logging, the exact 'intents' of the agent remain obscured.
  stage: automated-agent-execution
coverage:
- stage: automated-agent-execution
  status: covered
  steps:
  - artex-agent-tool-lead
  - high-frequency-execution-baseline
- stage: host-and-domain-credential-harvesting
  status: covered
  steps:
  - credential-file-access
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: external-reconnaissance-and-scanning
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: web-application-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: identity-brute-force-and-spraying
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: directory-and-cloud-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: cloud-privilege-escalation
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: exfiltration-and-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The rise of agentic AI frameworks like ARTEX allows threat actors
    to scale intrusions at machine speed. Detecting the transition from recon to credential
    harvesting across endpoint surfaces is critical for preventing rapid lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated agent is performing high-frequency tool execution to conduct
  reconnaissance and dump credentials from sensitive files like .env or /etc/shadow
  at machine speeds.
labels:
- hunt
- attack.t1651
- attack.t1059.001
- attack.t1059
- attack.t1552.001
- attack.t1003.008
- attack.t1003.006
- attack.t1558.003
- command and control
- credential access
- discovery
- execution
- initial access
- privilege escalation
- reconnaissance
name: Machine-Speed Agent Tooling and Credential Harvesting
parameters:
  artex_tools:
    default:
    - nc.exe
    - nc
    - netcat
    - telnet.exe
    - telnet
    - sqlmap.py
    - sqlmap
    - hydra.exe
    - hydra
    - medusa
    - ncrack
    - nmap
    description: Offensive tools pre-configured or commonly added to ARTEX agents.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog-artex
    type: list[string]
  exfil_domains:
    default:
    - webhook.site
    description: Known exfiltration and script delivery domains used by ARTEX agents.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog-artex
    type: list[domain]
  harvest_targets:
    default:
    - .env
    - my.cnf
    - web.config
    - shadow
    - passwd
    description: Sensitive files targeted for credential harvesting.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog-artex
    type: list[string]
  interpreters:
    default:
    - node.exe
    - node
    - python3
    - python.exe
    - powershell.exe
    - pwsh.exe
    - pwsh
    - git.exe
    - git
    - curl.exe
    - curl
    - wget.exe
    - wget
    description: Common interpreters used by ARTEX worker agents to execute intents.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog-artex
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers running web applications and Linux-based developer workstations
  where ARTEX-compatible tools and interpreters (Node, Python) are expected but high-frequency
  use is rare.
references:
- name: What defenders need to know about ARTEX, the agentic AI framework threat actors
    abuse
  url: https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/
related:
- hunt: artex-web-application-exploitation
  reason: This hunt focuses on post-exploitation endpoint activity; the web-facing
    SQLi and XXE attacks are covered by a sister hunt on HTTP and web server logs.
  relation: out-of-scope-alternative
- hunt: artex-ai-recon-identity-probing
  relation: follows
scenario:
  stages:
  - name: Autonomous External Reconnaissance
    observables:
    - nmap
    - whois
    - dig
    - curl
    - wget
    - ripgrep
    slug: external-reconnaissance-and-scanning
    tactic: reconnaissance
    techniques:
    - T1595.001
    - T1595.002
    - T1588.002
  - name: AI-Driven Web Application Exploitation
    observables:
    - sqlmap
    - SQL injection (SQLi)
    - XXE injection
    - web.config
    - my.cnf
    slug: web-application-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
    - T1213.006
  - name: Automated Credential Spraying
    observables:
    - hydra
    - medusa
    - ncrack
    - Machine-speed sign-in attempts against Microsoft 365 and identity providers
    slug: identity-brute-force-and-spraying
    tactic: credential-access
    techniques:
    - T1110.001
    - T1110.003
  - name: Machine-Speed Agent Tool Execution
    observables:
    - nc
    - telnet
    - Playwright
    - Chromium
    - node
    - python3
    - machine-speed command rotation
    slug: automated-agent-execution
    tactic: execution
    techniques:
    - T1651
    - T1059.001
    - T1059
  - name: Host and Domain Credential Dumping
    observables:
    - '*.env'
    - /etc/shadow
    - DCSync scripts
    - Kerberoasting scripts
    slug: host-and-domain-credential-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
    - T1003.008
    - T1003.006
    - T1558.003
  - name: Automated Directory and Cloud Discovery
    observables:
    - Microsoft Graph API enumeration
    - Active Directory privileged group enumeration
    - Cloud resource permission mapping
    - jq
    slug: directory-and-cloud-discovery
    tactic: discovery
    techniques:
    - T1087.002
    - T1087.004
    - T1580
  - name: Cloud Role Elevation
    observables:
    - Global Administrator role assignment to applications
    - privileged role assignment via cloud API
    slug: cloud-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1098.001
    - T1098.003
  - name: Exfiltration via Web Services
    observables:
    - webhook.site
    - mass cloud storage reads
    - outbound Tor infrastructure
    slug: exfiltration-and-c2
    tactic: command-and-control
    techniques:
    - T1102.002
    - T1090.003
    - T1530
  summary: ARTEX is a Go-based autonomous AI penetration testing framework used by
    threat actors like Storm-0940 and Salt Typhoon to automate reconnaissance, web
    exploitation, and lateral movement. The framework coordinates multiple LLM agents
    to execute off-the-shelf tools at machine speed, progressing from initial access
    to cloud privilege escalation and mass data exfiltration in minutes.
series:
  index: 2
  slug: what-defenders-need-to-know-about-artex-the-agentic-ai-framework-threat-actors-abuse
  title: What defenders need to know about ARTEX, the agentic AI framework threat
    actors abuse
  total: 3
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


# Machine-Speed Agent Tooling and Credential Harvesting

This hunt targets the endpoint activity of the ARTEX agentic AI framework. ARTEX uses a Go-based backend to orchestrate multiple LLM agents that execute offensive tools (like nc, sqlmap, and hydra) in rapid succession. This hunt identifies the 'machine-speed' execution pattern by baselining interpreter frequency within one-hour windows and corroborating that activity with access to sensitive credential stores like environment files and OS-level shadow files, alongside DNS signals to known exfiltration sites. An agent then evaluates the combined telemetry to distinguish between legitimate automation and an autonomous penetration testing framework.

## artex-agent-tool-lead
<!-- Search for ARTEX-associated offensive tools -->
Identify any execution of the specific offensive binaries and networking tools mentioned in the report, handling full paths.

```sqlite target=endpoint role=detection-candidate params=(artex_tools=artex_tools, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating that penetration testing tools like sqlmap or hydra are
  running. The query treats every directory and filename in the path as a potential
  match against the tool list.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{artex_tools}}' || ',', ',' || LOWER(replace(replace(process_name, '/', '\'), '\', ',')) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate execution speed and harvesting -->
parallel:
- → high-frequency-execution-baseline
- → credential-file-access
- → dns-exfiltration-signals
join: → triage-artex-behavior

## high-frequency-execution-baseline
<!-- Baseline for machine-speed interpreter use -->
Identify hosts running a burst of commands through common interpreters within a 1-hour window, suggesting AI-driven automation.

```sqlite target=endpoint role=baseline params=(interpreters=interpreters, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: 1h
expected: A stack-count of hosts showing dozens of interpreter launches in a single
  hour. Legitimate CI/CD pipelines might appear here and must be filtered by user
  context.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, user_name, strftime('%Y-%m-%d %H', time) AS hour_bucket, COUNT(*) AS launch_count, COUNT(DISTINCT process_name) AS unique_tools, MIN(time) AS first_launch, MAX(time) AS last_launch FROM hb_process_activity WHERE instr(',' || '{{interpreters}}' || ',', ',' || LOWER(replace(replace(process_name, '/', '\'), '\', ',')) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name, hour_bucket HAVING launch_count > 20 ORDER BY launch_count DESC
```

## credential-file-access
<!-- Correlate with credential file access -->
Check if processes are accessing files known to contain secrets, capturing the process name for correlation.

```sqlite target=endpoint role=enrichment params=(harvest_targets=harvest_targets, lookback_days=lookback_days)
~~~yaml
expected: Processes reading sensitive files like /etc/shadow or .env. The query is
  path-aware and captures the acting process to facilitate correlation with the tool-lead
  step.
reads:
- device_hostname
- process_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, actor_user_name, file_path, time FROM hb_file_activity WHERE (instr(',' || '{{harvest_targets}}' || ',', ',' || LOWER(replace(replace(file_path, '/', '\'), '\', ',')) || ',') > 0 OR LOWER(file_path) LIKE '%.env%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-exfiltration-signals
<!-- Check for DNS exfiltration to webhook sites -->
Identify hosts talking to webhook.site or other exfiltration domains mentioned in the report.

```sqlite target=endpoint role=enrichment params=(exfil_domains=exfil_domains, lookback_days=lookback_days)
~~~yaml
expected: Any row indicates a host communicating with a named exfiltration domain,
  often used by ARTEX for script delivery or data return.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-artex-behavior
<!-- Triage AI-driven tool behavior -->
```agent target=hunter
cite: required
context:
- artex-agent-tool-lead
- high-frequency-execution-baseline
- credential-file-access
- dns-exfiltration-signals
max_iterations: 6
objective: Determine if the pattern of offensive tools, high-speed execution bursts,
  sensitive file access, and DNS exfiltration signals indicates an automated AI-driven
  intrusion framework like ARTEX.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  tool names, launch counts within 1-hour windows, file paths, and DNS queries.
tools:
- endpoint
```

## verdict-routing
<!-- Route on agent verdict -->
if~: "the triage verdict is malicious for at least one host based on concurrent tool use and high-speed execution" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-artifact-review
unavailable: → manual-artifact-review (blind_spot: missing-linux-audit-data)
else: → incident-report-and-tuning

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve its memory for further analysis of the Go-based agent framework.
```
→ manual-artifact-review

## manual-artifact-review
<!-- Manual artifact review -->
```manual target=analyst
Review the process command lines and the parent process of any identified interpreters. Look for persistent connections to webhook.site or known C2 domains.
```
→ incident-report-and-tuning

## incident-report-and-tuning
<!-- Incident report and tuning -->
```manual target=analyst
Record the discovered indicators (hashes, paths). If legitimate automation was flagged, update the baseline exclusion filters for the user accounts responsible for those tasks.
```
→ end
