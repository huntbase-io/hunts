---
analysis: A standing rule for explorer.exe spawning a shell is too noisy; this hunt
  uses network lures and follow-on file-access patterns to provide the context an
  analyst needs to act.
blind_spots:
- id: no-proxy-telemetry
  question: Did the user click a redirect that bypasses endpoint-only HTTP logging?
  requires: hb_http_activity from a proxy or firewall
  risk: Endpoint agents may miss browser-internal redirects or specific AI-hosted
    artifacts that a network proxy would capture.
  stage: initial-access-phishing-lures
- id: cmd-line-truncation
  question: What was the complete payload pasted into the Run box?
  requires: Full process_cmd_line length
  risk: Attackers use long, encoded PowerShell strings; if truncated, key indicators
    like 'iex' may be lost.
  stage: execution-clickfix-win-r
coverage:
- stage: initial-access-phishing-lures
  status: covered
  steps:
  - lure-traffic
- stage: execution-clickfix-win-r
  status: covered
  steps:
  - clickfix-execution
- stage: persistence-rmm-abuse
  status: covered
  steps:
  - rogue-rmm-check
- stage: c2-infostealer-deployment
  status: covered
  steps:
  - infostealer-file-access
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: credential-access-token-theft
  status: out_of_scope
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: persistence-mailbox-manipulation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: User-driven manual execution via social engineering is a top-prevalence
    threat according to Huntress SOC data. This hunt provides the chain of evidence
    required to distinguish rogue RMM use from normal administration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has used AI-tuned phishing lures or ClickFix social engineering
  to trick a user into executing shell commands from the Run box, eventually deploying
  rogue RMM tools or infostealers.
labels:
- hunt
- attack.t1566
- attack.t1204.001
- attack.t1219
- attack.t1555
- attack.t1071.001
- command and control
- credential access
- execution
- initial access
- persistence
name: Endpoint Social Engineering and Malicious Execution
parameters:
  browser_files:
    default:
    - login data
    - cookies
    - web data
    description: Target files typically harvested by infostealers.
    type: list[string]
  legitimate_browsers:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    description: Legitimate browser process names to exclude from theft detection.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_domains:
    default:
    - claude.ai
    - railway.app
    - railway.com
    description: Domains known to host malicious artifacts or lures.
    from:
      kind: article
      observed: '2026-10-01'
      ref: huntress-tragic-quadrant
    type: list[domain]
  redirect_domains:
    default:
    - cisco.com
    - trendmicro.com
    - mimecast.com
    description: Legitimate service domains used as phishing redirectors.
    from:
      kind: article
      observed: '2026-10-01'
      ref: huntress-tragic-quadrant
    type: list[domain]
  rmm_names:
    default:
    - anydesk.exe
    - screenconnect.exe
    - atera.exe
    - splashtop.exe
    - tvnserver.exe
    description: Common RMM process names used to establish a prevalence baseline.
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty for
      all hosts.
    type: list[host]
  shell_names:
    default:
    - powershell.exe
    - cmd.exe
    description: Shell processes monitored for Run-box execution.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows endpoints where users have local administrative rights.
  Servers where RMM tools are expected can be filtered by hostname to reduce noise.
references:
- name: "Huntress \u2014 Tragic Quadrant: Top Cyber Threats Wrecking Businesses"
  url: https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats
related:
- hunt: mailbox-manipulation-persistence
  reason: Persistence via M365 mailbox rules is an identity-layer hunt and out of
    scope for this endpoint-focused lifecycle.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering with AI-Tuned Lures
    observables:
    - claude.ai
    - Railway
    - Cisco redirect URLs
    - Trend Micro redirect URLs
    - Mimecast redirect URLs
    - AI-tuned lures
    - fake document shares
    - service agreement lures
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: User-Driven ClickFix Command Execution
    observables:
    - Win+R
    - Windows Run box
    - Human Verification prompt
    - multi-stage infection command
    slug: execution-clickfix-win-r
    tactic: execution
    techniques:
    - T1204.001
  - name: Adversary-in-the-Middle and Device Code Token Harvesting
    observables:
    - session token
    - device code login flow
    - access token
    - Microsoft 365 login page impersonation
    slug: credential-access-token-theft
    tactic: credential-access
    techniques:
    - T1557
    - T1528
  - name: Persistence via Rogue RMM Installation
    observables:
    - rogue RMM tool
    - Remote Monitoring and Management tools
    slug: persistence-rmm-abuse
    tactic: persistence
    techniques:
    - T1219
  - name: Stealthy Mailbox Rule Manipulation
    observables:
    - inbox rules
    - RSS Feeds folder
    - Archive folders
    slug: persistence-mailbox-manipulation
    tactic: persistence
    techniques:
    - T1137.005
    - T1564.008
  - name: Infostealer and RAT Deployment
    observables:
    - LummaC2
    - SectopRAT
    - FakeAgent
    slug: c2-infostealer-deployment
    tactic: command-and-control
    techniques:
    - T1555
    - T1071.001
  summary: The Huntress Tragic Quadrant outlines common 2026 threats targeting SMBs,
    where attackers use AI-enhanced social engineering (ClickFix, fake lures) and
    trusted platforms (Claude.ai) to deliver infostealers and rogue RMM tools. The
    campaign progresses from initial access via session token theft (AiTM) or user-driven
    command execution to persistence through mailbox manipulation and remote management
    software abuse.
series:
  index: 1
  slug: huntress-tragic-quadrant-top-cyber-threats-wrecking-businesses
  title: 'Huntress Tragic Quadrant: Top Cyber Threats Wrecking Businesses'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Endpoint Social Engineering and Malicious Execution

This phased hunt investigates the full lifecycle of host-based infection as described in the Huntress Tragic Quadrant. It begins by identifying suspicious URI redirects and shell processes spawned directly by the Windows desktop shell (explorer.exe), which is the primary indicator of ClickFix social engineering. In the second phase, the hunt corroborates these findings by identifying unauthorized RMM tools and sensitive file access patterns characteristic of infostealers like LummaC2. An agent-driven analysis weighs the early-stage access signals against follow-on persistence and impact evidence to confirm the intrusion chain.

## scope-windows-hosts
<!-- Scope Windows Hosts -->
Identify Windows endpoints in the software inventory to target the hunt.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames representing the Windows estate. Silence means no Windows
  software inventory is present.
reads:
- device_hostname
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (package_type = 'msi' OR package_type = 'exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-parallel
<!-- Early Stage Parallel Analysis -->
parallel:
- → lure-traffic
- → clickfix-execution
join: → early-stage-triage

## lure-traffic
<!-- Phishing Lure Traffic -->
Find HTTP requests to AI platforms or known redirectors identified in the article.

```sqlite target=web role=triage params=(lure_domains=lure_domains, redirect_domains=redirect_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound traffic to domains like claude.ai or Railway following a redirect
  link. Silence means no report-specific traffic was found.
reads:
- device_hostname
- url_hostname
- url_full
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, url_hostname, url_full, time FROM hb_http_activity WHERE (instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR instr(',' || '{{redirect_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## clickfix-execution
<!-- ClickFix Shell Execution -->
Detect shell processes spawned by explorer.exe with encoded commands, typical of Run box pasting.

```sqlite target=endpoint role=detection-candidate params=(shell_names=shell_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A shell process launched directly from explorer.exe with suspicious arguments.
  This indicates a user-driven paste event.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%explorer.exe' AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(process_cmd_line) LIKE '%iex%' OR LOWER(process_cmd_line) LIKE '%-enc%' OR LOWER(process_cmd_line) LIKE '%getstring%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Early Stage Triage -->
```agent target=hunter
cite: required
context:
- lure-traffic
- clickfix-execution
max_iterations: 3
objective: Determine which hosts show high-confidence signs of social engineering
  leading to manual shell execution.
success_criteria: A list of hosts with confirmed early-stage social engineering activity.
tools:
- endpoint
- web
```

## follow-on-parallel
<!-- Follow-on Parallel Analysis -->
parallel:
- → rogue-rmm-check
- → infostealer-file-access
join: → full-chain-analysis

## rogue-rmm-check
<!-- Rogue RMM Check -->
Find rogue RMM tools by stack-counting common RMM names across the estate.

```sqlite target=endpoint role=baseline params=(rmm_names=rmm_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An RMM tool seen on three or fewer hosts. Tools found fleet-wide are likely
  authorized; rare ones suggest rogue installation.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{rmm_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## infostealer-file-access
<!-- Infostealer File Access -->
Identify non-browser processes accessing browser credential and session data using a list-based exclusion.

```sqlite target=endpoint role=enrichment params=(browser_files=browser_files, legitimate_browsers=legitimate_browsers, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any row showing an unknown process reading sensitive browser files. Silence
  means no such access was observed.
reads:
- device_hostname
- process_name
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, file_name, file_path, time FROM hb_file_activity WHERE instr(',' || '{{browser_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND instr(',' || '{{legitimate_browsers}}' || ',', ',' || LOWER(process_name) || ',') = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## full-chain-analysis
<!-- Full Chain Analysis -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- rogue-rmm-check
- infostealer-file-access
max_iterations: 6
objective: Determine whether the social engineering confirmed in early-stage-triage
  led to rogue persistence or infostealer activity.
success_criteria: A final per-host verdict citing evidence from both early and follow-on
  stages.
tools:
- endpoint
- web
```

## response-decision
<!-- Response Decision -->
if~: "the final verdict identifies malicious activity linking the initial lure to execution and subsequent RMM or infostealer activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-proxy-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host using the EDR. Revoke active SaaS session tokens and force a password reset for the logged-in user.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the full process command line from the shell execution step. Confirm if the rare RMM identified is a rogue instance or a one-off approved project tool. If the shell query is high-fidelity, promote it to a standing rule.
```
→ close-out

## close-out
<!-- Hunt Closure -->
```manual target=analyst
Record the hosts examined, any confirmed threats, and false positives for baseline tuning. Document coverage gaps for the HTTP surface if lures were missed.
```
→ end
