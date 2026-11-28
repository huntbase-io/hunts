---
analysis: A single detection rule may catch a browser spawning a shell; this hunt
  distinguishes an agentic loop from a one-off anomaly by correlating that shell with
  the high-tempo 30-second network buckets that provide the framework's instructions.
blind_spots:
- id: no-http-payload-visibility
  owner: Infrastructure Team
  question: What specific framework commands or exploit payloads were contained in
    the HTTP traffic?
  remediation: Enable full request logging on reverse proxies for critical web paths.
  requires: hb_http_activity with full_log_line or request_body
  risk: Without payload visibility, the hunt relies on tempo and parentage, which
    may increase false positives from benign automation.
  stage: initial-access-extensions-and-exploits
- id: browser-extension-inventory-gap
  owner: Endpoint Management
  question: Which specific extension is responsible for the shell execution?
  remediation: Configure osquery to collect the chrome_extensions table across the
    estate.
  requires: hb_software_inventory containing browser extension IDs
  risk: While parentage identifies the browser, it does not confirm the responsible
    extension ID without manual forensic investigation.
  stage: initial-access-extensions-and-exploits
coverage:
- stage: initial-access-extensions-and-exploits
  status: covered
  steps:
  - scoping-vulnerable-hosts
  - high-tempo-http
  - dns-c2-lookups
  - browser-shell-execution
- reason: 'Belongs to another part of the ''Inside the loop: Five AI attack frameworks
    that never ask permission'' series.'
  stage: agentic-cloud-identity-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the loop: Five AI attack frameworks
    that never ask permission'' series.'
  stage: high-tempo-command-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the loop: Five AI attack frameworks
    that never ask permission'' series.'
  stage: persistence-via-implants-and-webshells
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the loop: Five AI attack frameworks
    that never ask permission'' series.'
  stage: c2-and-proxy-infrastructure
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Agentic offensive frameworks outpace manual human response. A negative
    result confirms the web perimeter is not currently subject to automated AI-driven
    exploitation loops.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using agentic offensive frameworks like ARTEX or CyberStrikeAI
  to automate initial access and command execution, evidenced by high-frequency network
  bursts and browser processes spawning system shells.
labels:
- hunt
- attack.t1176
- attack.t1190
- attack.t1059
- attack.t1053.005
- attack.t1090.003
- command and control
- execution
- initial access
- persistence
name: High-Tempo Host Execution and C2 Burst Analysis
parameters:
  browser_names:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    - google-chrome
    - firefox
    description: Browser process names suspected of hosting malicious extensions.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: 'Tradecraft: T1176 Software Extensions'
    type: list[string]
  burst_threshold:
    default: '20'
    description: Minimum HTTP request count per source IP within a 30-second window
      to qualify as a potential automated burst.
    from:
      kind: article
      observed: '2026-11-13'
      ref: elastic-security-labs-agentic-offensive-frameworks
    type: number
  c2_domains:
    default:
    - com.apple.systemupdate
    - update.pentagi.com
    description: Infrastructure domains associated with the agentic frameworks mentioned
      in the research.
    from:
      kind: article
      observed: '2026-11-13'
      ref: elastic-security-labs-agentic-offensive-frameworks
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioral patterns.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: Hunt Designer
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames identified as vulnerable; leave empty for an unscoped
      fleet hunt.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: Hunt Designer
    type: list[host]
  shell_names:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - bash
    - sh
    - python.exe
    - python3
    description: Interpreters used by frameworks for automated command execution.
    from:
      kind: manual
      observed: '2026-11-13'
      ref: 'Tradecraft: T1059 Command and Scripting Interpreter'
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the behavioral parallel stage on the hostnames resolved from the
  scoping-vulnerable-hosts step. Prioritize servers and workstations where browser
  sessions are frequent and vulnerabilities exist.
references:
- name: 'Inside the loop: Five AI attack frameworks that never ask permission'
  url: https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex
related:
- hunt: agentic-cloud-identity-access
  reason: This hunt identifies entry points on hosts; abusing cloud credentials using
    agentic loops is a parallel cloud-native hunt.
  relation: out-of-scope-alternative
- hunt: agentic-identity-cloud-exploitation
  relation: follows
scenario:
  stages:
  - name: Initial Access via Extensions and Exploits
    observables:
    - ARTEX browser extension recording authenticated sessions
    - Vulnerability discovery scanning using stock settings
    - Exploitation of public-facing web applications
    - User-Agent strings identifying frameworks
    slug: initial-access-extensions-and-exploits
    tactic: initial-access
    techniques:
    - T1176
    - T1190
  - name: Agentic Cloud and Identity Access
    observables:
    - Sign-ins to AWS, Entra ID, Slack, and GitHub
    - Abuse of recorded session tokens from extensions
    - Automation of cloud CLI tools for account access
    slug: agentic-cloud-identity-access
    tactic: initial-access
    techniques:
    - T1078
  - name: High-Tempo Command and Tool Execution
    observables:
    - Command bursts occurring in 2-25 second intervals
    - Execution of curl, shells, and cloud CLIs
    - Model Context Protocol (MCP) server function calls (HexStrike)
    - Reflector agents sending human-like message responses (PentAGI)
    - Credential access actions including Kerberoasting
    slug: high-tempo-command-execution
    tactic: execution
    techniques:
    - T1059
    - T1558.003
  - name: Persistence via Implants and WebShells
    observables:
    - CyberStrikeAI WebShell manager connections
    - Creation of custom implants checking in every 5 seconds
    - Registry Run keys for implant startup
    - Windows Scheduled Tasks for recurring execution
    - Dropping of coding agent workers in containers (Cairn)
    slug: persistence-via-implants-and-webshells
    tactic: persistence
    techniques:
    - T1505.003
    - T1547.001
    - T1053.005
  - name: C2 and Proxy Infrastructure
    observables:
    - Connections to Telegram, Slack, Discord, and DingTalk C2 listeners
    - DNS queries for update.pentagi.com and com.apple.systemupdate
    - Traffic targeting 224.0.0.0
    - Routing through multi-hop proxies to bypass IP bans
    slug: c2-and-proxy-infrastructure
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Agentic offensive frameworks like ARTEX and CyberStrikeAI automate attack
    sequences using LLM planners to orchestrate tools like scanners, cloud CLIs, and
    custom implants in high-tempo bursts. These frameworks frequently bypass human
    authorization, interacting with cloud control planes and host endpoints via rapid-fire
    command execution and persistent backdoors.
series:
  index: 2
  slug: inside-the-loop-five-ai-attack-frameworks-that-never-ask-permission
  title: 'Inside the loop: Five AI attack frameworks that never ask permission'
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


# High-Tempo Host Execution and C2 Burst Analysis

Agentic offensive frameworks represent a shift from human-speed operators to automated planning loops that issue commands in intervals as short as two seconds. These frameworks often exploit web vulnerabilities (T1190) or abuse authenticated browser sessions via extensions (T1176). This hunt identifies the entry point by scoping to vulnerable internet-facing assets and then correlating three signals: high-density HTTP request patterns measured in 30-second windows, resolution of known framework-associated domains, and browser processes executing command-line interpreters. An agent weighs these behaviors per host to distinguish automated AI loops from benign web traffic or human administration.

## scoping-vulnerable-hosts
<!-- Identify vulnerable web-facing assets -->
Identify hosts with high-severity vulnerabilities in web-facing components. The analyst should resolve these device_uids to hostnames and populate the scope_hosts parameter for subsequent steps.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of vulnerable resources. The presence of these hosts prioritizes
  the behavioral checks in the parallel stage.
reads:
- device_uid
- resource_uid
- title
- cve_uid
- severity
- severity_id
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_uid, resource_uid, title, cve_uid, severity FROM hb_vulnerability_finding WHERE severity_id >= 4 AND (LOWER(title) LIKE '%rce%' OR LOWER(title) LIKE '%injection%' OR LOWER(title) LIKE '%web%')
```

## parallel-checks
<!-- Check network tempo and endpoint parentage -->
parallel:
- → high-tempo-http
- → dns-c2-lookups
- → browser-shell-execution
join: → triage-agent

## high-tempo-http
<!-- High-tempo HTTP bursts -->
Detect external IPs hitting hosts with request density exceeding human interaction by bucketing traffic into 30-second windows.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, burst_threshold=burst_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Source IPs with high request counts within single 30-second buckets, indicating
  an automated agentic loop.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, src_endpoint_ip, strftime('%Y-%m-%d %H:%M', time) || ':' || (CASE WHEN CAST(strftime('%S', time) AS INT) < 30 THEN '00' ELSE '30' END) AS window_30s, COUNT(*) AS req_count FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, src_endpoint_ip, window_30s HAVING req_count >= {{burst_threshold}}
```

## dns-c2-lookups
<!-- Resolution of framework-associated domains -->
Corroborate high-tempo network activity with resolutions for domains known to be used by agentic framework operators.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
expected: DNS resolutions for the framework-associated domains on the same hosts seeing
  high-tempo HTTP traffic.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS resolution_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname
```

## browser-shell-execution
<!-- Browser processes spawning shells -->
Identify shells executed by browsers, matching the T1176 tradecraft where extensions are used to drive local command execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, browser_names=browser_names, shell_names=shell_names)
~~~yaml
expected: Browser processes acting as parents to command shells or interpreters, specifically
  on the hosts being targeted by network bursts.
reads:
- device_hostname
- process_name
- parent_process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-14'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{browser_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Triage automated attack behavior -->
```agent target=hunter
cite: required
context:
- high-tempo-http
- dns-c2-lookups
- browser-shell-execution
max_iterations: 4
objective: Analyze the timing and frequency of HTTP bursts in the 30-second windows
  in relation to the browser-originated shell commands. Determine if the command execution
  pattern follows the network activity buckets, indicating an agentic controller.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  alignment of network burst windows and process events.
tools:
- endpoint
- web
```

## decision-route
<!-- Decision on triage results -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-payload-visibility)
else: → hunt-closeout

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active cloud sessions for the user accounts observed in the activity.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Examine the browser profile and extensions on the isolated host. Review proxy or WAF logs for the specific request paths associated with the HTTP buckets identified.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout -->
```manual target=analyst
Record results. If malicious activity was confirmed, promote the browser shell execution query to a standing detection rule.
```
→ end
