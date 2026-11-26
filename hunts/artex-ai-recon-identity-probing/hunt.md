---
analysis: "A standard rule might detect an individual tool like sqlmap. This hunt\
  \ identifies the machine-speed agentic pattern\u2014the rapid correlation of identity\
  \ sprays with specific web probing across multiple surfaces\u2014that distinguishes\
  \ ARTEX from disparate automated scans."
blind_spots:
- id: unmonitored-idp
  question: whether the spray occurred against a legacy or unmanaged provider
  requires: hb_auth_signin coverage for all identity providers
  risk: An attacker could gain access via a secondary identity provider that is not
    forwarding logs, bypassing the lead step.
  stage: identity-brute-force-and-spraying
- id: agent-gap
  question: whether offensive worker tools were run locally on the server
  requires: hb_process_activity on all Linux web servers
  risk: Without endpoint visibility on Linux web servers, the hunt may miss post-exploit
    tool execution even if HTTP probes are seen.
  stage: web-application-exploitation
- id: limited-http-logging
  question: the exact configuration files targeted by the scanner
  requires: Full url_path in hb_http_activity for all assets
  risk: Incomplete HTTP logging may mask the specific files being probed, preventing
    the config-file-probing query from matching.
  stage: external-reconnaissance-and-scanning
coverage:
- stage: external-reconnaissance-and-scanning
  status: covered
  steps:
  - config-file-probing
- stage: web-application-exploitation
  status: covered
  steps:
  - config-file-probing
  - worker-tool-execution
- stage: identity-brute-force-and-spraying
  status: covered
  steps:
  - identity-pressure-lead
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: automated-agent-execution
  status: out_of_scope
- reason: Belongs to another part of the 'What defenders need to know about ARTEX,
    the agentic AI framework threat actors abuse' series.
  stage: host-and-domain-credential-harvesting
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
  handoff: keep-as-periodic-hunt
  justification: AI-powered frameworks like ARTEX accelerate the attack chain to machine
    speed. Identifying the rapid transition from identity pressure to web probing
    is critical to stopping autonomous actors before they reach persistent access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous AI-powered framework is conducting high-speed perimeter
  scanning and identity pressure, transitioning from credential sprays to sensitive
  configuration discovery at machine speed.
labels:
- hunt
- attack.t1595.001
- attack.t1595.002
- attack.t1110.003
- attack.t1190
- attack.t1505.003
- attack.t1552.001
- command and control
- credential access
- discovery
- execution
- initial access
- privilege escalation
- reconnaissance
name: ARTEX AI-Driven Perimeter Recon and Identity Probing
parameters:
  auth_failure_threshold:
    default: '50'
    description: Minimum authentication failures from a single IP to trigger the lead.
    from:
      kind: manual
      observed: '2026-11-25'
      ref: triage-heuristic
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-25'
      ref: hunt-standard
    type: number
  offensive_tool_names:
    default:
    - sqlmap
    - hydra
    - medusa
    - ncrack
    - nmap
    - nc
    - telnet
    - whois
    - dig
    - curl
    - wget
    - git
    description: Offensive tools pre-configured in the ARTEX framework.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog
    type: list[string]
  scope_hosts:
    default: []
    description: Hosts identified as web servers; leave empty to hunt across the whole
      estate.
    from:
      kind: manual
      observed: '2026-11-25'
      ref: scoping-step
    type: list[host]
  web_config_paths:
    default:
    - /web.config
    - /my.cnf
    - /.env
    - /.git/config
    - /wp-config.php
    - /appsettings.json
    description: Sensitive configuration paths probed by ARTEX agents.
    from:
      kind: article
      observed: '2026-11-25'
      ref: msrc-blog
    type: list[path]
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
rationale: The hunt focuses on the internet-facing web server estate (Apache, Nginx,
  IIS) and the identity provider logs (Entra ID, Okta). High-velocity sprays against
  M365 or SaaS providers are the primary entry point.
references:
- name: What defenders need to know about ARTEX, the agentic AI framework threat actors
    abuse
  url: https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/
related:
- hunt: automated-agent-execution-artex
  reason: This hunt identifies initial recon and identity pressure; the next hunt
    in the series covers backend agent coordination and internal harvesting.
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
  index: 1
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# ARTEX AI-Driven Perimeter Recon and Identity Probing

This hunt identifies the early autonomous phases of an ARTEX intrusion. Threat actors like Storm-0940 use the framework to automate reconnaissance and initial access, often moving from a credential spray to web application probing in minutes. We start by scoping the web server estate and identifying high-volume authentication failures that serve as a cheap lead. A gated agent then decides whether to trigger expensive queries into web application probing and the execution of worker tools like sqlmap or hydra. The hunt concludes with a triage agent correlating external identity pressure with internal behavioral artifacts to confirm the presence of an autonomous penetration testing agent.

## scope-web-infrastructure
<!-- Scope potential web server targets -->
Identify hosts running web server software that are likely targets for autonomous scanning.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running common web services. This scopes follow-on queries
  to the internet-facing estate.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%sharepoint%' OR LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%httpd%' OR LOWER(package_name) LIKE '%iis%'
```

## identity-pressure-lead
<!-- High-volume identity pressure lead -->
Identify source IPs exhibiting machine-speed authentication failure patterns consistent with AI-driven sprays.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, auth_failure_threshold=auth_failure_threshold)
~~~yaml
expected: A single IP address attempting dozens or hundreds of logins across multiple
  accounts in a narrow window. This is the durable behavioral lead for ARTEX.
reads:
- src_endpoint_ip
- status_id
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT src_endpoint_ip, COUNT(*) AS attempt_count, COUNT(DISTINCT actor_user_name) AS unique_users, MIN(time) AS first_attempt, MAX(time) AS last_attempt FROM hb_auth_signin WHERE status_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING attempt_count >= {{auth_failure_threshold}} ORDER BY attempt_count DESC
```

## evaluate-lead-agent
<!-- Evaluate identity pressure -->
```agent target=hunter
cite: required
context:
- identity-pressure-lead
max_iterations: 3
objective: Decide if the authentication failure counts and account diversity from
  the lead indicate an automated ARTEX-like agent.
success_criteria: A verdict on whether to proceed with the full investigation based
  on the spray intensity.
tools:
- endpoint
- identity
- web
```

## gate-on-lead-decision
<!-- Gate on automated behavior -->
if~: "the evaluate-lead-agent verdict is malicious or suspicious for at least one source IP" (confidence: high, judge=hunter)
then: → gather-corroboration
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: unmonitored-idp)
else: → close-out

## gather-corroboration
<!-- Gather corroboration -->
parallel:
- → config-file-probing
- → worker-tool-execution
join: → triage-agent

## config-file-probing
<!-- Sensitive configuration file probing -->
Identify high-velocity HTTP requests for sensitive configuration files from the suspect IPs.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, web_config_paths=web_config_paths, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Bursts of requests for .env, web.config, or my.cnf files targeting the scoped
  web assets. Silence confirms these IPs did not probe these specific paths.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 5
reads:
- device_hostname
- src_endpoint_ip
- url_path
- status_code
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, status_code, COUNT(*) AS request_count, MIN(time) AS first_request FROM hb_http_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(',' || '{{web_config_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR url_path LIKE '%.env%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, url_path, status_code ORDER BY request_count DESC
```

## worker-tool-execution
<!-- Execution of offensive worker tools -->
Identify the execution of ARTEX's integrated worker tools on systems in the scoped estate.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, offensive_tool_names=offensive_tool_names, lookback_days=lookback_days)
~~~yaml
expected: Process execution for tools like nmap, hydra, or sqlmap. Silence proves
  these specific binaries did not run in the examined window.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
- process_original_file_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(',' || '{{offensive_tool_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{offensive_tool_names}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR process_cmd_line LIKE '%sqlmap%' OR process_cmd_line LIKE '%hydra%' OR process_cmd_line LIKE '%ncrack%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage AI agent behavior -->
```agent target=hunter
cite: required
context:
- evaluate-lead-agent
- config-file-probing
- worker-tool-execution
max_iterations: 5
objective: Determine if the identity spray, configuration file probing, and worker
  tool execution together confirm an intrusion by an autonomous AI framework.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  rows.
tools:
- endpoint
- identity
- web
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: agent-gap)
else: → close-out

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the triage and revoke any credentials identified as compromised in the spray lead.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the config-file-probing results for 200 OK responses. Inspect process trees on the isolated host for any follow-on exploitation shells or persistence attempts.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the findings. If the auth_failure_threshold resulted in benign noise, increase the value for future runs.
```
→ end
