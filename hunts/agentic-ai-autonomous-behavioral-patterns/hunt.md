---
analysis: AI agents generate unique commands on the fly; static rules for web shells
  fail to capture the autonomous reasoning loop and inhuman speed that this hunt identifies
  through multi-surface behavioral analysis.
blind_spots:
- id: script-telemetry-truncation
  owner: Endpoint Security
  question: Are the reasoning comments captured in full by the EDR?
  remediation: Audit script block logging limits and ensure interpreters are fully
    monitored.
  requires: hb_script_activity with full content
  risk: Large script blocks containing AI reasoning may be truncated, removing the
    primary behavioral fingerprint of the agent.
  stage: autonomous-agent-execution
- id: velocity-resolution
  owner: Data Platform
  question: Can we reliably distinguish the 1.4s AI gap from 20s human gap?
  remediation: Enable high-resolution process creation auditing.
  requires: process_activity with millisecond timestamps
  risk: If telemetry timestamps are rounded to the nearest second, velocity-based
    detection loses precision.
  stage: autonomous-agent-execution
coverage:
- stage: initial-access-web-shell-exploitation
  status: covered
  steps:
  - inhuman-command-velocity
- stage: autonomous-agent-execution
  status: covered
  steps:
  - inhuman-command-velocity
  - ai-reasoning-and-headers
  - agent-early-triage
- stage: iterative-privilege-escalation
  status: covered
  steps:
  - scope-vulnerable-kernels
- stage: discovery-cloud-reconnaissance
  status: covered
  steps:
  - cloud-recon-pivot
- stage: c2-and-persistence-tunneling
  status: covered
  steps:
  - c2-network-tunnels
  - agent-final-assessment
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Autonomous AI agents compress attack cycles from days to hours. Detecting
    the unique reasoning and velocity markers of these agents is essential for intercepting
    an intrusion before it completes exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous AI agent is conducting an intrusion, evidenced by inhuman
  command velocity, structured section headers in shell output, and chain-of-thought
  reasoning comments within script telemetry.
labels:
- hunt
- attack.t1059
- attack.t1059.001
- attack.t1505.003
- attack.t1190
- attack.t1572
- attack.t1041
- attack.t1068
- command and control
- discovery
- execution
- initial access
- privilege escalation
name: Agentic AI Autonomous Behavioral Patterns
parameters:
  ai_script_markers:
    default:
    - agent.py
    - reasoning.sh
    - thought.py
    - step_executor.py
    description: Filenames associated with AI agent scripts or autonomous executors.
    from:
      kind: article
      observed: '2024-11-24'
      ref: unit42-agentic-ai
    type: list[string]
  c2_ips:
    default:
    - 204.194.54.240
    - 150.242.254.199
    - 206.123.152.217
    - 38.253.224.12
    description: C2 and relay IPs associated with GSocket and SSH tunneling in agentic
      campaigns.
    from:
      kind: article
      observed: '2024-11-24'
      ref: unit42-agentic-ai
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-24'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Hostnames to scope; leave empty to hunt the whole estate.
    from:
      kind: manual
      observed: '2024-11-24'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/autonomous-ai-agent-threat-campaigns/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on internet-facing Linux and Windows servers where web shells
  are the primary entry point for agentic operators.
references:
- name: "Unit 42 \u2014 Recent Trends and Tactics of Agentic AI Attacks"
  url: https://unit42.paloaltonetworks.com/autonomous-ai-agent-threat-campaigns/
related:
- hunt: web-shell-behavioral-anomalies
  reason: This hunt focuses on the speed and reasoning of the operator behind the
    shell, not the shell's presence itself.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial access via web shell
    observables:
    - pastebin.com/raw/swqSMxYs
    - web.config
    - web shell installation via vulnerable web application
    slug: initial-access-web-shell-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
  - name: Autonomous AI agent execution
    observables:
    - inter-command gap ~1.4 seconds
    - === [Title] === headers in shell output
    - 'reasoning comments in scripts (e.g. # Step 1: Enumerating users)'
    - structured machine-readable output (JSON/XML) in shell
    - 800+ unique commands in 140 minutes
    slug: autonomous-agent-execution
    tactic: execution
    techniques:
    - T1059
    - T1059.001
  - name: Iterative privilege escalation
    observables:
    - CVE-2024-1086
    - CVE-2026-31431
    - on-target compilation of kernel exploits using gcc
    - sequential attempts of 5+ different privesc techniques
    slug: iterative-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Cloud and database reconnaissance
    observables:
    - AWS environment enumeration
    - database structure discovery
    - guidance.remote
    slug: discovery-cloud-reconnaissance
    tactic: discovery
    techniques:
    - T1046
    - T1087
    - T1482
  - name: C2 and protocol tunneling
    observables:
    - 204.194.54.240
    - 150.242.254.199
    - 206.123.152.217
    - 38.253.224.12
    - webhook.site/72f421ea-5576-4a4a-8c55-a2a79c19c8b8
    - GSocket relay
    - SSH tunnel relay
    slug: c2-and-persistence-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1041
  summary: Multiple global campaigns involve human operators gaining initial access
    via web shells on vulnerable web applications before handing control to autonomous
    AI agents. These agents then execute reconnaissance, iterative privilege escalation
    (including kernel exploit compilation), and lateral movement at machine speed,
    characterized by distinct behavioral markers like section headers and reasoning
    comments in scripts.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Agentic AI Autonomous Behavioral Patterns

The phased flow starts by scoping to vulnerable hosts likely to be targeted for kernel exploitation, then pivots to detect the unique behavioral markers of AI-driven execution before hunting for follow-on cloud reconnaissance and protocol tunneling. The adversary gains initial access via web shells and hands off control to an autonomous AI agent that operates at machine speed. The hunt first identifies vulnerable hosts prone to iterative privilege escalation attempts. It then searches for the unmistakable behavioral markers of agentic AI: an inhuman inter-command gap and reasoning comments embedded in shell scripts. The analyst reviews these automated triggers before pivoting to cloud-level discovery and network tunneling to confirm an active intrusion.

## scope-vulnerable-kernels
<!-- Scope to hosts vulnerable to kernel exploits -->
Identify Linux hosts carrying vulnerabilities that AI agents target for rapid, iterative privilege escalation.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of vulnerable device IDs. These are the high-priority targets where
  an agent may attempt compilation of custom exploits.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- title
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, title FROM hb_vulnerability_finding WHERE (cve_uid = 'CVE-2024-1086' OR cve_uid = 'CVE-2026-31431') AND status != 'suppressed'
```

## early-stage-behavior
<!-- Search for inhuman velocity and AI markers -->
parallel:
- → inhuman-command-velocity
- → ai-reasoning-and-headers
join: → agent-early-triage

## inhuman-command-velocity
<!-- Inhuman command execution velocity -->
Identify hosts where a single parent launches hundreds of unique children in a tight window, indicating automated agent control.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Hosts with hundreds of unique commands from a single parent. A median gap
  analysis by an analyst can confirm the 1.4s velocity mentioned in the report.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  rare_below: 3
reads:
- device_hostname
- user_name
- parent_process_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, user_name, parent_process_name, COUNT(*) AS total_commands, COUNT(DISTINCT process_name) AS unique_commands, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name, parent_process_name HAVING unique_commands > 100 ORDER BY total_commands DESC
```

## ai-reasoning-and-headers
<!-- Reasoning comments and section headers in scripts -->
Detect scripts containing conversational comments or machine-readable headers used by AI agents to navigate and parse their own results.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_script_markers=ai_script_markers)
~~~yaml
expected: Script contents showing 'chain-of-thought' reasoning or filenames from the
  ai_script_markers list. These markers are high-fidelity indicators of an autonomous
  operator.
reads:
- device_hostname
- script_type
- script_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, script_type, script_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%===[%' OR LOWER(script_content) LIKE '%thought:%' OR LOWER(script_content) LIKE '%reasoning:%' OR LOWER(script_content) LIKE '%step 1:%' OR instr(',' || '{{ai_script_markers}}' || ',', ',' || LOWER(script_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage early-stage automation -->
```agent target=hunter
cite: required
context:
- inhuman-command-velocity
- ai-reasoning-and-headers
max_iterations: 4
objective: Examine the volume of unique commands and the presence of structured reasoning
  or headers. Decide if this pattern represents an autonomous agent rather than a
  human administrator or a static script.
success_criteria: A verdict of malicious or suspicious for hosts showing the 'agentic'
  footprint.
tools:
- endpoint
- network
```

## follow-on-activity
<!-- Search for cloud recon and C2 tunnels -->
parallel:
- → cloud-recon-pivot
- → c2-network-tunnels
join: → agent-final-assessment

## cloud-recon-pivot
<!-- Follow-on cloud reconnaissance activity -->
Identify high-volume cloud API calls indicating the strategic discovery phase directed by the AI agent.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: High-volume discovery calls from a single IP or user account. These represent
  the automated mapping of the target environment.
reads:
- actor_user_name
- src_endpoint_ip
- api_service_name
- api_operation
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT actor_user_name, src_endpoint_ip, api_service_name, api_operation, COUNT(*) AS call_count FROM hb_cloud_api_activity WHERE (api_operation LIKE 'List%' OR api_operation LIKE 'Describe%' OR api_operation LIKE 'Get%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, api_service_name, api_operation HAVING call_count > 50 ORDER BY call_count DESC
```

## c2-network-tunnels
<!-- C2 network connections and protocol tunnels -->
Corroborate the automated activity with connections to known campaign IPs or protocol relays.

```sqlite target=network role=triage params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to the listed campaign IPs. Silence here but hits on earlier
  stages suggests a rotation of infrastructure.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-assessment
<!-- Final assessment of the agentic chain -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- cloud-recon-pivot
- c2-network-tunnels
max_iterations: 6
objective: Synthesize the early-stage triage with the follow-on cloud and network
  pivots. Does the evidence confirm an autonomous AI agent is conducting an intrusion?
success_criteria: A final verdict of malicious citing the full behavioral chain.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on agent verdict -->
if~: "the final assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: script-telemetry-truncation)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR. These agents operate at machine speed; containment must be prioritized to prevent full exfiltration or persistence.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Verify the inter-command gap in process_activity for the affected host. Review script_activity for 'chain-of-thought' logic that confirms an autonomous operator.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the efficacy of the velocity and reasoning marker queries. Evaluate if these patterns should be promoted to standing rules.
```
→ end
