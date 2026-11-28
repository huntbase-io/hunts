---
analysis: A simple rule might catch a Tor connection, but this hunt correlates delivery
  sentiment keywords, process parentage with directory prefix awareness, and network
  prevalence using an agent to weigh the intent and context of the entire chain.
blind_spots:
- id: missing-process-telemetry
  question: whether the execution occurred on hosts with missing EDR coverage
  requires: hb_process_activity with parent information
  risk: A host without EDR will not report the process spawns that trigger this gated
    hunt.
  stage: phishing-payload-execution
- id: missing-network-logs
  question: whether traffic was sent over common ports like 443 via a bridge
  requires: hb_network_connection egress logs
  risk: Tor bridges and private ORBs operating on port 443 are harder to distinguish
    from standard web traffic and may be missed by the rare-port prevalence query.
  stage: obfuscated-multi-hop-c2
coverage:
- stage: ai-generated-phishing-delivery
  status: covered
  steps:
  - phishing-dns-corroboration
- stage: phishing-payload-execution
  status: covered
  steps:
  - lead-process-spawns
- stage: obfuscated-multi-hop-c2
  status: covered
  steps:
  - multi-hop-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI-generated phishing scales rapidly and is often missed by traditional
    signature-based mail filters; detecting the behavioral execution and subsequent
    C2 is critical for stopping intrusions early.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using AI-generated phishing to deliver payloads that establish
  command-and-control via multi-hop proxy networks, disguising traffic through Tor
  or private relay nodes.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: AI-Crafted Phishing and Multi-Hop Proxies
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-30'
      ref: standard-retention
    type: number
  phishing_domains:
    default:
    - login-verify-ai.com
    - account-security-update.net
    - secure-mail-gateway.io
    description: Known domains from AI-phishing campaigns; refresh before running.
    from:
      kind: article
      observed: '2026-06-30'
      ref: red-canary-phishing-blog
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts from the lead step to scope expensive network
      queries.
    from:
      kind: manual
      ref: analyst-scoping
    type: list[host]
  scope_processes:
    default: []
    description: Specific process names discovered in the lead step to filter network
      and DNS activity.
    from:
      kind: manual
      ref: lead-step-pivot
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/phishing-ai-agent/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with general user workstations; prioritize those in departments like
  HR or Finance which are frequent targets for high-sentiment phishing.
references:
- name: "Red Canary \u2014 Train, triage, repeat: The AI agent changing how we fight\
    \ phishing"
  url: https://redcanary.com/blog/threat-detection/phishing-ai-agent/
related:
- hunt: scheduled-task-persistence-user-writable-paths
  reason: Phishing payloads often use scheduled tasks for persistence, which requires
    a separate investigation of hb_scheduled_job.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Generated Phishing Delivery
    observables:
    - high-sentiment email content
    - well-formatted malicious emails
    - suspicious sender domains
    - malicious URLs
    - domain abuse levels
    - urgent or emotive language
    slug: ai-generated-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Phishing Payload Execution
    observables:
    - process spawned from email clients (e.g., outlook.exe)
    - process spawned from browsers (e.g., chrome.exe)
    - execution of files from temp directories
    - downloads of executable payloads from high-reputation domains
    slug: phishing-payload-execution
    tactic: execution
    techniques:
    - T1566
  - name: Obfuscated Multi-Hop C2
    observables:
    - onion routing traffic
    - Tor exit node connections
    - .onion domain resolutions
    - operational relay box (ORB) network nodes
    - multi-hop VPS proxy chains
    - traffic to compromised IoT devices
    slug: obfuscated-multi-hop-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves the delivery of highly tailored, AI-generated phishing
    emails designed to bypass traditional filters by leveraging natural language and
    emotional triggers. Successful initial access via these messages leads to the
    execution of malicious payloads that utilize multi-hop proxy networks and onion
    routing to obfuscate command-and-control traffic.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI-Crafted Phishing and Multi-Hop Proxies

This hunt follows a gated flow to identify the lifecycle of an AI-assisted phishing attack. It begins with a lead query focused on suspicious child processes spawned from common email and browser parents in user-writable directories. If an agent confirms these executions as suspicious, the hunt opens a fan-out investigation into network and DNS telemetry. This second stage searches for multi-hop proxy connections—specifically Tor entry points and rare outbound ports—and matches DNS queries against domains with patterns typical of automated phishing campaigns, specifically filtered to the suspect processes identified in the lead. The final triage correlates delivery, execution, and C2 to confirm a multi-stage intrusion.

## lead-process-spawns
<!-- Suspicious processes from phishing vectors -->
Identify potential phishing payload execution by finding unusual child processes spawned by email clients or web browsers.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A list of processes executed from temporary or public paths by browsers
  or mail clients. Absence suggests no direct execution from these vectors occurred.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%\outlook.exe' OR LOWER(parent_process_name) LIKE '%\chrome.exe' OR LOWER(parent_process_name) LIKE '%\msedge.exe' OR LOWER(parent_process_name) LIKE '%\firefox.exe' OR LOWER(parent_process_name) LIKE '%\thunderbird.exe') AND (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\programdata\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess lead execution -->
```agent target=hunter
cite: required
context:
- lead-process-spawns
max_iterations: 3
objective: Determine if the child process spawned from a mail client or browser represents
  a suspicious execution or a potential downloader, citing command line arguments
  and paths.
success_criteria: A verdict of suspicious | benign per host.
tools:
- endpoint
- network
```

## gate-on-lead
<!-- Gate on lead suspicion -->
if~: "the assessment identifies at least one process execution as suspicious or high-risk" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-telemetry)
else: → close-out

## parallel-investigation
<!-- Parallel network and DNS investigation -->
parallel:
- → multi-hop-prevalence
- → phishing-dns-corroboration
join: → final-triage

## multi-hop-prevalence
<!-- Rare multi-hop and Tor connection ports -->
Find outbound connections to Tor entry points or rare high-ports that indicate multi-hop proxy or ORB use, excluding common browser noise.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to ports associated with Tor or rare destination ports that
  are unique to a few hosts. Exclusion of browsers prevents web noise from polluting
  the prevalence count.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_port
- process_name
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_port, process_name, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_port IN (9001, 9050, 9150) OR dst_endpoint_port > 1024) AND direction = 'outbound' AND LOWER(process_name) NOT LIKE '%\chrome.exe' AND LOWER(process_name) NOT LIKE '%\msedge.exe' AND LOWER(process_name) NOT LIKE '%\firefox.exe' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY dst_endpoint_port HAVING host_count < 5 ORDER BY host_count ASC
```

## phishing-dns-corroboration
<!-- Phishing domain and sentiment matches -->
Correlate the suspicious execution with DNS lookups for known phishing domains, filtered to the specific processes found in the lead.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts, scope_processes=scope_processes)
~~~yaml
expected: DNS queries for phishing infrastructure or domains containing urgent sentiment
  from the suspect processes. Filtering by process_name ensures the network activity
  is linked to the lead execution.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%verify-ai%' OR LOWER(query_hostname) LIKE '%secure-login%') AND ('{{scope_processes}}' = '' OR instr(',' || '{{scope_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## final-triage
<!-- Triage full attack chain -->
```agent target=hunter
cite: required
context:
- assess-lead
- multi-hop-prevalence
- phishing-dns-corroboration
max_iterations: 5
objective: Correlate the suspicious execution chain with outbound traffic to confirm
  a multi-stage intrusion involving AI-crafted delivery and multi-hop C2.
success_criteria: A verdict citing specific process IDs, network ports, and DNS domains.
tools:
- endpoint
- network
```

## route-final
<!-- Route on final triage -->
if~: "the triage verdict identifies a confirmed malicious execution followed by multi-hop proxy beaconing" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-network-logs)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR agent and revoke any active sessions for the user identified in the lead query.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Manually verify the process chain and network connections. Examine the suspected phishing domain for AI-typical sentiment patterns (over-professional language or high urgency) and document any new C2 indicators.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Add newly discovered C2 domains to the watch list and document any novel persistence mechanisms identified during investigation.
```
→ end
