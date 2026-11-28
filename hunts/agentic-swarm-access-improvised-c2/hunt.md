---
analysis: A single rule for public web hooks triggers excessive false positives; this
  hunt uses a gated approach to confirm the server's role before an agent weighs the
  timing and process context together.
blind_spots:
- id: no-endpoint-visibility
  question: whether targeted applications exist on unmanaged hosts
  requires: Endpoint sensor installation
  risk: A server without an agent contributes no process or DNS rows, hiding the initial
    breach.
  stage: initial-access-auth-and-exploit
- id: timing-analysis-gap
  question: whether the coordination follows the reported burst-and-pause pattern
  requires: sub-second timestamp resolution and timing analysis
  risk: Standard DNS lookups can see the destination but cannot resolve sub-second
    automated reasoning cycles, which is the primary behavioral differentiator.
  stage: c2-improvised-web-coordination
- id: blockchain-content-blindness
  question: what instructions were passed in the blockchain memos
  requires: Solana blockchain transaction auditing
  risk: We can see the DNS to the Solana mainnet but cannot observe the coordination
    payload without specialized blockchain monitoring.
  stage: c2-improvised-web-coordination
coverage:
- stage: initial-access-auth-and-exploit
  status: covered
  steps:
  - scoping-active-servers
  - anomalous-lineage
- stage: c2-improvised-web-coordination
  status: covered
  steps:
  - c2-network-indicators
- stage: exfiltration-improvised-data-parking
  status: covered
  steps:
  - c2-network-indicators
- reason: "Belongs to another part of the 'Oh, is it Thanksgiving? I hadn\u2019t noticed!'\
    \ series."
  stage: execution-agentic-high-speed-logic
  status: out_of_scope
- reason: "Belongs to another part of the 'Oh, is it Thanksgiving? I hadn\u2019t noticed!'\
    \ series."
  stage: discovery-predictable-probing
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous agents operate at machine speed; identifying the initial
    access and improvised coordination points is critical to stopping a campaign before
    it moves from a sandbox escape to deep network access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Autonomous agentic swarms have compromised public-facing web or management
  servers and are using improvised web services or blockchain memos for machine-speed
  coordination and data exfiltration.
labels:
- hunt
- attack.t1078
- attack.t1190
- attack.t1041
- attack.t1102
- attack.t1071.001
- command and control
- discovery
- execution
- exfiltration
- initial access
name: Agentic Swarm Access and Improvised C2
parameters:
  c2_domains:
    default:
    - webhook.site
    - api.mainnet-beta.solana.com
    - w32.9f1f11a708-100.sbx.tg
    - w32.f4b1f888f2-95.sbx.tg
    - w32.58d6fec4ba-95.sbx.tg
    - w32.fed979f93b-95.sbx.tg
    - w32.38d053135d-95.sbx.tg
    description: Improvised C2 and data-parking domains from the report.
    from:
      kind: article
      observed: '2026-11-25'
      ref: https://blog.talosintelligence.com/oh-is-it-thanksgiving-i-hadnt-noticed/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optionally limit behavioral checks to specific hosts found in the
      scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/oh-is-it-thanksgiving-i-hadnt-noticed/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts identified as public-facing application servers. Prioritize
  those running Drupal, Check Point management software, or common web server stacks
  (Nginx/Apache).
references:
- name: "Cisco Talos \u2014 Oh, is it Thanksgiving? I hadn\u2019t noticed!"
  url: https://blog.talosintelligence.com/oh-is-it-thanksgiving-i-hadnt-noticed/
related:
- hunt: discovery-predictable-probing
  reason: Internal network discovery by agents is handled in a separate hunt focused
    on internal reconnaissance.
  relation: out-of-scope-alternative
- hunt: autonomous-swarm-endpoint-operations
  relation: follows
scenario:
  stages:
  - name: Access via Valid Accounts and Exploitation
    observables:
    - Compromised credentials
    - Check Point Security Management server exploitation
    - Drupal Fail2Install RCE
    slug: initial-access-auth-and-exploit
    tactic: initial-access
    techniques:
    - T1078
    - T1190
  - name: High-Speed Agentic Execution
    observables:
    - VID001.exe
    - content.js
    - f4b1f888f29faa7fbec180f42bdc78596e8a8b908c0a6e6c419933703c81df85.js
    - burst-and-pause timing patterns
    - sub-second reasoning intervals
    slug: execution-agentic-high-speed-logic
    tactic: execution
    techniques:
    - T1059
    - T1204
  - name: Predictable State Probing
    observables:
    - artex-probe-* file names
    - predictable file naming conventions
    slug: discovery-predictable-probing
    tactic: discovery
    techniques:
    - T1083
    - T1018
  - name: C2 via Improvised Infrastructure
    observables:
    - webhook.site
    - Solana blockchain memos
    - highly specific URL parameters for state tracking
    slug: c2-improvised-web-coordination
    tactic: command-and-control
    techniques:
    - T1102
    - T1071.001
  - name: Data Parking and Exfiltration
    observables:
    - webhook.site
    - data parking before agent termination
    slug: exfiltration-improvised-data-parking
    tactic: exfiltration
    techniques:
    - T1041
  summary: Autonomous agentic swarms like ARTEX utilize compromised credentials or
    application exploits to rapidly penetrate networks, often progressing in under
    15 minutes. These threats are characterized by sub-second automated reasoning
    patterns and coordinate through public web services like Webhook.site for state
    tracking and data exfiltration.
series:
  index: 2
  slug: oh-is-it-thanksgiving-i-hadn-t-noticed
  title: "Oh, is it Thanksgiving? I hadn\u2019t noticed!"
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


# Agentic Swarm Access and Improvised C2

This hunt focuses on the 'agentic swarm' tradecraft described in recent research, where autonomous AI agents coordinate activities using public infrastructure to bypass sandboxes. The hunt targets vulnerable Check Point and Drupal servers, seeking evidence of 'burst-and-pause' timing patterns and exfiltration to public web hooks. We use a gated flow to first isolate high-risk servers before executing expensive behavioral and network-wide coordination checks.

## scoping-active-servers
<!-- Scope: Active Management and Web Servers -->
Identify hosts currently running software targeted by the swarm campaign, such as Drupal or Check Point management components.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts acting as high-risk application servers. Silence means no
  such servers were identified within the telemetry window.
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT DISTINCT device_hostname, process_name, process_path FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%drupal%' OR LOWER(process_path) LIKE '%checkpoint%' OR LOWER(process_name) LIKE '%httpd%' OR LOWER(process_name) LIKE '%nginx%' OR LOWER(process_name) LIKE '%php-fpm%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Lead -->
```agent target=hunter
cite: required
context:
- scoping-active-servers
max_iterations: 3
objective: Decide if any identified servers represent a likely target for the agentic
  swarm based on their role and presence in the estate.
success_criteria: A recommendation to proceed or close-out.
tools:
- endpoint
```

## gate-on-targets
<!-- Gate: Proceed to Investigation -->
if~: "the evaluate-lead agent suggests high-risk management or web servers are present in the estate" (confidence: high, judge=hunter)
then: → fan-out-behavior
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-visibility)
else: → close-out

## fan-out-behavior
<!-- Examine Coordination and Execution -->
parallel:
- → c2-network-indicators
- → anomalous-lineage
join: → triage-swarm-activity

## c2-network-indicators
<!-- Improvised C2 and Exfiltration Lookups -->
Detect DNS lookups to improvised web coordination and blockchain endpoints mentioned in the research.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating lookups to coordination infrastructure. High lookup counts
  from a single host suggest automated agent state tracking.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%solana%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookups DESC
```

## anomalous-lineage
<!-- Anomalous Web Shell Execution -->
Identify shells or downloaders launched by web server processes, which may indicate initial access or sandbox breakout.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A shell or utility launched by a web server. Rare across the fleet, this
  suggests unauthorized command execution.
reads:
- device_hostname
- process_name
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%php-fpm%' OR LOWER(parent_process_name) LIKE '%checkpoint%') AND (LOWER(process_name) IN ('sh', 'bash', 'cmd.exe', 'powershell.exe', 'curl', 'wget')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-swarm-activity
<!-- Triage Swarm Activity -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- c2-network-indicators
- anomalous-lineage
max_iterations: 5
objective: Determine if the combination of server software, DNS coordination lookups,
  and anomalous process lineage indicates an active agentic swarm compromise.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host showing both anomalous execution and coordination traffic" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: timing-analysis-gap)
else: → analyst-review

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host immediately to prevent further exfiltration. Collect process memory and web logs for investigation.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the DNS lookups to the webhook and Solana endpoints. Check for URL parameters containing state data or exfiltrated information. Correlate with web server access logs to identify the initial exploit vector.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record all findings and update detection exclusion lists for legitimate use of public webhooks. Determine if the 'anomalous-lineage' query should be promoted to a standing rule.
```
→ end
