---
analysis: A standard detection rule might catch the specific filenames, but this hunt
  uses a behavioral baseline of sub-second process bursts to find agents even when
  they rotate their filenames and hashes.
blind_spots:
- id: incomplete-process-logging
  question: whether the swarm executes more rapidly than the telemetry collector captures
  requires: sub-millisecond process logging
  risk: Agents may execute and terminate so quickly that they are missed between collection
    intervals.
  stage: execution-agentic-high-speed-logic
- id: ephemeral-probing-files
  question: whether the swarm deletes its probe files before the EDR can ship the
    creation event
  requires: hb_file_activity with close-to-real-time capture
  risk: Files may only exist for milliseconds, leading to missed discovery indicators.
  stage: discovery-predictable-probing
coverage:
- stage: execution-agentic-high-speed-logic
  status: covered
  steps:
  - swarm-ioc-lead
  - high-speed-execution-bursts
- stage: discovery-predictable-probing
  status: covered
  steps:
  - predictable-discovery-probing
- reason: Belongs to the initial access hunt in this series.
  stage: initial-access-auth-and-exploit
  status: out_of_scope
- reason: "Belongs to another part of the 'Oh, is it Thanksgiving? I hadn\u2019t noticed!'\
    \ series."
  stage: c2-improvised-web-coordination
  status: out_of_scope
- reason: "Belongs to another part of the 'Oh, is it Thanksgiving? I hadn\u2019t noticed!'\
    \ series."
  stage: exfiltration-improvised-data-parking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous swarms operate at machine speed, meaning a human-led response
    is too slow; identifying their sub-second execution patterns is the only way to
    detect them before they complete their objectives.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous agentic swarm is executing on endpoints, characterized by
  high-speed sub-second process bursts and predictable state-tracking file names like
  artex-probe.
labels:
- hunt
- attack.t1190
- attack.t1041
- attack.t1078
- attack.t1059
- attack.t1204
- attack.t1083
- attack.t1018
- command and control
- discovery
- execution
- exfiltration
- initial access
name: Autonomous Swarm Endpoint Operations
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-25'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts if the first step is too noisy.
    from:
      kind: manual
      ref: analyst-scoping
    type: list[host]
  swarm_filenames:
    default:
    - vid001.exe
    - content.js
    - f4b1f888f29faa7fbec180f42bdc78596e8a8b908c0a6e6c419933703c81df85.js
    description: Known filenames used by the swarm agents.
    from:
      kind: article
      observed: '2026-11-25'
      ref: talos
    type: list[path]
  swarm_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - f4b1f888f29faa7fbec180f42bdc78596e8a8b908c0a6e6c419933703c81df85
    - 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
    - fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
    - 38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55
    description: SHA256 hashes of agentic swarm binaries and scripts.
    from:
      kind: article
      observed: '2026-11-25'
      ref: talos
    type: list[hash]
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
rationale: Start with servers and development environments where container escapes
  are most likely. The high-speed burst query may trigger on compilation or CI/CD
  tasks; use scope_hosts to exclude known build servers if necessary.
references:
- name: "Talos \u2014 Oh, is it Thanksgiving? I hadn\u2019t noticed!"
  url: https://blog.talosintelligence.com/oh-is-it-thanksgiving-i-hadnt-noticed/
related:
- hunt: improvised-web-c2-coordination
  reason: This hunt focuses on the endpoint execution; the network side using services
    like webhook.site is covered in the sibling hunt.
  relation: out-of-scope-alternative
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
  index: 1
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


# Autonomous Swarm Endpoint Operations

This hunt targets the endpoint-side tradecraft of autonomous multi-agent systems. While these swarms coordinate over public web infrastructure, they exhibit unique behavioral markers on the host: specifically, automated reasoning patterns that result in sub-second process execution bursts and a reliance on predictable file-naming conventions to track state across distributed agents. We first identify known swarm IOCs by hash, filename, and command-line arguments, then parallelize the hunt to find high-speed execution patterns and discovery-oriented probing files.

## swarm-ioc-lead
<!-- Known swarm IOC execution -->
Identify any hosts executing known swarm binaries or scripts by hash, image name, or as arguments in a command line.

```sqlite target=endpoint role=scoping params=(swarm_hashes=swarm_hashes, swarm_filenames=swarm_filenames, lookback_days=lookback_days)
~~~yaml
expected: Direct hits on known agent filenames or hashes. This confirms presence of
  specific swarm versions.
reads:
- device_hostname
- process_cmd_line
- process_hash_sha256
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_hash_sha256, time FROM hb_process_activity WHERE (instr(',' || '{{swarm_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR instr(',' || '{{swarm_filenames}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(LOWER(process_cmd_line), 'content.js') > 0 OR instr(LOWER(process_cmd_line), 'f4b1f888f29faa7fbec180f42bdc78596e8a8b908c0a6e6c419933703c81df85.js') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-behavioral-hunt
<!-- Parallel behavioral analysis -->
parallel:
- → predictable-discovery-probing
- → high-speed-execution-bursts
join: → agent-triage

## predictable-discovery-probing
<!-- Predictable discovery probing -->
Find files created with the artex-probe prefix used by swarms to coordinate local state.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: File creation events for predictably named state files. This is a high-fidelity
  indicator of this specific agentic framework.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 5
reads:
- activity_name
- device_hostname
- file_name
- file_path
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, file_name, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_name) LIKE 'artex-probe-%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## high-speed-execution-bursts
<!-- High-speed process bursts -->
Detect the sub-second reasoning intervals where multiple processes are launched in the same second, typical of automated agents.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Groups of process launches occurring within the same second on a single
  host. High burst counts indicate automated script or agent activity.
reads:
- activity_id
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, substr(time, 1, 19) AS second_bucket, COUNT(*) AS burst_count FROM hb_process_activity WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, second_bucket HAVING burst_count > 5 ORDER BY burst_count DESC
```

## agent-triage
<!-- Agent triage of swarm activity -->
```agent target=hunter
cite: required
context:
- swarm-ioc-lead
- predictable-discovery-probing
- high-speed-execution-bursts
max_iterations: 6
objective: Determine if any host shows coordinated evidence of autonomous swarm activity
  by correlating IOC hits with high-speed process bursts and discovery file markers.
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  specific process and file rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: incomplete-process-logging)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and perform a full forensic imaging to capture in-memory swarm state before rebooting.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst investigation -->
```manual target=analyst
Examine the processes involved in the high-speed bursts; identify if they attempted to access sensitive local files or moved laterally after discovery.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
If the results were benign, document the noise level from the high-speed burst query and suggest thresholds for future tuning.
```
→ end
