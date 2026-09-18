---
analysis: A simple detection rule on 'Node.js to Claude.ai' would be noisy in a development
  environment. This hunt works by first establishing a behavioral cohort, then correlating
  exfiltration with lateral movement and ransomware indicators, requiring an analyst
  to weigh multiple behavioral artifacts before declaring an incident.
blind_spots:
- id: telemetry-gap
  question: Are there unmanaged hosts in the cohort that could be used for exfiltration?
  requires: Complete endpoint agent coverage
  risk: A host without an agent contributes no process or file data, allowing an intrusion
    to go undetected if it pivots through unmanaged assets.
- id: tls-encryption-blindness
  question: What specifically was sent to Claude.ai or other AI services?
  requires: TLS decryption / SSL interception
  risk: Adversaries can embed sensitive stolen data inside HTTPS POST requests to
    AI platforms; without decryption, only traffic volume and domains are visible.
  stage: exfiltration-over-c2
coverage:
- reason: Standard brute-force and credential access rules already monitor hb_auth_signin;
    this hunt pivots from those detections via the cohort scoping.
  stage: credential-theft-access
  status: existing_rule
- stage: lateral-movement-internal
  status: covered
  steps:
  - node-lateral-movement
- stage: exfiltration-over-c2
  status: covered
  steps:
  - node-exfiltration
  - rare-user-agents
- stage: ransomware-encryption-impact
  status: covered
  steps:
  - file-encryption-burst
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Modern ransomware campaigns utilize legitimate development tools
    (like Node.js) and legitimate external services (like AI platforms) to bypass
    traditional security perimeters. Identifying the specific cohort using these tools
    and correlating their behavior across multiple stages (lateral movement, exfiltration,
    encryption) provides a negative assurance that no such coordinated intrusion is
    active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are leveraging Node.js-based tools to exfiltrate data to AI
  platforms like Claude.ai before deploying ransomware to encrypt the environment.
labels:
- hunt
- attack.t1078
- attack.t1110
- attack.t1041
- attack.t1486
- attack.t1021
- attack.t1071.001
name: Intrusion, AI-Exfiltration, and Ransomware
parameters:
  exfil_domains:
    default:
    - claude.ai
    description: AI domains identified as exfiltration targets.
    from:
      kind: article
      observed: '2026-05-12'
      ref: elastic-security-mcp-app
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  node_processes:
    default:
    - node
    - node.exe
    description: Process names associated with Node.js.
    from:
      kind: article
      observed: '2026-05-12'
      ref: elastic-security-mcp-app
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to investigate; populate from the cohort step.
    type: list[host]
  scope_users:
    default: []
    description: Specific users to investigate; populate from the cohort step.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/elastic-security-mcp-app
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: First, establish the Node.js cohort to identify workstations used for development
  or AI integration. Use this focused list of hosts and users to drive the exfiltration
  and ransomware checks, which reduces the false-positive rate from legitimate file
  servers or general web browsing.
references:
- name: "Elastic Security Labs \u2014 Elastic Security MCP App"
  url: https://www.elastic.co/security-labs/blog/elastic-security-mcp-app
related:
- hunt: ransomware-file-entropy-detection
  reason: A more granular hunt looking for file entropy changes rather than just volume/renames.
  relation: sibling
scenario:
  stages:
  - name: Credential Theft and Initial Access
    observables:
    - Anomalous login events from unusual source IPs
    - Multiple failed authentication attempts across different services
    - Compromised user account activity
    slug: credential-theft-access
    tactic: credential-access
    techniques:
    - T1078
    - T1110
  - name: Internal Lateral Movement
    observables:
    - Internal SSH or RDP connections between hosts
    - Abnormal network events originating from internal workstations
    - Processes initiating connections to peer internal assets
    slug: lateral-movement-internal
    tactic: lateral-movement
    techniques:
    - T1021
    - T1071.001
  - name: Data Exfiltration via C2
    observables:
    - High volume of outbound network traffic to external domains
    - node.js processes initiating external connections
    - HTTP POST requests to external cloud services including claude.ai
    - Unusual user-agent strings in HTTP activity
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Data Encryption
    observables:
    - Rapid file modification and renaming operations
    - Creation of ransom note files across multiple directories
    - Process trees showing mass disk-scanning activity
    - Unusual file access patterns on sensitive data stores
    slug: ransomware-encryption-impact
    tactic: impact
    techniques:
    - T1486
  summary: This campaign involves a multi-stage progression from initial credential
    compromise to internal lateral movement, culminating in data exfiltration over
    a command-and-control channel and the deployment of ransomware. The adversary
    leverages stolen credentials and scripted exfiltration to compromise sensitive
    environments and disrupt business operations through encryption.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Intrusion, AI-Exfiltration, and Ransomware

This hunt targets the complete lifecycle of a multi-stage intrusion involving credential theft, lateral movement, data exfiltration through Node.js (often mimicking or using AI-bridge components), and final impact via ransomware. It uses a focused cohort of hosts running Node.js to reduce noise and correlates behavioral indicators across process, network, and file activity surfaces.

## identify-node-cohort
<!-- Identify Node.js Cohort -->
Identify specific hosts and users running Node.js to establish a focused cohort for behavior analysis, narrowing the scope from the entire fleet.

```sqlite target=endpoint role=scoping params=(node_processes=node_processes, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and users currently running Node.js. High counts or unusual
  users in this list should be prioritized for the subsequent steps.
reads:
- device_hostname
- user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, COUNT(*) as process_count FROM hb_process_activity WHERE (instr(',' || '{{node_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## correlate-intrusion
<!-- Correlate Intrusion Indicators -->
parallel:
- → node-exfiltration
- → rare-user-agents
- → file-encryption-burst
- → node-lateral-movement
join: → triage-intrusion

## node-exfiltration
<!-- Node.js External Connections -->
Detect Node.js processes making connections to the report's AI domains or general outbound connections from the cohort.

```sqlite target=network role=detection-candidate params=(node_processes=node_processes, exfil_domains=exfil_domains, scope_hosts=scope_hosts, scope_users=scope_users, lookback_days=lookback_days)
~~~yaml
expected: Node.js connecting to Claude.ai or suspicious external IPs from the targeted
  cohort.
reads:
- device_hostname
- user_name
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_name, dst_endpoint_hostname, dst_endpoint_ip, time FROM hb_network_connection WHERE (instr(',' || '{{node_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR direction = 'outbound') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-user-agents
<!-- Rare User Agents in Cohort -->
Identify rare User-Agent strings within the cohort that might signify custom scripts or exfiltration tools.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A User-Agent string restricted to a few hosts, potentially indicating a
  non-standard browser or client.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 3
reads:
- user_agent
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_agent, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS request_count FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 2 ORDER BY host_count ASC, request_count DESC
```

## file-encryption-burst
<!-- Ransomware-Scale File Modifications -->
Detect rapid file modification or renaming, characteristic of encryption activities, within the scoped hosts.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Sudden volume spikes in file renames or updates on single hosts, characteristic
  of ransomware.
reads:
- device_hostname
- activity_name
- activity_id
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, activity_name, COUNT(*) AS modification_volume, GROUP_CONCAT(DISTINCT file_path) AS sample_paths FROM hb_file_activity WHERE activity_id IN (3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING modification_volume > 100 ORDER BY modification_volume DESC
```

## node-lateral-movement
<!-- Internal Lateral Movement from Node.js -->
Detect lateral movement attempts originating specifically from the Node.js process or the scoped users.

```sqlite target=network role=enrichment params=(node_processes=node_processes, scope_hosts=scope_hosts, scope_users=scope_users, lookback_days=lookback_days)
~~~yaml
expected: Node.js processes initiating internal connections to other subnets, suggesting
  lateral spread.
reads:
- device_hostname
- user_name
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{node_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND direction = 'outbound' AND (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.16.%' OR dst_endpoint_ip LIKE '192.168.%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-intrusion
<!-- Correlated Intrusion Triage -->
```agent target=hunter
cite: required
context:
- identify-node-cohort
- node-exfiltration
- rare-user-agents
- file-encryption-burst
- node-lateral-movement
max_iterations: 5
objective: Determine if any host or user in the Node.js cohort shows a sequence of
  lateral movement, exfiltration to AI domains, and file modification bursts.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows from the parallel queries.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host, particularly where file encryption and exfiltration overlap" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensics
unavailable: → analyst-forensics (blind_spot: telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host(s) exhibiting confirmed ransomware or exfiltration behavior. Collect the Node.js process memory and suspicious files before taking further action.
```
→ analyst-forensics

## analyst-forensics
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the Node.js script content (via hb_script_activity if available) and process command lines. Analyze the files modified during the encryption burst and check the integrity of backups.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Document the negative findings. If specific users were identified in the cohort but had benign activity, note them for future reference.
```
→ end
