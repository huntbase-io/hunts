---
analysis: A single rule might fire on a GPO change, but it cannot correlate it with
  an hourly DNS burst and a sudden file-touch burst on the same host to distinguish
  a swarm from an administrator.
blind_spots:
- id: limited-endpoint-telemetry
  owner: Infrastructure Team
  question: whether a process on an unmanaged host is encrypting files
  remediation: Audit EDR deployment across sensitive database and model tiers.
  requires: EDR coverage on 100% of servers
  risk: A swarm could target a server segment without endpoint logging, leaving only
    AD audit logs visible.
  stage: exfiltration-and-impact
- id: dns-over-https-coordination
  owner: Network Security Team
  question: whether coordination traffic is hidden in HTTPS streams
  remediation: Enforce local DNS resolvers and block external DoH endpoints.
  requires: TLS inspection of DoH traffic
  risk: Agents using DoH bypass the hb_dns_activity surface, making the coordination
    layer invisible to this hunt.
  stage: c2-dns-beaconing
coverage:
- stage: persistence-and-traversal
  status: covered
  steps:
  - ad-gpo-persistence-lead
- stage: c2-dns-beaconing
  status: covered
  steps:
  - dns-coordination-beaconing
- stage: exfiltration-and-impact
  status: covered
  steps:
  - mass-file-system-impact
- reason: Belongs to another part of the 'One breach, please, and make no mistakes'
    series.
  stage: exploit-public-facing-app
  status: out_of_scope
- reason: Belongs to another part of the 'One breach, please, and make no mistakes'
    series.
  stage: identity-access-phishing
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Autonomous agents compress attack timelines from weeks to hours;
    early detection of their internal footprint prevents catastrophic data loss and
    encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An autonomous agent swarm is maintaining persistence through Active Directory
  GPO modifications while coordinating data theft via high-volume DNS beaconing and
  rapid file encryption.
labels:
- hunt
- attack.t1133
- attack.t1071.004
- attack.t1486
- attack.t1566
- command and control
- impact
- initial access
- persistence
name: Agentic Swarm Traversal and C2 Coordination
parameters:
  lookback_days:
    default: '7'
    description: Days of historical telemetry to examine.
    type: number
  min_dns_hourly:
    default: '1000'
    description: Hourly threshold for DNS queries to a single domain to flag as coordination.
    type: number
  scope_hosts:
    default: []
    description: Limit analysis to specific domain controllers or sensitive file servers.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/one-breach-please-and-make-no-mistakes/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the lookback and scope on domain controllers and high-value servers
  hosting proprietary data or AI models as identified in the article.
references:
- name: "Talos \u2014 One breach, please, and make no mistakes"
  url: https://blog.talosintelligence.com/one-breach-please-and-make-no-mistakes/
related:
- hunt: agentic-initial-access-phishing
  reason: This hunt targets post-compromise traversal, while entry via spoofed identities
    is handled separately.
  relation: out-of-scope-alternative
- hunt: autonomous-perimeter-probing-identity-abuse
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - High volume of SQL injection attempts
    - Requests from Python, curl, or wget user agents
    - Spike in WAF alerts
    - Automated traffic hitting unpatched vulnerabilities
    slug: exploit-public-facing-app
    tactic: initial-access
    techniques:
    - T1190
  - name: Identity Access and Phishing
    observables:
    - Phishing invoices sent at volume
    - HR onboarding requests for fabricated identities
    - MFA prompt-bombing (push/SMS fatigue)
    - VPN access attempts with valid credentials
    slug: identity-access-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1133
  - name: Internal Persistence and Traversal
    observables:
    - Malicious Group Policy Object (GPO) deployment
    - Active Directory modifications
    - Spike in east-west network traffic
    - Rapid rotation of stolen credentials
    - Worm-like traversal through internal segments
    slug: persistence-and-traversal
    tactic: persistence
    techniques:
    - T1133
  - name: Application Layer C2
    observables:
    - DNS beaconing for command-and-control
    - Anomalous DNS query volume
    - Traffic to external infrastructure used for agent coordination
    slug: c2-dns-beaconing
    tactic: command-and-control
    techniques:
    - T1071
  - name: Data Exfiltration and Impact
    observables:
    - Theft of AI model weights
    - Theft of customer data
    - Encryption of local and remote drives
    - Spam and package stuffing on public repositories (e.g., RubyGems)
    slug: exfiltration-and-impact
    tactic: impact
    techniques:
    - T1486
  summary: Autonomous AI agent swarms automate and compress the attack lifecycle into
    hours, utilizing high-volume automated probing, phishing, and vulnerability exploitation.
    Once inside, the agents adapt in real-time to traverse the network via Active
    Directory and DNS-based command-and-control to exfiltrate AI model weights or
    encrypt data.
series:
  index: 2
  slug: one-breach-please-and-make-no-mistakes
  title: One breach, please, and make no mistakes
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


# Agentic Swarm Traversal and C2 Coordination

This hunt identifies the footprint of an AI-driven swarm that use automation to traverse networks at machine speed. It looks for the early noisy signs of agentic activity: unauthorized Active Directory policy modifications, followed by a parallel check for anomalous DNS coordination traffic and mass file system interactions typical of data exfiltration or encryption for impact.

## ad-gpo-persistence-lead
<!-- Suspicious GPO and AD Entity Modifications -->
Identify unauthorized modifications to Group Policy Objects or sensitive AD containers that indicate an agent swarm establishing persistent internal traversal.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicating creation or update of GPO attributes by unexpected service
  accounts or newly seen administrative principals. Silence suggests no active AD-level
  persistence was attempted.
reads:
- device_hostname
- entity_name
- actor_user_name
- actor_user_uid
- attribute_name
- attribute_value
- time
silence: not_evidence_of_absence
source: hb_entity_management
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, entity_name, actor_user_name, actor_user_uid, attribute_name, attribute_value, time FROM hb_entity_management WHERE activity_id IN (1, 3) AND (LOWER(entity_name) LIKE '%\cn=policies%' OR LOWER(entity_name) LIKE '%\cn=gpo%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-telemetry-scan
<!-- Parallel Triage of C2 and Impact -->
parallel:
- → dns-coordination-beaconing
- → mass-file-system-impact
join: → agent-triage-swarm

## dns-coordination-beaconing
<!-- Anomalous DNS Query Volume -->
Detect high-frequency DNS query bursts that indicate agent coordination or C2 heartbeats using DNS as an transport.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days, min_dns_hourly=min_dns_hourly)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A single host querying the same domain over 1000 times in an hour. Low volume
  suggest the swarm is dormant or using stealthier protocols.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as query_count, strftime('%Y-%m-%d %H', time) as burst_hour FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, burst_hour HAVING query_count > {{min_dns_hourly}}
```

## mass-file-system-impact
<!-- High-Density File Activity Bursts -->
Identify processes interacting with an unusually large number of distinct files in a short window, suggesting exfiltration or encryption.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A process touching 500+ unique files in an hour. Excludes common system
  processes to minimize noise.
reads:
- device_hostname
- process_name
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) as unique_files_touched, strftime('%Y-%m-%d %H', time) as burst_hour FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (1, 3, 4) AND LOWER(process_name) NOT LIKE '%backup%' AND LOWER(process_name) NOT LIKE '%msmpeng%' AND LOWER(process_name) NOT LIKE '%search%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, burst_hour HAVING unique_files_touched > 500
```

## agent-triage-swarm
<!-- Weigh Coordinated Swarm Evidence -->
```agent target=hunter
cite: required
context:
- ad-gpo-persistence-lead
- dns-coordination-beaconing
- mass-file-system-impact
max_iterations: 6
objective: Determine if the evidence indicates a coordinated agent swarm. Prioritize
  hosts where at least two of the three telemetry leads overlap in time, as isolated
  GPO changes or high-density file touches can occur during normal administration.
success_criteria: Verdicts citing rows where AD modifications correlate with DNS or
  file bursts on the same host or for the same user account.
tools:
- endpoint
```

## decision-on-verdict
<!-- Route on Swarm Verdict -->
if~: "the agent triage indicates a high-confidence coordinated intrusion involving AD persistence and anomalous volume on a single host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: limited-endpoint-telemetry)
else: → close-out-negative

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the device_hostname identified in the malicious verdict. Request explicit approval before isolating any domain controller.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the cited DNS coordination domains and file bursts. Pivot to hb_auth_signin using the actor_user_name from the AD modifications to check for other compromised sessions.
```
→ close-out-negative

## close-out-negative
<!-- Close Out and Document -->
```manual target=analyst
Record the findings. If no activity was found, update the thresholds in the parameters if the hunt produced excessive noise from legitimate administrative work.
```
→ end
