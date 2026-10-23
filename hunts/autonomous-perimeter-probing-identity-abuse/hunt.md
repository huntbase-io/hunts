---
analysis: A single WAF rule might block a specific user agent or SQLi string, but
  this hunt correlates the volumetric perimeter probing with host-level process behavior
  and simultaneous pressure on the identity layer (MFA fatigue), which traditional
  single-surface rules cannot associate.
blind_spots:
- id: no-identity-telemetry
  question: whether the probing IPs targeted users on platforms not currently enrolled
    in the sign-in surface
  requires: hb_auth_signin with MFA failure details from all SSO providers
  risk: A coordination between probing and identity pressure would be invisible if
    the identity provider is not reporting to the lake.
  stage: identity-access-phishing
- id: encrypted-payload-blindness
  question: whether specific SQL injection or exploit payloads were present in the
    HTTP POST body
  requires: Decrypted HTTP body inspection in hb_http_activity
  risk: Volumetric probing is seen, but the intent (e.g., SQLi vs. directory traversal)
    may be obscured if the payload resides only in the request body.
  stage: exploit-public-facing-app
coverage:
- stage: exploit-public-facing-app
  status: covered
  steps:
  - high-volume-bot-probing
  - suspicious-web-children
- stage: identity-access-phishing
  status: covered
  steps:
  - identity-mfa-fatigue
- reason: Belongs to another part of the 'One breach, please, and make no mistakes'
    series.
  stage: persistence-and-traversal
  status: out_of_scope
- reason: Belongs to another part of the 'One breach, please, and make no mistakes'
    series.
  stage: c2-dns-beaconing
  status: out_of_scope
- reason: Belongs to another part of the 'One breach, please, and make no mistakes'
    series.
  stage: exfiltration-and-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Autonomous agents accelerate the speed of probing and exploitation;
    a negative result across internet-facing assets confirms that the organization
    is not currently being targeted by high-volume automated campaigns.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated swarm of AI agents is relentlessly probing public-facing
  applications for vulnerabilities while simultaneously attempting to fatigue employees
  with MFA prompts to secure initial access.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1133
- command and control
- impact
- initial access
- persistence
name: Autonomous Perimeter Probing and Identity Abuse
parameters:
  bot_ua_fragment:
    default: '%python%'
    description: SQL LIKE fragment to identify automated tool user agents.
    from:
      kind: article
      observed: '2026-10-07'
      ref: talos-agentic-threats
    type: string
  lookback_days:
    default: '7'
    description: Days of history to examine for automated probing spikes.
    from:
      kind: article
      observed: '2026-10-07'
      ref: talos-agentic-threats
    type: number
  probing_ips:
    default: []
    description: Source IPs identified in the first step to correlate with identity
      fatigue.
    from:
      kind: manual
      ref: analyst-entry
    type: list[ip]
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping query to focus the process behavior
      analysis.
    from:
      kind: manual
      ref: analyst-entry
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
rationale: Start with internet-facing web servers and DMZ hosts. If the estate is
  large, narrow the hunt to hosts reporting critical vulnerabilities in hb_vulnerability_finding.
references:
- name: "Talos \u2014 One breach, please, and make no mistakes"
  url: https://blog.talosintelligence.com/one-breach-please-and-make-no-mistakes/
related:
- hunt: lateral-movement-by-autonomous-agents
  reason: Once an agentic swarm gains access, it communicates internally and moves
    laterally, requiring internal network and process analysis.
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
  index: 1
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


# Autonomous Perimeter Probing and Identity Abuse

This hunt identifies the early 'noisy' phase of an agentic attack by detecting volumetric HTTP probing from non-browser user agents such as Python, curl, or wget. It then fans out to evaluate the behavior of web server processes on those targeted hosts and checks for concurrent MFA fatigue indicators originating from the same source infrastructure. An agent weighs these signals to distinguish between background internet noise and a coordinated, multi-stage autonomous campaign targeting both the organization's perimeter and its identity layer.

## high-volume-bot-probing
<!-- High-volume bot-like HTTP probing -->
Identify hosts receiving excessive traffic from automated tools, which often precedes an agentic exploit attempt.

```sqlite target=web role=scoping params=(bot_ua_fragment=bot_ua_fragment, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hostnames and source IPs showing high-volume requests from non-browser
  tools. Silence means no such volumetric probing occurred from these toolsets.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 3
reads:
- device_hostname
- url_hostname
- user_agent
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, url_hostname, user_agent, src_endpoint_ip, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(user_agent) LIKE '{{bot_ua_fragment}}' OR LOWER(user_agent) LIKE '%curl%' OR LOWER(user_agent) LIKE '%wget%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, user_agent, src_endpoint_ip HAVING request_count > 100 ORDER BY request_count DESC
```

## corroboration-fanout
<!-- Corroborate on two surfaces at once -->
parallel:
- → suspicious-web-children
- → identity-mfa-fatigue
join: → agent-triage

## suspicious-web-children
<!-- Suspicious child processes from web servers -->
Find shells or discovery tools launched by web server processes on the probed hosts, indicating successful exploitation.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Shells or reconnaissance tools spawned by a web server. Silence indicates
  no obvious command execution followed the probing phase.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%w3wp%' OR LOWER(parent_process_name) LIKE '%tomcat%') AND (LOWER(process_name) IN ('cmd.exe', 'powershell.exe', 'sh', 'bash', 'whoami', 'id', 'curl', 'wget')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## identity-mfa-fatigue
<!-- Identify MFA fatigue from probing IPs -->
Determine if the same source infrastructure used for probing is also attacking the identity layer via MFA prompt bombing.

```sqlite target=identity role=triage params=(probing_ips=probing_ips, lookback_days=lookback_days)
~~~yaml
expected: Spikes in authentication failures from the same IPs identified in the probing
  phase. Silence indicates the probing and identity attacks are not coordinated from
  the same source.
reads:
- actor_user_name
- src_endpoint_ip
- status_detail
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT actor_user_name, src_endpoint_ip, status_detail, COUNT(*) AS fail_count FROM hb_auth_signin WHERE status_id = 2 AND ('{{probing_ips}}' = '' OR instr(',' || '{{probing_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING fail_count > 15 ORDER BY fail_count DESC
```

## agent-triage
<!-- Evaluate coordinated agentic behavior -->
```agent target=hunter
cite: required
context:
- high-volume-bot-probing
- suspicious-web-children
- identity-mfa-fatigue
max_iterations: 6
objective: Determine if any host targeted in the probing phase shows suspicious process
  execution and if the same source IPs are responsible for MFA prompt-bombing patterns.
success_criteria: A verdict of malicious, suspicious, or benign citing correlated
  rows across at least two surfaces.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on agent verdict -->
if~: "the agent-triage verdict is malicious for at least one host or source IP" (confidence: high, judge=hunter)
then: → isolate-target
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: no-identity-telemetry)
else: → close-out

## isolate-target
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any active sessions for users identified in the MFA fatigue triage.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation and tuning -->
```manual target=analyst
Review the cited rows. Verify if the volumetric probing aligns with a known vulnerability scan or a legitimate automated process. Update the bot_ua_fragment parameter if new agents were observed.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the hosts targeted and whether any successful exploitation was suspected. Record any blind spots identified during the run.
```
→ end
