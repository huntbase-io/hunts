---
analysis: "A standard detection rule alerts on a single login failure; this hunt performs\
  \ a multi-surface stack-count of successful logons per IP, pivots to network flow\
  \ to identify jump boxes, and corroborates with DNS for automation tools\u2014an\
  \ analysis requiring the context of all three surfaces to distinguish malicious\
  \ persistence from legitimate corporate proxies."
blind_spots:
- id: incomplete-identity-logs
  question: Are there identities compromised on providers not currently reporting
    to hb_auth_signin?
  requires: Unified logs from every identity provider (SaaS/Cloud)
  risk: Adversary persistence on unmonitored platforms remains invisible.
  stage: session-token-persistence
- id: unmanaged-device-activity
  question: Is the adversary using compromised credentials from unmanaged devices
    that do not have the EDR agent?
  requires: Egress proxy logs or CASB telemetry
  risk: We would see the sign-in density but lose the correlation to an internal jump
    box/automation node.
  stage: session-token-persistence
coverage:
- stage: session-token-persistence
  status: covered
  steps:
  - high-density-auth-ips
  - outbound-to-vps-ips
  - automation-tool-dns
- reason: Belongs to the phishing-specific hunt in this series.
  stage: initial-access-phishing-mitm
  status: out_of_scope
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: automated-c2-and-workflows
  status: out_of_scope
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: adversary-discovery-scanning
  status: out_of_scope
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: browser-extension-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Tracking high-volume session maintenance is critical for containing
    large-scale identity thefts; identifying the underlying VPS infrastructure allows
    for proactive blocking across the enterprise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is maintaining persistent access to a large volume of compromised
  identities using automated workflows (Make.com, Telegram) originating from VPS infrastructure
  like Virtuo, visible as high-density account access from single external IPs.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1176
name: Identity Hijacking and Session Maintenance from Adversary VPS
parameters:
  adversary_vps_ips:
    default: []
    description: IP addresses of suspected adversary infrastructure; populate this
      with IPs discovered in the high-density-auth-ips step.
    from:
      kind: article
      observed: '2024-09-09'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[ip]
  automation_domains:
    default:
    - make.com
    - api.telegram.org
    - censys.io
    - toolbaz.com
    - docsbot.ai
    description: Domains associated with the adversary's automated workflows.
    from:
      kind: article
      observed: '2024-09-09'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  min_user_threshold:
    default: '5'
    description: Minimum number of unique user accounts from a single IP to trigger
      suspicion.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; populate this with hosts found communicating
      with VPS IPs to narrow the DNS hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially encompass the entire estate to identify all high-density
  auth events, then narrow to hosts involved in network pivots to reduce noise in
  the DNS results.
references:
- name: "Huntress \u2014 An attacker blunder gave us a look into their operations"
  url: https://www.huntress.com/blog/rare-look-inside-attacker-operation
related:
- hunt: initial-access-phishing-mitm
  reason: Capturing credentials via MITM (Evilginx) is a distinct precursor phase
    handled by its own hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and MitM Setup
    observables:
    - Evilginx
    - make.com
    - phishing messages
    slug: initial-access-phishing-mitm
    tactic: initial-access
    techniques:
    - T1566
  - name: Session Token Theft and Maintenance
    observables:
    - 12651980 CANADA INC
    - VIRTUO
    - session token refreshing
    - 2471 unique identities
    slug: session-token-persistence
    tactic: credential-access
    techniques:
    - T1566
  - name: Automated C2 via Make.com and Telegram
    observables:
    - make.com
    - api.telegram.org
    - Telegram Bot APIs
    - webhooks
    slug: automated-c2-and-workflows
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Infrastructure Discovery via Censys
    observables:
    - censys.io
    - Censys search for Evilginx
    slug: adversary-discovery-scanning
    tactic: discovery
  - name: Malicious or Monitoring Extensions
    observables:
    - Malwarebytes Browser Guard
    - Chrome browser extensions
    slug: browser-extension-persistence
    tactic: persistence
    techniques:
    - T1176
  summary: An attacker operating from a jump box on the Virtuo AS infrastructure conducted
    large-scale identity compromise and session token theft. They leveraged automated
    workflows via Make.com and Telegram bots to manage their operations and used Censys
    to discover targets like running Evilginx instances.
series:
  index: 1
  slug: an-attacker-blunder-gave-us-a-look-into-their-operations
  title: An attacker blunder gave us a look into their operations
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Identity Hijacking and Session Maintenance from Adversary VPS

This hunt targets the persistence and command-and-control phase of a large-scale identity compromise. By identifying external VPS IPs that successfully authenticate into an unusually high number of unique user accounts, we can track automated session token maintenance. The hunt corroborates this by looking for internal hosts communicating with these same IPs or resolving domains for the automation tools used to manage these workflows, as reported in recent research on attacker blunders.

## scoping-hosts
<!-- Scope to devices of interest -->
Inventory available hosts to facilitate pivoting and filtering in network activity queries.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Empty indicates no devices have reported within the
  window.
reads:
- hostname
- last_seen
- os_name
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, os_name, platform, last_seen FROM hb_devices WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## high-density-auth-ips
<!-- Find high unique-user density IPs -->
Identify external IPs successfully logging into multiple unique accounts, indicating automated session maintenance infrastructure.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, min_user_threshold=min_user_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Source IPs associated with many unique accounts. IPs belonging to VPS providers
  like Virtuo are high-priority findings.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 10
reads:
- actor_user_name
- auth_protocol
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_users, COUNT(*) AS total_events, GROUP_CONCAT(DISTINCT auth_protocol) AS protocols, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_users >= {{min_user_threshold}} ORDER BY unique_users DESC
```

## corroboration-parallel
<!-- Corroborate identity signals with network telemetry -->
parallel:
- → outbound-to-vps-ips
- → automation-tool-dns
join: → triage-persistence

## outbound-to-vps-ips
<!-- Internal connections to suspected VPS IPs -->
Identify internal hosts communicating with the IPs flagged in the identity logs, pivoting on discovered IPs rather than static indicators.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, adversary_vps_ips=adversary_vps_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts in the estate interacting with the same IPs logging into many user
  accounts. This supports the 'jump box' hypothesis.
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, protocol, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE (instr(',' || '{{adversary_vps_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, process_name
```

## automation-tool-dns
<!-- DNS lookups for automation platforms -->
Find DNS activity for Make.com or Telegram from hosts of interest to confirm the use of automated adversary workflows while reducing noise.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, automation_domains=automation_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Lookups for automation sites from specific hosts, particularly those seen
  in the VPS connection results. Silence means no automation tool usage was visible
  on those hosts.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{automation_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookups DESC
```

## triage-persistence
<!-- Synthesize identity and network evidence -->
```agent target=hunter
cite: required
context:
- high-density-auth-ips
- outbound-to-vps-ips
- automation-tool-dns
max_iterations: 4
objective: Determine if the identified IPs are adversary persistence nodes. Weigh
  the density of accounts against the presence of outbound connections or automation
  domain DNS lookups from internal hosts.
success_criteria: A verdict of malicious | suspicious | benign citing specific IPs
  and hostnames.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one IP or host" (confidence: high, judge=hunter)
then: → containment-action
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-identity-logs)
else: → analyst-close-out

## containment-action
<!-- Isolate suspect jump boxes -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the internal hosts identified as malicious. Revoke all active session tokens for the user accounts identified in the auth-density triage.
```
→ analyst-review

## analyst-review
<!-- Analyst verification and identity cleanup -->
```manual target=analyst
Verify the AS ownership of the high-density IPs. If they belong to Virtuo or other hosting providers, confirm the malicious status. Cross-reference the identified users with critical business roles.
```
→ end

## analyst-close-out
<!-- Close out hunt -->
```manual target=analyst
Document the number of compromised accounts identified. If results were benign corporate proxies, adjust min_user_threshold for future runs.
```
→ end
