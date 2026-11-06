---
analysis: 'A rule might flag discovery commands, but this hunt pivots between three
  signals: the remote support tool launch, external authentication from a suspicious
  tenant, and the execution of rare runtimes from user-writable paths. An analyst
  weighs these to confirm an incident.'
blind_spots:
- id: missing-endpoint-telemetry
  question: Whether Quick Assist was launched on unmanaged devices.
  requires: an endpoint agent on every host in scope
  risk: A user on a non-enrolled device could grant access that later pivots into
    the domain via identity infrastructure.
- id: teams-message-content
  question: What specifically was said in the Teams message.
  requires: Microsoft Teams audit log
  risk: The hunt relies on authentication patterns because direct social engineering
    content is not in endpoint telemetry.
  stage: teams-impersonation-phishing
coverage:
- stage: teams-impersonation-phishing
  status: covered
  steps:
  - external-teams-auth
- stage: remote-access-quick-assist
  status: covered
  steps:
  - scope-quick-assist
- stage: portable-runtime-staging
  status: covered
  steps:
  - kb-staging-creation
  - discovery-from-profile-runtimes
- stage: host-discovery
  status: covered
  steps:
  - discovery-from-profile-runtimes
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: ad-cs-assessment
  status: out_of_scope
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: ad-cs-certificate-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Social engineering via Teams bypasses email-based security. A user-approved
    remote session provides a high-privilege foothold; detecting the transition to
    runtime execution stops the attack before it targets identity infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has impersonated help desk staff via Microsoft Teams to establish
  a remote support session and execute portable runtimes from a user-writable directory
  to begin system discovery.
labels:
- hunt
- attack.t1566.003
- attack.t1566.004
- attack.t1219
- attack.t1036
- attack.t1059.003
- attack.t1059.007
- attack.t1016
- attack.t1057
- attack.t1082
- credential access
- discovery
- execution
- exfiltration
- initial access
name: Teams Impersonation and Portable Runtime Execution
parameters:
  discovery_commands:
    default:
    - ipconfig.exe
    - tasklist.exe
    - systeminfo.exe
    - net.exe
    - whoami.exe
    description: System discovery utilities (original filenames) used by the intruder.
    from:
      kind: article
      observed: '2026-10-30'
      ref: msrc-blog-2026-10-30
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  runtime_hashes:
    default:
    - 85b6c424117494d3056e88689dbc94c75e9afdb187a339714043aec0da109f17
    - f326201269f1ee2f803ae435317507263bb6e0dbfdeb70bd1bb5446e2e46f001
    - 06c5c14f043aee3bcc5843b5f50909623d5c9a6239a7c1fba9cddad4111469e7
    description: Known hashes for portable runtimes observed in the report.
    from:
      kind: article
      observed: '2026-10-30'
      ref: msrc-blog-2026-10-30
    type: list[hash]
  scope_hosts:
    default: []
    description: Hostnames to narrow the hunt, typically populated from the early
      access triage.
    type: list[host]
  staging_pattern:
    default: KB%
    description: SQL LIKE pattern for the attacker staging directory under user profiles.
    from:
      kind: article
      observed: '2026-10-30'
      ref: msrc-blog-2026-10-30
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize identifying any host that ran Quick Assist in the last 14 days.
  Filter on users who have not recently opened official support tickets.
references:
- name: "MSRC \u2014 From help desk impersonation to AD CS abuse"
  url: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
related:
- hunt: ad-cs-certificate-abuse-esc1-esc8
  reason: This hunt identifies the beachhead; the next hunt examines certificate issuance
    and relay behavior.
  relation: follows
scenario:
  stages:
  - name: Teams Helpdesk Impersonation
    observables:
    - onmicrosoft.com tenant names
    - support-oriented display names
    - Microsoft Teams messages and calls
    slug: teams-impersonation-phishing
    tactic: initial-access
    techniques:
    - T1566.003
    - T1566.004
  - name: Remote Support Hijack
    observables:
    - QuickAssist.exe
    - user-approved remote session
    slug: remote-access-quick-assist
    tactic: execution
    techniques:
    - T1219
  - name: Portable Runtime Staging
    observables:
    - KB-prefixed directory in user profile
    - archive in Downloads folder
    - renamed Bun executable
    - portable Python runtime
    - portable Java runtime
    slug: portable-runtime-staging
    tactic: execution
    techniques:
    - T1036
    - T1059.003
    - T1059.007
  - name: Host and Network Discovery
    observables:
    - ipconfig /all
    - tasklist
    - Windows version registry query
    slug: host-discovery
    tactic: discovery
    techniques:
    - T1016
    - T1057
    - T1082
  - name: AD CS Vulnerability Assessment
    observables:
    - LDAPS connections to domain infrastructure
    - SMB connections to domain infrastructure
    slug: ad-cs-assessment
    tactic: discovery
    techniques:
    - T1082
  - name: AD CS Privilege Escalation (ESC1/ESC8)
    observables:
    - ESC1 vulnerable template abuse
    - PetitPotam NTLM relay
    - Relay to AD CS Web Enrollment (ESC8)
    - PKINIT certificate-based Kerberos authentication
    slug: ad-cs-certificate-abuse
    tactic: credential-access
    techniques:
    - T1649
    - T1557
    - T1190
  - name: Privileged Data Exfiltration
    observables:
    - Exfiltration via privileged identity excluded from containment
    slug: data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1567.002
  summary: Threat actors use Microsoft Teams to impersonate help desk staff and persuade
    users to grant remote access via Quick Assist. From this foothold, they execute
    scripts via portable runtimes to discover and abuse AD CS configurations, specifically
    ESC1 and ESC8, to escalate privileges and obtain persistent domain access.
series:
  index: 1
  slug: from-help-desk-impersonation-to-ad-cs-abuse-investigating-esc1-and-esc8-intrusion-paths
  title: 'From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8
    intrusion paths'
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
tlp: clear
type: investigation
---


# Teams Impersonation and Portable Runtime Execution

This hunt identifies the transition from external social engineering to hands-on-keyboard access. It follows a phased approach: first, it identifies hosts with recent Quick Assist activity or cross-tenant Teams authentications. Second, it pivots to those hosts to find portable runtimes (Python, Bun, or Java) launched from user-profile staging directories that then execute system discovery commands. This behavior-based approach detects the execution environment and session context rather than relying solely on file indicators.

## scope-quick-assist
<!-- Scope hosts using Quick Assist -->
Identify hosts that have recently run Quick Assist, the primary vector for hands-on-keyboard access in this campaign.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts where Quick Assist was launched. None means no Quick Assist sessions
  occurred on managed hosts in this window.
reads:
- device_hostname
- user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, user_name, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%\\quickassist.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name
```

## early-access-parallel
<!-- Examine initial access and staging -->
parallel:
- → external-teams-auth
- → kb-staging-creation
join: → agent-triage-access

## external-teams-auth
<!-- Teams authentication from external tenants -->
Find users authenticating via Teams where the home tenant does not match the resource tenant, indicating cross-tenant contact.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A sign-in from an external tenant. This identifies the social engineering
  contact point.
reads:
- device_hostname
- actor_user_name
- home_tenant_id
- resource_tenant_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, actor_user_name, home_tenant_id, resource_tenant_id, time FROM hb_auth_signin WHERE provider = 'm365' AND home_tenant_id != resource_tenant_id AND time >= datetime('now', '-{{lookback_days}} days')
```

## kb-staging-creation
<!-- KB-prefixed staging directory creation -->
Find the creation of the specific staging directories used to host portable runtimes under user profiles.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, staging_pattern=staging_pattern)
~~~yaml
expected: New folders created under a user profile matching the staging prefix. None
  means no such folders were detected.
reads:
- device_hostname
- file_path
- file_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, file_path, file_name, actor_user_name, time FROM hb_file_activity WHERE activity_id = 1 AND LOWER(file_path) LIKE '%\\users\\%' AND LOWER(file_name) LIKE LOWER('{{staging_pattern}}') AND file_type = 'directory' AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-access
<!-- Weigh initial access evidence -->
```agent target=hunter
cite: required
context:
- scope-quick-assist
- external-teams-auth
- kb-staging-creation
max_iterations: 4
objective: Identify hosts where a remote session was established followed by suspicious
  file staging or external authentication. Provide a list of hostnames to focus the
  next behaviour search.
success_criteria: A per-host verdict of suspicious or benign, citing specific events.
tools:
- endpoint
- identity
```

## discovery-from-profile-runtimes
<!-- Discovery commands from profile-path runtimes -->
Identify discovery commands that processes in staging directories launch.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, discovery_commands=discovery_commands, runtime_hashes=runtime_hashes)
~~~yaml
expected: System discovery processes like ipconfig or tasklist running from a portable
  runtime located in a user profile.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- process_hash_sha256
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_original_file_name, process_hash_sha256, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\\users\\%' OR LOWER(process_path) LIKE '%\\appdata\\%') AND (instr(',' || '{{discovery_commands}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{runtime_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-behavior
<!-- Assess behavior and execution -->
```agent target=hunter
cite: required
context:
- agent-triage-access
- discovery-from-profile-runtimes
max_iterations: 5
objective: Determine if the discovery commands originated from runtimes staged during
  the social engineering phase identified by the previous agent.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-triage-behavior verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: missing-endpoint-telemetry)
else: → close-out-hunt

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke any active Teams sessions for the user. Collect the binary and scripts found in the KB-prefixed directory for analysis.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Investigation -->
```manual target=analyst
Examine the file creation events in the identified KB-prefixed directory. Verify if scripts were executed. Pivot to hb_network_connection to see if LDAPS or SMB connections were made to domain controllers.
```
→ end

## close-out-hunt
<!-- Close Out Hunt -->
```manual target=analyst
If results were benign, document Quick Assist usage. If suspicious, ensure escalation for AD CS abuse investigation.
```
→ end
