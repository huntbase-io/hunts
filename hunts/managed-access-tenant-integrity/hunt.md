---
analysis: A single rule cannot correlate a third-party sign-in, an unattended remote
  support session, and autonomous script behavior. This hunt uses a phased flow to
  build behavioral context across identity, process, and script surfaces.
blind_spots:
- id: session-truncation
  question: What were the full operational parameters of the agent script?
  requires: untruncated hb_script_activity logs
  risk: Large scripts may be truncated, hiding the final C2 destinations or specific
    data exfiltration targets.
  stage: autonomous-agent-execution
- id: no-policy-audit
  question: Which specific configuration change enabled the unauthorized cross-tenant
    sign-in?
  requires: Entra ID configuration audit logs
  risk: We see the sign-in (aftermath) but not the initial policy manipulation that
    enabled the persistent access.
  stage: tenant-governance-abuse
coverage:
- stage: tenant-governance-abuse
  status: covered
  steps:
  - unusual-cross-tenant-signins
- stage: remote-support-persistence
  status: covered
  steps:
  - unattended-remote-support
- stage: autonomous-agent-execution
  status: covered
  steps:
  - autonomous-agent-scripts
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - multi-hop-proxy-dns
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protecting tenant boundaries and ensuring remote support tools are
    not abused is a critical security obligation as organizations adopt autonomous
    AI agents.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence via cross-tenant delegated administration
  or unattended remote support, subsequently deploying autonomous agents that communicate
  through multi-hop proxies.
labels:
- hunt
- attack.t1078.004
- attack.t1219
- attack.t1059
- attack.t1090.003
name: Managed Access and Tenant Integrity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: standard-retention
    type: number
  proxy_relay_suffixes:
    default:
    - tor2web.org
    - onion.pet
    - onion.ws
    - onion.link
    description: Known public web-to-Tor proxy relay suffixes.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: known-tor-relays
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty to scan
      the entire estate.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: analyst-scoping
    type: list[host]
  third_party_providers:
    default:
    - aws
    - okta
    - palo alto
    description: Identity or security providers expected to show external actor activity.
    from:
      kind: article
      observed: '2026-08-27'
      ref: msrc-blog-aug-2026
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/27/whats-new-in-microsoft-security-august-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying hosts with Intune-managed support software
  to narrow the behavioral scope, then pivots to global identity logs.
references:
- name: "What\u2019s new in Microsoft Security: August 2026"
  url: https://www.microsoft.com/en-us/security/blog/2026/08/27/whats-new-in-microsoft-security-august-2026/
related:
- hunt: shadow-tenant-discovery
  reason: This hunt focuses on the abuse of existing cross-tenant access, not the
    initial creation of shadow tenants.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Cross-Tenant Identity Manipulation
    observables:
    - Shadow-tenant creation or discovery
    - Unauthorized cross-tenant delegated administration
    - Identity policy configuration drift in Entra ID
    - Sign-ins from unmanaged or third-party tenants
    slug: tenant-governance-abuse
    tactic: persistence
    techniques:
    - T1078.004
  - name: Unattended Support Session Abuse
    observables:
    - Windows Unattended Support with Remote Sign-In sessions without user interaction
    - Unauthorized device renames via Windows Autopilot device association
    - Remote sessions bypassing compliance checks
    - Intune-initiated remote support binary execution
    slug: remote-support-persistence
    tactic: persistence
    techniques:
    - T1219
  - name: Unauthorized AI Agent Activity
    observables:
    - AI agent-initiated actions without explicit user approval
    - Autonomous agent script execution
    - Usage of high-privilege permissions by agentic identities
    - Agent-driven process launches on endpoints
    slug: autonomous-agent-execution
    tactic: execution
    techniques:
    - T1059
  - name: Obfuscated C2 via Multi-hop Proxy
    observables:
    - DNS queries for .onion domains
    - Network connections to Tor onion routing nodes
    - Chained proxy traffic originating from autonomous processes
    - Traffic to known multi-hop proxy exit points
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves the compromise of cloud identity foundations and
    the abuse of administrative remote management features to maintain persistence.
    Adversaries leverage autonomous AI agents to execute unauthorized actions and
    employ multi-hop proxies to obfuscate command-and-control traffic across hybrid
    environments.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Managed Access and Tenant Integrity

This hunt validates tenant boundaries and the integrity of remote access features. It identifies unauthorized cross-tenant sign-ins, abuses of Windows Unattended Support sessions, and autonomous agent behavior that uses multi-hop proxies for command-and-control. The phased flow correlates early access and persistence indicators with follow-on execution and network obfuscation.

## scope-managed-endpoints
<!-- Identify managed support assets -->
Find hosts where Intune or remote-support tools are installed to scope the behavior hunt.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts running managed support software. Silence means no such
  software is inventoried.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%intune%' OR LOWER(package_name) LIKE '%remote help%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-access-persistence
<!-- Analyze early stage access and persistence -->
parallel:
- → unusual-cross-tenant-signins
- → unattended-remote-support
join: → agent-early-triage

## unusual-cross-tenant-signins
<!-- Unusual cross-tenant sign-ins -->
Find rare sign-ins from integrated third-party providers where an adversary may operate shadow tenants.

```sqlite target=identity role=baseline params=(third_party_providers=third_party_providers, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare sign-ins to specific hosts from external providers. Silence means no
  such sign-ins were recorded.
prevalence:
  by: dst_endpoint_name
  key:
  - actor_user_name
  - provider
  rare_below: 3
reads:
- actor_user_name
- provider
- dst_endpoint_name
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, provider, COUNT(DISTINCT dst_endpoint_name) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE instr(',' || '{{third_party_providers}}' || ',', ',' || LOWER(provider) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, provider HAVING host_count <= 3
```

## unattended-remote-support
<!-- Unattended remote support activity -->
Identify remote support sessions launched on endpoints, focusing on those that bypass user confirmation.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process logs for remote support binaries. Silence suggests no such sessions
  occurred on the scoped hosts.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%remotehelp%' OR LOWER(process_name) LIKE '%quickassist%' OR LOWER(process_name) LIKE '%remotesignin%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage early access evidence -->
```agent target=hunter
cite: required
context:
- unusual-cross-tenant-signins
- unattended-remote-support
max_iterations: 4
objective: Identify hosts where a third-party sign-in was followed by the execution
  of a remote support binary, citing temporal and user overlap.
success_criteria: Confirm malicious or suspicious persistence indicators per host.
tools:
- endpoint
- identity
```

## parallel-follow-on
<!-- Analyze post-persistence agent behavior -->
parallel:
- → autonomous-agent-scripts
- → multi-hop-proxy-dns
join: → agent-final-synthesis

## autonomous-agent-scripts
<!-- Autonomous agent script execution -->
Identify AI-agent framework keywords in script blocks executed after the suspected access events.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script contents suggesting autonomous automation or agent-driven logic.
  Silence means no matching keywords were captured.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%langchain%' OR LOWER(script_content) LIKE '%autogen%' OR LOWER(script_content) LIKE '%openai%' OR LOWER(script_content) LIKE '%agent%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## multi-hop-proxy-dns
<!-- Multi-hop proxy DNS lookups -->
Identify DNS lookups for .onion domains or known public web-to-Tor proxy relays.

```sqlite target=endpoint role=enrichment params=(proxy_relay_suffixes=proxy_relay_suffixes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries targeting obfuscation infrastructure. Silence provides evidence
  of absence for these specific domains.
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.onion' OR instr(',' || '{{proxy_relay_suffixes}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-synthesis
<!-- Final synthesis of agent behavior -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- autonomous-agent-scripts
- multi-hop-proxy-dns
max_iterations: 5
objective: Determine if any host identified as suspicious in the access phase also
  exhibits autonomous script execution or proxy-related DNS lookups.
success_criteria: A final verdict citing the correlated chain of events across all
  surfaces.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final synthesis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: session-truncation)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified by the agent and revoke any active third-party provider sessions for the involved identity.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the script contents and process command lines cited by the agent. Verify if the automation matches any approved administrative scripts or AI agent deployments.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the identified indicators and any legitimate automation scripts to be added to the exclusions list.
```
→ end
