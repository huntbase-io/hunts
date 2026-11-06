---
analysis: A single rule on mailbox rule creation generates excessive noise from IT
  automation. This hunt correlates sign-in anomalies with post-auth cloud behavior
  and endpoint DNS telemetry to distinguish BEC from routine admin work.
blind_spots:
- id: missing-cloud-audit-logs
  question: Whether the attacker created rules inside the mailbox.
  requires: hb_cloud_api_activity for provider m365
  risk: An attacker retains persistence while the hunt only observes the initial sign-in.
  stage: persistence-mailbox-manipulation
- id: ephemeral-infrastructure
  question: Whether the host contacted a domain not in the phishing_domains list.
  requires: hb_dns_activity
  risk: Infrastructure rotation makes domain matching an unreliable single signal.
  stage: credential-access-token-theft
coverage:
- stage: credential-access-token-theft
  status: covered
  steps:
  - scoping-anomalous-auth
  - phishing-dns-check
- stage: persistence-mailbox-manipulation
  status: covered
  steps:
  - mailbox-persistence-ops
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: initial-access-phishing-lures
  status: out_of_scope
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: execution-clickfix-win-r
  status: out_of_scope
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: persistence-rmm-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''Huntress Tragic Quadrant: Top Cyber Threats
    Wrecking Businesses'' series.'
  stage: c2-infostealer-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Session token theft via AiTM and Device Code flows is a prevalent
    threat that bypasses traditional MFA. Detecting the subsequent mailbox manipulation
    is critical to preventing financial fraud.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed multi-factor authentication via session token
  theft or device code phishing and established persistence by modifying mailbox rules
  to hide intercepted communications.
labels:
- hunt
- attack.t1566
- attack.t1557
- attack.t1528
- attack.t1137.005
- attack.t1564.008
- command and control
- credential access
- execution
- initial access
- persistence
name: Cloud Identity Hijacking and Mailbox Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - claude.ai
    - railway.app
    - railway.com
    description: Domains hosting token-harvesting infrastructure or malicious artifacts.
    from:
      kind: article
      observed: '2026-10-01'
      ref: Huntress Tragic Quadrant
    type: list[domain]
  rule_operations:
    default:
    - new-inboxrule
    - set-inboxrule
    - update-inboxrule
    description: Cloud API operations related to mailbox rule modification.
    from:
      kind: manual
      observed: '2026-10-01'
      ref: M365 Unified Audit Log Operations
    type: list[string]
  scope_hosts:
    default: []
    description: A list of hostnames to narrow the DNS investigation; leave empty
      to hunt across the entire estate.
    type: list[host]
  suspicious_folders:
    default:
    - rss feeds
    - archive
    - conversation history
    description: Target folders used for stealthy mail redirection.
    from:
      kind: article
      observed: '2026-10-01'
      ref: Huntress Tragic Quadrant
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value users such as executives and finance personnel. The
  analyst should populate scope_hosts from the workstations identified in the scoping
  query to improve DNS correlation precision.
references:
- name: 'Huntress Tragic Quadrant: Top Cyber Threats Wrecking Businesses'
  url: https://www.huntress.com/blog/huntress-tragic-quadrant-cyber-threats
related:
- hunt: initial-access-phishing-lures
  reason: Phishing delivery via email is out of scope for this post-authentication
    identity hunt.
  relation: out-of-scope-alternative
- hunt: endpoint-social-engineering-malicious-execution
  relation: follows
scenario:
  stages:
  - name: Social Engineering with AI-Tuned Lures
    observables:
    - claude.ai
    - Railway
    - Cisco redirect URLs
    - Trend Micro redirect URLs
    - Mimecast redirect URLs
    - AI-tuned lures
    - fake document shares
    - service agreement lures
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: User-Driven ClickFix Command Execution
    observables:
    - Win+R
    - Windows Run box
    - Human Verification prompt
    - multi-stage infection command
    slug: execution-clickfix-win-r
    tactic: execution
    techniques:
    - T1204.001
  - name: Adversary-in-the-Middle and Device Code Token Harvesting
    observables:
    - session token
    - device code login flow
    - access token
    - Microsoft 365 login page impersonation
    slug: credential-access-token-theft
    tactic: credential-access
    techniques:
    - T1557
    - T1528
  - name: Persistence via Rogue RMM Installation
    observables:
    - rogue RMM tool
    - Remote Monitoring and Management tools
    slug: persistence-rmm-abuse
    tactic: persistence
    techniques:
    - T1219
  - name: Stealthy Mailbox Rule Manipulation
    observables:
    - inbox rules
    - RSS Feeds folder
    - Archive folders
    slug: persistence-mailbox-manipulation
    tactic: persistence
    techniques:
    - T1137.005
    - T1564.008
  - name: Infostealer and RAT Deployment
    observables:
    - LummaC2
    - SectopRAT
    - FakeAgent
    slug: c2-infostealer-deployment
    tactic: command-and-control
    techniques:
    - T1555
    - T1071.001
  summary: The Huntress Tragic Quadrant outlines common 2026 threats targeting SMBs,
    where attackers use AI-enhanced social engineering (ClickFix, fake lures) and
    trusted platforms (Claude.ai) to deliver infostealers and rogue RMM tools. The
    campaign progresses from initial access via session token theft (AiTM) or user-driven
    command execution to persistence through mailbox manipulation and remote management
    software abuse.
series:
  index: 2
  slug: huntress-tragic-quadrant-top-cyber-threats-wrecking-businesses
  title: 'Huntress Tragic Quadrant: Top Cyber Threats Wrecking Businesses'
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


# Cloud Identity Hijacking and Mailbox Persistence

This hunt identifies session hijacking and subsequent mailbox persistence in Microsoft 365 environments. It begins by scoping anomalous sign-ins that use the device code flow or bypass MFA. The hunt then corroborates these leads by checking for the creation of stealthy inbox rules targeting low-visibility folders and DNS activity toward known token-harvesting infrastructure. An agent correlates these signals to confirm active account takeover and business email compromise preparation.

## scoping-anomalous-auth
<!-- Scoping anomalous sign-ins -->
Identify successful M365 sign-ins that used the device code flow or lacked recorded MFA prompts.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of user accounts and source IPs associated with non-standard sign-ins.
  Silence suggests no easily detectable token-theft or device-code flow attempts occurred.
reads:
- actor_user_name
- src_endpoint_ip
- src_endpoint_hostname
- event_type
- mfa
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, src_endpoint_ip, src_endpoint_hostname, event_type, mfa, time FROM hb_auth_signin WHERE provider = 'm365' AND status_id = 1 AND (LOWER(event_type) LIKE '%device%code%' OR (mfa IS NULL OR mfa = 'false')) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## parallel-corroboration
<!-- Corroborate on cloud and endpoint -->
parallel:
- → mailbox-persistence-ops
- → phishing-dns-check
join: → triage-identity-threat

## mailbox-persistence-ops
<!-- Mailbox rule and folder manipulation -->
Identify the creation of inbox rules or folder interactions that redirect mail for persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, rule_operations=rule_operations, suspicious_folders=suspicious_folders)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Audit events showing rule creation or movements to low-visibility folders.
  Frequent administrative updates are common; look for one-off rules on recently accessed
  accounts.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  - resource_uid
  rare_below: 2
reads:
- actor_user_name
- api_operation
- resource_name
- resource_uid
- src_endpoint_ip
- time
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, api_operation, resource_name, resource_uid, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (instr(',' || '{{rule_operations}}' || ',', ',' || LOWER(api_operation) || ',') > 0 OR instr(',' || '{{suspicious_folders}}' || ',', ',' || LOWER(resource_uid) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## phishing-dns-check
<!-- Phishing and AI platform DNS check -->
Corroborate identity activity by looking for resolutions to known token-harvesting domains on the scoped hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Any resolution to claude.ai or railway.app from a host associated with the
  anomalous sign-in. Silence means no DNS resolution for these specific domains occurred.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookups, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-identity-threat
<!-- Triage identity threat -->
```agent target=hunter
cite: required
context:
- scoping-anomalous-auth
- mailbox-persistence-ops
- phishing-dns-check
max_iterations: 6
objective: Determine if any user account shows a progression from a suspicious sign-in
  method to mailbox rule persistence. Cite the specific sign-in source IP and the
  name of any created inbox rules.
success_criteria: A verdict per user with clear row citations.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one user account" (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-cloud-audit-logs)
else: → close-out

## revoke-sessions
<!-- Revoke user sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active refresh tokens and initiate a password reset for the affected users in M365.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the inbox rules for the flagged users; check for actions moving mail with keywords like payment or invoice to the RSS Feeds folder.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the results; if false positives were high, refine the rule_operations parameter to exclude service accounts.
```
→ end
