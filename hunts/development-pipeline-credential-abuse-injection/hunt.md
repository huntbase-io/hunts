---
analysis: A simple alert on a GitHub push is too noisy; this hunt correlates push
  activity with rare secret enumeration and high-risk sign-in context across two telemetry
  surfaces (GitHub API and Entra/Okta auth), using stack-counting to isolate anomalous
  developer behavior.
blind_spots:
- id: limited-diff-visibility
  question: what specific lines of code were modified
  requires: direct repository audit of file diffs
  risk: The GitHub audit log confirms a push occurred but does not contain the code
    diff itself, requiring manual inspection.
  stage: initial-access-supply-chain-injection
- id: mfa-bypass-visibility
  question: whether the actor bypassed MFA or used a session cookie hijack
  requires: hb_auth_signin mfa result detail
  risk: Sophisticated session hijacking may appear as a successful login without explicit
    MFA failure logs.
  stage: credential-access-developer-harvesting
coverage:
- stage: credential-access-developer-harvesting
  status: covered
  steps:
  - secret-access-prevalence
  - high-risk-authentication
- stage: initial-access-supply-chain-injection
  status: covered
  steps:
  - github-push-events
  - manual-commit-review
- reason: "Belongs to another part of the 'ESET APT Activity Report Q2 2026\u2013\
    Q3 2026' series."
  stage: initial-access-mdaemon-exploit
  status: out_of_scope
- reason: "Belongs to another part of the 'ESET APT Activity Report Q2 2026\u2013\
    Q3 2026' series."
  stage: initial-access-recruitment-phishing
  status: out_of_scope
- reason: "Belongs to another part of the 'ESET APT Activity Report Q2 2026\u2013\
    Q3 2026' series."
  stage: execution-backdoor-deployment
  status: out_of_scope
- reason: "Belongs to another part of the 'ESET APT Activity Report Q2 2026\u2013\
    Q3 2026' series."
  stage: defense-evasion-llm-safety-trigger
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Compromise of the software supply chain through developer credential
    theft allows for stealthy, persistent access that can affect every downstream
    user; identifying these injections before they reach production is a critical
    security obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised developer credentials to harvest sensitive
  repository secrets and inject malicious code into private source code repositories,
  bypassing standard CI/CD protections.
labels:
- hunt
- attack.t1555
- attack.t1195
- attack.t1078
- credential access
- defense evasion
- execution
- initial access
name: Development Pipeline Credential Abuse and Injection
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: hunt-standard
    type: number
  scope_actors:
    default: []
    description: Developer accounts identified in the lead query to pivot on.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: lead-pivot
    type: list[string]
  target_repos:
    default: []
    description: Critical repositories to focus on; empty means all.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: inventory
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q2-2026-q3-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on critical repositories that control deployment pipelines
  and prioritize accounts with maintainer access.
references:
- name: "ESET APT Activity Report Q2 2026\u2013Q3 2026"
  url: https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q2-2026-q3-2026/
related:
- hunt: initial-access-mdaemon-exploit
  reason: Mail server exploitation is a separate initial access vector mentioned in
    the same report.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: MDaemon Mail Server Exploitation
    observables:
    - MDaemon mail servers
    - HELLAGE backdoor
    - HELLTAG backdoor
    slug: initial-access-mdaemon-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Recruitment-Themed Phishing
    observables:
    - recruitment-themed social engineering
    - AI-generated phishing lure images
    slug: initial-access-recruitment-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Developer Credential Harvesting
    observables:
    - harvesting developer credentials
    - private source code repositories
    slug: credential-access-developer-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Source Code Injection
    observables:
    - injecting malicious code into public and private source code repositories
    slug: initial-access-supply-chain-injection
    tactic: initial-access
    techniques:
    - T1195
  - name: Backdoor Execution
    observables:
    - PteroBox
    - PteroPSDoor
    - Rezzuar
    - HELLAGE
    - HELLTAG
    slug: execution-backdoor-deployment
    tactic: execution
    techniques:
    - T1059
  - name: AI Guardrail Evasion Decoy
    observables:
    - decoy request for instructions on building a nuclear weapon into a script comment
    slug: defense-evasion-llm-safety-trigger
    tactic: defense-evasion
    techniques:
    - T1027
  summary: APT groups in Q2-Q3 2026 targeted development environments via credential
    harvesting and source code injection, exploited MDaemon mail servers to deploy
    backdoors, and utilized AI-generated content and decoys for social engineering
    and defense evasion. Notable activities include North Korean DeceptiveDevelopment's
    supply chain attacks and the first documented destructive operation by Belarus-aligned
    FrostyNeighbor.
series:
  index: 1
  slug: eset-apt-activity-report-q2-2026-q3-2026
  title: "ESET APT Activity Report Q2 2026\u2013Q3 2026"
  total: 2
severity: critical
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


# Development Pipeline Credential Abuse and Injection

This hunt targets the code-injection tradecraft observed in North Korea-aligned campaigns where compromised developer credentials grant access to repositories and secrets. The hunt identifies unauthorized repository modifications in the GitHub audit log and correlates them with anomalous sign-in patterns and secret enumeration. The flow isolates the supply chain risk at the point of injection and pivots to identity telemetry to confirm the compromise.

## github-push-events
<!-- Detect unauthorized pushes and repository updates -->
Detect unauthorized pushes or commits to source code repositories.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, target_repos=target_repos)
~~~yaml
expected: Push events from developer accounts, particularly those associated with
  critical production repositories. Silence suggests no modifications were logged
  via the GitHub API.
reads:
- actor_user_name
- resource_name
- src_endpoint_ip
- api_operation
- user_agent
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT actor_user_name, resource_name, src_endpoint_ip, api_operation, user_agent, time FROM hb_cloud_api_activity WHERE provider = 'github' AND activity_id = 3 AND (LOWER(api_operation) LIKE '%push%' OR LOWER(api_operation) LIKE '%update%' OR LOWER(api_operation) LIKE '%commit%') AND ('{{target_repos}}' = '' OR instr(',' || '{{target_repos}}' || ',', ',' || resource_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-behavior
<!-- Corroborate pushes with identity and secret access -->
parallel:
- → secret-access-prevalence
- → high-risk-authentication
join: → triage-session-compromise

## secret-access-prevalence
<!-- Prevalence of secret enumeration -->
Identify if the actors were reading repository secrets, highlighting users who perform these operations rarely.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_actors=scope_actors)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Developers reading repository secrets outside of standard automated patterns.
  Silence suggests no rare secret harvesting was detected.
prevalence:
  by: actor_user_name
  key:
  - api_operation
  rare_below: 3
reads:
- api_operation
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT LOWER(api_operation) AS operation, COUNT(DISTINCT actor_user_name) AS users, COUNT(*) AS calls, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE provider = 'github' AND activity_id = 2 AND (LOWER(api_operation) LIKE '%secret%' OR LOWER(api_operation) LIKE '%key%' OR LOWER(api_operation) LIKE '%token%') AND ('{{scope_actors}}' = '' OR instr(',' || '{{scope_actors}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY operation HAVING users <= 3 ORDER BY users ASC
```

## high-risk-authentication
<!-- High-risk authentication context -->
Check for sign-in anomalies such as high risk levels or unusual source IPs for the actors in question.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, scope_actors=scope_actors)
~~~yaml
expected: A sign-in with an 'atRisk' state or a failed authentication attempt preceding
  the push activity. Silence means no anomalous logins were detected.
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- risk_state
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, risk_state, status, time FROM hb_auth_signin WHERE provider IN ('github', 'azure_ad', 'okta') AND (risk_state != 'none' OR status != 'Success') AND ('{{scope_actors}}' = '' OR instr(',' || '{{scope_actors}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-session-compromise
<!-- Triage session compromise -->
```agent target=hunter
cite: required
context:
- github-push-events
- secret-access-prevalence
- high-risk-authentication
max_iterations: 6
objective: Determine if pushes were performed by developer accounts that also show
  signs of rare secret harvesting or high-risk authentication. Look for time-boxed
  correlation between a risky authentication event and the first secret-access or
  push event for each account.
success_criteria: A verdict of malicious or suspicious for any account involved in
  push events from anomalous sources or after rare secret access.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one developer account" (confidence: high, judge=hunter)
then: → revoke-developer-sessions
indeterminate: → manual-commit-review
unavailable: → manual-commit-review (blind_spot: limited-diff-visibility)
else: → close-out

## revoke-developer-sessions
<!-- Revoke developer sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active Personal Access Tokens (PATs) and web sessions for the compromised developer account in GitHub.
```
→ manual-commit-review

## manual-commit-review
<!-- Manual commit and diff review -->
```manual target=analyst
Manually inspect the repository diffs for the commits identified in the lead query. Look for unauthorized changes to build scripts or dependencies.
```
→ close-out

## close-out
<!-- Record remediation and findings -->
```manual target=analyst
Document the scope of the exposure and the remediation steps taken. Determine if the lead query warrants a permanent detection rule.
```
→ end
