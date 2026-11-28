---
analysis: A detection rule alerts on the domain visit; this hunt is required because
  it joins intent with host vulnerability and the statistical rarity of authentication
  behavior. A single rule cannot weigh whether a phishing hit on a high-risk host
  with rare MFA-less logins constitutes a confirmed breach.
blind_spots:
- id: insufficient-proxy-visibility
  owner: Network Engineering
  question: Whether the user submitted credentials on the phishing subpath.
  remediation: Enable SSL decryption for known risky categories on the forward proxy.
  requires: hb_http_activity with decrypted SSL traffic
  risk: A domain-level hit is a lead, but without path visibility, we cannot distinguish
    a visit from a successful harvest.
  stage: initial-access-phishing-portals
- id: identity-log-gaps
  owner: Identity Team
  question: Whether the adversary used legacy protocols to bypass MFA.
  remediation: Onboard domain controller logs into the identity surface via Silverfort
    connector.
  requires: hb_auth_signin including on-prem legacy logs
  risk: Silverfort context is high-quality, but if the hunt lacks visibility into
    on-prem DCs, legacy protocol abuse remains a blind spot.
  stage: credential-abuse-and-mfa-evasion
coverage:
- stage: initial-access-phishing-portals
  status: covered
  steps:
  - phishing-lead
  - agent-triage-lead
- stage: vulnerability-and-exposure-discovery
  status: covered
  steps:
  - vulnerability-lookup
- stage: credential-abuse-and-mfa-evasion
  status: covered
  steps:
  - rare-auth-anomalies
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: suspicious-cloud-runtime-execution
  status: out_of_scope
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: lateral-movement-segmentation-violation
  status: out_of_scope
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: data-encryption-for-impact
  status: out_of_scope
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: incident-alerting-and-response
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Initial access through identity-led phishing is a top priority; verifying
    targeted hosts are not vulnerable to follow-on exploitation reduces breach risk.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has harvested credentials through a phishing portal and is
  now using them to access vulnerable assets while attempting to evade multi-factor
  authentication.
labels:
- hunt
- attack.t1566
- attack.t1078
- attack.t1078.004
- execution
- impact
- initial access
- lateral movement
- persistence
name: Identity Access and Exposure Investigation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for phishing hits and authentication anomalies.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard-config
    type: number
  phishing_domains:
    default:
    - bottleneck.the
    description: Domains identified as Mokn-realistic phishing portals or known harvesting
      sites.
    from:
      kind: article
      observed: '2026-08-19'
      ref: sekoia-ai-soc-2026
    type: list[domain]
  target_hosts:
    default: []
    description: Target hostnames extracted from the phishing lead step to focus the
      expensive queries.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-pivot
    type: list[host]
  target_users:
    default: []
    description: Usernames extracted from the phishing lead step to focus authentication
      analysis.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-pivot
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with public-facing users and servers. Focus on assets with recent
  high-severity vulnerability findings reported by Holm Security.
references:
- name: 6 AI SOC Integrations Actually Worth Connecting
  url: https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting
related:
- hunt: suspicious-cloud-runtime-execution
  reason: This hunt confirms initial ingress; the follow-on hunt monitors what happens
    once the cloud identity is used for suspicious execution.
  relation: follows
scenario:
  stages:
  - name: Credential Harvesting via Phishing Portals
    observables:
    - bottleneck.the
    - Mokn authentication portals
    - Credential testing activity
    slug: initial-access-phishing-portals
    tactic: initial-access
    techniques:
    - T1566
  - name: Vulnerability and Exposure Discovery
    observables:
    - Holm Security vulnerability scans
    - Asset risk profiling
    - Exposed human assets
    slug: vulnerability-and-exposure-discovery
    tactic: initial-access
    techniques:
    - T1078
  - name: Credential Abuse and MFA Evasion
    observables:
    - Silverfort MFA decisions
    - Suspicious access patterns
    - Policy actions
    - Hybrid environment authentication logs
    slug: credential-abuse-and-mfa-evasion
    tactic: persistence
    techniques:
    - T1078
  - name: Suspicious Cloud Runtime Execution
    observables:
    - Upwind runtime workload monitoring
    - Process accessing sensitive resource
    - Anomalous cloud asset behavior
    slug: suspicious-cloud-runtime-execution
    tactic: execution
    techniques:
    - T1078
  - name: Lateral Movement across Segments
    observables:
    - Akamai Guardicore network traffic logs
    - Communication between isolated workloads
    - Zero Trust policy violations
    slug: lateral-movement-segmentation-violation
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Data Encryption for Impact
    observables:
    - Ransomware activity
    - Spyware delivery
    - Mass file modification
    slug: data-encryption-for-impact
    tactic: impact
    techniques:
    - T1486
  - name: Incident Alerting and Response
    observables:
    - ilert incident notifications
    - Slack notification webhooks
    - Teams alert messages
    - Voice call escalation
    slug: incident-alerting-and-response
    tactic: impact
    techniques:
    - T1486
  summary: An adversary leverages deceptive authentication portals to harvest credentials
    and identifies unpatched vulnerabilities across the attack surface. The campaign
    progresses to cloud runtime execution and lateral movement across microsegmented
    workloads, culminating in ransomware encryption and automated incident notification.
series:
  index: 1
  slug: 6-ai-soc-integrations-actually-worth-connecting
  title: 6 AI SOC Integrations Actually Worth Connecting
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Identity Access and Exposure Investigation

Identifies traffic to phishing portals and correlates hits with critical asset vulnerabilities and rare authentication anomalies to detect credential abuse or MFA evasion.

## phishing-lead
<!-- Traffic to phishing portals -->
Identify hosts and users interacting with known credential harvesting domains to establish a lead.

```sqlite target=web role=detection-candidate params=(phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: Hostnames and users visiting suspicious domains. Silence means no recorded
  interaction with the indicators.
reads:
- device_hostname
- actor_user_name
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, url_hostname, url_path, time FROM hb_http_activity WHERE LOWER(url_hostname) IN ('{{phishing_domains}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-lead
<!-- Evaluate phishing lead -->
```agent target=hunter
cite: required
context:
- phishing-lead
max_iterations: 3
objective: Determine if the observed phishing interactions are credible threats needing
  deeper investigation.
success_criteria: A verdict of investigate for any confirmed portal hits.
tools:
- endpoint
- identity
- web
```

## gate-decision
<!-- Gate on phishing -->
if~: "the agent verdict is to investigate for at least one host" (confidence: medium, judge=hunter)
then: → investigate-risk
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: insufficient-proxy-visibility)
else: → negative-close-out

## investigate-risk
<!-- Investigate exposure and anomalies -->
parallel:
- → vulnerability-lookup
- → rare-auth-anomalies
join: → final-triage

## vulnerability-lookup
<!-- Affected asset vulnerability findings -->
Correlate the phishing lead with host vulnerability using Holm Security data.

```sqlite target=endpoint role=enrichment params=(target_hosts=target_hosts)
~~~yaml
expected: Critical or High findings on the target host. Silence means no severe vulnerabilities
  are present.
reads:
- device_uid
- cve_uid
- severity
- title
- severity_id
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT v.device_uid, d.hostname, v.cve_uid, v.severity, v.title FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE v.severity_id >= 4 AND (('{{target_hosts}}' = '') OR (instr(',' || '{{target_hosts}}' || ',', ',' || d.hostname || ',') > 0))
```

## rare-auth-anomalies
<!-- Rare authentication anomalies -->
Identify rare login failures or successful logins without MFA to detect credential abuse.

```sqlite target=identity role=baseline params=(target_users=target_users, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare failure patterns or MFA bypasses for the user. Silence means the authentication
  pattern is fleet-wide noise.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - auth_protocol
  - status_detail
  rare_below: 3
reads:
- actor_user_name
- auth_protocol
- status_detail
- device_hostname
- time
- status_id
- mfa
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, auth_protocol, status_detail, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE (status_id = 2 OR (status_id = 1 AND (mfa = 'false' OR mfa IS NULL))) AND (('{{target_users}}' = '') OR (instr(',' || '{{target_users}}' || ',', ',' || actor_user_name || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, auth_protocol, status_detail HAVING host_count <= 2
```

## final-triage
<!-- Cross-surface triage -->
```agent target=hunter
cite: required
context:
- agent-triage-lead
- vulnerability-lookup
- rare-auth-anomalies
max_iterations: 6
objective: Determine if the harvested credentials target vulnerable assets with suspicious
  login patterns.
success_criteria: A per-host verdict weighing vulnerabilities against the phishing
  hit.
tools:
- endpoint
- identity
- web
```

## route-decision
<!-- Route on evidence -->
if~: "the final triage verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → isolate-and-suspend
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: identity-log-gaps)
else: → negative-close-out

## isolate-and-suspend
<!-- Isolate host and suspend account -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the involved host and suspend the user identity in the primary provider.
```
→ manual-review

## manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review correlated evidence: verify the phishing portal URL, specific vulnerabilities, and rarity of authentication events. Adjust detections based on findings.
```
→ end

## negative-close-out
<!-- Negative close-out -->
```manual target=analyst
Log the negative result; verify if blind spots significantly limited the search.
```
→ end
