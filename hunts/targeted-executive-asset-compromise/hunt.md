---
analysis: "A rule fires on the Run value; the hunt asks whether the binary is rare,\
  \ whether it runs, and whether it talks \u2014 three surfaces, one decision."
blind_spots:
- id: mfa-telemetry-gap
  question: Whether a sign-in event successfully satisfied MFA requirements
  requires: Reliable MFA status code in hb_auth_signin
  risk: If the identity provider returns NULL or 'other' for MFA status, the gate
    might fail to identify an MFA bypass, missing the initial access event.
  stage: initial-access-executive-targeting
- id: command-line-truncation
  question: The specific script or encoded payload executed via LoTL utilities
  requires: Full process_cmd_line length from endpoint agent
  risk: Adversaries often use very long encoded commands; truncation by the EDR surface
    may prevent keyword matching or prevalence analysis from identifying the malicious
    intent.
  stage: evasive-lotl-execution
coverage:
- stage: initial-access-executive-targeting
  status: covered
  steps:
  - lead-executive-auth
  - assess-lead-auth
- stage: evasive-lotl-execution
  status: covered
  steps:
  - rare-lotl-behavior
- stage: sensitive-data-collection
  status: covered
  steps:
  - sensitive-keyword-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Executives are high-yield targets whose compromise can lead to material
    impact; a dedicated monthly hunt provides the 'magnifying glass' required to catch
    stealthy APT-style attacks that standard alerts miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary targets high-value executive assets using whaling and MFA
  bypass to access sensitive corporate roadmaps and financial data via stealthy living-off-the-land
  techniques.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1059
- attack.t1530
- attack.t1213
- collection
- execution
- initial access
name: Detection of Targeted Executive Asset Compromise
parameters:
  executive_usernames:
    default:
    - ceo@example.com
    - cfo@example.com
    - cto@example.com
    - board-chair@example.com
    description: Usernames of the principals enrolled in the executive protection
      program.
    from:
      kind: manual
      observed: '2026-09-29'
      ref: executive-asset-registry
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of authentication and activity logs to analyze; 30 is typical
      for ETD monthly reports.
    from:
      kind: manual
      observed: '2026-09-29'
      ref: monthly-hunt-cycle
    type: number
  lotl_tools:
    default:
    - powershell.exe
    - certutil.exe
    - mshta.exe
    - wscript.exe
    - bitsadmin.exe
    - curl.exe
    - vssadmin.exe
    description: Legitimate system utilities frequently repurposed for evasive execution.
    from:
      kind: article
      observed: '2026-09-29'
      ref: talos-lotl-intelligence
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames identified in the lead query to scope the behavioral
      fan-out.
    from:
      kind: manual
      observed: '2026-09-29'
      ref: analyst-triage
    type: list[host]
  sensitive_keywords:
    default:
    - merger
    - acquisition
    - financial
    - roadmap
    - payroll
    - board
    - strategy
    description: Keywords that indicate access to high-value executive-level data.
    from:
      kind: manual
      observed: '2026-09-29'
      ref: corporate-high-value-keywords
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/securing-the-keys-to-the-kingdom-announcing-executive-threat-detection/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope to the designated high-value principals (CEO, CFO, Board members).
  Use the identified source IP and device_hostname from authentication logs to narrow
  the expensive process and file queries.
references:
- name: 'Securing the keys to the kingdom: Announcing Executive Threat Detection'
  url: https://blog.talosintelligence.com/securing-the-keys-to-the-kingdom-announcing-executive-threat-detection/
related:
- hunt: whaling-phishing-infrastructure-monitoring
  reason: Monitoring for external phishing infrastructure targeting the organization
    requires external DNS and brand monitoring surfaces not covered here.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Executive Targeted Initial Access
    observables:
    - phishing kits designed to bypass MFA
    - zero-day exploits
    - vulnerable browser versions
    - outdated software
    - highly targeted whaling campaigns
    slug: initial-access-executive-targeting
    tactic: initial-access
    techniques:
    - T1190
    - T1566
  - name: Stealthy LoTL Execution
    observables:
    - living-off-the-land techniques
    - use of legitimate system tools to hide tracks
    - anomalous process behavior
    slug: evasive-lotl-execution
    tactic: execution
    techniques:
    - T1059
  - name: Sensitive Data Collection
    observables:
    - access to sensitive financial data
    - access to intellectual property
    - access to strategic roadmap communications
    slug: sensitive-data-collection
    tactic: collection
    techniques:
    - T1530
    - T1213
  summary: Sophisticated threat actors target executive-level assets using personalized
    phishing and zero-day exploitation to bypass traditional enterprise defenses.
    Once access is gained, they employ stealthy living-off-the-land (LoTL) techniques
    to maintain a persistent presence and exfiltrate high-yield corporate data, including
    financial records and intellectual property.
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


# Detection of Targeted Executive Asset Compromise

Sophisticated actors target executive accounts as high-yield entry points into the corporate network. This hunt implements the Executive Threat Detection methodology: first, the hunt performs a low-cost audit of executive authentication patterns. If the lead agent identifies anomalies like MFA bypass or geolocational mismatches, the hunt gates into an expensive behavioral analysis phase. During this phase, the hunt stack-counts living-off-the-land utility usage and monitors for sensitive keyword access (e.g., 'merger', 'financials') specifically on the hosts associated with the executive's session. Finally, an agent differentiates routine executive travel or administrative tasks from a targeted, long-term breach.

## lead-executive-auth
<!-- Lead: Executive Authentication Anomalies -->
Identify successful executive logins to establish a set of beachhead hosts for behavioral analysis.

```sqlite target=identity role=scoping params=(executive_usernames=executive_usernames, lookback_days=lookback_days)
~~~yaml
expected: A list of successful login events per executive. No results suggest no activity
  in the window.
reads:
- actor_user_name
- src_endpoint_ip
- mfa
- auth_protocol
- status_detail
- device_hostname
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, mfa, auth_protocol, status_detail, device_hostname, dst_endpoint_name, time FROM hb_auth_signin WHERE instr(',' || '{{executive_usernames}}' || ',', ',' || actor_user_name || ',') > 0 AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## assess-lead-auth
<!-- Assess lead for sign-in risk -->
```agent target=hunter
cite: required
context:
- lead-executive-auth
max_iterations: 3
objective: 'Review executive authentication events for anomalies: logins without MFA,
  unusual source countries, or protocols not typically used by these users. Explicitly
  generate the list of target hostnames from the lead-executive-auth results to populate
  the scope_hosts parameter for the subsequent parallel-deep-dive.'
success_criteria: A per-session assessment identifying which assets require deeper
  inspection and a clear list of target hostnames.
tools:
- endpoint
- identity
```

## gate-on-suspicion
<!-- Gate on Authentication Suspicion -->
if~: "the assess-lead-auth agent identifies at least one suspicious sign-in event for an enrolled executive" (confidence: medium, judge=hunter)
then: → parallel-deep-dive
indeterminate: → monthly-cadence-report
unavailable: → monthly-cadence-report (blind_spot: mfa-telemetry-gap)
else: → monthly-cadence-report

## parallel-deep-dive
<!-- Behavioral Deep-Dive -->
parallel:
- → rare-lotl-behavior
- → sensitive-keyword-access
join: → triage-combined-evidence

## rare-lotl-behavior
<!-- Rare LoTL Utility Usage -->
Find living-off-the-land tools running with command lines unique to the fleet, indicating tailored adversary execution.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lotl_tools=lotl_tools, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A set of rare process command lines. Silence over the window provides evidence
  of absence for common LoTL patterns.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- process_name
- device_hostname
- user_name
- on_disk
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT LOWER(process_cmd_line) AS cmd, process_name, device_hostname, user_name, on_disk, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{lotl_tools}}' || ',', ',' || LOWER(REPLACE(process_name, RTRIM(process_name, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.'), '')) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd, process_name, device_hostname, user_name, on_disk
```

## sensitive-keyword-access
<!-- Sensitive Keyword Data Access -->
Identify access to high-value files that an adversary would target following an executive account takeover.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, sensitive_keywords=sensitive_keywords, lookback_days=lookback_days)
~~~yaml
expected: Access to files matching corporate risk keywords on the scoped hosts.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, activity_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (instr(',' || '{{sensitive_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR instr(',' || '{{sensitive_keywords}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-combined-evidence
<!-- Synthesize Executive Breach Evidence -->
```agent target=hunter
cite: required
context:
- assess-lead-auth
- rare-lotl-behavior
- sensitive-keyword-access
max_iterations: 6
objective: Determine if the suspicious login established a beachhead for the observed
  LoTL behavior and subsequent sensitive data access. Distinguish between legitimate
  administrative activity and adversary operations targeting executive data.
success_criteria: A final verdict citing the rare command lines and keyword-matching
  file paths.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Final Verdict -->
if~: "the triage-combined-evidence agent returns a malicious verdict for any executive asset" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-incident-review
unavailable: → analyst-incident-review
else: → monthly-cadence-report

## isolate-host
<!-- Isolate Compromised Asset -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified workstation and revoke all active cloud/SaaS sessions for the affected executive account.
```
→ analyst-incident-review

## analyst-incident-review
<!-- Analyst Incident Review -->
```manual target=analyst
Review the triage verdict and cited rows. If a targeted intrusion is confirmed, escalate to an Emergency Response engagement via the Talos IR portal immediately.
```
→ end

## monthly-cadence-report
<!-- Monthly Cadence Reporting -->
```manual target=analyst
Log the hunt results, including any baseline anomalies that were assessed as benign, into the Monthly ETD Report. Include strategic recommendations for hardening the executive environment.
```
→ end
