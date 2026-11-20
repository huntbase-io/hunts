---
analysis: A simple rule might catch rundll32.exe with a DLL; this hunt pivots from
  an anomalous sign-in to a rare process to mass file operations, requiring an analyst
  and agent to correlate three distinct telemetry surfaces.
blind_spots:
- id: missing-auth-logs
  question: whether a user signed in via a provider not currently integrated
  requires: hb_auth_signin coverage for all identity providers
  risk: A sign-in on an unmonitored provider would bypass the lead query, preventing
    the gated investigation from starting.
  stage: credential-access-compromised-accounts
- id: no-process-visibility
  question: whether a LOLBin was used on a host without an agent
  requires: hb_process_activity on all workstations
  risk: Attackers can hide within unmonitored hosts; file operations may still alert
    us, but the source process would remain unknown.
  stage: defense-evasion-lolbin-proxy
- id: encryption-entropy-blindspot
  question: whether the file writes are actually encrypted content
  requires: file content entropy calculation
  risk: A high count of file writes can be benign (e.g., updates or backups); without
    entropy, we rely on count alone as a behavioral proxy.
  stage: impact-ransomware-encryption
coverage:
- reason: Matches anomalous authentication leads to subsequent host activity.
  stage: credential-access-compromised-accounts
  status: covered
  steps:
  - auth-lead-query
  - evaluate-lead
- reason: Identifies signed binaries proxying malicious payloads.
  stage: defense-evasion-lolbin-proxy
  status: covered
  steps:
  - lolbin-execution
- reason: Detects the high-frequency file touches characteristic of ransomware impact.
  stage: impact-ransomware-encryption
  status: covered
  steps:
  - encryption-patterns
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ransomware represents a critical risk to business continuity. Identifying
    the transition from credential abuse to malicious endpoint activity before full
    encryption is complete provides the only window for effective containment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used stolen credentials to gain initial access and is
  now using signed system binaries to proxy execution and encrypt files across the
  estate.
labels:
- hunt
- attack.t1078
- attack.t1218
- attack.t1486
- defense evasion
- impact
- initial access
name: Credential-driven LOLBin Proxying and Ransomware
parameters:
  file_op_threshold:
    default: '500'
    description: Number of file creates or renames per host in a one-hour window that
      triggers suspicion of mass encryption.
    from:
      kind: manual
      observed: '2026-11-02'
      ref: Huntress Blog
    type: number
  lolbin_names:
    default:
    - rundll32.exe
    - mshta.exe
    - certutil.exe
    - regsvr32.exe
    - vssadmin.exe
    - powershell.exe
    description: List of system binaries often used as proxies or for ransomware preparation.
    from:
      kind: manual
      observed: '2026-11-02'
      ref: Huntress Blog
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-02'
      ref: Huntress Blog
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the expensive investigation.
    from:
      kind: manual
      observed: '2026-11-02'
      ref: Huntress Blog
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/what-is-threat-hunting
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with network and remote interactive logons. Focus on servers and
  domain-admin workstations where impact is highest.
references:
- name: "Huntress \u2014 Threat Hunting: What It Is, How It Works, & Why It Matters"
  url: https://www.huntress.com/blog/what-is-threat-hunting
related:
- hunt: lateral-movement-rdp-abuse
  reason: This hunt focuses on direct ransomware impact after a breach, not the step-by-step
    lateral movement via RDP.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Sign-in via Stolen Credentials
    observables:
    - Sign-in from unusual source IP
    - Successful authentication using established user accounts
    - Anomalous geographic login patterns
    slug: credential-access-compromised-accounts
    tactic: initial-access
    techniques:
    - T1078
  - name: System Binary Proxy Execution
    observables:
    - Execution of signed Windows binaries (e.g., rundll32.exe, mshta.exe, certutil.exe)
      with malicious command line arguments
    - Unusual parent-child process relationships involving system tools
    - Loading of unsigned or suspicious modules by trusted binaries
    slug: defense-evasion-lolbin-proxy
    tactic: defense-evasion
    techniques:
    - T1218
  - name: Data Encrypted for Impact
    observables:
    - Massive file renaming activity
    - High-volume file write and delete operations
    - Presence of ransomware notes in multiple directories
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: This intrusion scenario involves an attacker using stolen credentials to
    gain initial access before leveraging native Windows binaries to proxy the execution
    of malicious code. The final stage of the attack involves the deployment of ransomware
    to encrypt local data for impact.
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


# Credential-driven LOLBin Proxying and Ransomware

This hunt follows a gated flow to first identify anomalous successful sign-ins as a cheap lead. If an account shows signs of takeover, the hunt opens an expensive search for behavioral evidence: the use of signed system binaries (LOLBins) to proxy malicious execution and high-volume file operations characteristic of ransomware encryption. An agent then correlates the initial access with the endpoint activity to isolate the host before encryption completes.

## auth-lead-query
<!-- Suspicious successful sign-ins -->
Identify successful authentications from network or remote interactive sessions as a lead for potential credential abuse.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of successful logons. Silence means no network-based logons occurred
  in the window.
reads:
- actor_user_name
- device_hostname
- logon_type
- src_endpoint_ip
- status_code
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, logon_type, status_code, status_id, time FROM hb_auth_signin WHERE status_id = 1 AND logon_type IN ('Network', 'Remote Interactive') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate sign-in lead -->
```agent target=hunter
cite: required
context:
- auth-lead-query
max_iterations: 3
objective: Examine the sign-in results and identify any accounts or source IPs that
  appear anomalous for the environment.
success_criteria: A per-host verdict of suspicious or benign.
tools:
- endpoint
- identity
```

## gate-decision
<!-- Gate: Proceed to investigation? -->
if~: "the evaluate-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → investigate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-auth-logs)
else: → close-out

## investigate-host
<!-- Fan-out: Investigate endpoint behavior -->
parallel:
- → lolbin-execution
- → encryption-patterns
join: → final-triage

## lolbin-execution
<!-- Proxied system binary execution -->
Identify LOLBins running with arguments typical of malicious payload delivery or defense evasion.

```sqlite target=endpoint role=detection-candidate params=(lolbin_names=lolbin_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Signed binaries with complex command lines. Silence proves no targeted LOLBin
  execution matched these patterns on the scoped hosts.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE instr(',' || '{{lolbin_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(process_cmd_line) LIKE '%.dll%' OR LOWER(process_cmd_line) LIKE '%http%' OR LOWER(process_cmd_line) LIKE '%-enc%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## encryption-patterns
<!-- High-volume file operations -->
Identify mass renames or writes that characterize ransomware encryption.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days, file_op_threshold=file_op_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Hosts with hundreds or thousands of file operations in a one-hour window.
  Silence proves no mass file activity occurred on monitored hosts.
prevalence:
  by: device_hostname
  key:
  - device_hostname
  rare_below: 2
reads:
- activity_id
- activity_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, activity_name, strftime('%Y-%m-%d %H', time) AS hour_bin, COUNT(*) AS file_ops FROM hb_file_activity WHERE activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, activity_name, hour_bin HAVING file_ops > {{file_op_threshold}} ORDER BY file_ops DESC
```

## final-triage
<!-- Correlate authentication and endpoint behavior -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- lolbin-execution
- encryption-patterns
max_iterations: 5
objective: 'Determine if any host shows the complete pattern: successful anomalous
  authentication followed by proxy binary execution and/or mass file operations.'
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-process-visibility)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to prevent further file encryption or lateral movement. Revoke the credentials for the identified compromised account.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the correlated evidence from authentication, process activity, and file operations. If malicious, ensure isolation was completed and initiate the full ransomware recovery playbook.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. If the sign-in was suspicious but no endpoint activity followed, consider monitoring the account for future anomalies.
```
→ end
