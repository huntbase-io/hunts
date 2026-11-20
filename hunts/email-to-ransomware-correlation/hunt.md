---
analysis: A single rule might flag a risky sign-in or a mass file change, but rarely
  correlates them with a specific email delivery event. This hunt uses cross-surface
  context (Mail + Identity + Endpoint) to distinguish ransomware from legitimate batch
  file processing.
blind_spots:
- id: missing-m365-logs
  owner: Cloud Security Team
  question: whether the phishing email was received by a user not currently being
    audited
  remediation: Ensure M365 UAL is enabled and ingested for all licensed users.
  requires: Full M365 Unified Audit Log ingestion
  risk: The initial vector may be invisible, preventing the identification of the
    full attack chain.
  stage: initial-access-email-threats
- id: encryption-threshold
  owner: Endpoint Engineering
  question: whether ransomware is encrypting files at a rate below 100 files per lookback
    window
  remediation: Implement entropy-based detection for file writes to identify encryption
    regardless of volume.
  requires: hb_file_activity with higher resolution
  risk: Stealthy ransomware that encrypts files slowly over a long period may bypass
    the mass-modification threshold.
  stage: impact-ransomware-encryption
coverage:
- stage: initial-access-email-threats
  status: covered
  steps:
  - identify-anomalous-access
  - examine-phishing-delivery
- stage: impact-ransomware-encryption
  status: covered
  steps:
  - detect-mass-encryption
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ransomware represents a critical risk to business continuity; correlating
    initial access with final impact confirms the effectiveness of security controls
    and identifies successful breaches.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established initial access via a phishing email, resulting
  in an anomalous sign-in and subsequent mass file encryption by a non-system process.
labels:
- hunt
- attack.t1566
- attack.t1486
- impact
- initial access
- microsoft-365
name: Email-to-Ransomware Attack Correlation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the entire
      estate.
    type: list[host]
  scope_users:
    default: []
    description: List of usernames to focus the investigation on.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-joins-microsoft-integrated-cloud-email-security-ices-ecosystem
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on users with existing identity risk flags or those who have recently
  reported phishing. Expand to all hosts if a cluster of mass encryption events is
  observed.
references:
- name: Proofpoint Joins Microsoft Integrated Cloud Email Security (ICES) Ecosystem
  url: https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-joins-microsoft-integrated-cloud-email-security-ices-ecosystem
related:
- hunt: lateral-movement-discovery
  reason: This hunt focuses on the initial infection and encryption impact; the lateral
    movement stages between them require separate monitoring of hb_auth_signin and
    hb_smb_activity.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and BEC Delivery
    observables:
    - phishing emails
    - business email compromise (BEC) attempts
    - malicious links
    - www.proofpoint.com
    slug: initial-access-email-threats
    tactic: initial-access
    techniques:
    - T1566
  - name: Ransomware Data Encryption
    observables:
    - ransomware activity
    - unauthorized file encryption
    - data unavailability
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Microsoft and Proofpoint have integrated their security platforms to provide
    layered defense against email-based threats including phishing, business email
    compromise, and ransomware. The integration pushes Proofpoint's API-based detections
    into the Microsoft Defender portal to centralize visibility for security analysts
    investigating initial access and subsequent impacts.
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
  microsoft-365:
    category: siem
    huntbase:
      product: microsoft-365
    name: microsoft 365
tlp: clear
type: investigation
---


# Email-to-Ransomware Attack Correlation

This hunt correlates initial delivery telemetry from Microsoft 365 mail services with endpoint-based file and process activity to identify the full progression of email-borne ransomware campaigns. By linking anomalous authentication events and email reception with subsequent mass file modifications, the hunt identifies the 'patient zero' and the scope of impact. The hunt follows a funnel approach, starting with identity risk leads and then fanning out to check for ransomware-like file behavior and phishing context. An agent weighs these signals to determine if a coordinated attack is underway, enabling rapid containment of affected hosts.

## identify-anomalous-access
<!-- Identify anomalous authentication -->
Find users and hosts with high-risk sign-in events to narrow the scope of potential victims.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
expected: A list of users and hosts with risky authentication flags. Silence indicates
  no reported identity risk in the window.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- risk_state
- is_proxy
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-27'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, risk_state, is_proxy, time FROM hb_auth_signin WHERE (risk_state IN ('atRisk', 'confirmedCompromised') OR is_proxy = 'true') AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate ransomware activity -->
parallel:
- → detect-mass-encryption
- → examine-phishing-delivery
join: → agent-triage-attack-chain

## detect-mass-encryption
<!-- Detect mass file encryption -->
Identify processes performing an unusually high volume of file updates or renames outside of standard system paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, scope_users=scope_users)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process modifying hundreds of files on a single host. High file counts
  from user-space processes are strong indicators of ransomware activity.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- actor_user_name
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-27'
~~~
SELECT device_hostname, actor_user_name, process_name, COUNT(DISTINCT file_path) AS file_count, MIN(time) AS start_time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND activity_id IN (1, 3, 5) AND LOWER(process_name) NOT LIKE 'c:\windows\%' AND LOWER(process_name) NOT LIKE 'c:\program files\%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, process_name HAVING file_count > 100
```

## examine-phishing-delivery
<!-- Examine phishing email delivery -->
Search the mail audit logs for recent emails with attachments that might have served as the infection vector.

```sqlite target=microsoft-365 role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Emails with attachments received by users who subsequently exhibited anomalous
  host activity. Silence suggests the vector was not email-borne.
reads:
- from
- subject
- received_date_time
- body_preview
- tenant_id
silence: not_evidence_of_absence
source: microsoft365_mail_message
verified: dry-run
verified_at: '2026-10-27'
~~~
SELECT "from", subject, received_date_time, body_preview, tenant_id FROM microsoft365_mail_message WHERE has_attachments = 'true' AND received_date_time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-attack-chain
<!-- Agent triage of attack chain -->
```agent target=hunter
cite: required
context:
- identify-anomalous-access
- detect-mass-encryption
- examine-phishing-delivery
max_iterations: 5
objective: Determine if any host shows a temporal and causal link between an anomalous
  sign-in, the receipt of a suspicious email, and subsequent mass file encryption.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  authentication risk flags and encryption process details.
tools:
- endpoint
- identity
- microsoft-365
```

## evaluate-triage-results
<!-- Evaluate triage results -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-affected-endpoint
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: missing-m365-logs)
else: → hunt-close-out

## isolate-affected-endpoint
<!-- Isolate affected endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR. Collect the suspicious binary and any file ransom notes for further analysis.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the correlated evidence. Use the identified email sender to search for other recipients across the tenant. Verify if the identified process is a known ransomware variant.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the outcome. If the mass-encryption query caught a real infection, promote it to a standing rule after tuning.
```
→ end
