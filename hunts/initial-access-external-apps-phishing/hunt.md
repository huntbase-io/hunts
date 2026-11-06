---
analysis: A standard rule alerts on a single high-risk sign-in; this hunt correlates
  the vulnerability state of the host with rare application crashes and identity flags,
  finding the 'living off the land' beachhead that a single-surface rule would miss.
blind_spots:
- id: no-identity-logging
  question: whether a successful login used an MFA bypass technique
  requires: hb_auth_signin with full risk detail
  risk: If the identity provider does not log the specific MFA method used, we cannot
    distinguish between a legitimate login and a bypass.
  stage: phishing-and-email-compromise
- id: crash-log-omission
  question: whether a non-standard web service was exploited
  requires: hb_application_error covering all custom services
  risk: Standard server logs (IIS, Apache) are captured, but proprietary or legacy
    applications may not report crashes to the OS error logging service.
  stage: inbound-application-exploitation
coverage:
- stage: inbound-application-exploitation
  status: covered
  steps:
  - vulnerable-device-scoping
  - rare-application-crashes
- stage: phishing-and-email-compromise
  status: covered
  steps:
  - suspicious-identity-events
- reason: Belongs to another part of the 'When confusion reigns, trusted vendors must
    guide their SMB customers' series.
  stage: evasive-execution-and-rmm
  status: out_of_scope
- reason: Belongs to another part of the 'When confusion reigns, trusted vendors must
    guide their SMB customers' series.
  stage: credential-theft-infostealers
  status: out_of_scope
- reason: Belongs to another part of the 'When confusion reigns, trusted vendors must
    guide their SMB customers' series.
  stage: ransomware-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SMBs are the primary entry point for supply-chain attacks; a negative
    result for perimeter exploitation and high-risk identity events confirms that
    the exposed attack surface remains secure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access by either exploiting a critical
  vulnerability in a public-facing application or by use of stolen credentials from
  a phishing campaign, resulting in anomalous application crashes or high-risk authentication
  events on perimeter assets.
labels:
- hunt
- attack.t1190
- attack.t1195
- attack.t1566
- attack.t1078
- credential access
- defense evasion
- impact
- initial access
name: Initial Access via External Applications and Phishing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavior.
    from:
      kind: manual
      observed: '2024-11-01'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step to narrow the behavioral
      queries.
    from:
      kind: manual
      observed: '2024-11-01'
      ref: scoping-result
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/when-confusion-reigns-trusted-vendors-guide-smb-customers/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin by querying the vulnerability inventory for hosts with active critical
  CVEs (severity_id 4 or 5). Use these hostnames to narrow the behavioral queries
  in the next steps.
references:
- name: When confusion reigns, trusted vendors must guide their SMB customers
  url: https://www.welivesecurity.com/en/business-security/when-confusion-reigns-trusted-vendors-guide-smb-customers/
related:
- hunt: evasive-execution-and-rmm
  reason: Once initial access is gained, the adversary moves to evasive execution;
    that is a sibling hunt focusing on process behavior.
  relation: follows
scenario:
  stages:
  - name: Public-Facing Application Exploitation
    observables:
    - Exploitation of web servers
    - AI-discovered zero-day exploits
    - Manipulation of software update or delivery mechanisms
    - Anomalous HTTP requests targeting vulnerabilities
    slug: inbound-application-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1195
  - name: Phishing and Business Email Compromise
    observables:
    - Emails containing malicious attachments
    - Phishing links delivered via email
    - Unauthorized access to business email accounts
    slug: phishing-and-email-compromise
    tactic: initial-access
    techniques:
    - T1566
  - name: Living off the Land and Unsanctioned RMM
    observables:
    - Execution via signed Microsoft binaries (LOLBAS)
    - Unsanctioned remote monitoring and management (RMM) software
    - Use of 'safe-looking' administrative tools for malicious activity
    slug: evasive-execution-and-rmm
    tactic: defense-evasion
    techniques:
    - T1218
  - name: Infostealers and Credential Harvest
    observables:
    - Infostealer malware execution
    - Searching for credentials in password stores
    - Abuse of compromised valid accounts for session access
    slug: credential-theft-infostealers
    tactic: credential-access
    techniques:
    - T1555
    - T1078
  - name: Data Encryption for Impact
    observables:
    - Deployment of ransomware binaries
    - Mass file encryption on local or remote drives
    - Creation of ransom notes
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Adversaries target SMBs as a pathway into larger supply chains, using phishing
    and exploitation of public-facing applications for initial access. Post-compromise,
    they utilize 'living off the land' techniques and unsanctioned remote monitoring
    and management (RMM) tools to steal credentials and deploy ransomware.
series:
  index: 1
  slug: when-confusion-reigns-trusted-vendors-must-guide-their-smb-customers
  title: When confusion reigns, trusted vendors must guide their SMB customers
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
tlp: clear
type: investigation
---


# Initial Access via External Applications and Phishing

Following research that suggests SMBs are frequently targeted as supply-chain beachheads, this hunt identifies assets with known critical vulnerabilities. The hunt then launches parallel queries to find rare application faults in web services and high-risk authentication flags from identity providers. Finally, an agent correlates these disparate signals to determine if a perimeter breach has occurred, and an analyst reviews the evidence to confirm the intrusion vector.

## vulnerable-device-scoping
<!-- Identify vulnerable perimeter assets -->
Identify devices with critical active vulnerabilities that could serve as the initial entry point for an adversary.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with critical CVEs. Silence indicates no active critical
  vulnerabilities are reported in the scanner inventory.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- cvss_score
- severity_id
- status
- resource_type
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_uid, resource_uid AS device_hostname, cve_uid, severity, cvss_score FROM hb_vulnerability_finding WHERE severity_id >= 4 AND status = 'active' AND resource_type = 'device' ORDER BY cvss_score DESC
```

## perimeter-anomaly-fan-out
<!-- Examine behavior across application and identity surfaces -->
parallel:
- → rare-application-crashes
- → suspicious-identity-events
join: → initial-access-triage

## rare-application-crashes
<!-- Rare application crashes on vulnerable hosts -->
Find rare application failures in web services that could indicate memory corruption or exploit attempts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A crash in a web server or database process occurring on fewer than 3 hosts.
  Silence suggests no rare fatal application errors occurred.
prevalence:
  by: device_hostname
  key:
  - app_name
  - exception_code
  rare_below: 3
reads:
- device_hostname
- app_name
- exception_code
- time
silence: not_evidence_of_absence
source: hb_application_error
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, app_name, exception_code, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_application_error WHERE (LOWER(app_name) LIKE '%w3wp%' OR LOWER(app_name) LIKE '%httpd%' OR LOWER(app_name) LIKE '%nginx%' OR LOWER(app_name) LIKE '%sql%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY app_name, exception_code HAVING host_count < 3 ORDER BY host_count ASC
```

## suspicious-identity-events
<!-- High-risk authentication and credential abuse -->
Identify sign-ins flagged by providers as high-risk or indicating brute-force/MFA exhaustion.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful or failed sign-ins with 'atRisk' states or codes for brute force/MFA
  failure. Silence indicates no high-risk identity alerts.
reads:
- dst_endpoint_hostname
- actor_user_name
- src_endpoint_ip
- risk_state
- status_code
- event_type
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT dst_endpoint_hostname AS device_hostname, actor_user_name, src_endpoint_ip, risk_state, status_code, event_type, time FROM hb_auth_signin WHERE (risk_state != 'none' OR status_code IN ('50126', '50053', '500121')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## initial-access-triage
<!-- Triage initial access signals -->
```agent target=hunter
cite: required
context:
- vulnerable-device-scoping
- rare-application-crashes
- suspicious-identity-events
max_iterations: 4
objective: Review the critical vulnerabilities on scoping hosts and correlate them
  with any rare application crashes or high-risk authentication events on those same
  hosts. Decide if the timing and nature of these signals represent a successful intrusion.
success_criteria: A verdict for each host in the context, citing specific rows for
  crashes or sign-in risks.
tools:
- endpoint
- identity
```

## intrusion-decision
<!-- Route based on intrusion verdict -->
if~: "the initial-access-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → incident-response-task
unavailable: → incident-response-task (blind_spot: no-identity-logging)
else: → remediation-task

## isolate-compromised-host
<!-- Isolate the compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified as malicious and revoke all active sessions for the involved users in the identity provider (Entra ID/Okta).
```
→ incident-response-task

## incident-response-task
<!-- Forensic lead analysis -->
```manual target=analyst
Review the application errors and authentication logs. If an application crash was found, correlate with hb_http_activity to find the URI and source IP that triggered the fault. If auth risk was found, check for subsequent hb_process_activity or hb_file_activity that indicates hands-on-keyboard activity.
```
→ remediation-task

## remediation-task
<!-- Close the gaps -->
```manual target=analyst
Immediately patch the CVEs identified on any malicious or suspicious hosts. Review the conditional access policies for any accounts flagged for risk to ensure phishing-resistant MFA is required for perimeter access.
```
→ end
