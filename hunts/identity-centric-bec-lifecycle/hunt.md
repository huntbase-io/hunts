---
analysis: A standard rule flags a mailbox rule change, but this hunt correlates those
  changes with anomalous identity sources and endpoint execution to provide confirming
  context.
blind_spots:
- id: cloud-audit-latency
  question: Are rule changes missed that occurred just before the hunt window?
  requires: hb_cloud_api_activity for M365
  risk: Attackers can manipulate rules and delete evidence within minutes; ingestion
    delays may mask transient persistence.
  stage: persistence-mailbox-manipulation
- id: tls-inspection-gap
  question: Can we see the full request URI for encrypted traffic?
  requires: TLS inspection in hb_http_activity
  risk: Without inspection, only the hostname is visible; attackers using legitimate
    compromised services for phishing remain hidden.
  stage: initial-access-phishing-aitm
coverage:
- stage: initial-access-phishing-aitm
  status: covered
  steps:
  - scoping-vulnerable-assets
  - aitm-traffic-search
- stage: account-takeover-unauthorized-login
  status: covered
  steps:
  - rare-proxy-logins
- stage: persistence-mailbox-manipulation
  status: covered
  steps:
  - mailbox-rule-persistence
- stage: execution-malicious-attachments
  status: covered
  steps:
  - suspicious-email-execution
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Business Email Compromise is a primary driver of financial loss.
    Negative results provide assurance that communication channels and identities
    remain uncompromised.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked an identity through an Adversary-in-the-Middle
  proxy or by exploiting a public-facing vulnerability, then manipulates mailbox rules
  to hide fraudulent communication and spreads malicious internal attachments.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1078
- attack.t1564.008
- attack.t1204.002
- credential access
- execution
- initial access
- persistence
name: Identity-Centric Business Email Compromise
parameters:
  email_clients:
    default:
    - outlook.exe
    - thunderbird.exe
    description: Common email client processes to monitor for suspicious child processes.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: endpoint-standard
    type: list[path]
  interpreter_names:
    default:
    - cmd.exe
    - powershell.exe
    - wscript.exe
    - cscript.exe
    description: Suspicious child processes often spawned by malicious attachments.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: common-attack-interpreters
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: standard-lookback
    type: number
  mailbox_ops:
    default:
    - New-InboxRule
    - Set-InboxRule
    - UpdateInboxRule
    description: Cloud API operations associated with mailbox rule persistence.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: m365-audit-docs
    type: list[string]
  phishing_domains:
    default:
    - outlook-security.com
    - verify-microsoft.net
    - login.microsoftonline.security-verify.com
    description: Known or suspected AiTM/phishing domains from research.
    from:
      kind: article
      observed: '2024-10-14'
      ref: huntress-bec-2024
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hostnames to narrow the hunt; leave empty for all.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/what-is-business-email-compromise-bec
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on users in finance, HR, and executive roles for proxy-based logins.
  Examine internet-facing servers with critical vulnerabilities first.
references:
- name: "Huntress \u2014 What Is Business Email Compromise (BEC)?"
  url: https://www.huntress.com/blog/what-is-business-email-compromise-bec
related:
- hunt: mfa-fatigue-investigation
  reason: This hunt focuses on AiTM and mailbox persistence; push-fatigue scenarios
    require distinct authentication success/failure counts.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and Adversary-in-the-Middle
    observables:
    - Phishing domains
    - Adversary-in-the-Middle (AiTM) proxy URLs
    - Exploitation of internet-facing software vulnerabilities
    slug: initial-access-phishing-aitm
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Account Takeover and Unauthorized Authentication
    observables:
    - Login attempts from unusual locations
    - Anonymizing proxy IPs (is_proxy=true)
    - Atypical User-Agent strings
    - MFA exhaustion or bypass
    slug: account-takeover-unauthorized-login
    tactic: credential-access
    techniques:
    - T1078
  - name: Persistence via Mailbox Rules
    observables:
    - Creation of new inbox rules (New-InboxRule)
    - Rules designed to move messages to 'RSS Feeds' or 'Deleted Items'
    - Modification of mailbox permissions
    - Changes to MFA settings or recovery options
    slug: persistence-mailbox-manipulation
    tactic: persistence
    techniques:
    - T1564.008
  - name: Execution of Malicious Attachments
    observables:
    - Users opening suspicious attachments from 'trusted' internal senders
    - Spawning of interpreters or suspicious processes from email clients
    - Creation of unexpected files in temporary directories
    slug: execution-malicious-attachments
    tactic: execution
    techniques:
    - T1204.002
  summary: Business Email Compromise (BEC) involves attackers gaining unauthorized
    access to corporate email accounts via phishing, AiTM, or vulnerability exploitation
    to perform financial fraud. Once inside, they often manipulate mailbox rules to
    hide their presence and impersonate trusted figures to redirect payments or steal
    data.
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


# Identity-Centric Business Email Compromise

This hunt follows the full lifecycle of a Business Email Compromise (BEC) attack using a phased approach. It first identifies early-stage risk: successful logins from anonymizing proxies and endpoint traffic to known phishing landing pages. It then pivots to look for follow-on persistence through M365 mailbox rule modifications and potential payload execution where the attacker uses a compromised account to deliver malicious attachments to internal peers. Two agents weigh the evidence sequentially to distinguish between legitimate administrative activity and a coordinated intrusion.

## scoping-vulnerable-assets
<!-- Identify exposed vulnerable assets -->
Find internet-facing devices with high-severity vulnerabilities that could serve as initial access vectors.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts with unpatched critical vulnerabilities. Silence suggests the external
  surface is well-defended against known exploits.
reads:
- device_uid
- affected_package_name
- affected_package_version
- severity
- cve_uid
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_uid, affected_package_name, affected_package_version, severity, cve_uid FROM hb_vulnerability_finding WHERE (is_kev = 'true' OR severity_id >= 4) AND resource_type = 'device'
```

## access-investigation
<!-- Investigate initial access signals -->
parallel:
- → rare-proxy-logins
- → aitm-traffic-search
join: → early-stage-triage

## rare-proxy-logins
<!-- Stack-count proxy-based logins -->
Find logins originating from anonymizing proxies to highlight rare actor behavior.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of proxy IPs used by only one or two accounts, suggesting targeted
  attacker access.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- time
- is_proxy
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS login_attempts, MIN(time) AS first_seen FROM hb_auth_signin WHERE is_proxy = 'true' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING user_count <= 2 ORDER BY user_count ASC
```

## aitm-traffic-search
<!-- Hunt for AiTM proxy domains -->
Identify endpoints communicating with known phishing or AiTM proxy domains.

```sqlite target=web role=triage params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts contacting malicious domains. Silence means these specific domains
  were not used in the lookback window.
reads:
- device_hostname
- src_endpoint_ip
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-triage
<!-- Triage initial identity risk -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-assets
- rare-proxy-logins
- aitm-traffic-search
max_iterations: 3
objective: Determine if specific users have both successful logins from rare proxy
  IPs and HTTP traffic to phishing domains.
success_criteria: A per-user risk verdict citing specific proxy IPs and domain traffic
  rows.
tools:
- endpoint
- identity
- web
```

## follow-on-investigation
<!-- Investigate follow-on BEC actions -->
parallel:
- → mailbox-rule-persistence
- → suspicious-email-execution
join: → full-bec-assessment

## mailbox-rule-persistence
<!-- Monitor for mailbox rule persistence -->
Detect the creation of inbox rules used to hide attacker communication or redirect mail.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, mailbox_ops=mailbox_ops)
~~~yaml
expected: Users creating rules to move mail to RSS Feeds or Deleted Items. Silence
  proves no such rules were created during the audit window.
reads:
- cloud_account_uid
- actor_user_name
- api_operation
- resource_name
- status_detail
- time
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT cloud_account_uid, actor_user_name, api_operation, resource_name, status_detail, time FROM hb_cloud_api_activity WHERE api_service_name = 'm365' AND instr(',' || '{{mailbox_ops}}' || ',', ',' || api_operation || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-email-execution
<!-- Execution from email clients -->
Identify suspicious child processes launched from common email clients.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, email_clients=email_clients, interpreter_names=interpreter_names, scope_hosts=scope_hosts)
~~~yaml
expected: Outlook or Thunderbird spawning interpreters. Silence indicates no macro-style
  execution was caught by the process sensor.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE instr(',' || '{{email_clients}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{interpreter_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## full-bec-assessment
<!-- Synthesize full BEC assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- mailbox-rule-persistence
- suspicious-email-execution
max_iterations: 4
objective: Confirm if any risky identities identified in the first stage also performed
  mailbox rule changes or suspicious endpoint execution.
success_criteria: A malicious/suspicious verdict per user, citing the relationship
  between login behavior and M365 actions.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route based on BEC verdict -->
if~: "the full-bec-assessment verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → contain-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-audit-latency)
else: → analyst-review

## contain-and-remediate
<!-- Contain and remediate compromise -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions and MFA tokens for the identified users; delete the identified malicious inbox rules; isolate identified endpoint hostnames to prevent lateral movement.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Audit impacted mailboxes for access to sensitive financial files; verify outbound email for fraudulent payment instructions sent to vendors.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the proxy IPs and phishing domains as new indicators; promote the mailbox rule logic to a standing detection rule.
```
→ end
