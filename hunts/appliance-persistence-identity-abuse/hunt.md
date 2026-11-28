---
analysis: A standard detection rule on Slack webhooks would trigger on legitimate
  IT notifications. This hunt is effective because it pivots from suspicious security-related
  task modifications to specific exfiltration behaviors and then corroborates with
  identity-provider anomalies (MFA bypass) to confirm malicious intent.
blind_spots:
- id: appliance-visibility-gap
  question: whether the adversary modified an internal configuration file or binary
    that does not appear in the scheduled task list
  requires: Deep OS-level auditing on network appliances
  risk: Low-level persistence within the appliance OS would be missed by hb_scheduled_job.
  stage: authentication-process-modification
- id: webhook-content-blindness
  question: the specific content of the exfiltrated data
  requires: TLS inspection for outbound HTTPS
  risk: We can detect the destination and the exfiltration tool (curl), but cannot
    confirm which specific credentials or tokens were stolen.
  stage: credential-exfiltration-webhook
coverage:
- stage: authentication-process-modification
  status: covered
  steps:
  - suspicious-appliance-jobs
  - non-mfa-logins
- stage: credential-exfiltration-webhook
  status: covered
  steps:
  - exfiltration-webhooks
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: initial-access-collaboration-phishing
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: trusted-channel-impersonation
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: endpoint-payload-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Compromised network appliances provide deep persistence; monitoring
    for script-driven MFA removal and native webhook exfiltration protects the core
    identity boundary even when traditional endpoint logs are unavailable.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has modified appliance scheduled tasks to disable MFA and
  is exfiltrating credentials via native Slack webhook integrations.
labels:
- hunt
- attack.t1556
- attack.t1566
- attack.t1684.001
name: Appliance Persistence and Identity Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of appliances or services to focus on; leave empty to scan
      the whole estate.
    type: list[host]
  slack_hook_domain:
    default: hooks.slack.com
    description: Slack webhook endpoint used for exfiltration.
    from:
      kind: article
      observed: '2026-08-20'
      ref: unit42-comm-channels
    type: domain
  suspicious_user_agents:
    default:
    - curl
    - python-requests
    - wget
    - go-http-client
    description: User agents typically used by scripts rather than standard integrations.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hostnames indicating network infrastructure (e.g., vpn-*, fw-*).
  Use the output of the first query to populate the scope_hosts parameter for the
  parallel branch.
references:
- name: "Unit 42 \u2014 Identity Abuse Through Trusted Communication Channels"
  url: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
related:
- hunt: initial-access-collaboration-phishing
  reason: This hunt focuses on post-compromise appliance persistence; the initial
    phishing via Teams or Slack is handled by a separate hunt focusing on communication
    logs.
  relation: out-of-scope-alternative
- hunt: collaboration-platform-phishing-and-execution
  relation: follows
scenario:
  stages:
  - name: Identity Phishing via Collaboration Tools
    observables:
    - hooks.slack.com
    - Google Sites authentication links
    - External federation chat requests in Microsoft Teams
    - Requests to approve MFA notifications
    slug: initial-access-collaboration-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Impersonation of Trusted Personas
    observables:
    - Google Meet interview sessions
    - IT support impersonation
    - Recruitment-themed social engineering
    - Malicious GitHub repository cloning
    slug: trusted-channel-impersonation
    tactic: stealth
    techniques:
    - T1684.001
  - name: User-Executed Malicious Payloads
    observables:
    - WinRAR.exe
    - lpk.dll
    - npm install
    - Explorer.exe launching RAR files
    - Extraction of masquerading DLLs
    slug: endpoint-payload-execution
    tactic: execution
    techniques:
    - T1566
  - name: Modification of Authentication Process
    observables:
    - Removal of MFA/2FA from privileged accounts
    - Scripts on VPN/firewall appliances disabling security settings
    - Creation of weekly scheduled tasks for credential collection
    slug: authentication-process-modification
    tactic: persistence
    techniques:
    - T1556
  - name: Exfiltration via Native Slack Webhook
    observables:
    - POST requests to hooks.slack.com
    - curl user-agent in outbound appliance traffic
    - Native Slack notification integrations on network hardware
    slug: credential-exfiltration-webhook
    tactic: exfiltration
    techniques:
    - T1556
  summary: Threat actors exploit trusted collaboration platforms like Microsoft Teams
    and Slack to deliver phishing links and impersonate internal stakeholders for
    initial access. Post-compromise, they maintain persistence by modifying authentication
    settings on network appliances and use native Slack webhook integrations to exfiltrate
    credentials and sensitive data.
series:
  index: 2
  slug: identity-abuse-through-trusted-communication-channels
  title: Identity Abuse Through Trusted Communication Channels
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Appliance Persistence and Identity Abuse

The adversary disables multifactor authentication and exfiltrates credentials by modifying network appliance configuration scripts. This hunt identifies these post-compromise activities. It focuses on the discovery of suspicious scheduled tasks referencing identity controls, correlated with outbound webhook traffic to Slack and successful sign-ins where MFA was bypassed. An analyst reviews the resulting behavioral signals to confirm an appliance-based intrusion.

## suspicious-appliance-jobs
<!-- Suspicious scheduled tasks on appliances -->
Identify tasks that reference MFA or credential modification, indicating unauthorized persistence.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Tasks that modify authentication or collect secrets. Results identify potential
  appliance hosts for subsequent pivots.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%.conf%' OR LOWER(job_cmd_line) LIKE '%/etc/%' OR LOWER(job_cmd_line) LIKE '%sed -i%' OR LOWER(job_cmd_line) LIKE '%auth sufficient%' OR LOWER(job_cmd_line) LIKE '%mfa%' OR LOWER(job_cmd_line) LIKE '%2fa%' OR LOWER(job_cmd_line) LIKE '%password%' OR LOWER(job_cmd_line) LIKE '%disable%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-signals
<!-- Correlate exfiltration and identity bypass -->
parallel:
- → exfiltration-webhooks
- → non-mfa-logins
join: → triage-evidence

## exfiltration-webhooks
<!-- Slack webhook exfiltration attempts -->
Detect outbound POST requests to Slack hooks from script-based tools, isolating traffic patterns atypical for standard appliance integrations.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, slack_hook_domain=slack_hook_domain, suspicious_user_agents=suspicious_user_agents, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound Slack traffic from a scoped appliance using a generic tool like
  curl. Silence suggests no active exfiltration via this channel.
prevalence:
  by: device_hostname
  key:
  - user_agent
  - url_path
  rare_below: 3
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, COUNT(*) as request_count, MIN(time) as first_seen FROM hb_http_activity WHERE url_hostname = '{{slack_hook_domain}}' AND http_method = 'POST' AND (instr(',' || LOWER('{{suspicious_user_agents}}') || ',', ',' || LOWER(user_agent) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path, user_agent HAVING request_count <= 10
```

## non-mfa-logins
<!-- Logins without MFA to sensitive services -->
Find successful authentications where MFA was bypassed, confirming the impact of the appliance modification.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Success logins for privileged accounts without MFA. Focus on accounts associated
  with the compromised appliances.
reads:
- actor_user_name
- dst_endpoint_name
- provider
- src_endpoint_ip
- mfa
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, dst_endpoint_name, provider, src_endpoint_ip, mfa, status, time FROM hb_auth_signin WHERE (LOWER(mfa) IN ('false', '0', 'no', 'disabled') OR mfa IS NULL) AND status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage appliance persistence and identity signals -->
```agent target=hunter
cite: required
context:
- suspicious-appliance-jobs
- exfiltration-webhooks
- non-mfa-logins
max_iterations: 5
objective: Determine if the scheduled tasks on potential appliances correlate with
  suspicious Slack webhooks and subsequent MFA-less logins for related accounts.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  specific task commands and exfiltration timestamps.
tools:
- endpoint
- identity
- web
```

## route-investigation
<!-- Route based on compromise verdict -->
if~: "the triage verdict identifies at least one host with both suspicious scheduled jobs and outbound Slack webhook traffic using script-based user agents" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → forensic-appliance-audit
unavailable: → forensic-appliance-audit (blind_spot: appliance-visibility-gap)
else: → forensic-appliance-audit

## isolate-and-remediate
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the reporting device, disable the compromised user identities, and revoke all active sessions for those users.
```
→ forensic-appliance-audit

## forensic-appliance-audit
<!-- Forensic audit of appliance configuration -->
```manual target=analyst
Review all configured scripts, webhooks, and local user settings on the appliance management console to identify hidden persistence mechanisms or modified 2FA policies.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings, update the risk register regarding appliance visibility, and confirm the restoration of MFA controls.
```
→ end
