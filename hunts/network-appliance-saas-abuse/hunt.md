---
analysis: A simple detection rule for 'hooks.slack.com' is often prone to false positives
  due to legitimate developer integrations. This hunt solves this by baselining integration
  prevalence across the fleet and correlating it with suspicious scheduling behavior
  and identity state changes (MFA status) that a single surface rule cannot see.
blind_spots:
- id: missing-appliance-telemetry
  owner: Infrastructure Team
  question: Are the scheduled tasks visible on the specific firewall/VPN appliance?
  remediation: Enable and forward audit/configuration change logs from VPN and firewall
    appliances to the central SIEM/Lake.
  requires: endpoint agent (osquery/sysmon) or native configuration logs on network
    appliances
  risk: Many network appliances do not support third-party agents, making the creation
    of scripts and tasks invisible unless native audit logs are explicitly forwarded
    to a central lake.
  stage: appliance-scheduled-persistence
- id: encrypted-webhook-payloads
  owner: Network Security Team
  question: What specifically is being exfiltrated in the POST request body to Slack?
  remediation: Implement TLS inspection for outbound traffic to known collaboration
    and cloud storage domains from critical server subnets.
  requires: TLS inspection or local proxy logs with request bodies
  risk: HTTPS encryption prevents the hunt from seeing if credentials, MFA tokens,
    or sensitive configuration files are being exfiltrated inside the Slack payload.
  stage: slack-webhook-exfiltration
coverage:
- stage: authentication-persistence-modification
  status: covered
  steps:
  - active-users-no-mfa
  - triage-agent
- stage: appliance-scheduled-persistence
  status: covered
  steps:
  - suspicious-scheduled-jobs
  - triage-agent
- stage: slack-webhook-exfiltration
  status: covered
  steps:
  - slack-webhook-outbound
  - rare-webhook-activity
  - triage-agent
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: collaboration-channel-phishing
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: impersonation-led-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: malicious-certificate-trust
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are misusing trusted SaaS integration points (Slack
    Webhooks) to bypass traditional perimeter security and exfiltrate data from critical
    infrastructure after disabling identity-based controls like MFA. A negative result
    confirms that active identities maintain their MFA posture and network infrastructure
    is not being used as an automated exfiltration bridge.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has modified authentication mechanisms to disable MFA and
  established persistence via scheduled tasks on network infrastructure to exfiltrate
  credentials using legitimate Slack webhooks.
labels:
- hunt
- attack.t1556
- attack.t1566
- attack.t1684.001
name: Network Infrastructure Persistence and SaaS Integration Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioral and network events.
    from:
      kind: manual
      observed: '2026-08-20'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: A list of hostnames to focus the hunt on (e.g., VPN appliances, firewalls).
    from:
      kind: manual
      observed: '2026-08-20'
      ref: analyst-defined
    type: list[host]
  webhook_domains:
    default:
    - hooks.slack.com
    description: Target domains for webhook exfiltration mentioned in the report.
    from:
      kind: article
      observed: '2026-08-20'
      ref: unit42-comm-risks
    type: list[domain]
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
rationale: Start with critical network infrastructure like VPN concentrators, firewalls,
  and management servers. Broaden to servers and cloud compute instances if exfiltration
  patterns are detected.
references:
- name: "Unit 42 \u2014 Identity Abuse Through Trusted Communication Channels"
  url: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
related:
- hunt: collaboration-channel-phishing
  reason: This hunt focuses on post-compromise exfiltration and persistence, whereas
    the initial phishing delivery via Slack/Teams is a separate concern covered in
    a sibling hunt.
  relation: out-of-scope-alternative
- hunt: saas-collaboration-impersonation-execution
  relation: follows
scenario:
  stages:
  - name: Phishing via Collaboration Channels
    observables:
    - Microsoft Teams external federation chat requests
    - Slack direct messages from impersonated administrators
    - Links to credential harvesting pages
    - Request to visit phishing sites or approve MFA notifications
    slug: collaboration-channel-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1684.001
  - name: Social Engineering and Execution
    observables:
    - Google Meet video interviews with impersonated HR managers
    - Cloning malicious GitHub repositories
    - Execution of 'npm install' on untrusted code
    - Downloading RAR files from Teams links to Downloads folder
    - WinRAR.exe extracting lpk.dll (DLL sideloading)
    slug: impersonation-led-execution
    tactic: execution
    techniques:
    - T1684.001
  - name: Malicious Root Certificate Installation
    observables:
    - Requests to install a malicious root certificate via Google Sites
    - macOS binary download and execution from phishing sites
    slug: malicious-certificate-trust
    tactic: defense-evasion
    techniques:
    - T1556
  - name: Authentication Mechanism Modification
    observables:
    - Disabling two-factor authentication (2FA) for privileged accounts
    - MFA removal on compromised identities
    slug: authentication-persistence-modification
    tactic: persistence
    techniques:
    - T1556
  - name: Network Appliance Scheduled Persistence
    observables:
    - Weekly scheduled tasks on VPN/firewall appliances
    - Built-in appliance scripting used to retrieve privileged passwords
    slug: appliance-scheduled-persistence
    tactic: persistence
    techniques:
    - T1556
  - name: Exfiltration via Slack Webhooks
    observables:
    - HTTP POST requests to hooks.slack.com
    - Requests using 'curl' user agent from network appliances
    - Credential exfiltration via native Slack notifications
    slug: slack-webhook-exfiltration
    tactic: exfiltration
    techniques:
    - T1556
  summary: Attackers exploit the inherent trust in enterprise collaboration platforms
    like Slack and Teams to conduct identity phishing, impersonate support personnel,
    and deliver malware. Post-compromise, they leverage legitimate SaaS integrations
    such as Slack webhooks and appliance-based scheduled tasks to maintain persistence,
    disable MFA, and exfiltrate credentials.
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
    huntbase:
      product: hb-endpoint-control
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


# Network Infrastructure Persistence and SaaS Integration Abuse

This hunt targets post-compromise activity where attackers bridge on-premises appliance persistence with SaaS-based exfiltration, as seen in recent campaigns against manufacturing and infrastructure targets. We search for active accounts where multifactor authentication (MFA) has been disabled, alongside the creation of scheduled jobs on critical network infrastructure (VPNs, firewalls) that execute scripts designed to exfiltrate data to trusted collaboration platforms like Slack. The hunt leverages HTTP telemetry to identify 'curl' or script-based requests to Slack webhooks, a technique that frequently bypasses traditional perimeter monitoring due to the trusted nature of the destination domain and the use of native appliance features.

## identify-critical-infrastructure
<!-- Identify critical network infrastructure -->
Locate active devices that are likely to be network appliances or servers to focus the search for persistence.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames representing firewalls, VPNs, or servers. Silence means
  no devices match these naming conventions.
reads:
- hostname
- platform
- last_seen
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, platform, last_seen FROM hb_devices WHERE lifecycle_state = 'active' AND (LOWER(hostname) LIKE '%vpn%' OR LOWER(hostname) LIKE '%fw%' OR LOWER(hostname) LIKE '%gate%' OR LOWER(hostname) LIKE '%svr%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-persistence-search
<!-- Parallel search for persistence and exfiltration -->
parallel:
- → active-users-no-mfa
- → suspicious-scheduled-jobs
- → slack-webhook-outbound
- → rare-webhook-activity
join: → triage-agent

## active-users-no-mfa
<!-- Active identities with MFA disabled -->
Identify active accounts that lack multifactor authentication, serving as a primary risk indicator for authentication persistence (T1556).

```sqlite target=identity role=baseline
~~~yaml
expected: Active accounts with MFA disabled. The presence of a privileged user here
  is a high-risk finding.
reads:
- name
- email
- provider
- mfa_enabled
- status
- created_at
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT name, email, provider, mfa_enabled, status, created_at FROM hb_users WHERE LOWER(status) = 'active' AND NOT mfa_enabled
```

## suspicious-scheduled-jobs
<!-- Scheduled jobs for credential access or exfiltration -->
Detect persistence mechanisms on infrastructure that target passwords or use native appliance scripting (T1556).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Jobs running scripts with keywords related to credential theft or exfiltration
  to external webhooks on targeted infrastructure.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_schedule
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_schedule, time FROM hb_scheduled_job WHERE (LOWER(device_hostname) LIKE '%vpn%' OR LOWER(device_hostname) LIKE '%fw%' OR LOWER(device_hostname) LIKE '%gate%') AND (LOWER(job_cmd_line) LIKE '%mfa%' OR LOWER(job_cmd_line) LIKE '%password%' OR LOWER(job_cmd_line) LIKE '%curl%' OR LOWER(job_cmd_line) LIKE '%slack%' OR LOWER(job_cmd_line) LIKE '%powershell%' OR LOWER(job_cmd_line) LIKE '%bash%' OR LOWER(job_cmd_line) LIKE '%base64%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## slack-webhook-outbound
<!-- Outbound HTTP requests to Slack webhooks -->
Identify direct HTTP communication to Slack hooks using command-line tools or scripts, matching the reporting of appliance-based exfiltration.

```sqlite target=web role=enrichment params=(webhook_domains=webhook_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Direct POST requests to Slack from script-like user agents. Silence proves
  these specific script patterns didn't run.
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
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE (LOWER(device_hostname) LIKE '%vpn%' OR LOWER(device_hostname) LIKE '%fw%' OR LOWER(device_hostname) LIKE '%gate%') AND instr(',' || '{{webhook_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND (LOWER(user_agent) LIKE '%curl%' OR LOWER(user_agent) LIKE '%python%' OR LOWER(user_agent) LIKE '%wget%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-webhook-activity
<!-- Baseline: Rare webhook traffic across the fleet -->
Filter out established, legitimate integrations by finding webhook destinations seen on very few hosts.

```sqlite target=web role=baseline params=(webhook_domains=webhook_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Webhook destinations unique to one or two hosts. Fleet-wide integrations
  (e.g., global developer hooks) are ignored.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  - user_agent
  rare_below: 3
reads:
- url_hostname
- url_path
- user_agent
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, url_path, user_agent, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE instr(',' || '{{webhook_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path, user_agent HAVING host_count <= 2
```

## triage-agent
<!-- Triage identities and infrastructure -->
```agent target=hunter
cite: required
context:
- active-users-no-mfa
- suspicious-scheduled-jobs
- slack-webhook-outbound
- rare-webhook-activity
max_iterations: 6
objective: Determine if any host or user identity shows signs of both authentication
  persistence modification and automated exfiltration via Slack webhooks from critical
  network infrastructure.
success_criteria: A verdict of malicious | suspicious | benign for each host/user,
  citing specific scheduled jobs or rare HTTP requests.
tools:
- endpoint
- identity
- web
```

## route-verdict
<!-- Route on triage verdict -->
if~: "The triage verdict indicates that a network appliance has suspicious scheduled jobs coinciding with rare Slack webhook activity, or an active account has had MFA disabled." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-appliance-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR or Network security control. Following isolation, disable the relevant scheduled tasks and investigate the originating binary or script.
```
→ analyst-review

## analyst-review
<!-- Analyst triage and investigation -->
```manual target=analyst
Review the identified Slack webhooks and scheduled jobs. Check the 'created_at' and 'mfa_enabled' history for the associated users in the Identity Provider (e.g., Okta, Azure AD) and correlate with recent administrative logins.
```
→ end
