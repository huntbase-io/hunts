---
analysis: A standard detection might fire on a GitHub login from an unusual IP, but
  it would not distinguish between a dev on a new VPN and an attacker. This hunt uses
  the phishing lure (HTTP visit) as a temporal pivot to confirm the authorization
  was coerced, and then correlates it with the unique 'parent=copilot-agent' behavioral
  signal on the endpoint.
blind_spots:
- id: no-cloud-api-telemetry
  owner: Cloud Infrastructure Team
  question: Which specific private repositories were exfiltrated by the phished token?
  remediation: Enable the GitHub Enterprise Cloud connector in Microsoft Defender
    for Cloud Apps.
  requires: hb_cloud_api_activity with GitHub connector
  risk: Without GitHub audit logs, we can identify the theft but not the scope of
    data loss, leaving IP theft unquantified.
  stage: cloud-repository-access
- id: agent-shell-truncation
  owner: Endpoint Security Team
  question: Were sensitive credentials passed into the steered terminal sessions?
  remediation: Increase the process command-line capture length to 2048 characters.
  requires: Full process command line capture
  risk: If the EDR truncates long command lines, the specific steering commands (including
    exfiltration URLs or secondary lures) may be hidden.
  stage: agent-remote-steering
coverage:
- stage: spearphishing-link-delivery
  status: covered
  steps:
  - lure-page-visits
- stage: device-code-authorization
  status: covered
  steps:
  - rare-github-logins
  - authorization-read
- stage: agent-remote-steering
  status: covered
  steps:
  - agent-command-execution
- stage: cloud-repository-access
  status: covered
  steps:
  - cloud-resource-manipulation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI coding agents have privileged access to source code and local
    terminals. A hijacked agent session can result in immediate IP theft and lateral
    movement onto developer machines, making a proactive hunt for phished authorizations
    a high-priority business requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has hijacked an AI coding agent by phishing a device code
  from a developer, obtaining an OAuth token to steer local terminal sessions and
  exfiltrate private repository data.
labels:
- hunt
- attack.t1566.002
- attack.t1528
- attack.t1190
- collection
- credential access
- execution
- initial access
name: AI Coding Agent Device Code Hijacking
parameters:
  copilot_client_ids:
    default:
    - Iv1.b50115654fd18491
    description: OAuth Client IDs for known AI agents like GitHub Copilot CLI.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: github-oauth-docs
    type: list[string]
  device_login_urls:
    default:
    - github.com/login/device
    description: Legitimate device login URLs used in phishing lures.
    from:
      kind: article
      observed: '2026-11-17'
      ref: msrc-blog
    type: list[url]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on; leave empty to hunt across
      the entire estate.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: analyst-defined
    type: list[host]
  shell_interpreters:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - bash
    - sh
    description: Common shell interpreters launched by coding agents during steering.
    from:
      kind: manual
      observed: '2026-11-17'
      ref: standard-shells
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on systems where the developer-focused 'gh' or 'copilot' binaries
  are present in software inventory. If the organization uses a centralized proxy,
  the HTTP activity should be examined there to capture lure visits from all hosts.
references:
- name: The risks of device code authentication for AI coding agents
  url: https://www.microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents/
related:
- hunt: m365-device-code-phishing
  reason: This hunt is specific to GitHub AI agents; general M365 device code phishing
    is handled by a separate sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spearphishing Link Delivery
    observables:
    - github.com/login/device
    - Lure via Microsoft Teams message
    - Lure via Email
    - Pretext of IT request or Copilot license check
    slug: spearphishing-link-delivery
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Device Code Authorization
    observables:
    - OAuth device flow
    - GitHub Copilot CLI public client ID
    - 'Requested scopes: repo, read:user, read:org, gist, codespace'
    - Approval from IP address differing from requesting client IP
    slug: device-code-authorization
    tactic: credential-access
    techniques:
    - T1528
  - name: AI Agent Remote Steering
    observables:
    - Copilot CLI remote control enabled
    - Agent running commands on user machine
    - Interactive session steering
    - Anomalous parent-child process relationship involving copilot-agent
    slug: agent-remote-steering
    tactic: execution
    techniques:
    - T1190
  - name: Cloud Repository Access
    observables:
    - Accessing private repositories via OAuth token
    - Reading synchronized Copilot CLI sessions
    - Modification of AI memory via /memory command
    - Enumeration of organization resources
    slug: cloud-repository-access
    tactic: collection
    techniques:
    - T1528
  summary: Attackers leverage device code phishing to trick users into authorizing
    OAuth tokens for AI coding agents like GitHub Copilot CLI. This authorized access
    enables the attacker to remotely steer active agent sessions, inject malicious
    instructions into the agent's memory, and exfiltrate source code from private
    repositories.
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


# AI Coding Agent Device Code Hijacking

This hunt targets the abuse of OAuth device flows where an attacker lures a user into authorizing a legitimate application client like GitHub Copilot CLI. The hunt follows a phased flow: first scoping to hosts with coding agents, then identifying lure-page visits and anomalous authentication from unusual IPs, and finally hunting for the resulting local command execution and cloud repository enumeration. By correlating the phishing lure with the resulting agent behavior, the hunt distinguishes legitimate developer workflow from a remote takeover.

## scope-copilot-hosts
<!-- Identify hosts with AI coding agents -->
Define the hunt scope by identifying systems where GitHub Copilot or similar CLI tools are installed.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames belonging to developers or systems using AI tools. Silence
  means no such software was recorded by package managers.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%copilot%' OR LOWER(package_name) LIKE '%gh-cli%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-signals
<!-- Capture early-stage phishing and auth -->
parallel:
- → lure-page-visits
- → rare-github-logins
join: → authorization-read

## lure-page-visits
<!-- Visits to device code verification pages -->
Find users who navigated to the legitimate GitHub device login page, which is the required user action for the phishing attack.

```sqlite target=web role=enrichment params=(device_login_urls=device_login_urls, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicate a user followed a link to enter a device code. Silence means
  no one visited the login page from an enrolled host.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{device_login_urls}}' || ',', ',' || LOWER(url_hostname) || LOWER(url_path) || ',') > 0 OR instr(',' || '{{device_login_urls}}' || ',', ',' || LOWER(url_full) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-github-logins
<!-- Rare GitHub sign-ins by IP -->
Identify GitHub sign-ins using AI agent clients that originate from rare source IPs, potentially representing an attacker finishing the OAuth flow.

```sqlite target=identity role=baseline params=(copilot_client_ids=copilot_client_ids, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A sign-in from an IP address not common for a given user or client ID. Fleet-wide
  IPs used by many users are suppressed.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- app_id
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT src_endpoint_ip, actor_user_name, app_id, COUNT(DISTINCT device_hostname) as hosts, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_auth_signin WHERE provider = 'github' AND (LOWER(dst_endpoint_name) LIKE '%copilot%' OR instr(',' || '{{copilot_client_ids}}' || ',', ',' || app_id || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, app_id HAVING hosts <= 3
```

## authorization-read
<!-- Analyze authorization context -->
```agent target=hunter
cite: required
context:
- scope-copilot-hosts
- lure-page-visits
- rare-github-logins
max_iterations: 4
objective: Determine if any sign-in from a rare IP was preceded by a visit to the
  GitHub device login page on a host associated with the same user, suggesting the
  user authorized an attacker's client.
success_criteria: A verdict of malicious | suspicious | benign per user/host with
  cited evidence.
tools:
- endpoint
- identity
- web
```

## follow-on-evidence
<!-- Hunt for steering and exfiltration -->
parallel:
- → agent-command-execution
- → cloud-resource-manipulation
join: → intrusion-verdict

## agent-command-execution
<!-- Remote steering via coding agent -->
Detect the agent running local shell commands, which confirms the attacker is steering the active terminal session remotely.

```sqlite target=endpoint role=detection-candidate params=(shell_interpreters=shell_interpreters, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Shell processes spawned by the AI agent. Legitimate use exists (e.g., a
  dev asking the agent to run a test), so correlation with the suspicious sign-in
  is critical.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%copilot-agent%' OR LOWER(parent_process_name) LIKE '%gh-copilot%') AND instr(',' || '{{shell_interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## cloud-resource-manipulation
<!-- GitHub repository and memory access -->
Find evidence of the attacker using the phished token to enumerate private repositories or modify the agent's memory to poison future interactions.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: API activity targeting private code or the agent's memory store. High volume
  of repository enumeration from the rare IP identified earlier is a strong hit.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'github' AND (LOWER(api_operation) LIKE '%repository%' OR LOWER(api_operation) LIKE '%memory%' OR LOWER(api_operation) LIKE '%gist%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## intrusion-verdict
<!-- Final intrusion assessment -->
```agent target=hunter
cite: required
context:
- authorization-read
- agent-command-execution
- cloud-resource-manipulation
max_iterations: 6
objective: Determine if an attacker successfully hijacked a coding agent session.
  Consider the verdict from the authorization analysis together with shell activity
  and cloud API resource access.
success_criteria: A final verdict citing the phished account, the source IP of the
  attacker, and the confirmed impact (steering or exfiltration).
tools:
- endpoint
- identity
- web
```

## route-response
<!-- Route based on verdict -->
if~: "the intrusion-verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → revoke-token
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-api-telemetry)
else: → hunt-close-out

## revoke-token
<!-- Revoke GitHub OAuth tokens -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke the authorized OAuth application for the affected user in the GitHub Enterprise admin panel, specifically focusing on Copilot CLI or the identified app_id.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the GitHub audit logs for every repository accessed by the token. Inspect the host for any persistence (e.g., new cron jobs or SSH keys) dropped during the period the agent was steered.
```
→ end

## hunt-close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the legitimate source IPs and common command patterns used by the coding agent to reduce false positives in future detections. Close the hunt report.
```
→ end
