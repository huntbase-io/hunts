---
analysis: A standard detection rule would likely alert on any PowerShell on macOS;
  this hunt pivots from software inventory into HTTP User-Agents and then into specific
  cloud authentication patterns to distinguish developer activity from malicious agent
  abuse.
blind_spots:
- id: missing-cloud-agent-metadata
  question: Can we definitively confirm an OBO flow occurred directly from the log
    fields?
  requires: hb_auth_signin with full Agentic sub-fields (agentType, agentSubjectType)
  risk: Without these sub-fields, we must infer OBO behavior from the AppID and IP,
    which may increase false positives for legitimate developers.
  stage: agent-obo-sign-in
- id: consent-audit-gap
  question: When and how was the initial consent granted to the agent blueprint?
  requires: Entra ID AuditLogs for 'Add delegated permission grant' operations
  risk: The hunt only identifies post-consent activity. Missing the root cause (consent
    grant) delays detection until the adversary takes their first action.
  stage: consent-grant-access-agent
coverage:
- blind_spot: consent-audit-gap
  reason: Requires Entra ID AuditLogs for delegated permission grants, which are not
    currently available in the listed surfaces.
  stage: consent-grant-access-agent
  status: not_visible
- stage: powershell-client-trigger
  status: covered
  steps:
  - scope-powershell-inventory
  - detect-powershell-ua
- stage: agent-obo-sign-in
  status: covered
  steps:
  - graph-cli-logins
  - rare-auth-ips
- reason: Detection of HTTP traffic from the versioned PowerShell UA to Graph endpoints
    covers the exfiltration phase.
  stage: graph-api-malicious-action
  status: covered
  steps:
  - detect-powershell-ua
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Entra Agent ID introduces a novel impersonation vector that can bypass
    traditional MFA once delegated consent is granted. Monitoring these workflows
    ensures that even if an attacker bypasses MFA via consent, their subsequent actions
    can be identified.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is abusing Entra Agent ID by tricking users into granting
  'access_agent' scopes, then triggering malicious On-Behalf-Of (OBO) workflows via
  a specific macOS PowerShell client.
labels:
- hunt
- attack.t1059.001
name: Suspicious Entra Agentic Workflows
parameters:
  graph_cli_client_id:
    default: 14d82eec-204b-4c2f-b7e8-296a70dab67e
    description: The Entra Client ID for the Microsoft Graph Command Line Tools application.
    from:
      kind: article
      observed: '2026-06-08'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  powershell_version:
    default: 7.6.1
    description: The specific PowerShell version observed in the malicious User-Agent.
    from:
      kind: article
      observed: '2026-06-08'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    type: string
  scope_hosts:
    default: []
    description: Limit behavioral queries to hosts found in the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins with hb_software_inventory to identify hosts with any version
  of PowerShell installed. This narrows the behavioral checks to the relevant macOS
  or developer systems.
references:
- name: "Red Canary \u2014 Investigating suspicious AI workflows in Microsoft Entra\
    \ Agent ID"
  url: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
related:
- hunt: azure-consent-fix-monitoring
  reason: The consent-grant portion of this attack overlaps with 'ConsentFix' techniques
    used to maintain persistence via localhost redirects.
  relation: sibling
scenario:
  stages:
  - name: Consent to Agent Blueprint Scope
    observables:
    - access_agent
    - 14d82eec-204b-4c2f-b7e8-296a70dab67e
    - http://localhost/
    - beddadf7-4f3b-4e9b-8443-0b0cf777446e
    slug: consent-grant-access-agent
    tactic: initial-access
  - name: PowerShell Execution from MacOS
    observables:
    - PowerShell/7.6.1
    - Mozilla/5.0 (Macintosh; macOS 26.4.1; en-US) PowerShell/7.6.1
    - 51.3.97.221
    slug: powershell-client-trigger
    tactic: execution
    techniques:
    - T1059.001
  - name: Agentic On-Behalf-Of Sign-in
    observables:
    - 8cd0a10f-0be8-413a-9bf2-f44bc568d1e4
    - agenticAppInstance
    - notAgentic
    - Group.Read.All
    - Mail.ReadWrite
    - Mail.Send
    - MailboxSettings.ReadWrite
    - User.Read
    slug: agent-obo-sign-in
    tactic: credential-access
  - name: Graph API Email Exfiltration
    observables:
    - bigwig_CFO@importantcompany.com
    - Here is your invoice
    - 40.126.23.26
    slug: graph-api-malicious-action
    tactic: exfiltration
  summary: An attacker leverages Microsoft Entra Agent ID's On-Behalf-Of (OBO) flow
    by inducing a user to consent to an agent blueprint, enabling the attacker to
    impersonate the user. Using a PowerShell client on macOS, the attacker triggers
    the agent to send malicious emails via the Microsoft Graph API, leaving identifiable
    traces in sign-in metadata and network traffic.
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


# Suspicious Entra Agentic Workflows

Entra ID assistive agents can act on behalf of users, inheriting their permissions and potentially bypassing MFA. This hunt targets the specific tradecraft of using a macOS-based PowerShell client (version 7.6.1) to trigger these workflows. It first identifies hosts with PowerShell installed, then looks for the unique HTTP User-Agent string associated with the reported exploit, and correlates these triggers with rare non-interactive sign-ins to the Microsoft Graph Command Line Tools application.

## scope-powershell-inventory
<!-- Scope hosts with PowerShell installed -->
Identify macOS or other hosts that have PowerShell installed, as it is the primary execution vector for triggering the malicious agentic workflow.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Silence suggests the specific trigger software is not
  present in the estate, which limits the threat surface.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%powershell%' OR LOWER(package_name) LIKE '%pwsh%')
```

## parallel-check
<!-- Correlate HTTP traffic and Entra sign-ins -->
parallel:
- → detect-powershell-ua
- → graph-cli-logins
- → rare-auth-ips
join: → triage-agentic-activity

## detect-powershell-ua
<!-- Identify versioned PowerShell User-Agent -->
Find HTTP traffic originating from the specific PowerShell version (7.6.1) used in the reported assistive agent exploit.

```sqlite target=web role=detection-candidate params=(powershell_version=powershell_version, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to Graph endpoints with the versioned UA. This is a high-confidence
  indicator of the specific PowerShell client trigger.
reads:
- device_hostname
- src_endpoint_ip
- url_hostname
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, user_agent, time FROM hb_http_activity WHERE user_agent LIKE '%PowerShell/{{powershell_version}}%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## graph-cli-logins
<!-- Monitor sign-ins to Graph Command Line Tools -->
Identify authentications to the Microsoft Graph Command Line Tools app, which is the primary target for OBO impersonation in this scenario.

```sqlite target=identity role=triage params=(graph_cli_client_id=graph_cli_client_id, lookback_days=lookback_days)
~~~yaml
expected: Successful sign-ins to the Graph CLI. Overlap with the HTTP UA IPs indicates
  the 'True IP' of the attacker.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%graph command line%' OR instr(LOWER(dst_endpoint_name), '{{graph_cli_client_id}}') > 0) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-auth-ips
<!-- Baseline authentication source IPs -->
Stack-count source IPs to find rare endpoints accessing Entra ID, which helps isolate the adversary beachhead from common office IPs.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare source IPs used by 2 or fewer users. This highlights the non-corporate
  source IPs used to trigger the Graph API.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS auth_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING user_count <= 2 ORDER BY user_count ASC
```

## triage-agentic-activity
<!-- Triage Agentic Activity -->
```agent target=hunter
cite: required
context:
- scope-powershell-inventory
- detect-powershell-ua
- graph-cli-logins
- rare-auth-ips
max_iterations: 5
objective: Determine if the combination of PowerShell hosts, versioned HTTP User-Agents,
  and Graph CLI sign-ins indicate an unauthorized assistive agent workflow.
success_criteria: A verdict of malicious or suspicious for any user/host/IP correlation
  that matches the reported OBO workflow signature.
tools:
- endpoint
- identity
- web
```

## route-on-triage
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one user-host pair showing the OBO pattern" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-cloud-agent-metadata)
else: → analyst-manual-review

## isolate-and-revoke
<!-- Isolate Beachhead and Revoke Sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
1. Isolate the identified macOS host via the endpoint agent.
2. Revoke all active sessions and refresh tokens for the identified user in Entra ID.
3. Audit all recent delegated permission grants for that user in the Entra portal.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the correlated HTTP traffic and Sign-in logs. Verify if the user intentionally consented to an AI agent blueprint (e.g., 'access_agent' scope). Identify the specific Agent ID used and document the blueprint principal.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document the findings, specifically the malicious Agent Blueprint IDs and source IPs. If the PowerShell User-Agent version (7.6.1) was confirmed as malicious, promote the detection step to a permanent alerting rule.
```
→ end
