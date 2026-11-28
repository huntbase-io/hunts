---
analysis: A single rule cannot correlate natural language email receipt with subsequent
  cloud-to-cloud data access across SharePoint and Exchange. This hunt uses a phased
  approach to baseline normal activity and pivots to agent-specific behaviors that
  require an analyst's weigh-in.
blind_spots:
- id: missing-body-telemetry
  question: whether encrypted or early-deleted emails contained the injection payload
  requires: access to decrypted email body content
  risk: If an email is encrypted (S/MIME) or purged before ingestion, the trigger
    remains invisible, leaving only the cloud audit aftermath.
  stage: prompt-injection-obfuscation
- id: agent-attribution-gap
  question: whether an action was performed manually by the user or automatically
    by their agent
  requires: distinct User-Agent or AppId for AI services
  risk: Legitimate user activity might be flagged as agent-driven if the audit log
    does not explicitly distinguish the AI service principal's session.
  stage: ai-assisted-collection
coverage:
- stage: ai-generated-phishing-delivery
  status: covered
  steps:
  - suspicious-ai-emails
- stage: prompt-injection-obfuscation
  status: covered
  steps:
  - suspicious-ai-emails
- stage: ai-assisted-collection
  status: covered
  steps:
  - ai-agent-collection
- stage: agent-driven-exfiltration
  status: covered
  steps:
  - ai-agent-exfiltration
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI agents increasingly handle sensitive organizational context, making
    prompt injection a high-impact vector for silent exfiltration. A negative result
    confirms the integrity of automated assistants.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has delivered a prompt-injection email that manipulated a
  cloud-hosted AI agent into collecting sensitive SharePoint documents and exfiltrating
  them via outbound email.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1530
- attack.t1567
- collection
- exfiltration
- initial access
- microsoft-365
name: AI Agent Manipulation and Data Exfiltration
parameters:
  internal_domains:
    default:
    - example.com
    description: Internal domains to exclude from sender analysis.
    from:
      kind: article
      observed: '2026-11-25'
      ref: https://www.microsoft.com/en-us/security/blog/2026/11/25/microsoft-named-a-leader-in-the-2026-gartner-magic-quadrant-for-email-security/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty for the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/25/microsoft-named-a-leader-in-the-2026-gartner-magic-quadrant-for-email-security/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt prioritizes users with modern Teams and Office installations (v24+)
  as they support integrated AI agents. Start with these hosts before widening to
  all cloud users.
references:
- name: "Microsoft Security Blog \u2014 AI is changing both sides of the inbox"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/25/microsoft-named-a-leader-in-the-2026-gartner-magic-quadrant-for-email-security/
related:
- hunt: m365-bec-unusual-mail-rules
  reason: Standard BEC hunts for mail rule changes; this hunt specifically targets
    AI agent manipulation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-generated Phishing Delivery
    observables:
    - Natural language emails with perfect grammar
    - Plausible requests following previous business context
    - Lack of malicious attachments or links
    slug: ai-generated-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Prompt Injection via Hidden Text
    observables:
    - White text on a white background in email body
    - Instructions to AI agents hidden in email content
    - Directives to 'gather financial documents' or 'send to outside address'
    slug: prompt-injection-obfuscation
    tactic: initial-access
    techniques:
    - T1190
    - T1566
  - name: AI-assisted Document Collection
    observables:
    - AI assistant accessing financial documents (Excel, PDF) in SharePoint or OneDrive
      immediately following email receipt
    - Automated retrieval of sensitive documents by Copilot or similar agents
    slug: ai-assisted-collection
    tactic: collection
    techniques:
    - T1530
  - name: Agent-driven Exfiltration
    observables:
    - AI agent sending gathered data to an external email address
    - Outbound web requests from AI service accounts to unknown external addresses
    slug: agent-driven-exfiltration
    tactic: exfiltration
    techniques:
    - T1567
  summary: Attackers leverage generative AI to create contextually accurate phishing
    emails that bypass traditional filters by containing no malicious links or attachments.
    These emails may include hidden prompt injection instructions, such as white text
    on a white background, designed to trick AI assistants into collecting financial
    documents and exfiltrating them to external addresses.
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


# AI Agent Manipulation and Data Exfiltration

This hunt targets the manipulation of AI agents, such as Microsoft Copilot, through hidden prompt injection in emails. Attackers bypass traditional phishing filters by using natural language that contains directives for the AI assistant rather than malicious links. The hunt follows a phased flow: first, it identifies suspicious emails containing prompt-injection keywords and baselines rare sign-ins to AI-integrated services. It then pivots to cloud audit logs to detect automated file access and outbound messaging performed by AI principals on behalf of users. By correlating the trigger email with subsequent automated activity, the hunt identifies successful agent-driven compromises.

## scope-ai-users
<!-- Scope hosts with AI-integrated software -->
Identify hosts running modern, AI-integrated versions of Teams and Office to narrow the hunt to likely AI users.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running AI-capable application versions. Silence implies
  no modern office suites are installed via standard packaging.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'microsoft teams' OR LOWER(package_name) LIKE 'microsoft 365%') AND (package_version LIKE '24%' OR package_version LIKE '25%' OR package_version LIKE '26%')
```

## early-indicators
<!-- Branch for phishing and logon indicators -->
parallel:
- → suspicious-ai-emails
- → rare-teams-logons
join: → agent-trigger-analysis

## suspicious-ai-emails
<!-- Email with prompt injection keywords -->
Find external emails containing keywords used to override AI agent instructions.

```sqlite target=microsoft-365 role=detection-candidate params=(lookback_days=lookback_days, internal_domains=internal_domains)
~~~yaml
expected: Messages containing directives for AI agents. Silence suggests no plain-text
  prompt injection attempts matched these keywords.
reads:
- id
- sender
- subject
- body_preview
- body
- received_date_time
- tenant_id
silence: not_evidence_of_absence
source: microsoft365_mail_message
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT id, sender, subject, body_preview, received_date_time, tenant_id FROM microsoft365_mail_message WHERE received_date_time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(body) LIKE '%ignore previous%' OR LOWER(body) LIKE '%system prompt%' OR LOWER(body) LIKE '%financial documents%' OR LOWER(body) LIKE '%forward to %') AND NOT (instr(',' || '{{internal_domains}}' || ',', ',' || LOWER(substr(sender, instr(sender, '@') + 1)) || ',') > 0)
```

## rare-teams-logons
<!-- Rare logons to AI-integrated services -->
Identify anomalous source IPs for sign-ins to AI interfaces, providing potential session context for an attack.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs seen on only one or two hosts, potentially indicating unauthorized
  access or proxying. Silence is evidence of absence for rare IP logons to these specific
  services.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 2
reads:
- actor_user_name
- src_endpoint_ip
- device_hostname
- dst_endpoint_name
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%teams%' OR LOWER(dst_endpoint_name) LIKE '%office%' OR LOWER(dst_endpoint_name) LIKE '%copilot%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING hosts <= 2
```

## agent-trigger-analysis
<!-- Evaluate trigger indicators -->
```agent target=hunter
cite: required
context:
- scope-ai-users
- suspicious-ai-emails
- rare-teams-logons
max_iterations: 3
objective: Identify suspicious emails that likely carry prompt injection instructions
  and correlate them with any rare authentication activity.
success_criteria: A list of targeted users and the exact time they received the suspicious
  email, cited from the results.
tools:
- endpoint
- identity
- microsoft-365
```

## follow-on-activity
<!-- Branch for agent-driven consequences -->
parallel:
- → ai-agent-collection
- → ai-agent-exfiltration
join: → agent-full-chain

## ai-agent-collection
<!-- Automated AI document collection -->
Detect AI agents accessing or downloading multiple sensitive files from SharePoint or OneDrive.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A pattern of rapid document access by an AI service principal. Silence suggests
  no automated file interaction by known AI strings.
reads:
- actor_user_name
- src_endpoint_ip
- api_operation
- resource_name
- time
- user_agent
- api_service_name
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT actor_user_name, src_endpoint_ip, api_operation, resource_name, time, user_agent FROM hb_cloud_api_activity WHERE api_service_name IN ('SharePoint', 'OneDrive') AND (LOWER(user_agent) LIKE '%copilot%' OR LOWER(actor_user_name) LIKE '%copilot%') AND api_operation IN ('FileDownloaded', 'FileAccessed', 'FilePreviewed') AND time >= datetime('now', '-{{lookback_days}} days')
```

## ai-agent-exfiltration
<!-- Agent-driven outbound email exfiltration -->
Detect AI agents sending messages to external domains, potentially carrying gathered documents.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, internal_domains=internal_domains)
~~~yaml
expected: Outbound email initiated by an AI agent to an external recipient. Silence
  is evidence that no AI-driven outbound mail occurred to external domains.
reads:
- actor_user_name
- api_operation
- target_user_name
- time
- user_agent
- api_service_name
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT actor_user_name, api_operation, target_user_name, time, user_agent FROM hb_cloud_api_activity WHERE api_service_name = 'Exchange' AND api_operation = 'Send' AND (LOWER(user_agent) LIKE '%copilot%' OR LOWER(actor_user_name) LIKE '%copilot%') AND NOT (instr(',' || '{{internal_domains}}' || ',', ',' || LOWER(substr(target_user_name, instr(target_user_name, '@') + 1)) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-full-chain
<!-- Final full-chain correlation -->
```agent target=hunter
cite: required
context:
- agent-trigger-analysis
- ai-agent-collection
- ai-agent-exfiltration
max_iterations: 6
objective: Determine if the suspicious emails identified earlier directly resulted
  in the AI agent accessing sensitive documents and sending them to external addresses.
success_criteria: A timeline per user showing email receipt, followed within minutes
  by AI agent document access and exfiltration.
tools:
- endpoint
- identity
- microsoft-365
```

## route-on-verdict
<!-- Route on full-chain verdict -->
if~: "the agent verdict is malicious for at least one user, showing a prompt injection email followed by agent-driven data theft" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-body-telemetry)
else: → close-out

## isolate-identity
<!-- Isolate identity and revoke sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the affected user, reset their password, and disable AI agent permissions (e.g., Copilot license) pending a full investigation.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Inspect the full content of the suspicious email to confirm the presence of prompt injection directives and verify if the documents accessed by the agent were sensitive.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the findings and update email filtering policies to include identified prompt-injection strings as high-risk indicators.
```
→ end
