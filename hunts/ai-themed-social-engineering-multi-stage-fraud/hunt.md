---
analysis: A simple detection rule would alert on a known AI domain; this hunt pivots
  from the network lure to look for the specific execution of rare AI-themed binaries
  on the host and correlates it with cloud-based authentication anomalies, covering
  the full multi-stage chain.
blind_spots:
- id: limited-cloud-auth-retention
  question: whether the device code abuse occurred before the current 14-day window
  requires: long-term hb_auth_signin retention (90+ days)
  risk: A session token harvested weeks ago may still be active but would not appear
    in the current hunt window.
  stage: aitm-token-harvesting
- id: browser-extension-visibility
  question: whether malicious AI-themed browser extensions were installed instead
    of standalone binaries
  requires: hb_file_activity or browser database monitoring
  risk: Silent installation of a browser extension might not trigger a process activity
    row, leading to a false negative for execution.
  stage: endpoint-malware-execution
coverage:
- stage: ai-themed-initial-access
  status: covered
  steps:
  - http-ai-lures
  - dns-ai-lookalikes
  - early-stage-agent
- stage: aitm-token-harvesting
  status: covered
  steps:
  - auth-device-code-abuse
  - follow-on-agent
- stage: endpoint-malware-execution
  status: covered
  steps:
  - process-stealer-execution
- reason: Surfaces for credit card data exposure are not available; BEC impact like
    inbox rules needs M365-specific mailbox activity logs not listed in the dossier.
  stage: fraudulent-impact-actions
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI brands currently carry a high level of employee trust and curiosity;
    identifying attacks that borrow this trust is a high-priority exposure that signature-based
    tools often miss due to the fast rotation of lookalike domains.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using lookalike AI domains and installers to trick users
  into downloading stealers or performing device-code authentication, leading to token
  theft and financial fraud.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1555
- attack.t1486
name: AI-Themed Social Engineering and Multi-Stage Fraud
parameters:
  ai_domains:
    default:
    - chatgpt-plus.io
    - claude-ai.biz
    - deepseek-installer.io
    - openai-update.com
    - chatgpt-payment.net
    description: Known or suspected AI-themed lookalike domains from the report.
    from:
      kind: article
      observed: '2026-09-10'
      ref: msrc-blog-2026-09-10
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins with hosts showing any AI-themed process activity to narrow
  the estate. It then expands to check network delivery across the entire environment,
  as phishing may target users who haven't yet run a binary.
references:
- name: Detect and disrupt AI-themed attacks with Microsoft Defender
  url: https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/
related:
- hunt: m365-inbox-rule-manipulation
  reason: Once an AI-themed token is harvested, the next step in the BEC chain is
    often creating inbox rules to hide fraudulent activity.
  relation: follows
scenario:
  stages:
  - name: AI-Themed Delivery and Lures
    observables:
    - ChatGPT-themed phishing emails requesting payment updates
    - Malvertising for fake AI Windows plugins
    - Fraudulent DeepSeek installers distributed via GitHub
    - Lookalike domains for AI service sign-in pages
    - Claude-themed phishing lures
    slug: ai-themed-initial-access
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Identity and Token Harvesting
    observables:
    - Microsoft device code sign-in flow abuse
    - Adversary-in-the-middle (AiTM) redirection chains
    - Harvesting of session access tokens
    - Credential harvesting via fake sign-in forms
    slug: aitm-token-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1566
  - name: Malware Execution and Stealer Deployment
    observables:
    - Vidar stealer execution from AI plugin installers
    - Execution of fraudulent DeepSeek installer binaries
    - Unauthorized installation of AI-themed browser extensions or plugins
    slug: endpoint-malware-execution
    tactic: execution
    techniques:
    - T1486
  - name: Financial Fraud and BEC Impact
    observables:
    - Creation of suspicious inbox rules for email concealment
    - Payroll fraud execution through compromised accounts
    - Unauthorized use of harvested credit card data
    slug: fraudulent-impact-actions
    tactic: impact
    techniques:
    - T1486
  summary: "Threat actors like Storm-3075 are exploiting AI-themed lures\u2014impersonating\
    \ brands like ChatGPT, Copilot, and Claude\u2014to conduct phishing, malvertising,\
    \ and fraudulent GitHub-hosted distribution. These multi-stage campaigns leverage\
    \ adversary-in-the-middle (AiTM) techniques to harvest credentials and tokens,\
    \ deliver infostealers like Vidar, and execute financial fraud such as business\
    \ email compromise and payroll redirection."
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


# AI-Themed Social Engineering and Multi-Stage Fraud

This hunt identifies multi-stage attacks where AI brands like ChatGPT, Claude, and DeepSeek are used as lures. It starts by finding hosts interacting with lookalike domains via HTTP and DNS, then pivots to identify fraudulent installers or suspicious Microsoft 365 device-code authentication patterns. By correlating the initial lure with follow-on execution or identity anomalies, the hunt distinguishes between legitimate AI usage and social engineering campaigns.

## scoping-ai-activity
<!-- Scope hosts with AI-themed process activity -->
Find hosts that have already executed processes containing AI brand names in their path or filename.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames that have handled AI-related binaries; silence indicates
  no overt AI-themed execution has occurred yet.
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%gpt%' OR LOWER(process_name) LIKE '%deepseek%' OR LOWER(process_name) LIKE '%claude%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-delivery
<!-- Correlate delivery surfaces -->
parallel:
- → http-ai-lures
- → dns-ai-lookalikes
join: → early-stage-agent

## http-ai-lures
<!-- HTTP requests to AI lookalike domains -->
Identify users interacting with suspected phishing or malvertising sites disguised as AI services.

```sqlite target=web role=triage params=(ai_domains=ai_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct URL hits indicating a user visited a lure site. Multiple unique paths
  suggest active navigation on the malicious site.
reads:
- device_hostname
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-ai-lookalikes
<!-- DNS resolutions for AI themes -->
Detect resolution of lookalike domains even when full HTTP payload is unavailable or encrypted.

```sqlite target=endpoint role=baseline params=(ai_domains=ai_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Resolution rows for known lures or high-entropy variations of AI brands.
  Grouping by process identifies the originating application.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as resolution_count FROM hb_dns_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LOWER(query_hostname) LIKE '%chatgpt%' AND LOWER(query_hostname) NOT LIKE '%openai.com')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## early-stage-agent
<!-- Analyze AI-themed delivery -->
```agent target=hunter
cite: required
context:
- http-ai-lures
- dns-ai-lookalikes
max_iterations: 3
objective: Determine if any host has successfully resolved or connected to lookalike
  AI infrastructure that deviates from official service providers.
success_criteria: A per-host verdict citing specific domain resolutions and URL paths
  found.
tools:
- endpoint
- identity
- web
```

## parallel-execution-auth
<!-- Identify execution and credential theft -->
parallel:
- → process-stealer-execution
- → auth-device-code-abuse
join: → follow-on-agent

## process-stealer-execution
<!-- Stealer execution from AI installers -->
Identify Vidar stealer or other payloads executed via fake AI installers.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Execution of binaries with AI names from user-writable directories. Rare
  parent-child pairs for these processes suggest non-standard installation.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 2
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%gpt%' OR LOWER(process_name) LIKE '%deepseek%' OR LOWER(process_name) LIKE '%installer%') AND (LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_path) LIKE '%\\public\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## auth-device-code-abuse
<!-- Microsoft device code authentication patterns -->
Identify potential session token harvesting through abuse of the legitimate device code sign-in flow.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Successful device code authentication events. Correlate with the source
  IP to see if the user is typically associated with that location.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- provider
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, time FROM hb_auth_signin WHERE provider = 'm365' AND LOWER(auth_protocol) LIKE '%device%code%' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-agent
<!-- Multi-stage attack correlation -->
```agent target=hunter
cite: required
context:
- process-stealer-execution
- auth-device-code-abuse
- early-stage-agent
max_iterations: 5
objective: Evaluate whether the delivery signals from the early-stage agent correlate
  with subsequent stealer execution or unusual device-code authentication on the same
  host or for the same user.
success_criteria: A final malicious/suspicious verdict per host, identifying the specific
  AI brand impersonated and the impact (stealer or token theft).
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on attack confirmation -->
if~: "The follow-on agent identifies a confirmed correlation between an AI-themed lure and stealer execution or token harvesting." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review-investigation
unavailable: → analyst-review-investigation (blind_spot: limited-cloud-auth-retention)
else: → close-out-report

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the verdict. Revoke any active sessions for users associated with device-code authentication findings.
```
→ analyst-review-investigation

## analyst-review-investigation
<!-- Review evidence and identity risk -->
```manual target=analyst
Verify the AI domains identified. For users who successfully used device-code authentication, check for new email forwarding or inbox rules in M365 that could indicate BEC.
```
→ close-out-report

## close-out-report
<!-- Close out and tune lures -->
```manual target=analyst
Document the findings. If malicious AI-themed domains were found, add them to the global blocklist and update the hunt parameters.
```
→ end
