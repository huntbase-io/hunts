---
analysis: A simple rule might catch OpenRouter DNS, but this hunt correlates it with
  specific third-party service lookups (Roblox, DoorDash) and the presence of locally
  staged evidence files, providing the context needed to confirm a mature infostealer
  operation.
blind_spots:
- id: no-http-transparency
  question: whether the POST request to OpenRouter occurred and what it contained
  requires: hb_http_activity or decrypted proxy logs
  risk: If HTTP inspection is missing, we only see DNS for OpenRouter, which is common
    for developer AI usage, leading to false negatives.
  stage: ai-triage-and-assessment
- id: self-deletion-evasion
  question: whether Identity_Report.txt was created and then immediately removed
  requires: hb_file_activity real-time event streaming
  risk: The malware is self-deleting; if snapshot-based file collection misses the
    creation window, the primary file indicator is lost.
  stage: ai-triage-and-assessment
coverage:
- stage: session-driven-enrichment
  status: covered
  steps:
  - dns-leads-to-enrichment
  - file-artifact-creation
- stage: ai-triage-and-assessment
  status: covered
  steps:
  - http-api-triage-requests
  - file-artifact-creation
- reason: 'Belongs to another part of the ''Appraisal by AI: Model-driven victim prioritization
    in the VOLTA infostealer'' series.'
  stage: malware-execution-and-logging
  status: out_of_scope
- reason: 'Belongs to another part of the ''Appraisal by AI: Model-driven victim prioritization
    in the VOLTA infostealer'' series.'
  stage: credential-harvesting-and-abe-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Appraisal by AI: Model-driven victim prioritization
    in the VOLTA infostealer'' series.'
  stage: exfiltration-and-self-deletion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VOLTA uses AI to automate the analysis of stolen data, drastically
    increasing the attacker's monetization speed. Detecting this post-harvest phase
    allows us to identify the full scope of a breach beyond simple credential theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using stolen session tokens to query third-party APIs for
  victim data enrichment and calling LLMs to prioritize assets for exfiltration.
labels:
- hunt
- attack.t1041
- attack.t1555
- attack.t1539
- attack.t1114.002
- attack.t1005
- collection
- credential access
- execution
- exfiltration
name: Cloud Service Enrichment and AI Assessment
parameters:
  enrichment_domains:
    default:
    - openrouter.ai
    - rolimons.com
    - battle.net
    - hide.me
    - ubereats.com
    - doordash.com
    - grubhub.com
    description: Domains used by VOLTA for victim enrichment and AI assessment.
    from:
      kind: article
      observed: '2026-10-31'
      ref: talos-volta-ai
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-31'
      ref: retention-policy
    type: number
  report_files:
    default:
    - Identity_Report.txt
    - AI_Analysis.txt
    - volta_dox.zip
    description: Local artifacts generated during the enrichment and AI triage phase.
    from:
      kind: article
      observed: '2026-10-31'
      ref: talos-volta-ai
    type: list[path]
  scope_hosts:
    default: []
    description: Target hosts to narrow the hunt; populate with results from the DNS
      scoping step.
    from:
      kind: manual
      observed: '2026-10-31'
      ref: analyst-scoping
    type: list[host]
  volta_process_names:
    default:
    - 9BY0tjwOc3ut.exe
    - yLP9m5J3i2Aw.exe
    description: Process names identified as responsible for enrichment DNS lookups.
    from:
      kind: article
      observed: '2026-10-31'
      ref: talos-sample-details
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations and high-value user profiles where cloud
  tokens (Gmail, Slack) are likely to be present. Use the DNS lead query to identify
  candidates for the full HTTP and File inspection via the scope_hosts parameter.
references:
- name: "Talos \u2014 Appraisal by AI: Model-driven victim prioritization in the VOLTA\
    \ infostealer"
  url: https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
related:
- hunt: volta-stealer-core-harvesting
  reason: The harvesting of credentials and session tokens precedes the enrichment
    and AI triage phase covered here.
  relation: follows
scenario:
  stages:
  - name: Malware execution and logging
    observables:
    - 9BY0tjwOc3ut.exe
    - yLP9m5J3i2Aw.exe
    - '%APPDATA%\volta_debug.txt'
    slug: malware-execution-and-logging
    tactic: execution
    techniques:
    - T1204.002
  - name: Credential harvesting and ABE bypass
    observables:
    - chrome.exe --headless
    - WlanGetProfileList
    - Identity_Report.txt
    slug: credential-harvesting-and-abe-bypass
    tactic: credential-access
    techniques:
    - T1555
    - T1555.003
  - name: Session-driven enrichment
    observables:
    - rolimons.com
    - battle.net
    - hide.me
    - order history requests to DoorDash/UberEats
    - Gmail API queries for receipts
    slug: session-driven-enrichment
    tactic: collection
    techniques:
    - T1539
    - T1114.002
  - name: AI triage and assessment
    observables:
    - openrouter.ai/api/v1/chat/completions
    - AI_Analysis.txt
    - 'system prompt: forensic intelligence analyst drafting a target assessment'
    slug: ai-triage-and-assessment
    tactic: collection
    techniques:
    - T1005
  - name: Exfiltration and self-deletion
    observables:
    - volta_dox.zip
    - deletion of 9BY0tjwOc3ut.exe
    slug: exfiltration-and-self-deletion
    tactic: exfiltration
    techniques:
    - T1041
    - T1070.004
  summary: "VOLTA is a Windows infostealer that automates post-compromise victim prioritization\
    \ using Large Language Models. After harvesting credentials and personal data\u2014\
    enriched via stolen sessions for services like Gmail and UberEats\u2014it POSTs\
    \ a structured bundle to the OpenRouter API to generate a monetization dossier\
    \ before exfiltrating the results and self-deleting."
series:
  index: 2
  slug: appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer
  title: 'Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Cloud Service Enrichment and AI Assessment

This hunt identifies the post-collection behavior of the VOLTA infostealer, where it uses harvested sessions to profile victims and uses AI for asset triage. After harvesting credentials, the malware queries services like Gmail, DoorDash, and Roblox to enrich a victim dossier. It then POSTs this bundle to OpenRouter (an AI aggregator) to rank the monetization value. We hunt for this by correlating DNS lookups for enrichment domains with specific HTTP POSTs to AI providers and the creation of local report artifacts like Identity_Report.txt.

## dns-leads-to-enrichment
<!-- DNS resolutions for enrichment and AI services -->
Identify hosts resolving domains associated with session-based enrichment or AI prioritization as a starting lead.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, enrichment_domains=enrichment_domains)
~~~yaml
expected: Rare resolutions for OpenRouter or niche food/gaming domains indicate potential
  enrichment activity. Silence suggests no such lookups occurred.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-01'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{enrichment_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## corroborate-activity
<!-- Corroborate leads on HTTP and File surfaces -->
parallel:
- → http-api-triage-requests
- → file-artifact-creation
join: → triage-volta-behavior

## http-api-triage-requests
<!-- HTTP POSTs to enrichment and AI APIs -->
Detect specific API calls that send the victim dossier for assessment or query third-party enrichment services.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, enrichment_domains=enrichment_domains, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to OpenRouter or enrichment endpoints, specifically from hosts
  identified in the scoping step.
reads:
- device_hostname
- http_method
- src_endpoint_ip
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-01'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, url_path, http_method, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{enrichment_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-artifact-creation
<!-- Creation of Identity and AI analysis reports -->
Find the local evidence bundles and AI dossiers created before exfiltration, including activity from processes linked to enrichment lookups.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, report_files=report_files, volta_process_names=volta_process_names, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The presence of files named Identity_Report.txt or AI_Analysis.txt, or files
  created by known VOLTA processes.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-01'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND (instr(',' || '{{report_files}}' || ',', ',' || file_name || ',') > 0 OR instr(',' || '{{volta_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-volta-behavior
<!-- Weigh the evidence for VOLTA -->
```agent target=hunter
cite: required
context:
- dns-leads-to-enrichment
- http-api-triage-requests
- file-artifact-creation
max_iterations: 5
objective: 'Determine if the host exhibits the VOLTA behavior pattern: resolving enrichment
  domains, POSTing to OpenRouter, and creating report files.'
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows for each indicator.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on VOLTA verdict -->
if~: "the triage-volta-behavior verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-transparency)
else: → close-out

## contain-host
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Immediately revoke the user's active sessions for Google (Gmail), Discord, and Slack, as these are actively being used for post-harvest enrichment.
```
→ analyst-review

## analyst-review
<!-- Review AI dossiers and telemetry -->
```manual target=analyst
Examine the Identity_Report.txt if it survived. Identify which third-party services were successfully enriched (e.g., UberEats, Roblox). Search for other hosts showing the same enrichment DNS pattern.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Summarize the findings, record the number of hosts requiring remediation, and suggest detection rules for OpenRouter API POST activity.
```
→ end
