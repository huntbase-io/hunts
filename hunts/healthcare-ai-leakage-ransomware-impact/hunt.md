---
analysis: A standard detection rule might alert on a known ransomware extension, but
  this hunt pivots between AI data submission patterns and subtle file/process behavioral
  anomalies to find stealthy leakage and behavioral precursors to encryption.
blind_spots:
- id: missing-endpoint-telemetry
  question: Are critical diagnostic machines without agents currently being encrypted?
  requires: Endpoint agent coverage on all medical imaging and diagnostic systems
  risk: Legacy or proprietary medical systems may not support the telemetry required
    for file and process monitoring, leaving encryption events invisible.
  stage: ransomware-encryption-for-impact
- id: proxy-encryption-gap
  question: What specifically was sent in the prompt text?
  requires: HTTPS inspection on corporate proxies
  risk: Without TLS termination, the hunt only sees the hostname and the POST method,
    not the presence of PII/PHI in the request body.
  stage: ai-prompt-data-leakage
coverage:
- stage: ai-prompt-data-leakage
  status: covered
  steps:
  - ai-interaction-lead
  - evidence-triage
- stage: ransomware-encryption-for-impact
  status: covered
  steps:
  - ransomware-file-spikes
  - suspicious-binary-prevalence
  - evidence-triage
- reason: Belongs to another part of the 'Healthcare Cyberattacks Hit Harder, Cost
    More' series.
  stage: ai-phishing-and-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'Healthcare Cyberattacks Hit Harder, Cost
    More' series.
  stage: ai-vendor-supply-chain-risk
  status: out_of_scope
- reason: Belongs to another part of the 'Healthcare Cyberattacks Hit Harder, Cost
    More' series.
  stage: healthcare-account-compromise
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Healthcare organizations face massive operational disruption costs
    from ransomware. Combining data leakage monitoring with encryption behavior provides
    a holistic view of current risks to patient care continuity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Sensitive healthcare data is being leaked via AI chat prompts while ransomware
  actors prepare or execute high-impact encryption on clinical endpoints, potentially
  using the same AI interfaces to automate data analysis or extortion.
labels:
- hunt
- attack.t1566
- attack.t1486
- attack.t1195
- impact
- initial access
name: Healthcare Data Leakage and Ransomware Impact
parameters:
  ai_domains:
    default:
    - openai.com
    - anthropic.com
    - claude.ai
    - gemini.google.com
    - chatgpt.com
    description: Domains of AI services where sensitive data leakage via prompts might
      occur.
    from:
      kind: article
      observed: '2026-10-13'
      ref: "Proofpoint \u2014 Healthcare Cyberattacks Hit Harder, Cost More"
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts identified in the lead; leave empty
      to scan the entire estate.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: scoping-parameter
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/healthcare-cyberattacks-hit-harder-cost-more
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on clinician workstations, hospital administration hosts, and servers
  hosting Electronic Medical Record (EMR) databases. Use the initial AI interaction
  lead to identify high-risk hosts before running the expensive ransomware queries.
references:
- name: "Proofpoint \u2014 Healthcare Cyberattacks Hit Harder, Cost More"
  url: https://www.proofpoint.com/us/newsroom/news/healthcare-cyberattacks-hit-harder-cost-more
related:
- hunt: ai-phishing-and-social-engineering
  reason: This hunt focuses on the high-impact aftermath of an intrusion (leakage
    and encryption), whereas phishing focuses on initial access.
  relation: out-of-scope-alternative
- hunt: healthcare-identity-ai-supply-chain-hunt
  relation: follows
scenario:
  stages:
  - name: AI-Enhanced Phishing and Social Engineering
    observables:
    - AI-generated phishing emails
    - Social engineering scams
    - Phishing links in healthcare-themed messages
    slug: ai-phishing-and-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: AI Vendor Supply Chain Risk
    observables:
    - Compromised third-party AI vendor tools
    - Manipulation of AI service delivery mechanisms
    slug: ai-vendor-supply-chain-risk
    tactic: initial-access
    techniques:
    - T1195
  - name: Healthcare Account Compromise
    observables:
    - Compromised healthcare worker accounts
    - Unauthorized authentication events
    slug: healthcare-account-compromise
    tactic: initial-access
    techniques:
    - T1566
  - name: Sensitive Data Leakage via AI Prompts
    observables:
    - Medical records submitted to AI chatbot prompts
    - HTTP POST requests to AI service domains such as openai.com
    slug: ai-prompt-data-leakage
    tactic: initial-access
    techniques:
    - T1566
  - name: Ransomware Encryption for Impact
    observables:
    - Encryption of patient care data
    - Clinical system unavailability
    - Deployment of ransomware payloads
    slug: ransomware-encryption-for-impact
    tactic: impact
    techniques:
    - T1486
  summary: Healthcare organizations are facing an escalation in cyberattacks characterized
    by AI-enhanced phishing, compromised credentials, and supply chain vulnerabilities
    in AI vendors. These incidents frequently lead to operational disruptions through
    ransomware encryption of patient records or the unauthorized leakage of sensitive
    medical data via AI prompts.
series:
  index: 2
  slug: healthcare-cyberattacks-hit-harder-cost-more
  title: Healthcare Cyberattacks Hit Harder, Cost More
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Healthcare Data Leakage and Ransomware Impact

This hunt identifies two concurrent risks in healthcare environments: the unauthorized submission of patient data to AI chatbots and the behavioral spikes associated with ransomware encryption. It begins by identifying hosts interacting with AI services via HTTP POST requests, then fans out to analyze massive file modification events and rare or detached processes on those same systems. An agent triages these signals to determine if a data leakage incident or an encryption event is in progress on clinician workstations.

## ai-interaction-lead
<!-- AI interaction via HTTP POST -->
Identify hosts sending data to AI services, which may contain sensitive medical records and establishes the initial scope.

```sqlite target=web role=scoping params=(ai_domains=ai_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The query returns specific hosts and the AI endpoints they are posting data
  to; high POST counts suggest frequent data submission. Silence implies no detectable
  interaction with the listed domains.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) as post_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_http_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND http_method = 'POST' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path
```

## corroborate-impact
<!-- Corroborate impact -->
parallel:
- → ransomware-file-spikes
- → suspicious-binary-prevalence
join: → evidence-triage

## ransomware-file-spikes
<!-- Ransomware file activity spikes -->
Find high-frequency file creation, deletion, and renaming events on suspected hosts that typify ransomware encryption.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process on a scoped host touching hundreds of files within a short window
  indicates potential encryption. Silence suggests no massive file-churn on these
  hosts.
reads:
- activity_id
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, LOWER(process_name) as process_name_case, COUNT(*) as activity_count, MIN(time) as start_time, MAX(time) as end_time FROM hb_file_activity WHERE activity_id IN (1, 4, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, LOWER(process_name) HAVING activity_count > 500 ORDER BY activity_count DESC
```

## suspicious-binary-prevalence
<!-- Suspicious binary prevalence -->
Identify rare processes or processes running from temporary paths on suspect hosts that may be acting as ransomware droppers or AI data exfiltrators.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries or fileless processes running from atypical locations across
  very few scoped hosts. Silence means no suspicious process anomalies were detected
  on the scoped set.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 3
reads:
- device_hostname
- on_disk
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT LOWER(process_name) as process_name_case, process_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (on_disk = 0 OR LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '/tmp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name), process_path HAVING host_count <= 2
```

## evidence-triage
<!-- Triage AI leakage and encryption evidence -->
```agent target=hunter
cite: required
context:
- ai-interaction-lead
- ransomware-file-spikes
- suspicious-binary-prevalence
max_iterations: 5
objective: Determine if the observed HTTP POSTs to AI domains correlate with mass
  file activity or suspicious processes on the same host, indicating either sensitive
  data leakage or active ransomware impact.
success_criteria: The agent returns a verdict for every host that appeared in more
  than one query result.
tools:
- endpoint
- web
```

## impact-routing
<!-- Route on impact verdict -->
if~: "the evidence-triage verdict is Malicious for at least one host due to active encryption or high-volume data posting" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → incident-review
unavailable: → incident-review (blind_spot: missing-endpoint-telemetry)
else: → hunt-closure

## isolate-endpoint
<!-- Isolate the endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to prevent continued exfiltration of medical records or further encryption of clinical data.
```
→ incident-review

## incident-review
<!-- Incident review -->
```manual target=analyst
Verify the contents of the AI interaction by checking proxy logs if decryption is available. Confirm the identity of the rare process found in the triage step. Oversee the recovery of any encrypted files from backup and notify the privacy officer.
```
→ end

## hunt-closure
<!-- Hunt closure -->
```manual target=analyst
Document the baseline of AI domain usage in the organization. Recommend AI usage policies if leakage risks are high even if not currently malicious. Update the hunt parameters with any new AI services discovered.
```
→ end
