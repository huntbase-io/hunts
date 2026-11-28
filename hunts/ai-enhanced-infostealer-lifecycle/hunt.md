---
analysis: A single detection rule on headless Chrome flags too much legitimate automation.
  This hunt pivots between process parentage, file access patterns, and LLM-specific
  network traffic to confirm a malicious narrative.
blind_spots:
- id: missing-process-telemetry
  question: whether headless browser launches occurred on unmanaged systems
  requires: endpoint agent process monitoring
  risk: An attacker on a system without an agent can harvest data silently until exfiltration
    is detected at the network layer.
  stage: headless-browser-execution
- id: browser-internal-visibility
  question: what specific data was retrieved from webmail services inside the browser
    session
  requires: TLS-inspecting proxy or browser-level tracing
  risk: We can see the browser ran and the host connected to the webmail domain, but
    not the specific search terms for receipts or home addresses.
  stage: email-enrichment-collection
coverage:
- stage: headless-browser-execution
  status: covered
  steps:
  - headless-launch-analysis
- stage: credential-and-wallet-harvesting
  status: covered
  steps:
  - sensitive-file-access
- blind_spot: browser-internal-visibility
  reason: Standard endpoint logs cannot see interaction between a headless browser
    and webmail APIs once the session is established.
  stage: email-enrichment-collection
  status: not_visible
- stage: ai-prioritized-exfiltration
  status: covered
  steps:
  - llm-exfiltration-dns
- stage: evasion-via-self-deletion
  status: covered
  steps:
  - malware-self-deletion
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The VOLTA infostealer drastically reduces attacker monetization time
    by using AI to prioritize stolen data; a negative result across the estate confirms
    that no such automated harvesting campaign is currently active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed an infostealer that uses headless browser sessions
  to harvest credentials and cryptocurrency wallets, followed by exfiltration to LLM
  providers for AI-driven data prioritization and automated cleanup via self-deletion.
labels:
- hunt
- attack.t1486
- attack.t1555
- attack.t1552.001
- attack.t1566
- attack.t1204.002
- attack.t1114.002
- attack.t1041
- attack.t1070.004
- collection
- credential access
- defense evasion
- execution
- exfiltration
name: AI-Enhanced Infostealer Lifecycle
parameters:
  llm_domains:
    default:
    - api.openai.com
    - api.anthropic.com
    - api.cohere.ai
    - api.groq.com
    - api.mistral.ai
    - api.perplexity.ai
    description: LLM API endpoints used for data prioritization and analysis.
    from:
      kind: article
      observed: '2026-11-05'
      ref: talos
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-05'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Restrict the hunt to specific hosts; leave empty to scan the entire
      estate.
    from:
      kind: manual
      observed: '2026-11-05'
      ref: analyst-scoping
    type: list[host]
  sensitive_filenames:
    default:
    - seed.txt
    - mnemonic.txt
    - wallet.json
    - key.txt
    - cookies
    - login data
    description: Filenames associated with cryptocurrency wallets and browser credential
      stores.
    from:
      kind: article
      observed: '2026-11-05'
      ref: talos
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/bring-a-tent-ive-got-the-coffee-lessons-from-it-sa/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin by focusing on hosts where developer tools or high-value crypto-related
  software is expected. Widen the hunt if DNS activity to LLM domains is observed
  on unrelated systems.
references:
- name: "Cisco Talos \u2014 Bring a tent, I've got the coffee: Lessons from it-sa"
  url: https://blog.talosintelligence.com/bring-a-tent-ive-got-the-coffee-lessons-from-it-sa/
related:
- hunt: generic-headless-chrome-abuse
  reason: This hunt is specifically tailored to the VOLTA infostealer's AI-driven
    lifecycle, not general browser automation abuse.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Headless Browser Launch
    observables:
    - chrome.exe launching with the --headless flag
    slug: headless-browser-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Credential and Wallet Harvesting
    observables:
    - Accessing Chrome App-Bound Encryption
    - Reading plaintext seed phrases for cryptocurrency wallets from disk
    - Harvesting session tokens and browser credentials
    slug: credential-and-wallet-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1552.001
  - name: AI-Assisted Email Enrichment
    observables:
    - Using stolen session tokens to search victim emails for purchase receipts
    - Extracting physical home addresses from email content
    slug: email-enrichment-collection
    tactic: collection
    techniques:
    - T1114.002
  - name: LLM-Based Data Prioritization
    observables:
    - Sending structured evidence bundles to LLM APIs for ranking
    - Multi-model failover to different AI providers if primary assessment is refused
    - Exfiltration of a prioritized dossier of high-value assets
    slug: ai-prioritized-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Malware Self-Deletion
    observables:
    - Malware executable deleting itself from the filesystem after exfiltration
    slug: evasion-via-self-deletion
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: VOLTA is a mature Windows infostealer that automates victim profiling by
    using LLMs to prioritize stolen data. The malware harvests credentials and cryptocurrency
    wallets before using stolen session access to search the victim's emails for physical
    addresses to enrich the data, finally exfiltrating a prioritized dossier and self-deleting.
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
tlp: clear
type: investigation
---


# AI-Enhanced Infostealer Lifecycle

This hunt identifies the mature VOLTA infostealer lifecycle by correlating behavioral endpoint indicators with network-based data prioritization patterns. It begins by scoping hosts with browser installations, then parallelizes the search for headless browser execution and sensitive file access (wallets/cookies). An agent triages these early-stage results before the hunt pivots to observe exfiltration to LLM API endpoints and malware self-deletion. This phased approach allows for the detection of automated, AI-assisted theft that baseline detection rules often miss due to the modular nature of the attack.

## scoping-chrome-installation
<!-- Scope hosts with browser installations -->
Identify hosts in the estate that have Chrome or Chromium installed, focusing the hunt on platforms capable of supporting VOLTA's headless browser harvesting.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where browser software is present. Silence means no hosts
  match, which restricts the hunt only to those systems.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%chromium%'
```

## early-stage-investigation
<!-- Investigate execution and harvesting -->
parallel:
- → headless-launch-analysis
- → sensitive-file-access
join: → early-stage-triage

## headless-launch-analysis
<!-- Headless browser launch analysis -->
Identify processes launching Chrome with the --headless flag and stack-count the parents to find rare, suspicious binaries.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare parent processes launching headless Chrome. Legitimate automation (CI/CD,
  Selenium) will cluster together, while infostealer binaries will stand out.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- parent_process_name
- parent_process_cmd_line
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, process_name, parent_process_name, parent_process_cmd_line, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%--headless%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## sensitive-file-access
<!-- Access to wallets and browser stores -->
Find file activity where suspicious processes access cryptocurrency seeds or browser credential files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_filenames=sensitive_filenames)
~~~yaml
expected: Non-browser processes reading files related to credentials or crypto wallets.
  Any hit here is a high-fidelity indicator of harvesting.
reads:
- device_hostname
- process_name
- file_path
- file_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, process_name, file_path, file_name, activity_name, time FROM hb_file_activity WHERE (instr(',' || '{{sensitive_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR LOWER(file_path) LIKE '%\google\chrome\user data%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Early-stage harvesting triage -->
```agent target=hunter
cite: required
context:
- headless-launch-analysis
- sensitive-file-access
max_iterations: 4
objective: Identify hosts where the headless browser execution correlates with unauthorized
  file access to sensitive credential stores or wallets.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  relevant rows.
tools:
- endpoint
```

## follow-on-investigation
<!-- Investigate exfiltration and evasion -->
parallel:
- → llm-exfiltration-dns
- → malware-self-deletion
join: → final-lifecycle-triage

## llm-exfiltration-dns
<!-- Exfiltration to LLM endpoints -->
Correlate the suspicious hosts with DNS queries to known LLM API domains used for AI-driven data prioritization.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, llm_domains=llm_domains)
~~~yaml
expected: Hosts already flagged for harvesting now resolving LLM provider domains.
  This confirms the prioritization and exfiltration phase.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE instr(',' || '{{llm_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## malware-self-deletion
<!-- Cleanup via malware self-deletion -->
Find file activity where a process deletes its own executable, the final evasion step in the VOLTA lifecycle.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A binary deleting itself. While some installers do this, it is rare for
  sustained user processes and highly suspicious when following harvesting.
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE activity_id = 4 AND LOWER(process_name) = LOWER(file_path) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-lifecycle-triage
<!-- Final lifecycle assessment -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- llm-exfiltration-dns
- malware-self-deletion
max_iterations: 6
objective: Determine if the identified hosts exhibit the full lifecycle of the AI-enhanced
  infostealer, citing correlation between execution, harvesting, exfiltration to AI
  domains, and self-deletion.
success_criteria: A final malicious | suspicious verdict per host with a reasoning
  chain.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final assessment -->
if~: "the final-lifecycle-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: missing-process-telemetry)
else: → close-out

## contain-and-revoke
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke all active browser-based session tokens for the affected user. If crypto seed phrases were identified in the harvesting phase, treat the associated wallets as fully compromised and initiate fund migration protocols.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the host for evidence of the initial breach (e.g., suspicious Homebrew installations or phishing links). Use HTTP logs if available to trace what specific email contents were accessed during the AI enrichment phase.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Document all findings. If legitimate automation servers were flagged, update the baseline exclusion list for the headless browser launch query.
```
→ end
