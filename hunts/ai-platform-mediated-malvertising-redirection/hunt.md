---
analysis: "A simple block on AI platforms is impractical for most organizations. This\
  \ hunt uses prevalence analysis to identify rare AI artifact paths and correlates\
  \ them with behavioral signals (browser-spawned shells) and known redirectors\u2014\
  context a single static rule cannot weigh accurately without high false positives."
blind_spots:
- id: no-tls-decryption
  question: whether the specific /artifacts/ or /share/ path components are visible
  requires: hb_http_activity with URI inspection (via decryption)
  risk: Without TLS decryption, only the root AI domain (e.g., claude.ai) is visible,
    making it difficult to distinguish a malicious artifact lure from standard platform
    usage.
  stage: initial-access-seo-redirection
- id: rotating-delivery-infrastructure
  question: whether the redirector domain has changed since publication
  requires: continuously updated malicious_domains parameter
  risk: Attackers rotate delivery domains frequently; a negative result for 'downloading-api.it.com'
    does not prove absence of newer redirection variants.
  stage: malicious-payload-delivery
coverage:
- stage: initial-access-seo-redirection
  status: covered
  steps:
  - ai-platform-lead
  - rare-shared-ai-paths
- stage: malicious-payload-delivery
  status: covered
  steps:
  - malicious-redirect-connections
  - browser-spawned-shells
- reason: 'Belongs to another part of the ''The AI Attack Surface: How Threat Actors
    Abuse Trusted AI Platforms'' series.'
  stage: clipboard-command-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''The AI Attack Surface: How Threat Actors
    Abuse Trusted AI Platforms'' series.'
  stage: stealer-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''The AI Attack Surface: How Threat Actors
    Abuse Trusted AI Platforms'' series.'
  stage: sensitive-data-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors weaponize the inherent trust in legitimate AI platforms
    to bypass domain reputation filters. Identifying the specific chain from a trusted
    domain to a shell execution or malicious redirect is critical for detecting initial
    access in the current AI attack surface.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is abusing trusted AI platforms such as Claude or ChatGPT
  to host malicious redirection lures via SEO poisoning, funnelling users from legitimate
  AI domains to secondary malware delivery infrastructure.
labels:
- hunt
- attack.t1566.002
- attack.t1204.001
name: AI Platform Mediated Malvertising and Redirection
parameters:
  ai_domains:
    default:
    - claude.ai
    - chatgpt.com
    - grok.com
    - www.claude.ai
    - www.chatgpt.com
    description: Trusted AI domains used in redirection lures.
    from:
      kind: article
      observed: '2026-08-27'
      ref: https://www.huntress.com/blog/ai-attack-surface
    type: list[domain]
  browser_indicators:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - safari
    - brave.exe
    - google chrome
    - microsoft edge
    description: Browser process names acting as parents for ClickFix-style execution.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-designer
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-policy
    type: number
  malicious_domains:
    default:
    - downloading-api.it.com
    description: Known malicious redirect and payload delivery domains named in the
      research.
    from:
      kind: article
      observed: '2026-08-27'
      ref: https://www.huntress.com/blog/ai-attack-surface
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hosts to target; leave empty to hunt across the entire estate.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-scoping
    type: list[host]
  shell_indicators:
    default:
    - powershell.exe
    - pwsh.exe
    - cmd.exe
    - bash
    - zsh
    - sh
    - terminal
    description: Shell and interpreter process names to monitor for browser-spawned
      execution.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-designer
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ai-attack-surface
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins with broad DNS visibility for AI platforms, narrowing only
  once rare shared paths or secondary redirection domains are identified. High-value
  workstations or users likely to use AI for development/support should be prioritized.
references:
- name: "Huntress \u2014 The AI Attack Surface: How Threat Actors Abuse Trusted AI\
    \ Platforms"
  url: https://www.huntress.com/blog/ai-attack-surface
related:
- hunt: browser-paste-terminal-execution
  reason: The direct execution of commands pasted from the clipboard (ClickFix) is
    a behavioral stage requiring deep script-block analysis, whereas this hunt focuses
    on the AI-mediated redirection chain.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI Platform SEO Redirection
    observables:
    - claude.ai
    - chatgpt.com
    - grok.com
    - claude.ai/share
    - sponsored search results
    - Bing
    - Google Search
    slug: initial-access-seo-redirection
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.001
  - name: AI-Themed Payload Delivery
    observables:
    - downloading-api.it.com
    - ClaudeDesktop.exe
    slug: malicious-payload-delivery
    tactic: execution
    techniques:
    - T1204.001
  - name: Terminal and PowerShell Execution
    observables:
    - curl
    - powershell
    - zsh
    - bash
    - Terminal
    - Apple Support install guide lure
    - Clear disk space lure
    slug: clipboard-command-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1059.004
  - name: Malware Persistence
    observables:
    - new scheduled tasks
    - SectopRAT
    - AMOS
    - MacSync
    slug: stealer-persistence
    tactic: persistence
    techniques:
    - T1053.005
  - name: Credential and Secret Theft
    observables:
    - ~/.ssh
    - ~/.aws
    - ~/Library/Keychains
    - browser cookies
    - Telegram sessions
    slug: sensitive-data-access
    tactic: credential-access
    techniques:
    - T1555
    - T1539
    - T1552
  summary: Threat actors are utilizing SEO poisoning to lure victims into interacting
    with malicious artifacts and shared conversations on trusted AI platforms like
    Claude, ChatGPT, and Grok. These interactions lead to either the download of fake
    installers from malicious redirect domains or the execution of commands via Terminal
    and PowerShell that deploy credential stealers. The resulting malware, such as
    AMOS and MacSync, establishes persistence via scheduled tasks and exfiltrates
    sensitive credentials, cloud keys, and browser data.
series:
  index: 1
  slug: the-ai-attack-surface-how-threat-actors-abuse-trusted-ai-platforms
  title: 'The AI Attack Surface: How Threat Actors Abuse Trusted AI Platforms'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI Platform Mediated Malvertising and Redirection

This hunt identifies hosts that interact with shared AI platform content—specifically Claude Artifacts and shared conversations—and subsequently connect to known malicious redirect domains or exhibit suspicious browser-to-shell transitions. Attackers exploit the high domain reputation of AI platforms to bypass filters and establish trust before delivering payload-carrying commands or binaries. We focus on the rare transition from a trusted AI domain to a malicious delivery domain, a pattern that identifies initial access attempts mediated by these platforms.

## ai-platform-lead
<!-- Identify AI platform resolution -->
Identify hosts that have interacted with targeted AI platforms to establish the initial candidate set for the redirection hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, ai_domains=ai_domains)
~~~yaml
expected: A list of hosts and the specific AI domains they resolved. Silence indicates
  no traffic to these platforms, proving absence of the reported redirection chain.
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.claude.ai' OR LOWER(query_hostname) LIKE '%.chatgpt.com') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookup_count DESC
```

## corroborate-lures
<!-- Corroborate lures and behavioral signals -->
parallel:
- → rare-shared-ai-paths
- → malicious-redirect-connections
- → browser-spawned-shells
join: → triage-redirection

## rare-shared-ai-paths
<!-- Rare shared AI platform paths -->
Identify hosts visiting specific shared content that is rare across the fleet, suggesting a targeted lure rather than general platform usage.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, ai_domains=ai_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare URLs visiting shared AI content. Rare paths are high-probability
  candidates for malicious artifacts.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 3
reads:
- url_hostname
- url_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT url_hostname, url_path, COUNT(DISTINCT device_hostname) AS host_count, GROUP_CONCAT(DISTINCT device_hostname) AS hosts FROM hb_http_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND (LOWER(url_path) LIKE '%/share/%' OR LOWER(url_path) LIKE '%/artifacts/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path HAVING host_count <= 3 ORDER BY host_count ASC
```

## malicious-redirect-connections
<!-- Check for malicious redirect traffic -->
Detect network connections to infrastructure identified as the secondary delivery stage following an AI platform redirection.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, malicious_domains=malicious_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Any connection to the specified redirect domains. Hits indicate the user
  progressed past the initial lure to the payload site.
reads:
- device_hostname
- dst_endpoint_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_ip, process_name, time FROM hb_network_connection WHERE instr(',' || '{{malicious_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## browser-spawned-shells
<!-- Browser-spawned terminal processes -->
Detect behavioral signals of 'ClickFix' where a browser redirects a user to instructions that result in terminal execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, shell_indicators=shell_indicators, browser_indicators=browser_indicators, scope_hosts=scope_hosts)
~~~yaml
expected: Shell launches where the parent is a web browser. This behavior is highly
  suspicious when it occurs immediately following an AI platform visit.
reads:
- device_hostname
- process_name
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{shell_indicators}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{shell_indicators}}' || ',', ',' || LOWER(process_path) || ',') > 0) AND (instr(',' || '{{browser_indicators}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-redirection
<!-- Correlate redirection and behavior -->
```agent target=hunter
cite: required
context:
- ai-platform-lead
- rare-shared-ai-paths
- malicious-redirect-connections
- browser-spawned-shells
max_iterations: 6
objective: 'Determine if a host followed the AI redirection sequence: accessed a trusted
  AI platform, visited a rare shared link or artifact, and then connected to a malicious
  domain or spawned a shell. Cite specific timestamps to demonstrate a temporal link
  between the lure and the behavioral signal.'
success_criteria: A per-host verdict of malicious, suspicious, or benign citing correlated
  rows.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route based on agent verdict -->
if~: "the triage verdict is malicious for at least one host, indicating a confirmed transition from a rare AI artifact to malicious infrastructure or browser-spawned shells" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-tls-decryption)
else: → close-out

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Retrieve any associated binaries identified in the browser-spawned shell command lines for further analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Verify the AI platform shared paths and check hb_script_activity for commands matching ClickFix lures. Confirm whether the redirection resulted in a successful malware infection (e.g., SectopRAT or AMOS).
```
→ close-out

## close-out
<!-- Hunt closure -->
```manual target=analyst
Record the results of the triage and any identified malicious indicators. If browser-spawned shell behavior is verified as high-confidence, promote it to a standing detection rule.
```
→ end
