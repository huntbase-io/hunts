---
analysis: A static detection rule for 'curl piped to bash' is too noisy for developer
  estates. This hunt moves beyond a single rule by correlating that behavior with
  the preceding access to specific AI domains and the subsequent access to credential
  stores, while using prevalence counting to highlight attacker-crafted commands across
  the fleet.
blind_spots:
- id: encrypted-uri-blindspot
  question: whether the user specifically visited a /share/ or /artifact/ path on
    the AI domain.
  requires: hb_http_activity with full URI visibility
  risk: Without full URI visibility, we rely on the temporal correlation of AI base
    domain traffic and terminal commands, which is less precise than identifying the
    malicious artifact URL directly.
  stage: legitimate-ai-platform-access
- id: clipboard-monitoring-gap
  question: whether the command was pasted from a browser into a terminal.
  requires: Endpoint telemetry for clipboard events
  risk: Direct evidence of a paste from a browser process into a shell process would
    definitively prove the social engineering vector; without it, we must infer it
    from timing and rarity.
  stage: user-driven-clipboard-execution
coverage:
- stage: legitimate-ai-platform-access
  status: covered
  steps:
  - dns-to-ai-platforms
- stage: malicious-domain-redirection
  status: covered
  steps:
  - dns-to-ai-platforms
- stage: user-driven-clipboard-execution
  status: covered
  steps:
  - rare-interpreter-commands
- stage: credential-secret-theft
  status: covered
  steps:
  - credential-file-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: "Threat actors are weaponizing trusted infrastructure that users\
    \ are increasingly required to use for productivity. Identifying abuse of these\
    \ 'trust boundaries'\u2014where a legitimate domain masks a malicious instruction\u2014\
    is critical to preventing credential theft that traditional filters miss."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is abusing trust in legitimate AI platforms (Claude, ChatGPT,
  Grok) to socially engineer users into executing malicious shell commands or downloading
  malware via shared conversations and artifacts.
labels:
- hunt
- attack.t1566.002
- attack.t1204.001
- attack.t1204.002
- attack.t1059.001
- attack.t1059.004
- attack.t1005
- attack.t1552.004
- attack.t1555.001
name: AI Platform Abuse and Clipboard Execution
parameters:
  ai_domains:
    default:
    - claude.ai
    - chatgpt.com
    - grok.com
    - openai.com
    description: Legitimate AI domains identified in the research as hosting lures.
    from:
      kind: article
      observed: '2026-08-27'
      ref: huntress-ai-attack-surface
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: standard-lookback
    type: number
  malicious_redirects:
    default:
    - downloading-api.it.com
    description: External domains identified as hosting malware following the AI lures.
    from:
      kind: article
      observed: '2026-08-27'
      ref: huntress-ai-attack-surface
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to restrict the hunt to, typically those identified in
      the scoping or DNS steps.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: analyst-pasted
    type: list[host]
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
rationale: The hunt scopes initially to hosts with browsers or shell environments.
  If the environment is developer-heavy, prioritize results where the AI domain traffic
  occurs within 10 minutes of a rare shell execution.
references:
- name: "Huntress \u2014 The AI Attack Surface: How Threat Actors Abuse Trusted AI\
    \ Platforms"
  url: https://www.huntress.com/blog/ai-attack-surface
related:
- hunt: socially-engineered-cli-patterns
  reason: General ClickFix patterns often share these shell indicators but use different
    lures (e.g., fake support pages).
  relation: sibling
scenario:
  stages:
  - name: Access to Trusted AI Platforms via SEO
    observables:
    - claude.ai
    - chatgpt.com
    - grok.com
    - claude.ai/share
    - Claude Artifacts
    slug: legitimate-ai-platform-access
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Redirection to Malicious Malware Hosting
    observables:
    - downloading-api.it.com
    slug: malicious-domain-redirection
    tactic: execution
    techniques:
    - T1204.001
  - name: User-Driven Command Execution
    observables:
    - curl
    - Terminal
    - PowerShell
    - ClaudeDesktop.exe
    - ClickFix instructions
    slug: user-driven-clipboard-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1059.004
    - T1204.002
  - name: Credential and Secret Exfiltration
    observables:
    - Keychain secrets
    - Telegram sessions
    - SSH keys
    - Cloud keys
    - Browser cookies
    - ~/.ssh
    slug: credential-secret-theft
    tactic: collection
    techniques:
    - T1005
    - T1552.004
    - T1555.001
  summary: Threat actors are exploiting the trust associated with AI platforms like
    Claude, ChatGPT, and Grok by using SEO poisoning and sponsored search results
    to lure users to malicious artifacts or shared conversations. Once on these legitimate
    domains, victims are tricked into downloading trojanized installers or pasting
    malicious terminal commands that deploy stealers such as AMOS, MacSync, and SectopRAT
    to exfiltrate credentials and sensitive system secrets.
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
tlp: clear
type: investigation
---


# AI Platform Abuse and Clipboard Execution

This hunt identifies the pivot from legitimate AI platform interaction to local execution of malicious payloads, a technique used to deliver stealers like MacSync and AMOS. It starts by identifying hosts with the necessary software surface (browsers and shells), then correlates DNS requests for AI-shared content with rare, attacker-crafted 'ClickFix' shell commands and subsequent sensitive file access. By weighing the sequence of events—web traffic followed by clipboard-driven terminal execution—the hunt distinguishes social engineering from developer activity.

## scope-to-affected-software
<!-- Scope to hosts with browsers or shells -->
Filter the estate to hosts that have the software required for this attack chain (browsers for the lure, shells for the execution).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. These are the systems where the attack vector is plausible.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) IN ('safari', 'google chrome', 'microsoft edge', 'firefox') OR LOWER(package_name) LIKE '%powershell%') AND (LOWER(vendor_name) IN ('apple', 'google', 'microsoft') OR vendor_name IS NULL)
```

## dns-to-ai-platforms
<!-- DNS activity to AI shares and redirects -->
Identify hosts that visited the AI platforms or the malicious redirect domains named in the report within the scoped population.

```sqlite target=endpoint role=triage params=(ai_domains=ai_domains, malicious_redirects=malicious_redirects, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts talking to Claude, ChatGPT, Grok, or the known malicious redirect
  domain. Silence means no observed interaction with these specific indicators.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, MIN(time) as first_seen, COUNT(*) as lookup_count FROM hb_dns_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{malicious_redirects}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## investigate-activity
<!-- Investigate Execution and Collection -->
parallel:
- → rare-interpreter-commands
- → credential-file-access
join: → triage-agent

## rare-interpreter-commands
<!-- Rare ClickFix-style shell execution -->
Detect rare command-line patterns typically used when a user is tricked into pasting a command from an AI interface.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Highly rare or unique command lines involving pipes to interpreters or download-and-execute
  patterns. Benign administrative commands will stack higher.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 4
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%powershell%' OR LOWER(process_name) LIKE '%bash%' OR LOWER(process_name) LIKE '%sh' OR LOWER(process_name) LIKE '%zsh%') AND (LOWER(process_cmd_line) LIKE '%| bash%' OR LOWER(process_cmd_line) LIKE '%| sh%' OR LOWER(process_cmd_line) LIKE '%iex%' OR LOWER(process_cmd_line) LIKE '%-enc%' OR LOWER(process_cmd_line) LIKE '%curl %downloading-api%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 3
```

## credential-file-access
<!-- Access to credential and secret stores -->
Corroborate suspicious commands by looking for the final stage of the attack: reading sensitive local files.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Access to identity-rich files by unexpected processes (not the browser itself).
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.ssh/%' OR LOWER(file_path) LIKE '%/keychain%' OR LOWER(file_path) LIKE '%/cookies%' OR LOWER(file_path) LIKE '%/login data%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage AI platform abuse -->
```agent target=hunter
cite: required
context:
- dns-to-ai-platforms
- rare-interpreter-commands
- credential-file-access
max_iterations: 6
objective: Determine if the host's access to AI platforms was followed by a social-engineering-driven
  command execution that exfiltrated or accessed sensitive local secrets. Differentiate
  between developer activity and 'ClickFix' instructions.
success_criteria: A detailed verdict citing specifically which shell command correlates
  with which AI platform visit and subsequent file access.
tools:
- endpoint
```

## verdict-decision
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host, indicating a high-confidence attack chain." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-uri-blindspot)
else: → close-out

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect all browser history and the full shell history (.bash_history, .zsh_history) for the affected user session.
```
→ analyst-review

## analyst-review
<!-- Review and record findings -->
```manual target=analyst
Confirm the malicious nature of the shell command. Verify the connection between the AI platform visit (e.g., share link or artifact) and the execution timestamp.
```
→ end

## close-out
<!-- Close hunt -->
```manual target=analyst
If shell activity was determined to be benign (e.g., development work), document the command pattern to reduce future noise. Record the percentage of the scoped estate that showed zero AI platform traffic.
```
→ end
