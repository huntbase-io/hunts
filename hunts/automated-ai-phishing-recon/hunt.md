---
analysis: This is a hunt because these services (Make.com, Google Translate, Censys)
  are often legitimate. A single detection rule would be too noisy. The hunt pivots
  between domain resolution, fleet-wide rarity, and keyword-based web patterns to
  build a suspicious context an agent and analyst must weigh.
blind_spots:
- id: encrypted-traffic-blind-spot
  owner: Network Engineering
  question: What are the specific URL paths and payloads being sent to Make.com or
    AI assistants?
  remediation: Deploy TLS break-and-inspect on corporate gateways for higher-risk
    egress.
  requires: TLS inspection / proxy decryption
  risk: Without inspection, we only see the domains. We cannot distinguish between
    a user asking ChatGPT for a recipe vs. an attacker generating phishing lure content.
  stage: automated-targeting-recon
- id: self-hosted-automation
  owner: Security Operations
  question: Is the attacker using self-hosted automation tools like n8n or local LLMs?
  remediation: Include queries for common self-hosted automation tool ports and binary
    names.
  requires: hb_network_connection / hb_process_activity
  risk: These would not appear in DNS queries for public domains like Make.com, bypassing
    the scoping query.
  stage: automated-targeting-recon
coverage:
- stage: automated-targeting-recon
  status: covered
  steps:
  - dns-recon-leads
  - tool-prevalence-stack
  - web-recon-patterns
- stage: external-infrastructure-discovery
  status: covered
  steps:
  - dns-recon-leads
  - web-recon-patterns
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: identity-compromise-maintenance
  status: out_of_scope
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: infrastructure-and-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Threat actors are increasingly embedding AI and legitimate low-code
    automation into their kill chain to scale operations. Detecting these blunders
    and workflow anomalies is critical for preempting phishing campaigns.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using legitimate automation platforms and AI-writing assistants
  to generate localized phishing content and discover external infrastructure, visible
  through specific DNS and web telemetry patterns.
labels:
- hunt
- attack.t1566
- attack.t1583.001
- attack.t1589.002
name: Automated AI-Driven Phishing Reconnaissance
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  recon_domains:
    default:
    - make.com
    - toolbaz.com
    - docsbot.ai
    - explo.ai
    - censys.io
    - api.telegram.org
    description: Domains associated with the attacker's automation and reconnaissance
      toolset.
    from:
      kind: article
      observed: '2024-09-11'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with general user workstations. Marketing or Sales departments may
  have a higher baseline for Make.com; focus initial analysis on rare instances in
  IT or Engineering segments.
references:
- name: "Huntress \u2014 An attacker blunder gave us a look into their operations"
  url: https://www.huntress.com/blog/rare-look-inside-attacker-operation
related:
- hunt: identity-compromise-maintenance
  reason: Once the reconnaissance is successful, the next phase involves maintenance
    of compromised identities.
  relation: follows
scenario:
  stages:
  - name: AI-Driven Phishing Automation
    observables:
    - make.com
    - toolbaz.com
    - docsbot.ai
    - explo.ai
    - Telegram Bot API integration
    - Google Translate for phishing localization
    - csv generator ai
    slug: automated-targeting-recon
    tactic: initial-access
    techniques:
    - T1566
  - name: Evilginx Instance Discovery
    observables:
    - censys.io
    - Evilginx MITM framework instances
    slug: external-infrastructure-discovery
    tactic: discovery
  - name: Session Token Theft and Identity Abuse
    observables:
    - 2471 unique identities
    - session token refreshing
    - malicious mail rule creation
    slug: identity-compromise-maintenance
    tactic: credential-access
  - name: Jump Box Proxy and Persistence
    observables:
    - AS 12651980 CANADA INC (VIRTUO)
    - Malwarebytes browser guard extension
    - Autoruns research
    - Jump box operations
    slug: infrastructure-and-persistence
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1176
  summary: "An attacker's operational security failure\u2014installing a security\
    \ agent on their own jump box\u2014revealed a highly automated workflow using\
    \ AI tools and Make.com for phishing and targeting. The actor specialized in credential\
    \ theft through Evilginx instances and maintained long-term access to thousands\
    \ of identities by refreshing session tokens and creating malicious mail rules."
series:
  index: 1
  slug: an-attacker-blunder-gave-us-a-look-into-their-operations
  title: An attacker blunder gave us a look into their operations
  total: 3
severity: medium
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Automated AI-Driven Phishing Reconnaissance

This hunt identifies hosts interacting with a specific set of automation (Make.com), AI generation (Toolbaz, DocsBot, Explo), and infrastructure discovery (Censys) services mentioned in recent research. It focuses on the 'automated-targeting-recon' and 'external-infrastructure-discovery' stages by looking for anomalous combinations of these tools, which indicate an attacker streamlining their reconnaissance and content generation workflows.

## dns-recon-leads
<!-- DNS resolution for recon and automation domains -->
Identify hosts resolving domains used for AI content generation and infrastructure discovery.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, recon_domains=recon_domains)
~~~yaml
expected: Hosts resolving make.com, toolbaz.com, or censys.io. While some (like Make.com)
  may be legitimate, Toolbaz and DocsBot are less common in corporate environments.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{recon_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## parallel-corroboration
<!-- Analyze prevalence and web behavior -->
parallel:
- → tool-prevalence-stack
- → web-recon-patterns
join: → triage-recon-activity

## tool-prevalence-stack
<!-- Fleet-wide prevalence of recon domains -->
Stack-count unique host associations with the recon domains to isolate outliers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, recon_domains=recon_domains)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Domains like 'toolbaz.com' or 'docsbot.ai' appearing on only one or two
  hosts, whereas 'make.com' might appear across many.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen_in_window FROM hb_dns_activity WHERE instr(',' || '{{recon_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 5
```

## web-recon-patterns
<!-- HTTP patterns matching recon activity -->
Find web requests containing keywords like 'censys' or 'translate' that indicate manual or automated discovery.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to search engines or translation services involving 'Evilginx'
  or Censys search queries.
reads:
- device_hostname
- time
- url_hostname
- url_path
- url_query
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (LOWER(url_hostname) LIKE '%censys%' OR LOWER(url_path) LIKE '%translate%' OR LOWER(url_hostname) LIKE '%evilginx%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-recon-activity
<!-- Triage AI and Recon Signals -->
```agent target=hunter
cite: required
context:
- dns-recon-leads
- tool-prevalence-stack
- web-recon-patterns
max_iterations: 3
objective: Determine if any host is using the combination of Make.com, AI writing
  tools, and Censys for malicious reconnaissance or phishing content generation.
success_criteria: Categorize hosts as 'suspicious' if they use multiple rare tools
  from the list, particularly when combined with Censys searches.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on triage result -->
if~: "The triage verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → analyst-review
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-traffic-blind-spot)
else: → close-out

## analyst-review
<!-- Manual Review of AI Workflow -->
```manual target=analyst
Examine the browser history and network activity of the flagged host. Look for logins to Make.com and check if the automation triggers match phishing campaigns or infrastructure discovery. Check for use of 'Evilginx' or 'Censys' keywords in search engines.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Document any identified legitimate business uses for the AI tools and adjust the prevalence thresholds for future runs.
```
→ end
