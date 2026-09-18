---
analysis: A simple detection rule for 'Make.com' would yield unusable noise. This
  hunt uses prevalence to find rare operators and keywords (phish, mitm, evilginx)
  to surface intent, pivoting between endpoint extensions and network behavior.
blind_spots:
- id: http-tls-blind-spot
  question: What were the specific queries or payloads sent to automation webhooks?
  requires: hb_http_activity with full URI/Body visibility
  risk: Legitimate use of Make.com may look identical to malicious use without deep
    packet inspection or full URI visibility.
  stage: adversary-discovery-scanning
- id: extension-source-visibility
  question: Does the rare extension have permissions to read browser cookies or history?
  requires: Extension manifest data (permissions, background scripts)
  risk: A benign-looking rare extension could be a custom-built infostealer or session-hijacking
    tool.
  stage: browser-extension-persistence
coverage:
- stage: initial-access-phishing-mitm
  status: covered
  steps:
  - discovery-tools-usage
  - triage-agent
- stage: automated-c2-and-workflows
  status: covered
  steps:
  - automation-traffic-baseline
  - triage-agent
- stage: adversary-discovery-scanning
  status: covered
  steps:
  - discovery-tools-usage
- stage: browser-extension-persistence
  status: covered
  steps:
  - browser-extension-inventory
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: session-token-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Modern adversaries are moving away from traditional C2 towards legitimate
    SaaS platforms. A negative result confirms that the fleet is not being used to
    host automated attack infrastructure for phishing or MitM operations.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using legitimate automation platforms and external scanning
  tools to conduct phishing operations and manage C2 workflows through automated webhooks.
labels:
- hunt
- attack.t1090.003
- attack.t1176
- attack.t1566
name: Automated Attack Infrastructure and Discovery
parameters:
  automation_domains:
    default:
    - make.com
    - api.telegram.org
    - integromat.com
    - toolbaz.com
    - docsbot.ai
    - explo.ai
    description: Domains for legitimate automation and AI workflow platforms used
      for C2.
    from:
      kind: article
      observed: '2024-09-11'
      ref: huntress-attacker-blunder
    type: list[domain]
  discovery_domains:
    default:
    - censys.io
    - shodan.io
    - hunter.how
    - zoomeye.org
    description: Infrastructure discovery and search engine domains.
    from:
      kind: manual
      observed: '2024-09-11'
      ref: common-discovery-tools
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2024-09-11'
      ref: hunt-designer
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt.
    from:
      kind: manual
      observed: '2024-09-11'
      ref: analyst
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations assigned to IT, devops, or marketing where automation
  platforms are more common, but look for anomalous process use (e.g., cmd.exe or
  non-standard browsers making the lookups).
references:
- name: "Huntress \u2014 An attacker blunder gave us a look into their operations"
  url: https://www.huntress.com/blog/rare-look-inside-attacker-operation
related:
- hunt: session-token-persistence
  reason: This hunt focuses on the infrastructure used for automation, while session
    token persistence focuses on the post-compromise identity activity.
  relation: out-of-scope-alternative
- hunt: identity-hijacking-session-maintenance-vps
  relation: follows
scenario:
  stages:
  - name: Phishing and MitM Setup
    observables:
    - Evilginx
    - make.com
    - phishing messages
    slug: initial-access-phishing-mitm
    tactic: initial-access
    techniques:
    - T1566
  - name: Session Token Theft and Maintenance
    observables:
    - 12651980 CANADA INC
    - VIRTUO
    - session token refreshing
    - 2471 unique identities
    slug: session-token-persistence
    tactic: credential-access
    techniques:
    - T1566
  - name: Automated C2 via Make.com and Telegram
    observables:
    - make.com
    - api.telegram.org
    - Telegram Bot APIs
    - webhooks
    slug: automated-c2-and-workflows
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Infrastructure Discovery via Censys
    observables:
    - censys.io
    - Censys search for Evilginx
    slug: adversary-discovery-scanning
    tactic: discovery
  - name: Malicious or Monitoring Extensions
    observables:
    - Malwarebytes Browser Guard
    - Chrome browser extensions
    slug: browser-extension-persistence
    tactic: persistence
    techniques:
    - T1176
  summary: An attacker operating from a jump box on the Virtuo AS infrastructure conducted
    large-scale identity compromise and session token theft. They leveraged automated
    workflows via Make.com and Telegram bots to manage their operations and used Censys
    to discover targets like running Evilginx instances.
series:
  index: 2
  slug: an-attacker-blunder-gave-us-a-look-into-their-operations
  title: An attacker blunder gave us a look into their operations
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


# Automated Attack Infrastructure and Discovery

This hunt identifies hosts behaving as adversary nodes or jump boxes by detecting connections to automation platforms (Make.com, Telegram) and infrastructure discovery tools (Censys) mentioned in recent threat research. It looks for rare browser extensions, anomalous automation-related DNS lookups, and HTTP traffic containing keywords related to proxies, phishing, and webhooks.

## browser-extension-inventory
<!-- Inventory of rare browser extensions -->
Identify hosts with browser extensions that are rare across the fleet, which may indicate specialized operator tools or security-monitoring bypasses.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of extensions and the hosts they reside on. Rare extensions stand
  out for further triage.
prevalence:
  by: device_hostname
  key:
  - package_name
  - vendor_name
  rare_below: 5
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE package_type = 'extension' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-activity
<!-- Corroborate C2 and Discovery Activity -->
parallel:
- → automation-traffic-baseline
- → discovery-tools-usage
join: → triage-agent

## automation-traffic-baseline
<!-- Automation platform DNS activity baseline -->
Detect rare process lookups for automation platforms used for C2 workflows, stack-counted by host.

```sqlite target=endpoint role=detection-candidate params=(automation_domains=automation_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes querying platforms like Make.com or Telegram. Normal business
  automation will stack-count, leaving anomalies visible.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  - process_name
  rare_below: 5
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{automation_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name, query_hostname
```

## discovery-tools-usage
<!-- HTTP requests to infrastructure tools and keywords -->
Identify hosts searching for MitM infrastructure or using discovery engines, with broader keyword searches for malicious context.

```sqlite target=web role=enrichment params=(discovery_domains=discovery_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP traffic to Censys/Shodan or URIs containing automation/attack keywords.
  Silence suggests no visible automated scanning.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- user_agent
- time
- url_full
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{discovery_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_full) LIKE '%evilginx%' OR LOWER(url_full) LIKE '%phish%' OR LOWER(url_full) LIKE '%proxy%' OR LOWER(url_full) LIKE '%mitm%' OR LOWER(url_full) LIKE '%webhook%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Triage automated infrastructure activity -->
```agent target=hunter
cite: required
context:
- browser-extension-inventory
- automation-traffic-baseline
- discovery-tools-usage
max_iterations: 4
objective: Identify hosts showing a combination of rare browser extensions, automation
  platform use (Make/Telegram), and infrastructure discovery searches (Censys/Evilginx).
success_criteria: A verdict of malicious | suspicious | benign citing specific extensions
  and network events.
tools:
- endpoint
- web
```

## decision-route
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host based on corroborated automation and discovery traffic" (confidence: medium, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: http-tls-blind-spot)
else: → analyst-review

## isolate-host
<!-- Isolate potential operator host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any active browser-based sessions for the logged-in user, and initiate a forensic review of browser data.
```
→ analyst-review

## analyst-review
<!-- Forensic Review and Tuning -->
```manual target=analyst
Examine the browser extension paths and network activity. Determine if the Make.com usage is part of a sanctioned business process and record the process name to whitelist in future detections.
```
→ end
