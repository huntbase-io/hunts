---
analysis: A single alert on Make.com or AI tools is prone to noise. This hunt identifies
  the cluster of research, automation, and session management characterizing an adversary
  operating machine.
blind_spots:
- id: nat-correlation-gap
  question: Which specific device belongs to the IP performing high-volume sign-ins?
  requires: VPN or DHCP logs correlating src_endpoint_ip to internal hostnames
  risk: A sign-in anomaly identifies a network location but cannot pin it to a device
    without additional correlation data.
  stage: identity-persistence-via-session-refresh
- id: dns-visibility-limitation
  question: Is the adversary using DoH to hide AI research activity?
  requires: Endpoint process-to-network correlation with SNI capture
  risk: Standard DNS logging misses lookups if the adversary uses custom DNS-over-HTTPS
    providers.
  stage: phishing-research-and-ai-generation
coverage:
- stage: phishing-research-and-ai-generation
  status: covered
  steps:
  - ai-research-dns
- stage: automation-infrastructure-setup
  status: covered
  steps:
  - automation-infra-dns
- stage: identity-persistence-via-session-refresh
  status: covered
  steps:
  - identity-session-maintenance
- stage: host-persistence-and-tool-usage
  status: covered
  steps:
  - scope-security-tools
  - adversary-tool-usage
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries using automation and AI to manage thousands of stolen
    sessions represents a significant escalation in capability. Identifying these
    hubs neutralizes large-scale phishing backends.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is operating a jump box characterized by the installation
  of multiple security products for research, the use of AI for phishing content generation,
  and high-volume session maintenance across many compromised identities.
labels:
- hunt
- attack.t1090.003
- attack.t1176
- attack.t1566
name: Adversary Operational Workflow and AI Automation
parameters:
  ai_research_domains:
    default:
    - toolbaz.com
    - docsbot.ai
    - explo.ai
    - translate.google.com
    - censys.io
    description: AI writing assistants and phishing research domains used by the adversary.
    from:
      kind: article
      observed: '2024-09-09'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[domain]
  automation_domains:
    default:
    - make.com
    - api.telegram.org
    description: Workflow automation and bot communication domains.
    from:
      kind: article
      observed: '2024-09-09'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty for
      fleet-wide.
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
rationale: Focus first on systems with multiple security products (Malwarebytes, Bitdefender)
  as adversaries often use them for testing evasion. The identity sign-in query is
  fleet-wide to identify the source IP.
references:
- name: "Huntress Blog \u2014 Rare Look Inside Attacker Operation"
  url: https://www.huntress.com/blog/rare-look-inside-attacker-operation
related:
- hunt: evilginx-infrastructure-detection
  reason: This hunt focuses on the adversary operating machine, not the phishing landing
    pages themselves.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Assisted Phishing and Target Research
    observables:
    - censys.io
    - toolbaz.com
    - docsbot.ai
    - explo.ai
    - translate.google.com
    - search for Evilginx instances
    - csv generator ai
    - free ai no signup
    slug: phishing-research-and-ai-generation
    tactic: initial-access
    techniques:
    - T1566
  - name: Workflow Automation and Bot Communication
    observables:
    - make.com
    - api.telegram.org
    - Telegram Bot APIs
    - webhook configuration
    - AS 12651980 CANADA INC
    slug: automation-infrastructure-setup
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Identity Access and Session Maintenance
    observables:
    - session token refreshing
    - access to 2471 unique identities
    - malicious mail rule creation
    slug: identity-persistence-via-session-refresh
    tactic: persistence
    techniques:
    - T1566
  - name: Endpoint Persistence and Software Discovery
    observables:
    - Malwarebytes Browser Guard extension
    - autoruns.exe
    - unique machine name
    - Bitdefender search
    slug: host-persistence-and-tool-usage
    tactic: persistence
    techniques:
    - T1176
  summary: A threat actor accidentally installed a security agent on their own operating
    host, revealing a workflow that utilizes AI tools like Make.com and Toolbaz to
    automate phishing and message crafting. The adversary searched for Evilginx instances
    via Censys and maintained access to thousands of compromised identities through
    session token refreshes from infrastructure hosted on the VIRTUO AS.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Adversary Operational Workflow and AI Automation

This hunt identifies the operating patterns of a professional threat actor who integrates workflow automation and AI into their phishing operations. It follows the adversary's lifecycle from initial software evaluation and research to the backend management of thousands of stolen user sessions. By clustering competitor security software installation with AI writing assistant usage and high-volume authentication attempts from a single source, the hunt pinpoints the attacker's primary infrastructure.

## scope-security-tools
<!-- Identify hosts with overlapping security tools -->
Find systems where multiple security agents are installed, indicating an adversary evaluating competitor defenses.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: Hosts with more than one security product installed; standard assets usually
  run exactly one.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, COUNT(DISTINCT package_name) as tool_count FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%malwarebytes%' OR LOWER(package_name) LIKE '%bitdefender%' OR LOWER(package_name) LIKE '%huntress%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname HAVING tool_count > 1
```

## early-indicators
<!-- Examine research and automation indicators -->
parallel:
- → ai-research-dns
- → automation-infra-dns
join: → early-stage-triage

## ai-research-dns
<!-- DNS queries for AI writing and research -->
Identify hosts resolving domains for AI-driven text generation and vulnerability research.

```sqlite target=endpoint role=baseline params=(ai_research_domains=ai_research_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare resolutions for AI writing assistants or Censys. This establishes the
  phishing research phase.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{ai_research_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname
```

## automation-infra-dns
<!-- Automation infrastructure lookups -->
Identify traffic to automation platforms and bot APIs used for command and control.

```sqlite target=endpoint role=enrichment params=(automation_domains=automation_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts resolving Make.com or Telegram API establishing automated infrastructure
  presence.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{automation_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname
```

## early-stage-triage
<!-- Triage early research and automation -->
```agent target=hunter
cite: required
context:
- scope-security-tools
- ai-research-dns
- automation-infra-dns
max_iterations: 3
objective: Identify hosts displaying clustered activity of security software evaluation,
  AI research, and automation. Distinguish between an external attacker VPS (public
  IP, no agent presence) and a compromised internal host (private IP, agent present
  in software inventory).
success_criteria: A verdict for each host specifying if the pattern matches an adversary
  operating host.
tools:
- endpoint
- identity
- network
```

## follow-on-evidence
<!-- Examine session maintenance and network correlation -->
parallel:
- → identity-session-maintenance
- → ip-to-device-correlation
join: → adversary-tool-usage

## identity-session-maintenance
<!-- High-volume identity access from single IP -->
Identify source IPs maintaining access to many unique identities.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A single IP address managing sessions for a disproportionate number of users.
reads:
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_identities, COUNT(*) AS auth_events, MIN(time) AS first_seen FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_identities > 5 ORDER BY unique_identities DESC
```

## ip-to-device-correlation
<!-- Correlate IP to internal hostname -->
Map source IPs from the authentication logs back to internal hostnames using network events.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Rows mapping suspicious IPs to specific internal devices.
reads:
- src_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT src_endpoint_ip, device_hostname FROM hb_network_connection WHERE state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days')
```

## adversary-tool-usage
<!-- Execution of research and persistence tools -->
Identify execution of tools like Autoruns, rclone, or AnyDesk on candidate hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process execution rows showing attacker tools on a host identified in previous
  phases.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%autoruns%' OR LOWER(process_name) LIKE '%rclone%' OR LOWER(process_name) LIKE '%anydesk%' OR LOWER(process_cmd_line) LIKE '%evilginx%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## final-operational-triage
<!-- Final operational verdict -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- identity-session-maintenance
- ip-to-device-correlation
- adversary-tool-usage
max_iterations: 6
objective: Determine if a host or IP is functioning as an adversary jump box by correlating
  AI research, automation DNS, high-volume identity access, and specific tool execution.
success_criteria: A final verdict of malicious per host/IP, citing evidence across
  all phases.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-operational-triage verdict is malicious for at least one host or source IP" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → analyst-audit
unavailable: → analyst-audit (blind_spot: nat-correlation-gap)
else: → close-out

## contain-and-revoke
<!-- Contain host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the suspect jump box via EDR. Revoke all active sessions and refresh MFA for every identity identified in the session maintenance step.
```
→ analyst-audit

## analyst-audit
<!-- Remediation audit and mail rule review -->
```manual target=analyst
Verify host isolation. Manually audit compromised identities for mail-forwarding or hiding rules created to sustain access.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record identified adversary infrastructure. Update AI and automation domain parameters if new indicators were discovered.
```
→ end
