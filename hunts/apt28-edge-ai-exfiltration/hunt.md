---
analysis: 'This hunt correlates signals across three surfaces: DNS hijacking (edge
  manipulation), file activity (automated bulk harvesting), and rare network connections
  (AI-based exfiltration). A single detection rule would struggle to distinguish legitimate
  browser traffic to AI tools from automated malware exfiltration without this broader
  context.'
blind_spots:
- id: incomplete-telemetry-gap
  question: Whether the host is receiving malicious responses from an edge device
    that the local agent logs as valid traffic
  requires: Network-level packet capture for DNS
  risk: If an edge router rewrites DNS responses at the network level, the local host
    log only sees a successful resolution from its expected upstream, masking the
    rogue resolver.
  stage: c2-edge-device-hijacking
- id: encrypted-exfiltration-visibility
  question: What specific data was contained in the requests to AI service providers
  requires: TLS inspection on HTTP/HTTPS traffic
  risk: While we can identify connections to AI APIs, we cannot confirm if the request
    body contained a harvested document without decryption.
  stage: exfiltration-llm-infostealer
coverage:
- stage: c2-edge-device-hijacking
  status: covered
  steps:
  - dns-hijacking-lead
  - ai-and-tunnel-activity
- stage: exfiltration-llm-infostealer
  status: covered
  steps:
  - bulk-document-harvesting
  - agent-triage
- reason: 'Belongs to another part of the ''APT28: An Evolution of Tradecraft from
    X-Agent to LLM Malware'' series.'
  stage: initial-access-phishing-and-vulnerability-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''APT28: An Evolution of Tradecraft from
    X-Agent to LLM Malware'' series.'
  stage: privilege-escalation-gooseegg
  status: out_of_scope
- reason: 'Belongs to another part of the ''APT28: An Evolution of Tradecraft from
    X-Agent to LLM Malware'' series.'
  stage: credential-harvesting-ntlm-relay
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: APT28 has shifted to using legitimate AI services and hijacked consumer-grade
    edge infrastructure to bypass traditional IP-based reputation filters; this hunt
    identifies the behavioural intersection of these trends.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked local DNS settings via compromised edge infrastructure
  and is using a rare, non-browser process to automate the harvesting of documents
  for exfiltration via AI APIs or high-port tunnels.
labels:
- hunt
- attack.t1572
- attack.t1041
- attack.t1566
- attack.t1190
name: APT28 Edge Hijacking and AI-Driven Exfiltration
parameters:
  ai_domains:
    default:
    - api.openai.com
    - api.anthropic.com
    - api.cohere.ai
    description: Legitimate AI service domains used by modern infostealers for command
      generation and data processing.
    from:
      kind: manual
      observed: '2026-06-22'
      ref: sekoia-apt28-evolution
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Comma-separated list of hostnames to narrow the search; leave empty
      for the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/apt28-an-evolution-of-tradecraft
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize hosts with frequent external lookups. Widen the scope if the
  network connection surface shows traffic to the AI domains even without the high
  NXDOMAIN count, as some edge devices may selectively hijack traffic.
references:
- name: "Sekoia \u2014 APT28: An Evolution of Tradecraft from X-Agent to LLM Malware"
  url: https://www.sekoia.com/blog/apt28-an-evolution-of-tradecraft
related:
- hunt: apt28-gooseegg-privesc
  reason: GooseEgg privilege escalation is a precursor to the harvesting phase; that
    hunt focuses on Print Spooler exploitation.
  relation: out-of-scope-alternative
- hunt: apt28-outlook-printspooler-exploitation
  relation: follows
scenario:
  stages:
  - name: Initial Access via Phishing and Vulnerabilities
    observables:
    - CVE-2023-23397 (Outlook)
    - CVE-2022-38028 (Windows Print Spooler)
    - SedKit exploit kit
    - Spear phishing emails
    - UKR.NET phishing landing pages
    slug: initial-access-phishing-and-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Privilege Escalation via GooseEgg
    observables:
    - GooseEgg utility
    - Windows Print Spooler service exploitation
    - SYSTEM-level execution
    slug: privilege-escalation-gooseegg
    tactic: execution
    techniques:
    - T1190
  - name: Net-NTLMv2 Hash Harvesting
    observables:
    - Net-NTLMv2 hashes
    - Authentication to attacker-controlled SMB shares
    - Crafted Outlook reminders
    - Spoofed UKR.NET webmail portal
    slug: credential-harvesting-ntlm-relay
    tactic: credential-access
    techniques:
    - T1555
  - name: Infrastructure Hijacking on Edge Devices
    observables:
    - MooBot botnet
    - FrostArmada campaign
    - Ubiquiti EdgeRouters
    - MikroTik and TP-Link routers
    - Rewritten DNS/DHCP settings pointing to actor-controlled resolvers
    - X-Tunnel network pivot
    slug: c2-edge-device-hijacking
    tactic: command-and-control
    techniques:
    - T1572
  - name: LLM-Integrated Data Exfiltration
    observables:
    - LLM-integrated infostealer
    - Harvesting Office, PDF, and TXT documents
    - Commands generated by legitimate AI services
    slug: exfiltration-llm-infostealer
    tactic: exfiltration
    techniques:
    - T1041
  summary: APT28 (Fancy Bear) has transitioned from a decade-long reliance on a stable
    in-house implant suite like X-Agent to a highly fragmented, disposable toolkit
    and extensive infrastructure hijacking. The actor currently weaponizes edge devices
    such as Ubiquiti and MikroTik routers for proxying traffic and harvesting credentials,
    while integrating LLM-driven malware for automated document exfiltration.
series:
  index: 2
  slug: apt28-an-evolution-of-tradecraft-from-x-agent-to-llm-malware
  title: 'APT28: An Evolution of Tradecraft from X-Agent to LLM Malware'
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
tlp: clear
type: investigation
---


# APT28 Edge Hijacking and AI-Driven Exfiltration

This hunt targets the modernization of APT28 tradecraft, specifically the shift toward edge infrastructure exploitation (MooBot and FrostArmada) for C2 and the use of LLM-integrated malware for automated data theft. It identifies hosts exhibiting DNS resolver hijacking signatures, such as excessive internal resolution failures alongside external successes. The flow then correlates these leads with bulk document access patterns and rare process communication to legitimate AI service providers or non-standard proxy ports used by X-Tunnel. An agent weighs the multi-surface evidence to identify high-confidence intrusions.

## dns-hijacking-lead
<!-- DNS anomalies and edge hijacking -->
Identify hosts showing signatures of hijacked DNS resolvers where internal domain resolution fails while external connectivity remains intact.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts with over 100 NXDOMAIN errors for internal resources despite successful
  external lookups, suggesting the edge device is misdirecting or failing to resolve
  local zones.
reads:
- device_hostname
- query_hostname
- rcode
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, COUNT(CASE WHEN rcode = 'NXDOMAIN' AND (LOWER(query_hostname) LIKE '%.local' OR LOWER(query_hostname) LIKE '%.internal') THEN 1 END) AS internal_fail_count, COUNT(CASE WHEN rcode = 'NOERROR' AND LOWER(query_hostname) NOT LIKE '%.local' AND LOWER(query_hostname) NOT LIKE '%.internal' THEN 1 END) AS external_success_count FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING internal_fail_count > 100 AND external_success_count > 0 ORDER BY internal_fail_count DESC
```

## parallel-corroboration
<!-- Corroborate harvesting and network behavior -->
parallel:
- → bulk-document-harvesting
- → ai-and-tunnel-activity
join: → agent-triage

## bulk-document-harvesting
<!-- Bulk document access patterns -->
Detect automated document harvesting by processes reading an unusual volume of sensitive file types within a short window.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single process reading more than 100 unique documents in an hour. This
  distinguishes automated harvesting from normal user file interaction.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- actor_user_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, actor_user_name, strftime('%Y-%m-%d %H:00:00', time) AS hour_bucket, COUNT(DISTINCT file_path) AS unique_files FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id = 2 AND (LOWER(file_path) LIKE '%.doc%' OR LOWER(file_path) LIKE '%.pdf%' OR LOWER(file_path) LIKE '%.txt') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, actor_user_name, hour_bucket HAVING unique_files > 100 ORDER BY unique_files DESC
```

## ai-and-tunnel-activity
<!-- Rare process AI and tunnel communication -->
Identify non-browser processes communicating with AI service providers or using high ports typical of the X-Tunnel pivot.

```sqlite target=network role=baseline params=(ai_domains=ai_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to OpenAI/Anthropic APIs or high-port outbound tunnels from
  processes that are rare across the fleet and are not standard web browsers.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR dst_endpoint_port IN (1080, 8080) OR dst_endpoint_port > 10000) AND LOWER(process_name) NOT LIKE '%chrome%' AND LOWER(process_name) NOT LIKE '%firefox%' AND LOWER(process_name) NOT LIKE '%msedge%' AND LOWER(process_name) NOT LIKE '%safari%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3
```

## agent-triage
<!-- Weigh correlated evidence -->
```agent target=hunter
cite: required
context:
- dns-hijacking-lead
- bulk-document-harvesting
- ai-and-tunnel-activity
max_iterations: 5
objective: Determine if any host exhibits combined indicators of DNS resolver hijacking,
  automated document harvesting (100+ files/hour), and rare process communication
  with AI domains or high-port proxies.
success_criteria: A verdict of malicious or suspicious citing specific rows where
  a non-browser process accessed many documents and subsequently communicated with
  an AI domain or tunnel proxy.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on agent verdict -->
if~: "The triage verdict is malicious or suspicious for at least one host due to correlated exfiltration and C2 behavior." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the suspicious process binary and capture a memory dump for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the file paths accessed by the process. Check the local hosts file and registry DNS settings for anomalies. Confirm if the AI service interaction was an expected part of a legitimate business tool (e.g., an LLM desktop client).
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the total count of documents potentially exfiltrated. Document any new AI service endpoints or proxy ports found to improve future detection rules.
```
→ end
