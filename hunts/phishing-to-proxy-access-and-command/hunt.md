---
analysis: A single detection rule might catch a Tor DNS lookup, but this hunt pivots
  from rare software inventory to suffix-matched DNS anomalies, and then to rare network
  connections correlated by process name, providing the context an analyst needs to
  confirm a multi-stage intrusion.
blind_spots:
- id: email-content-visibility
  owner: Messaging Team
  question: What were the subject lines and sender reputations of the phishing emails?
  remediation: Ingest M365 or Google Workspace email logs into a future hb_email_activity
    surface.
  requires: hb_email_activity surface (currently missing)
  risk: We rely on DNS and process aftermath; we cannot see the lure itself or blocked
    delivery attempts without email telemetry.
  stage: initial-access-phishing
- id: ephemeral-processes
  owner: Security Engineering
  question: Did an ephemeral process spawn and terminate before the snapshot?
  remediation: Ensure process auditing (e.g. Sysmon Event ID 1) is enabled on all
    endpoints.
  requires: hb_process_activity with high-frequency logging
  risk: Snapshot-based process sources may miss brief execution stages of a phishing
    payload.
  stage: payload-execution
coverage:
- stage: initial-access-phishing
  status: covered
  steps:
  - phishing-dns-patterns
  - rare-software-scoping
- stage: payload-execution
  status: covered
  steps:
  - execution-from-productivity-apps
- stage: multi-hop-c2
  status: covered
  steps:
  - rare-proxy-egress
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Phishing leading to multi-hop proxy C2 represents a sophisticated
    breach attempt that bypasses perimeter blocks. Correlating rare software, unusual
    parent-child process relationships, and proxy traffic provides a defense-in-depth
    detection mechanism.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained initial access via a phishing lure and executed
  a malicious payload, which is now communicating with a multi-hop proxy or Tor network
  to mask its command-and-control traffic.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Phishing-to-Proxy Access and Command
parameters:
  child_process_list:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - wscript.exe
    - cscript.exe
    - mshta.exe
    - certutil.exe
    description: Shells or admin tools suspicious when spawned by productivity apps.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  parent_app_list:
    default:
    - outlook.exe
    - excel.exe
    - winword.exe
    - chrome.exe
    - msedge.exe
    description: Productivity applications typically targeted for phishing execution.
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to these hostnames; leave empty for the full estate.
    type: list[host]
  tor_ports:
    default:
    - '9001'
    - '9030'
    - '9050'
    - '9051'
    description: Common ports used by Tor entry and relay nodes.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/phishing-ai-agent/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets hosts with 'rare' software installations (present on <3
  devices) as these are high-risk targets for novel phishing payloads. A wide lookback
  of 14 days captures the lifecycle from installation to C2.
references:
- name: "Red Canary \u2014 Train, triage, repeat: The AI agent changing how we fight\
    \ phishing"
  url: https://redcanary.com/blog/threat-detection/phishing-ai-agent/
related:
- hunt: suspicious-browser-extensions
  reason: Phishing can also lead to the installation of malicious browser extensions
    rather than direct process execution.
  relation: sibling
scenario:
  stages:
  - name: Phishing Delivery and Enrichment
    observables:
    - raw email metadata
    - domain reputation
    - abuse levels
    - indicators from past phishing campaigns
    - NLP features such as sentiment and intent
    - phishing email subject lines
    - suspicious sender domains
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Malicious Payload Execution
    observables:
    - suspicious child processes from browser
    - execution of downloaded scripts
    - shell spawning from office applications
    slug: payload-execution
    tactic: execution
    techniques:
    - T1566
  - name: Multi-hop Proxy C2
    observables:
    - Tor network traffic
    - onion routing
    - multi-hop proxy chains
    - connections to .onion addresses
    - lookups for .hiddenservice.net
    slug: multi-hop-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign leverages phishing emails to obtain initial access, using
    malicious links or attachments characterized by high abuse levels and poor domain
    reputation. Following successful access, command-and-control communications are
    established using multi-hop proxies and onion routing to obfuscate the origin
    of the traffic.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Phishing-to-Proxy Access and Command

This hunt identifies the transition from initial phishing delivery to established command-and-control via multi-hop proxies. It begins by identifying hosts with rare software installations, then concurrently examines three telemetry surfaces: DNS for resolution of suspicious top-level domains using suffix matching, process activity for shells or scripting engines spawned from productivity apps (checking for injected code or off-disk binaries), and network connections for rare egress traffic to known proxy ports (e.g., Tor), correlated by process name. An agent then correlates these signals per host to identify coordinated attack chains.

## rare-software-scoping
<!-- Identify hosts with rare software -->
Focus the hunt on hosts that have installed uncommon software, which may include malicious payloads dropped via phishing.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with software present on 3 or fewer devices in the estate.
  This narrows the hunt to machines with unique software footprints.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE package_name IN (SELECT package_name FROM hb_software_inventory GROUP BY package_name HAVING COUNT(DISTINCT device_hostname) <= 3)
```

## parallel-behavior-check
<!-- Concurrent hunt for phishing and proxy indicators -->
parallel:
- → phishing-dns-patterns
- → execution-from-productivity-apps
- → rare-proxy-egress
join: → triage-agent

## phishing-dns-patterns
<!-- Phishing-related DNS lookups -->
Identify hosts resolving domains with suspicious TLDs using suffix matching to avoid brittle extraction logic.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries for suspicious suffixes or keywords. Phishing domains often
  use cheap or recently available TLDs like .top or .zip.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.top' OR LOWER(query_hostname) LIKE '%.xyz' OR LOWER(query_hostname) LIKE '%.zip' OR LOWER(query_hostname) LIKE '%.review' OR LOWER(query_hostname) LIKE '%.bid' OR LOWER(query_hostname) LIKE '%login%' OR LOWER(query_hostname) LIKE '%verify%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## execution-from-productivity-apps
<!-- Execution from productivity apps -->
Detect shells or scripting engines launched from browsers/office, including off-disk binaries indicating injection.

```sqlite target=endpoint role=detection-candidate params=(parent_app_list=parent_app_list, child_process_list=child_process_list, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Shells spawned by user apps. The presence of on_disk = 0 or unusual process_path
  is a high-confidence indicator of exploitation.
reads:
- device_hostname
- process_name
- process_path
- on_disk
- process_cmd_line
- parent_process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, on_disk, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{parent_app_list}}' || ',', LOWER(parent_process_name)) > 0) AND (instr(',' || '{{child_process_list}}' || ',', LOWER(process_name)) > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-proxy-egress
<!-- Rare network connections to proxy ports -->
Identify outbound proxy connections that are rare across the fleet and correlate them with the initiating process.

```sqlite target=network role=baseline params=(tor_ports=tor_ports, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Network connections to ports like 9050 (Tor) where the destination IP is
  only seen on 1-3 hosts. Returning the process_name allows for correlation with the
  execution step.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, MIN(time) as first_seen FROM hb_network_connection WHERE (instr(',' || '{{tor_ports}}' || ',', CAST(dst_endpoint_port AS TEXT)) > 0) AND dst_endpoint_ip IN (SELECT dst_endpoint_ip FROM hb_network_connection WHERE (instr(',' || '{{tor_ports}}' || ',', CAST(dst_endpoint_port AS TEXT)) > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING COUNT(DISTINCT device_hostname) <= 3) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port
```

## triage-agent
<!-- Correlate phishing and C2 indicators -->
```agent target=hunter
cite: required
context:
- phishing-dns-patterns
- execution-from-productivity-apps
- rare-proxy-egress
max_iterations: 4
objective: Determine if any host shows the complete progression from a suspicious
  DNS suffix match to a shell-based execution (especially off-disk) and subsequent
  rare proxy connection.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  process paths and TLD matches.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: email-content-visibility)
else: → close-out-task

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host and initiate an incident response procedure to verify the scope of the intrusion.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the cited rows for the host. Compare the rare software found in scoping with the process execution events. Validate if the proxy connection matches a sanctioned business tool (e.g., development proxy).
```
→ end

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document the negative result. If rare software scoping produces too many false positives, tune the rarity threshold.
```
→ end
