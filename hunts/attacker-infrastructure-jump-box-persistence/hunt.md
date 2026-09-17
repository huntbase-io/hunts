---
analysis: A simple detection rule for 'Autoruns' or 'Malwarebytes' would be too noisy.
  This hunt pivots between software inventory and network behavior (high-fan-out unique
  IP counts) to identify 'jump box' patterns that a single rule cannot contextualize.
blind_spots:
- id: incomplete-telemetry
  question: Can we see the process associated with every outbound connection?
  requires: Complete Netflow and EDR process binding
  risk: Some network connections may not be attributeable to a process, hiding the
    true source of jump box activity.
  stage: infrastructure-and-persistence
- id: browser-extension-visibility
  question: Does our software inventory capture all browser extensions for all profiles?
  requires: hb_software_inventory with full browser extension coverage
  risk: Malicious extensions in non-default profiles may be missed by standard inventory
    scans.
  stage: infrastructure-and-persistence
coverage:
- stage: infrastructure-and-persistence
  status: covered
  steps:
  - suspicious-software-scoping
  - jump-box-outbound-behavior
  - infrastructure-connections
  - tunneling-process-corroboration
- reason: Belongs to another hunt in this series.
  stage: automated-targeting-recon
  status: out_of_scope
- reason: Belongs to another hunt in this series.
  stage: identity-compromise-maintenance
  status: out_of_scope
- reason: Belongs to another part of the 'An attacker blunder gave us a look into
    their operations' series.
  stage: external-infrastructure-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Jump boxes allow attackers to bypass egress filtering and internal
    segmentation while masking their origin. This hunt uses the specific 'blunder'
    markers from the Huntress report to identify these critical beachheads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using internal hosts as jump boxes or proxies to mask
  their origin, identifiable by high-fan-out outbound connections to external infrastructure
  and the presence of browser-based persistence or unusual maintenance tools.
labels:
- hunt
- attack.t1090.003
- attack.t1176
name: Attacker Infrastructure and Jump Box Persistence
parameters:
  attacker_infrastructure_ips:
    default: []
    description: Known IPs associated with VIRTUO / 12651980 CANADA INC (AS12651980).
    from:
      kind: article
      observed: '2024-09-09'
      ref: https://www.huntress.com/blog/rare-look-inside-attacker-operation
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of network and process history to examine.
    type: number
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
rationale: Focus on workstations where 'Malwarebytes' is not the standard EDR and
  servers exhibiting high outbound network connection counts. Start by providing IP
  ranges for Virtuo infrastructure if available.
references:
- name: "Huntress \u2014 An attacker blunder gave us a look into their operations"
  url: https://www.huntress.com/blog/rare-look-inside-attacker-operation
related:
- hunt: automated-targeting-recon
  reason: Reconnaissance activities using Make.com or AI tools are covered in the
    recon hunt.
  relation: out-of-scope-alternative
- hunt: automated-ai-phishing-recon
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
  index: 3
  slug: an-attacker-blunder-gave-us-a-look-into-their-operations
  title: An attacker blunder gave us a look into their operations
  total: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Attacker Infrastructure and Jump Box Persistence

This hunt focuses on the infrastructure blunders and persistence mechanisms used by sophisticated actors, as seen in recent research. We look for 'jump box' behavior—single processes (excluding browsers) initiating connections to a wide range of external IP addresses—and corroborate this with the presence of suspicious software inventory items like the 'Malwarebytes Browser Guard' extension or 'Autoruns' research tools on non-admin hosts. Finally, we check for direct connections to IP ranges associated with the 'VIRTUO' (12651980 CANADA INC) infrastructure frequently used by this actor.

## suspicious-software-scoping
<!-- Suspicious Software and Extension Inventory -->
Identify hosts that have installed 'Malwarebytes Browser Guard' or 'Autoruns' tools, which the article notes as indicators of an attacker operating environment.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts containing software mentioned in the research. Malwarebytes
  Browser Guard on an enterprise workstation is anomalous; Autoruns on a non-IT machine
  is a red flag.
reads:
- device_hostname
- package_name
- vendor_name
- package_type
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, vendor_name, package_type, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%malwarebytes%' OR LOWER(package_name) LIKE '%autoruns%') AND package_type IN ('application', 'extension', 'utility')
```

## parallel-behavior-check
<!-- Investigate Network and Process Behavior -->
parallel:
- → jump-box-outbound-behavior
- → infrastructure-connections
- → tunneling-process-corroboration
join: → triage-agent

## jump-box-outbound-behavior
<!-- Identify Potential Jump Box Outbound Activity -->
Detect processes exhibiting multi-hop or jump box behavior by counting unique external IP destinations per non-browser process.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Processes that are NOT browsers but are talking to many unique IPs. This
  behavior is characteristic of a jump box or proxy (T1090.003).
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- time
- activity_id
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT dst_endpoint_ip) AS unique_dst_ips, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE activity_id = 1 AND LOWER(process_name) NOT IN ('chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'safari', 'teams.exe', 'outlook.exe') AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.1[6-9].%' AND dst_endpoint_ip NOT LIKE '172.2[0-9].%' AND dst_endpoint_ip NOT LIKE '172.3[0-1].%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_dst_ips > 20 ORDER BY unique_dst_ips DESC
```

## infrastructure-connections
<!-- Connections to Attacker-Associated VPS Infrastructure -->
Identify direct connections to the VIRTUO AS or other provided infrastructure IPs.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, attacker_infrastructure_ips=attacker_infrastructure_ips)
~~~yaml
expected: Any connection to the specified IPs. If the parameter is empty, this query
  will correctly return zero rows.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS conn_count, MIN(time) AS first_seen FROM hb_network_connection WHERE instr(',' || '{{attacker_infrastructure_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port
```

## tunneling-process-corroboration
<!-- Process Command Lines for Tunneling or Proxying -->
Search for process execution indicators of proxying, such as SSH tunneling or common proxy utility command lines.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Execution of tools or command line flags typically associated with local
  or remote port forwarding (T1090).
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(process_name) LIKE '%proxy%' OR LOWER(process_name) LIKE '%tunnel%' OR LOWER(process_name) LIKE '%plink%' OR LOWER(process_name) LIKE '%ngrok%' OR LOWER(process_cmd_line) LIKE '% -L %' OR LOWER(process_cmd_line) LIKE '% -R %' OR LOWER(process_cmd_line) LIKE '% -D %') AND LOWER(process_name) NOT LIKE '%vpn%'
```

## triage-agent
<!-- Weigh Evidence for Jump Box Compromise -->
```agent target=hunter
cite: required
context:
- suspicious-software-scoping
- jump-box-outbound-behavior
- infrastructure-connections
- tunneling-process-corroboration
max_iterations: 4
objective: Determine if any host is being used as a jump box or proxy by weighing
  the suspicious software (Autoruns/Malwarebytes extension) against the high-fan-out
  network behavior and tunneling command lines.
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign with cited
  rows.
tools:
- endpoint
- network
```

## decide-route
<!-- Route Based on Verdict -->
if~: "the agent verdict is 'Malicious' for any host due to combined network and inventory signals" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-task-review
unavailable: → analyst-task-review (blind_spot: incomplete-telemetry)
else: → analyst-task-review

## isolate-host
<!-- Isolate Malicious Jump Box -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified as an active jump box. Collect browser history and forensic artifacts from the user profile.
```
→ analyst-task-review

## analyst-task-review
<!-- Review Jump Box and Proxy Evidence -->
```manual target=analyst
Review the jump box behavior (unique IP counts) and the presence of extensions. Verify if the 'Malwarebytes' extension is a legitimate corporate standard or an attacker-installed anomaly. Close out any identified persistence.
```
→ end
