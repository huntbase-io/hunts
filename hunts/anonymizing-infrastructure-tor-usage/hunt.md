---
analysis: A simple rule flags a .onion domain query; this hunt correlates unauthorized
  software presence with fleet-wide port rarity and identity-plane proxy flags. This
  multi-surface correlation identifies persistent infrastructure even when domains
  are rotated or hidden.
blind_spots:
- id: portable-executables
  question: whether Tor was run as a portable executable from a user-writable path
  requires: hb_process_activity with deep path inspection
  risk: The lead software query only finds registered packages; portable binaries
    will be missed, requiring behavioral network signals to detect.
  stage: tor-browser-execution
- id: obfuscated-bridges
  question: whether Tor was using obfs4 bridges on port 443
  requires: hb_http_activity or protocol inspection on hb_network_connection
  risk: Standard port-based detection misses Tor traffic that is obfuscated to look
    like HTTPS web traffic.
  stage: onion-network-interaction
coverage:
- stage: anonymizing-vpn-connection
  status: covered
  steps:
  - lead-software-scan
  - network-relay-counts
- stage: tor-browser-execution
  status: covered
  steps:
  - lead-software-scan
- stage: onion-network-interaction
  status: covered
  steps:
  - network-relay-counts
  - proxy-signins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Unauthorized anonymization tools allow users or intruders to bypass
    perimeter monitoring, DLP controls, and identity restrictions, rendering the network
    perimeter uninspected.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder or unauthorized user is using commercial VPNs or the Tor Browser
  to bypass network security controls, leaving evidence in software inventory, rare
  outbound port patterns, and proxy-flagged authentications.
labels:
- hunt
- attack.t1090.003
- attack.t1133
- attack.t1190
- command and control
- defense evasion
- initial access
name: Anonymizing Infrastructure and Tor Usage
parameters:
  anonymizer_keywords:
    default:
    - tor browser
    - protonvpn
    - nordvpn
    - mullvad
    - expressvpn
    - windscribe
    - cyberghost
    description: Keywords to identify anonymizing or VPN software in package names.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://www.huntress.com/blog/pulling-back-the-curtain-a-journey-through-the-dark-web
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for network and sign-in activity.
    from:
      kind: manual
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: A list of hostnames to focus on, typically populated from the lead
      query results.
    from:
      kind: manual
      ref: analyst-scoping
    type: list[host]
  tor_relay_ports:
    default:
    - '9001'
    - '9050'
    - '9150'
    description: Network ports associated with Tor relays and proxy listeners.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://www.huntress.com/blog/pulling-back-the-curtain-a-journey-through-the-dark-web
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/pulling-back-the-curtain-a-journey-through-the-dark-web
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying servers and admin workstations in the software inventory.
  If the lead is empty, run the expensive checks unscoped to find portable Tor binaries
  by port patterns alone.
references:
- name: "Huntress \u2014 What Does the Dark Web Look Like? Pulling Back the Curtain"
  url: https://www.huntress.com/blog/pulling-back-the-curtain-a-journey-through-the-dark-web
related:
- hunt: tor-onion-dns-standing-rule
  reason: DNS-based Tor detection is already covered by a standing rule; this hunt
    focuses on software and connection patterns.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: VPN-Based Anonymization
    observables:
    - Connections to known VPN provider endpoints
    - High volume of encrypted outbound traffic to atypical external services
    - Presence of VPN client software in software inventory
    slug: anonymizing-vpn-connection
    tactic: initial-access
    techniques:
    - T1133
  - name: Tor Browser Execution
    observables:
    - Execution of tor.exe or firefox.exe from suspected Tor Browser installation
      paths
    - Installation of 'Tor Browser' software packages
    - Browser configuration changes to disable JavaScript
    - Execution of processes with 'Tor' or 'onion' in the file path or name
    slug: tor-browser-execution
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: Interaction with Onion Infrastructure
    observables:
    - DNS queries for .onion domains
    - Network connections to known Tor relay nodes or entry/exit nodes
    - Sign-in events flagged with is_proxy=true in authentication logs
    - Traffic destined for atypical ports associated with Tor relays (e.g., 9001,
      9050)
    slug: onion-network-interaction
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This campaign involves the use of anonymizing infrastructure, specifically
    VPNs and the Tor network, to conduct activities such as accessing underground
    markets and maintaining anonymity. Threat actors leverage .onion domains and multi-hop
    proxies to host services and obscure their physical locations during operations.
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


# Anonymizing Infrastructure and Tor Usage

This hunt identifies the presence and active use of anonymizing tools designed to obscure network traffic. It follows a gated flow: first performing a broad scan for known anonymizing software packages, then gating expensive network and identity checks behind a manual host scoping step. The hunt correlates rare outbound relay ports with identity-plane proxy flags to detect persistent tunnels that avoid standard domain-based detection rules.

## lead-software-scan
<!-- Lead: Anonymizing software in inventory -->
Identify hosts where known VPN or Tor Browser packages are registered in the managed software inventory.

```sqlite target=endpoint role=scoping params=(anonymizer_keywords=anonymizer_keywords)
~~~yaml
expected: A list of hostnames and the specific anonymizing packages they have installed.
  Absence suggests no known packages are in the managed inventory.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{anonymizer_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0)
```

## gate-read-software
<!-- Lead triage -->
```agent target=hunter
cite: required
context:
- lead-software-scan
max_iterations: 3
objective: Summarize the software findings and identify specific hosts that appear
  to have unauthorized anonymization tools installed.
success_criteria: A list of hosts with confirmed unauthorized software.
tools:
- endpoint
- identity
- network
```

## is-software-concerning
<!-- Gate: Proceed to expensive checks? -->
if~: "the gate-read-software verdict confirms unauthorized software on at least one host" (confidence: high, judge=hunter)
then: → expensive-checks
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: portable-executables)
else: → close-out

## expensive-checks
<!-- Corroborate with network and identity data -->
parallel:
- → network-relay-counts
- → proxy-signins
join: → final-triage

## network-relay-counts
<!-- Rare traffic to Tor relay ports -->
Identify active connections to typical Tor listener ports that are rare across the fleet.

```sqlite target=network role=baseline params=(tor_relay_ports=tor_relay_ports, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to Tor relay ports that stand out from fleet-wide behavior.
  Silence suggests no active listeners on these specific ports for the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, MIN(time) AS first_seen FROM hb_network_connection WHERE (instr(',' || '{{tor_relay_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port
```

## proxy-signins
<!-- Sign-ins from anonymizing proxies -->
Find authentication events flagged as originating from known proxies in the identity plane.

```sqlite target=identity role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Sign-ins where is_proxy is true. This corroborates endpoint software with
  active identity usage from the dark web.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- is_proxy
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, is_proxy, time FROM hb_auth_signin WHERE is_proxy = 'true' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final triage -->
```agent target=hunter
cite: required
context:
- gate-read-software
- network-relay-counts
- proxy-signins
max_iterations: 5
objective: Determine if the presence of anonymizing software is coupled with active
  network relays or proxy-based sign-ins, suggesting bypass of security controls.
success_criteria: A final verdict citing rows from all three surfaces for confirmed
  malicious hosts.
tools:
- endpoint
- identity
- network
```

## route-remediation
<!-- Route based on triage -->
if~: "the final-triage verdict is malicious for at least one host based on correlated software and network/identity activity" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: obfuscated-bridges)
else: → analyst-review

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate a forensic review to capture active Tor sessions or unauthorized VPN tunnel data.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the identified hosts and sign-ins. Confirm with the users whether the tools were used for a legitimate, sanctioned business purpose. Record any approved VPN clients as exclusions for future runs.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the results of the hunt. If no software was found but network port patterns were identified, document the risk of portable binaries.
```
→ end
