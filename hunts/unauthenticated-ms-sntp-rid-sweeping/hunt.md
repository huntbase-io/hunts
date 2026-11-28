---
analysis: A standing rule on UDP/123 volume is prone to noise from periodic time-sync.
  This hunt correlates that volume with specific process execution artifacts and DC
  registry configuration states to provide the high-fidelity context required to isolate
  a host.
blind_spots:
- id: payload-visibility-gap
  question: Can we distinguish between the 68-byte legacy and 120-byte extended MS-SNTP
    authenticators?
  requires: Network packet capture (PCAP) or Deep Packet Inspection (DPI)
  risk: We can only see connection volume, not the content; we cannot confirm which
    cryptographic form was harvested without payload inspection.
  stage: credential-access-mac-harvesting
- id: unmanaged-device-blind-spot
  question: Can we see RID sweeping from unmanaged devices or BYOD?
  requires: hb_network_connection with flow log coverage for all subnets
  risk: If network flow logs do not cover all client subnets, a sweep from an unmanaged
    device will be invisible to the endpoint-centric connection surface.
  stage: initial-access-unauthenticated-ntp
coverage:
- stage: initial-access-unauthenticated-ntp
  status: covered
  steps:
  - ntp-sweep-volume
- stage: discovery-rid-enumeration
  status: covered
  steps:
  - ntp-sweep-volume
- blind_spot: payload-visibility-gap
  reason: The available surfaces provide connection metadata but not the packet payload
    required to see the MS-SNTP authenticators.
  stage: credential-access-mac-harvesting
  status: not_visible
- stage: execution-roasting-tooling
  status: covered
  steps:
  - roasting-tool-execution
- stage: defense-evasion-crypto-downgrade
  status: covered
  steps:
  - registry-downgrade-check
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Timeroasting allows an unauthenticated adversary to harvest password-derived
    MACs for any domain account without generating logon events. This hunt is required
    to detect the network signature of RID sweeping and the configuration downgrades
    that facilitate it.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is performing unauthenticated MS-SNTP RID sweeping against
  Domain Controllers to harvest password-derived MACs, often preceded by a configuration
  downgrade to allow legacy MD5 authenticators.
labels:
- hunt
- attack.t1558.003
- attack.t1087.002
- attack.t1190
- attack.t1562.001
- credential access
- defense evasion
- discovery
- execution
- initial access
name: Unauthenticated MS-SNTP RID Sweeping
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  roasting_tool_names:
    default:
    - timeroast.py
    - trustroast.py
    - netexec
    - kerbwolf
    - timeroast-ng
    description: Known roasting tool filenames to search for.
    from:
      kind: article
      observed: '2024-11-19'
      ref: https://www.huntress.com/blog/detecting-timeroasting
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of Domain Controllers to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/detecting-timeroasting
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Identify Domain Controllers by the KDC service to focus the network and
  registry searches. If no DCs are found, run the hunt against all Windows servers
  by clearing the scope_hosts parameter.
references:
- name: "Huntress \u2014 Detecting Timeroasting the Hard Way"
  url: https://www.huntress.com/blog/detecting-timeroasting
- name: "Tom Tervoort (Secura) \u2014 Timeroasting, Trustroasting and Computer Spraying"
  url: https://www.secura.com/blog/timeroasting-trustroasting-and-computer-spraying
related:
- hunt: kerberoasting-tgs-request-anomalies
  reason: Both hunts involve Kerberos-related credential harvesting, but Timeroasting
    is unauthenticated and uses MS-SNTP.
  relation: sibling
scenario:
  stages:
  - name: Unauthenticated NTP Request
    observables:
    - UDP/123
    - Domain Controller IP addresses
    - Unauthenticated network traffic to w32time service
    slug: initial-access-unauthenticated-ntp
    tactic: initial-access
    techniques:
    - T1190
  - name: MS-SNTP RID Sweeping
    observables:
    - Sequential RID requests at offset 48 of NTP packet
    - Targeting AZUREADSSOACC
    - Targeting trust accounts and machine accounts ($)
    - Enumeration of Relative Identifiers (RIDs)
    slug: discovery-rid-enumeration
    tactic: discovery
    techniques:
    - T1087.002
  - name: MS-SNTP MAC Harvesting
    observables:
    - 68-byte UDP/123 packets (Legacy MD5 form)
    - 120-byte UDP/123 packets (Extended HMAC-SHA512 form)
    - KeyIdentifier at packet offset 48
    - USE_OLDKEY_VERSION flag (0x01) at offset 53
    slug: credential-access-mac-harvesting
    tactic: credential-access
    techniques:
    - T1558.003
  - name: Roasting Tool Execution
    observables:
    - timeroast.py
    - trustroast.py
    - netexec timeroast module
    - KerbWolf
    - timeroast-ng
    slug: execution-roasting-tooling
    tactic: execution
    techniques:
    - T1059.006
  - name: Forced Legacy Authentication Downgrade
    observables:
    - Registry value SignatureAuthAllowed set to 0
    - Forcing 68-byte legacy MD5 authenticators
    slug: defense-evasion-crypto-downgrade
    tactic: defense-evasion
    techniques:
    - T1562.001
  summary: Timeroasting exploits the MS-SNTP protocol extension on Windows Domain
    Controllers to obtain password-derived MACs for computer and trust accounts without
    authentication. Attackers perform unauthenticated RID sweeping over UDP port 123
    to collect 68-byte or 120-byte authenticator blobs for offline brute-force cracking.
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


# Unauthenticated MS-SNTP RID Sweeping

Timeroasting abuses Microsoft's NTP authentication extension (MS-SNTP) to obtain encrypted authenticators for any domain account without prior authentication. The adversary sweeps Relative Identifiers (RIDs) via UDP/123, collecting MACs that can be cracked offline. This hunt identifies the attack by correlating volumetric NTP spikes reaching Domain Controllers with the presence of roasting tools and specific registry downgrades (SignatureAuthAllowed=0) that force the use of weaker MD5-based authenticators. It follows a phased flow: first establishing the DC scope and initial network indicators, then confirming the configuration state of the targets.

## find-domain-controllers
<!-- Identify Domain Controllers -->
Identify hosts running the Kerberos Key Distribution Center (KDC) service, which is unique to Domain Controllers.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames acting as Domain Controllers. Silence means no DCs were
  identified via service logs in the window.
reads:
- device_hostname
- service_name
- service_start_name
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT DISTINCT device_hostname, service_name, service_start_name FROM hb_service_activity WHERE LOWER(service_name) = 'kdc' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-investigation
<!-- Parallel network and execution search -->
parallel:
- → ntp-sweep-volume
- → roasting-tool-execution
join: → early-triage

## ntp-sweep-volume
<!-- Volumetric NTP connection spikes -->
Detect high-frequency UDP/123 connections from a single source, characteristic of a RID sweep.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A source IP making hundreds of NTP requests to a DC. Normal time-sync is
  periodic and low-volume.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- device_hostname
- dst_endpoint_port
- protocol
- traffic_packets
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT src_endpoint_ip, device_hostname, COUNT(*) as request_count, SUM(traffic_packets) as total_packets, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE dst_endpoint_port = 123 AND protocol = 'udp' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname HAVING request_count > 100 ORDER BY request_count DESC
```

## roasting-tool-execution
<!-- Roasting tool execution -->
Find evidence of offensive tools specifically built for Timeroasting and MS-SNTP abuse.

```sqlite target=endpoint role=detection-candidate params=(roasting_tool_names=roasting_tool_names, lookback_days=lookback_days)
~~~yaml
expected: Process execution records for known roasting tools or command lines containing
  roasting keywords.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{roasting_tool_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%timeroast%' OR LOWER(process_cmd_line) LIKE '%trustroast%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage
<!-- Initial triage of network activity -->
```agent target=hunter
cite: required
context:
- find-domain-controllers
- ntp-sweep-volume
- roasting-tool-execution
max_iterations: 3
objective: Identify if the NTP traffic spikes are indicative of unauthenticated RID
  sweeping and whether they originate from hosts running roasting tools.
success_criteria: A list of suspicious source IPs and targeted DCs.
tools:
- endpoint
- network
```

## registry-downgrade-check
<!-- Registry crypto downgrade -->
Detect configuration changes on DCs that allow legacy MD5 authenticators, facilitating easier offline cracking.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Registry values showing SignatureAuthAllowed set to 0. Silence indicates
  no downgrade was performed or detected.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\w32time\config\signatureauthallowed' AND reg_value_data = '0' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-verdict
<!-- Final Timeroasting assessment -->
```agent target=hunter
cite: required
context:
- early-triage
- registry-downgrade-check
max_iterations: 5
objective: Evaluate the combined evidence to determine if a coordinated Timeroasting
  attack has occurred, specifically highlighting where security controls were weakened
  to support it.
success_criteria: A per-host verdict of malicious, suspicious, or benign.
tools:
- endpoint
- network
```

## evaluate-maliciousness
<!-- Evaluate maliciousness -->
if~: "the final assessment identifies at least one host as malicious due to correlated network spikes and registry downgrades" (confidence: high, judge=hunter)
then: → isolate-beachhead
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: payload-visibility-gap)
else: → close-out

## isolate-beachhead
<!-- Isolate beachhead -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the source host identified by the network and process telemetry. Revoke its active sessions.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the connection counts and source IPs. Verify if the registry change on the DCs was an authorized maintenance action. Confirm if the roasting tools were part of an authorized penetration test.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the final status. If any DC was found with SignatureAuthAllowed=0, ensure it is reverted to 1. Document the lack of packet visibility for the platform team.
```
→ end
