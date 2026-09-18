---
analysis: A simple detection rule flags Tor or known VPNs; this hunt pivots from those
  indicators to identify 'Remote Unattended Support' misuse and stack-counts management
  traffic to find rare ORB hostnames that blocklists fail to catch.
blind_spots:
- id: missing-auth-logs
  owner: Cloud Infrastructure Team
  question: whether the adversary accessed a 'shadow' tenant not currently enrolled
    in the security monitoring platform
  remediation: Enroll all discovered Entra tenants into central logging via Entra
    Tenant Governance.
  requires: Complete hb_auth_signin coverage for all cloud tenants
  risk: A multi-tenant adversary could move laterally through unmonitored tenants,
    bypassing the hunt entirely.
  stage: obfuscated-identity-login
- id: ephemeral-orb-nodes
  owner: Security Engineering
  question: whether the connection was to a residential IP acting as an ORB node not
    in the static proxy list
  remediation: Integrate a real-time residential proxy feed or implement JA3 fingerprinting
    for management processes.
  requires: High-frequency IP reputation data or netflow to low-reputation ASNs
  risk: ORB networks often use residential nodes that rotate faster than static blocklists,
    leading to false negatives on IP-based detection.
  stage: multi-hop-proxy-obfuscation
coverage:
- stage: multi-hop-proxy-obfuscation
  status: covered
  steps:
  - obfuscated-cloud-signins
  - management-process-outbound-prevalence
  - orb-dns-resolutions
- stage: obfuscated-identity-login
  status: covered
  steps:
  - obfuscated-cloud-signins
- stage: remote-management-persistence
  status: covered
  steps:
  - management-software-scoping
  - management-process-outbound-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The shift toward agentic and autonomous cloud management introduces
    high-privilege persistence vectors that traditional detections miss. This hunt
    confirms that remote management tools are not being misused via known obfuscation
    infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies or Operational Relay Box (ORB)
  networks to mask their origin while misusing cloud-native remote management features
  (Intune/Autopilot) for persistence and lateral movement.
labels:
- hunt
- attack.t1090.003
- attack.t1078.004
- attack.t1021.001
name: Proxy-Obfuscated Cloud Access and Remote Management Misuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  orb_domains:
    default:
    - hopto.org
    - zapto.org
    - sytes.net
    - ddns.net
    description: Dynamic DNS domains often associated with Operational Relay Box (ORB)
      traffic.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: ORB research indicators
    type: list[domain]
  proxy_vps_ips:
    default:
    - 45.33.0.0
    - 104.196.0.0
    - 139.162.0.0
    - 172.104.0.0
    description: Known VPS or proxy egress IPs used for ORB activity.
    from:
      kind: manual
      observed: '2026-08-27'
      ref: Common VPS provider ranges
    type: list[ip]
  scope_hosts:
    default: []
    description: Output hosts from the scoping step; paste them here to filter subsequent
      queries.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/27/whats-new-in-microsoft-security-august-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and administrative workstations that have Microsoft
  Intune or specialized remote support tools installed. The scoping step output should
  be used to populate the 'scope_hosts' parameter for all subsequent network and DNS
  queries.
references:
- name: "What\u2019s new in Microsoft Security: August 2026"
  url: https://www.microsoft.com/en-us/security/blog/2026/08/27/whats-new-in-microsoft-security-august-2026/
related:
- hunt: unauthorized-tenant-governance-changes
  reason: Changes to Entra Tenant Governance configurations themselves require a separate
    hunt over cloud control-plane logs.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-hop Proxy C2 Obfuscation
    observables:
    - DNS queries for onion domains (.onion, .onion.ca, .onion.direct)
    - Outbound network connections to known Tor exit nodes
    - Traffic to VPS-hosted Operational Relay Box (ORB) infrastructure
    slug: multi-hop-proxy-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Cloud Identity Access via Proxy
    observables:
    - Sign-in events to Okta, AWS, or M365 originating from known proxy or VPS IP
      ranges
    - Anomalous authentication attempts following cross-tenant configuration changes
      in Microsoft Entra
    slug: obfuscated-identity-login
    tactic: initial-access
    techniques:
    - T1078.004
  - name: Remote Support Feature Misuse
    observables:
    - Execution of Windows Unattended Support sessions via Microsoft Intune
    - Remote sign-in events associated with new Windows Autopilot device associations
    - Execution of remote support processes without corresponding user-initiated support
      tickets
    slug: remote-management-persistence
    tactic: persistence
    techniques:
    - T1021.001
  summary: Adversaries utilize multi-hop proxy networks like Tor or Operational Relay
    Boxes (ORBs) to disguise their origin while targeting cloud identity providers
    and management consoles. This obfuscation facilitates unauthorized access to environments
    (AWS, Okta, M365) and the subsequent misuse of remote management tools, such as
    Windows Unattended Support, for persistence on endpoints.
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


# Proxy-Obfuscated Cloud Access and Remote Management Misuse

This hunt targets the intersection of network obfuscation and cloud-native management misuse. It identifies authentication attempts originating from known VPS and proxy infrastructure, correlates them with the use of 'Windows Unattended Support' and 'Autopilot' features, and baselines outbound network activity from these management processes. By combining identity signals with network prevalence, the hunt identifies cases where remote support tools are being turned into persistent backdoors.

## management-software-scoping
<!-- Identify Hosts with Remote Management Capabilities -->
Identify hosts with Intune, Autopilot, or Remote Support tools installed. The resulting hostnames must be used to filter the later outbound prevalence and DNS resolution queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently reporting management software. Silence indicates
  a lack of managed assets or incorrect software inventory reporting.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%intune%' OR LOWER(package_name) LIKE '%autopilot%' OR LOWER(package_name) LIKE '%remote%support%')
```

## corroborate-proxy-and-management
<!-- Corroborate Proxy Access and Management Activity -->
parallel:
- → obfuscated-cloud-signins
- → management-process-outbound-prevalence
- → orb-dns-resolutions
join: → triage-proxy-misuse

## obfuscated-cloud-signins
<!-- Cloud Sign-ins from VPS/Proxy IPs -->
Detect identity access attempts to M365, AWS, or Okta originating from known VPS ranges, potentially indicating multi-hop proxy usage. Includes status and protocol to distinguish stuffing from breaches.

```sqlite target=identity role=detection-candidate params=(proxy_vps_ips=proxy_vps_ips, lookback_days=lookback_days)
~~~yaml
expected: Sign-in events from non-residential IP ranges. High signal if success (status_id=1)
  is followed by remote management interactions.
reads:
- actor_user_name
- src_endpoint_ip
- provider
- dst_endpoint_name
- status_id
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, provider, dst_endpoint_name, status_id, auth_protocol, time FROM hb_auth_signin WHERE (instr(',' || '{{proxy_vps_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## management-process-outbound-prevalence
<!-- Prevalence of Outbound Connections from Management Processes -->
Stack-count outbound connections from remote support binaries to identify rare C2 channels. Uses destination hostname to aggregate connections to dynamic ORB infrastructure and filters for established traffic.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A management process talking to a hostname that only 1 or 2 hosts in the
  estate have seen. Rare hostnames suggest dynamic DNS or ORB infrastructure.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_hostname
  rare_below: 3
reads:
- process_name
- dst_endpoint_hostname
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, dst_endpoint_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%remotesupport%' OR LOWER(process_name) LIKE '%intune%' OR LOWER(process_name) LIKE '%autopilot%') AND activity_id IN (1, 6) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## orb-dns-resolutions
<!-- DNS Resolutions for Suspected ORB Domains -->
Identify hosts resolving dynamic DNS domains common in ORB infrastructure, restricted to the hosts identified in the scoping step.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, orb_domains=orb_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Resolutions for DDNS providers. Suspicious if paired with management processes
  like Intune or Remote Support.
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
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{orb_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-proxy-misuse
<!-- Triage Proxy-Cloud Access and Management Misuse -->
```agent target=hunter
cite: required
context:
- management-software-scoping
- obfuscated-cloud-signins
- management-process-outbound-prevalence
- orb-dns-resolutions
max_iterations: 3
objective: Determine if any host or user shows signs of using multi-hop proxies to
  access cloud management features or if management tools are beaconing to ORB nodes.
success_criteria: A per-host verdict citing specific IPs, users, and process names.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one user or host showing VPS-based management access" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review-triage
unavailable: → analyst-review-triage (blind_spot: missing-auth-logs)
else: → close-out

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host(s) identified in the triage verdict. Revoke cloud sessions for associated users and investigate Intune/Autopilot audit logs for unauthorized configuration changes.
```
→ analyst-review-triage

## analyst-review-triage
<!-- Analyst Review of Proxy Findings -->
```manual target=analyst
Review the cited IPs and DNS domains. Check internal support tickets to see if the 'Remote Unattended Support' session was authorized. If the scoping step returned many false positives, adjust the software filter.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the IPs identified as malicious to the organization's blocklist and note any new management processes observed.
```
→ end
