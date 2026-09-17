---
analysis: A single rule for M365 logons from internal IPs might trigger too many false
  positives if users legitimately use internal proxies; this hunt combines that signal
  with appliance hostnames and rare VPN source IPs to find the specific pattern of
  VerdantBamboo.
blind_spots:
- id: no-vpn-logs
  question: How did the adversary initially gain VPN access?
  requires: VPN authentication logs with long retention
  risk: Short retention (as noted in the article) prevents tracing the initial compromise
    point.
  stage: initial-access-valid-credentials-vpn
- id: appliance-edr-gap
  question: Was the PLENET backdoor executed on the Synology NAS?
  requires: Endpoint telemetry (hb_process_activity) for NAS/Appliances
  risk: Many appliances do not support traditional EDR agents, leaving 'on-disk' and
    process activity invisible.
  stage: impact-synology-nas-compromise
coverage:
- stage: initial-access-valid-credentials-vpn
  status: covered
  steps:
  - rare-vpn-source-ips
- stage: lateral-movement-m365-proxying
  status: covered
  steps:
  - m365-signins-from-internal-ips
- stage: impact-synology-nas-compromise
  status: covered
  steps:
  - scope-appliances
  - appliance-ssh-egress
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: privilege-escalation-sudo-tee-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: persistence-cron-modification
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: command-and-control-brickstorm-doh
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The use of storage appliances as proxies to evade Conditional Access
    is a high-impact technique that bypasses standard perimeter security by making
    malicious cloud access appear as internal corporate traffic.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised credentials to access the internal network
  via VPN and then leveraging internal appliances (Storage Sync, NAS) as proxies to
  reach SaaS environments or move laterally while evading IP-based conditional access.
labels:
- hunt
- attack.t1078
- attack.t1071
- attack.t1133
- attack.t1090.003
name: VerdantBamboo Identity Misuse and Proxy Access
parameters:
  internal_appliance_keywords:
    default:
    - egnyte
    - synology
    - storage
    - nas
    - pfsense
    description: Keywords used to identify potential proxying appliances in hostnames
      or software inventory.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize appliances that are internet-facing or managed
  by MSPs. Focus on Egnyte, Synology, and pfSense/firewall hostnames first.
references:
- name: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
- name: "Volexity \u2014 VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall"
  url: https://volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: verdantbamboo-backdoor-persistence
  reason: This hunt focuses on the identity/proxy aspect; the persistence mechanisms
    (cron, AGENTPSD) are handled in the sibling hunt.
  relation: sibling
scenario:
  stages:
  - name: Initial Access via Compromised VPN Credentials
    observables:
    - egnyteservice account
    - SSH connections from internal VPN IP range
    - Source IP assigned by web-based SSL VPN
    slug: initial-access-valid-credentials-vpn
    tactic: initial-access
    techniques:
    - T1078
    - T1133
  - name: Local Privilege Escalation via Sudo Tee
    observables:
    - sudo tee
    - /usr/local/bin/egnyte/rsync_data_migration.sh
    - /usr/bin/config_network
    - inadvertent sudo configuration for egnyteservice
    slug: privilege-escalation-sudo-tee-abuse
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Persistence via Cron Jobs
    observables:
    - /etc/cron.d/ssync
    - /home/egnyteservice/ssync.sh
    - /etc/crontab modification
    - egnyte_host_monitor_client
    - executed at 14:20 on the 15th day of every month
    slug: persistence-cron-modification
    tactic: persistence
    techniques:
    - T1505.003
  - name: C2 via DNS over HTTPS
    observables:
    - TLS connections to 8.8.8.8
    - Cloudflare-fronted domains
    - BRICKSTORM malware in /usr/sbin/
    - No standard DNS traffic for C2 domains
    slug: command-and-control-brickstorm-doh
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: M365 Access via Appliance Proxy
    observables:
    - M365 sign-ins originating from Storage Sync appliance IP
    - Bypass of Conditional Access policies
    slug: lateral-movement-m365-proxying
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Deployment of PLENET on NAS
    observables:
    - Synology NAS web interface admin login
    - SSH enabled on Synology NAS
    - PLENET backdoor deployment
    slug: impact-synology-nas-compromise
    tactic: persistence
    techniques:
    - T1078
    - T1133
  summary: VerdantBamboo compromised an organization's Egnyte Storage Sync and Synology
    NAS appliances using credentials stolen from a breached Managed Service Provider.
    The actor deployed the BRICKSTORM backdoor and AGENTPSD python shell, using the
    appliances as proxies to access Microsoft 365 environments and evade conditional
    access policies.
series:
  index: 1
  slug: verdantbamboo-just-another-brickstorm-in-the-firewall
  title: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
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


# VerdantBamboo Identity Misuse and Proxy Access

This hunt focuses on the 'identity misuse' phase of the VerdantBamboo (UNC5221) campaign. It specifically seeks to identify instances where internal Linux-based appliances, such as Egnyte Storage Sync or Synology NAS, are used as proxies for Microsoft 365 access—a technique used to blend with legitimate traffic and bypass conditional access. The hunt also examines VPN authentication patterns for anomalous source IPs and subsequent lateral movement via SSH from these appliances.

## scope-appliances
<!-- Identify internal storage and network appliances -->
Find hosts that match the profile of appliances targeted by VerdantBamboo for proxying and persistence.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of appliances. Silence is evidence of absence for these specific
  naming conventions, but not for all appliances.
reads:
- hostname
- device_uid
- platform
- ip_address
- last_seen
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT hostname, device_uid, platform, ip_address, last_seen FROM hb_devices WHERE (LOWER(hostname) LIKE '%egnyte%' OR LOWER(hostname) LIKE '%synology%' OR LOWER(hostname) LIKE '%nas%' OR LOWER(hostname) LIKE '%storage%') AND lifecycle_state = 'active'
```

## parallel-evidence-gathering
<!-- Gather independent evidence of proxying and lateral access -->
parallel:
- → m365-signins-from-internal-ips
- → rare-vpn-source-ips
- → appliance-ssh-egress
join: → triage-identity-misuse

## m365-signins-from-internal-ips
<!-- M365 sign-ins originating from internal IP addresses -->
Identify M365 authentication events where the source IP is an internal private IP, suggesting a proxy/VPN tunnel is being used to bypass external IP filters.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Auth events showing internal IPs as the source for cloud-based M365 logons.
  In a non-proxy environment, these should not exist.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- status_id
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, COUNT(*) as signin_count, MIN(time) as first_seen FROM hb_auth_signin WHERE provider = 'm365' AND (src_endpoint_ip LIKE '10.%' OR src_endpoint_ip LIKE '192.168.%' OR src_endpoint_ip LIKE '172.%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name
```

## rare-vpn-source-ips
<!-- Rare user/IP pairs for VPN authentication -->
Detect potentially compromised accounts by finding VPN sign-ins from IPs rarely associated with specific users.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few login events from a source IP that a user has not used before. These
  require cross-referencing with known threat actor IP ranges.
prevalence:
  by: actor_user_name
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- auth_protocol
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(*) as login_total, COUNT(DISTINCT src_endpoint_ip) as unique_ips, MIN(time) as first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%vpn%' OR LOWER(auth_protocol) LIKE '%vpn%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING login_total < 5 ORDER BY login_total ASC
```

## appliance-ssh-egress
<!-- SSH egress activity from appliances -->
Detect appliances initiating SSH connections internally, which matches VerdantBamboo's pivoting behavior.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Outbound connections from storage appliances to internal servers or cloud
  IPs on SSH/HTTPS ports. Appliances typically should not initiate these connections.
reads:
- device_hostname
- process_name
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (dst_endpoint_port = 22 OR dst_endpoint_port = 443) AND (LOWER(device_hostname) LIKE '%egnyte%' OR LOWER(device_hostname) LIKE '%synology%' OR LOWER(device_hostname) LIKE '%storage%' OR LOWER(device_hostname) LIKE '%nas%') AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-identity-misuse
<!-- Triage Identity and Proxy Evidence -->
```agent target=hunter
cite: required
context:
- scope-appliances
- m365-signins-from-internal-ips
- rare-vpn-source-ips
- appliance-ssh-egress
max_iterations: 4
objective: Determine if any host or user shows overlapping signals of compromised
  VPN access followed by appliance-mediated cloud access or internal pivoting.
success_criteria: Verdicts (Malicious, Suspicious, Benign) for each host/user identified
  in the queries, citing the specific rows that link the identity to the proxy behavior.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for any host or user" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-vpn-logs)
else: → close-out

## isolate-appliance
<!-- Isolate compromised appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified Egnyte or Synology appliance. Ensure that SSH and web management interfaces are blocked from internet and VPN access.
```
→ manual-review

## manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the sign-in logs and network flows cited by the agent. Check the identified appliances for unusual cron jobs or script files in /usr/sbin/ or /home/egnyteservice/.
```
→ end

## close-out
<!-- Close-out and Documentation -->
```manual target=analyst
Document the absence of proxy-like authentication and appliance pivoting. Note any blind spots in appliance telemetry.
```
→ end
