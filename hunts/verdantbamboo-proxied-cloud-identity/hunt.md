---
analysis: A standard detection rule might alert on any MFA-less login, but it cannot
  differentiate a legitimate admin on-site from a proxied session. This hunt correlates
  the identity plane (rare IPs for users) with the network plane (atypical appliance
  egress) to find the link.
blind_spots:
- id: incomplete-identity-logs
  question: Can we definitively see when MFA was explicitly bypassed vs not required?
  requires: hb_auth_signin with full coverage of MFA outcomes
  risk: If the source does not report MFA status accurately, we may miss proxying
    that exploits legacy authentication which bypasses CA/MFA naturally.
  stage: impact-proxied-m365-access
- id: appliance-visibility-gap
  question: Which specific binary on the appliance is proxying the traffic?
  requires: EDR/osquery on the appliances
  risk: Without endpoint visibility on the appliances (Egnyte, pfSense), we only see
    the traffic from the IP, which can be shared with legitimate appliance functions.
  stage: impact-proxied-m365-access
coverage:
- stage: impact-proxied-m365-access
  status: covered
  steps:
  - m365-signin-from-egress
  - rare-user-ip-signins
  - appliance-outbound-web-traffic
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: initial-access-vpn-credentials
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: privilege-escalation-sudo-tee
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: persistence-appliance-backdoors
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: c2-brickstorm-doh
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: lateral-movement-nas-pivot
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VerdantBamboo uses proxied access specifically to defeat modern identity
    controls. A negative result confirms that your edge trust model is intact and
    that stolen credentials are not currently being used from your own 'safe' IPs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a compromised internal appliance as a proxy to authenticate
  to M365, appearing to originate from a trusted corporate egress IP to bypass security
  controls.
labels:
- hunt
- attack.t1078
- attack.t1090.003
name: VerdantBamboo Proxied Cloud Identity Access
parameters:
  appliance_keywords:
    default:
    - egnyte
    - pfsense
    - synology
    - storage
    - sync
    - vpn
    - firewall
    description: Keywords to identify potential proxy hostnames or device names.
    type: list[string]
  corporate_egress_ips:
    default: []
    description: Public IPs of corporate egress points (VPN/Firewall) that M365 trusts.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step to focus network analysis.
    type: list[host]
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
rationale: Start by identifying all unmanaged Linux-based appliances in the network.
  Focus the hunt on administrative users who typically have MFA enabled; sign-ins
  from corporate IPs for these users that bypass MFA are highest priority.
references:
- name: 'Volexity: VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: appliance-backdoor-persistence
  reason: This hunt looks for the impact of proxying; the persistence on the appliance
    itself is a separate behavior requiring registry/file/cron monitoring.
  relation: out-of-scope-alternative
- hunt: verdantbamboo-edge-appliance-backdoor
  relation: follows
scenario:
  stages:
  - name: Initial Access via SSL VPN
    observables:
    - egnyteservice
    - Administrative credentials for VPN
    - Web SSL VPN login
    - Stolen MSP credentials
    slug: initial-access-vpn-credentials
    tactic: initial-access
    techniques:
    - T1133
    - T1078
  - name: Privilege Escalation via Sudo Tee
    observables:
    - sudo /usr/bin/tee
    - 'egnyteservice ALL = PASSWD: EGNYTEAPPS'
    - rsync_data_migration.sh
    slug: privilege-escalation-sudo-tee
    tactic: privilege-escalation
    techniques:
    - T1059.004
    - T1548.003
  - name: Backdoor Deployment and Cron Persistence
    observables:
    - /etc/cron.d/ssync
    - /home/egnyteservice/ssync.sh
    - /usr/sbin/BRICKSTORM
    - /etc/crontab
    - /usr/local/bin/egnyte/egnyte_host_monitor_client
    - /etc/rc.d/cron
    - /usr/local/libexec/ipsec/blacklist
    - AGENTPSD
    - PLENET
    - pfSense web shells
    slug: persistence-appliance-backdoors
    tactic: persistence
    techniques:
    - T1053.003
    - T1505.003
  - name: Command and Control via DoH Proxying
    observables:
    - 8.8.8.8
    - TLS connection to Google DNS
    - Cloudflare IP addresses
    - DNS over HTTPS
    slug: c2-brickstorm-doh
    tactic: command-and-control
    techniques:
    - T1071.004
    - T1090.003
  - name: Lateral Movement to Internal NAS
    observables:
    - SSH to Synology NAS
    - Synology administrative interface
    - Internal IP assigned by firewall VPN
    slug: lateral-movement-nas-pivot
    tactic: lateral-movement
    techniques:
    - T1021.004
  - name: Proxied Microsoft 365 Authentication
    observables:
    - Microsoft 365 (M365) environment
    - Login from edge appliance IP
    - Bypassing Conditional Access policies
    slug: impact-proxied-m365-access
    tactic: credential-access
    techniques:
    - T1078
    - T1090.003
  summary: VerdantBamboo compromised a Managed Services Provider (MSP) to gain credentials
    and persistent access to client edge appliances, including Egnyte Storage Sync,
    pfSense firewalls, and Synology NAS systems. The threat actor deployed BRICKSTORM
    and AGENTPSD backdoors, leveraging a local privilege escalation on the Storage
    Sync system to maintain root-level access and proxy traffic to Microsoft 365,
    successfully evading location-based Conditional Access policies.
series:
  index: 2
  slug: verdantbamboo-just-another-brickstorm-in-the-firewall
  title: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
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


# VerdantBamboo Proxied Cloud Identity Access

This hunt targets the 'impact-proxied-m365-access' stage observed in VerdantBamboo (WARP PANDA) operations. The actor compromises unmanaged appliances (storage sync, firewalls, NAS) and uses them to proxy authentication traffic. This allows them to use stolen credentials from a 'trusted' network location, often evading Conditional Access policies. We identify these appliances, look for anomalous M365 logins from egress IPs lacking MFA, and correlate with outbound appliance traffic to cloud services.

## identify-potential-proxy-appliances
<!-- Identify Potential Proxy Appliances -->
Locate internal appliances matching the profile of systems VerdantBamboo compromises for proxying.

```sqlite target=endpoint role=scoping params=(appliance_keywords=appliance_keywords, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames/IPs for devices like firewalls or storage sync systems.
  These are the expected origins of proxied traffic.
reads:
- hostname
- device_name
- ip_address
- os_name
- provider
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, device_name, ip_address, os_name, provider FROM hb_devices WHERE (instr(',' || '{{appliance_keywords}}' || ',', ',' || LOWER(hostname) || ',') > 0 OR instr(',' || '{{appliance_keywords}}' || ',', ',' || LOWER(device_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## m365-signin-from-egress
<!-- Successful M365 Logins from Egress IPs -->
Identify successful authentications to M365 from known corporate IPs that bypassed MFA or used legacy protocols.

```sqlite target=identity role=detection-candidate params=(corporate_egress_ips=corporate_egress_ips, lookback_days=lookback_days)
~~~yaml
expected: Logins from 'trusted' IPs that lack MFA. These are high-risk for proxied
  access.
reads:
- actor_user_name
- src_endpoint_ip
- auth_protocol
- mfa
- status_id
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, auth_protocol, mfa, time FROM hb_auth_signin WHERE provider = 'm365' AND status_id = 1 AND (('{{corporate_egress_ips}}' = '') OR (instr(',' || '{{corporate_egress_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0)) AND (mfa IS FALSE OR mfa IS NULL OR auth_protocol NOT IN ('OAuth2', 'SAML')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-behavior
<!-- Corroborate Behavior -->
parallel:
- → rare-user-ip-signins
- → appliance-outbound-web-traffic
join: → triage-proxied-sessions

## rare-user-ip-signins
<!-- Rare User and Source IP Sign-ins -->
Baseline user-IP relationships to find users appearing on a corporate IP they don't usually use.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Successful logins where the user-IP pair is rare for that user, suggesting
  a session proxied through an unusual corporate location.
prevalence:
  by: actor_user_name
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- src_endpoint_ip
- status_id
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(*) AS login_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE provider = 'm365' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING login_count < 5 ORDER BY login_count ASC
```

## appliance-outbound-web-traffic
<!-- Appliance Outbound Web Traffic -->
Find outbound HTTPS traffic from identified appliances that might be the source of proxied authentication.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Storage or network appliances making outbound connections to M365/Azure
  IP ranges, which is atypical for their primary function.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, protocol, time FROM hb_network_connection WHERE dst_endpoint_port IN (80, 443) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-proxied-sessions
<!-- Triage Proxied Sessions -->
```agent target=hunter
cite: required
context:
- identify-potential-proxy-appliances
- m365-signin-from-egress
- rare-user-ip-signins
- appliance-outbound-web-traffic
max_iterations: 5
objective: Determine if anomalous M365 logins align with outbound appliance traffic,
  indicating a compromised appliance being used as a proxy.
success_criteria: 'A verdict per suspicious user/host pair: malicious (clear evidence
  of proxying), suspicious (anomalous logins), or benign.'
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict identifies at least one user with malicious proxied sign-in activity originating from a candidate appliance IP" (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-identity-logs)
else: → close-out

## revoke-sessions
<!-- Revoke Identity Sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all M365/Azure sessions for the affected users and trigger a mandatory password reset with MFA enforcement.
```
→ analyst-review

## analyst-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the identified appliances for signs of BRICKSTORM or PLENET. Check for unauthorized SSH access or web management sessions from unexpected IPs.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the hunt results. If no malicious activity was found, document the verified user-to-IP baseline.
```
→ end
