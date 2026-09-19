---
analysis: While rules exist for known Tor domains, this hunt pivots across the identity
  layer and uses prevalence to find non-standard tunneling tools and command-line
  arguments that single-surface rules miss.
blind_spots:
- id: unmanaged-device-blindspot
  question: Was the proxy software executed on a BYOD or unmanaged server?
  requires: EDR agent coverage on all devices
  risk: Authentications from VPS IPs are visible in Okta, but the subsequent tunneling
    on unmanaged hardware will be invisible to the endpoint surfaces.
  stage: covert-c2-via-proxy-tunneling
- id: residential-proxy-evasion
  question: Did the attacker use a residential botnet proxy rather than a datacenter
    VPS?
  requires: Residential proxy IP reputation feed
  risk: The vps_ips list primarily captures datacenter infrastructure; botnet-based
    proxies will likely bypass this specific identity filter.
  stage: identity-authentication-via-multi-hop-proxy
coverage:
- stage: identity-authentication-via-multi-hop-proxy
  status: covered
  steps:
  - vps-authentications
- stage: covert-c2-via-proxy-tunneling
  status: covered
  steps:
  - rare-proxy-processes
  - anomalous-proxy-ports
  - onion-dns-lookups
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries use multi-hop proxies to evade geographical controls
    and mask C2 traffic. Correlating SaaS logs with endpoint behavior is a high-friction
    task that requires automated data shaping to scale, making it a prime candidate
    for a hunt over simple detection rules.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised an identity (Okta) via multi-hop proxy infrastructure
  and is currently maintaining persistent command-and-control using tunneling software
  on a managed endpoint.
labels:
- hunt
- attack.t1090.003
name: Anonymized Identity Access and Proxy Tunneling
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_ports:
    default:
    - '9001'
    - '9050'
    - '9051'
    - '9150'
    description: Default ports commonly used by Tor or other proxy relays.
    type: list[string]
  proxy_software_patterns:
    default:
    - tor
    - ngrok
    - chisel
    - tailscale
    - zerotier
    - ligolo
    - frp
    description: Software packages associated with network proxying or tunneling.
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow endpoint correlation; paste results
      from the scoping step here.
    type: list[host]
  vps_ips:
    default:
    - 185.220.101.0
    - 162.247.74.0
    - 104.244.72.0
    - 176.10.99.200
    - 192.42.116.16
    description: Known Tor exit nodes or VPS provider IPs used for source masking.
    from:
      kind: article
      observed: '2026-06-11'
      ref: red-canary-threat-hunting-scaled
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/threat-hunting-scaled/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to hosts with known proxy/VPN software in their inventory
  (hb_software_inventory) to focus correlation on the most likely beachheads for multi-hop
  C2.
references:
- name: "Red Canary \u2014 How threat hunting evolves at scale"
  url: https://redcanary.com/blog/threat-detection/threat-hunting-scaled/
related:
- hunt: mfa-fatigue-and-anomalous-logon
  reason: MFA fatigue often precedes a successful sign-in from a masked source.
  relation: precedes
scenario:
  stages:
  - name: Identity authentication via multi-hop proxy
    observables:
    - Okta sign-in events from known VPS provider IP ranges
    - Authentication attempts from Tor exit nodes
    - Successful logins following MFA challenges from disparate geolocations
    slug: identity-authentication-via-multi-hop-proxy
    tactic: initial-access
    techniques:
    - T1090.003
  - name: Covert C2 via proxy tunneling
    observables:
    - DNS queries for .onion or .hiddenservice.net domains
    - Network connections to known Tor relay node ports 9001 and 9050
    - Execution of proxy or tunneling binaries like tor.exe or ngrok
    - High-frequency network traffic to cloud VPS instances on non-standard ports
    slug: covert-c2-via-proxy-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An adversary uses multi-hop proxies to obfuscate their geographic and network
    origin while authenticating to identity providers like Okta. Following access,
    the attacker establishes covert command-and-control channels using tunneling tools
    and operational relay boxes to mask ongoing activity from internal endpoints.
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


# Anonymized Identity Access and Proxy Tunneling

This hunt bridges the gap between identity-level authentication anomalies and endpoint-level network behavior. It first identifies managed hosts with proxy-capable software, then correlates successful authentications from known VPS/Tor infrastructure with subsequent execution of rare tunneling binaries and connections to proxy ports. By joining these surfaces, we can distinguish between legitimate remote access and an active multi-hop proxy intrusion.

## find-proxy-capable-hosts
<!-- Identify hosts with proxy/tunneling software -->
Scope the hunt to endpoints that have known proxying or tunneling software installed, which could be leveraged for multi-hop C2.

```sqlite target=endpoint role=scoping params=(proxy_software_patterns=proxy_software_patterns)
~~~yaml
expected: A list of hosts with proxy-related software installed. Silence indicates
  no managed hosts have these specific packages in their inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{proxy_software_patterns}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%tunnel%')
```

## vps-authentications
<!-- Successful Okta logons from VPS/Tor IPs -->
Identify successful authentications at the identity provider level (Okta) that originated from known anonymization infrastructure.

```sqlite target=identity role=triage params=(vps_ips=vps_ips, lookback_days=lookback_days)
~~~yaml
expected: Login events from provided IPs. Any hit suggests a user session originating
  from infrastructure commonly used for source-masking.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
- status_id
- activity_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE activity_id = 1 AND status_id = 1 AND instr(',' || '{{vps_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-endpoint-behavior
<!-- Corroborate with endpoint telemetry -->
parallel:
- → rare-proxy-processes
- → anomalous-proxy-ports
- → onion-dns-lookups
join: → triage-agent

## rare-proxy-processes
<!-- Rare proxy binary execution -->
Identify execution of rare or atypically named binaries that use common proxying command-line arguments, prioritizing those on the scoped hosts.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary or command line used for proxying seen on very few hosts. This
  highlights non-standard tools used for tunneling.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '% -proxy %' OR LOWER(process_cmd_line) LIKE '% -socks %' OR LOWER(process_cmd_line) LIKE '% -tunnel %' OR LOWER(process_cmd_line) LIKE '% -remote %') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_cmd_line HAVING host_count <= 3
```

## anomalous-proxy-ports
<!-- Connections to Tor and relay ports -->
Capture network connections directed at ports commonly associated with Tor relays and multi-hop infrastructure.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, proxy_ports=proxy_ports, lookback_days=lookback_days)
~~~yaml
expected: Endpoints communicating via traditional Tor ports (9001/9050).
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
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## onion-dns-lookups
<!-- DNS queries for hidden services -->
Identify DNS activity for TLDs used by the Tor network, which indicates the use of an onion proxy on the endpoint.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Lookups for .onion domains; this is a high-fidelity marker for Tor usage.
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
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%.hiddenservice.net%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Correlate identity and endpoint events -->
```agent target=hunter
cite: required
context:
- vps-authentications
- rare-proxy-processes
- anomalous-proxy-ports
- onion-dns-lookups
max_iterations: 5
objective: Review the successful VPS logons (vps-authentications) and correlate them
  with the rare proxy execution (rare-proxy-processes), anomalous ports (anomalous-proxy-ports),
  and onion DNS lookups (onion-dns-lookups). Look for temporal alignment between the
  login and the networking/process activity.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing the
  relevant rows from all surfaces.
tools:
- endpoint
- identity
- network
```

## triage-decision
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host exhibiting both VPS sign-ins and endpoint tunneling" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: unmanaged-device-blindspot)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Revoke all active Okta sessions for the identified user. Block the src_endpoint_ip at the firewall.
```
→ analyst-review

## analyst-review
<!-- Review correlated intrusion -->
```manual target=analyst
Verify if the proxy software found was authorized for business use. Investigate the identified user for signs of credential theft (e.g., unusual password resets or MFA updates).
```
→ close-out

## close-out
<!-- Close hunt and tune -->
```manual target=analyst
Log any new VPS IPs found. If the onion DNS signal was high fidelity, promote it to a standing detection rule.
```
→ end
