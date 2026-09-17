---
analysis: A standard rule might detect any 8.8.8.8:443 traffic, but this hunt adds
  the critical context of process path analysis (/usr/sbin), host-wide DNS prevalence
  stacking, and an agent-driven triage of 'DNS silence' to filter out legitimate browser-based
  DoH.
blind_spots:
- id: no-network-telemetry
  question: Can we see encrypted traffic to 8.8.8.8 on port 443?
  requires: hb_network_connection with dst_endpoint_ip and port
  risk: If network telemetry is missing for specific appliances, the hunt cannot observe
    the primary C2 indicator.
  stage: command-and-control-brickstorm-doh
- id: doh-diversity
  question: Does the threat actor use other DoH providers?
  requires: hb_dns_activity (absence) + hb_network_connection
  risk: If the threat actor rotates away from 8.8.8.8 to a less common resolver or
    an actor-controlled DoH server, this hunt may miss the signal.
  stage: command-and-control-brickstorm-doh
coverage:
- stage: command-and-control-brickstorm-doh
  status: covered
  steps:
  - identify-doh-traffic
  - stack-doh-processes
  - check-dns-silence
  - check-system-path-rarity
  - triage-implants
- reason: This stage is handled by another hunt in the series focusing on VPN auth
    logs.
  stage: initial-access-valid-credentials-vpn
  status: out_of_scope
- reason: This stage is handled by another hunt in the series focusing on sudo/shell
    activity.
  stage: privilege-escalation-sudo-tee-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: persistence-cron-modification
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: lateral-movement-m365-proxying
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: impact-synology-nas-compromise
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: VerdantBamboo targets edge appliances without EDR to establish stealthy
    C2 via DoH. A negative result confirms that your perimeter devices are not beaconing
    to known resolver-based C2 infrastructure, mitigating the risk of long-term (18+
    month) undetected compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A compromised system is performing command-and-control over DNS-over-HTTPS
  (DoH) to bypass network inspection, evidenced by TLS connections to public DNS resolvers
  from unusual binaries.
labels:
- hunt
- attack.t1071.004
- attack.t1090.003
- attack.t1505.003
name: 'VerdantBamboo: Evasive Outbound C2 via DoH'
parameters:
  lookback_days:
    default: '14'
    description: Days of network and process history to examine.
    type: number
  malware_paths:
    default:
    - /usr/sbin/%
    - /usr/local/libexec/%
    - /home/egnyteservice/%
    description: Common paths used by BRICKSTORM for manual execution.
    from:
      kind: article
      observed: '2026-06-04'
      ref: https://volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    type: list[path]
  public_dns_ips:
    default:
    - 8.8.8.8
    - 8.8.4.4
    - 1.1.1.1
    - 1.0.0.1
    description: Public DNS resolvers often used for DoH; 8.8.8.8 is the primary indicator.
    from:
      kind: article
      observed: '2026-06-04'
      ref: https://volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    type: list[ip]
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
rationale: Focus the hunt on Linux-based appliances (Storage Sync, Synology, pfSense)
  and servers in the DMZ. These devices are VerdantBamboo's primary targets for evading
  EDR.
references:
- name: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
- name: "Volexity \u2014 VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall"
  url: https://volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: verdantbamboo-privilege-escalation-sudo
  reason: This hunt focuses on C2; privilege escalation via sudo tee abuse is a sibling
    hunt.
  relation: out-of-scope-alternative
- hunt: verdantbamboo-vpn-persistence
  reason: VPN-based access and persistence via crontab is handled in a separate hunt.
  relation: out-of-scope-alternative
- hunt: linux-appliance-backdooring-persistence
  relation: follows
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
  index: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# VerdantBamboo: Evasive Outbound C2 via DoH

This hunt identifies signs of the BRICKSTORM implant, which uses DNS-over-HTTPS (specifically to Google's 8.8.8.8) to resolve Cloudflare-fronted C2 domains. By correlating network connections to public resolvers with the absence of local DNS logs and the presence of rare binaries in system directories like /usr/sbin/, we can identify hosts evading standard DNS-based filtering and monitoring.

## identify-doh-traffic
<!-- Identify DNS-over-HTTPS (DoH) Traffic -->
Find hosts making TLS connections to public DNS resolvers on port 443.

```sqlite target=network role=scoping params=(lookback_days=lookback_days, public_dns_ips=public_dns_ips)
~~~yaml
expected: A list of processes and hosts connecting to Google or Cloudflare DNS over
  HTTPS. Browsers are expected; non-browser system binaries (e.g., in /usr/sbin) are
  highly suspicious.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, COUNT(*) as connection_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE dst_endpoint_port = 443 AND instr(',' || '{{public_dns_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_path, dst_endpoint_ip
```

## analyze-behaviour-prevalence
<!-- Analyze Process Prevalence and DNS Silence -->
parallel:
- → stack-doh-processes
- → check-dns-silence
- → check-system-path-rarity
join: → triage-implants

## stack-doh-processes
<!-- Stack-Count DoH-Capable Processes -->
Identify rare binaries making DoH connections across the fleet.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, public_dns_ips=public_dns_ips)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A binary that only appears on one or two hosts and is not a standard web
  browser.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_name
- process_path
- device_hostname
- dst_endpoint_ip
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as connection_count FROM hb_network_connection WHERE dst_endpoint_port = 443 AND instr(',' || '{{public_dns_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count <= 2 ORDER BY host_count ASC
```

## check-dns-silence
<!-- Check for DNS Silence -->
Verify the absence of standard DNS traffic for hosts doing DoH.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts with very low standard DNS volume relative to their uptime, suggesting
  redirection to DoH or other channels.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, COUNT(query_hostname) as dns_queries, GROUP_CONCAT(DISTINCT query_hostname) as sample_queries FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING dns_queries < 100
```

## check-system-path-rarity
<!-- Check System Path Binary Rarity -->
Look for binaries in system paths that are not typically seen running or are not on disk.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A binary like 'blacklist' or 'ssync' or a generic name in /usr/sbin/ that
  is not a standard system daemon.
reads:
- device_hostname
- process_name
- process_path
- user_name
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, user_name, on_disk, COUNT(*) as count FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/usr/sbin/%' OR LOWER(process_path) LIKE '/usr/local/libexec/%' OR LOWER(process_path) LIKE '/home/egnyteservice/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_path, user_name, on_disk
```

## triage-implants
<!-- Triage Potential BRICKSTORM Implants -->
```agent target=hunter
cite: required
context:
- identify-doh-traffic
- stack-doh-processes
- check-dns-silence
- check-system-path-rarity
max_iterations: 4
objective: 'Determine if any host shows the pattern of: (1) Rare process in a system
  path like /usr/sbin, (2) Outbound TLS to 8.8.8.8, and (3) Absence of standard DNS
  activity for the same time window.'
success_criteria: Verdicts for each host citing process names, network endpoints,
  and DNS volume.
tools:
- endpoint
- network
```

## decide-on-threat
<!-- Decide on Threat Presence -->
if~: "the triage verdict is malicious for at least one host based on DoH traffic from rare system-path binaries" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Prioritize Linux VMs and firewall appliances. Collect memory and /usr/sbin binaries for forensic analysis.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the processes flagged by the agent. Check crontab files for entries like 'egnyte_host_monitor_client' (AGENTPSD) and verify if the SSL VPN was used as a pivot point. Check for root-level sudo abuse of 'tee' or 'rsync'.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
If no malicious activity was found, document the hosts scanned and the lack of DoH/suspicious processes.
```
→ end
