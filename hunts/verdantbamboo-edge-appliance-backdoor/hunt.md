---
analysis: This is a hunt because detection rules for 'sudo tee' often have high false
  positives on developer workstations. The hunt strictly scopes to edge appliances
  and pivots between authentication anomalies, unusual DoH network patterns, and specific
  cron persistence locations to identify VerdantBamboo activity.
blind_spots:
- id: missing-appliance-telemetry
  question: Does the appliance allow the installation of an agent to report file and
    job activity?
  requires: Endpoint agent coverage on proprietary appliances
  risk: If an appliance does not support an agent, the sudo-tee and cron-persistence
    signals will not be visible on the endpoint surfaces.
  stage: persistence-appliance-backdoors
- id: doh-traffic-visibility
  question: Can the network fabric differentiate DoH traffic to 8.8.8.8 from standard
    HTTPS traffic?
  requires: TLS inspection or NetFlow with process correlation
  risk: If DoH is used, standard DNS query logs will remain silent, making the 8.8.8.8:443
    network pattern the primary behavioral indicator.
  stage: c2-brickstorm-doh
coverage:
- stage: initial-access-vpn-credentials
  status: covered
  steps:
  - vpn-login-anomalies
- stage: privilege-escalation-sudo-tee
  status: covered
  steps:
  - sudo-tee-misuse
- stage: persistence-appliance-backdoors
  status: covered
  steps:
  - cron-persistence-anomalies
- stage: c2-brickstorm-doh
  status: covered
  steps:
  - doh-c2-activity
- reason: Requires Synology-specific web logs or internal SSH session telemetry not
    available in the listed surfaces.
  stage: lateral-movement-nas-pivot
  status: not_visible
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: impact-proxied-m365-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VerdantBamboo targets unmanaged edge appliances to bypass MFA and
    EDR; a negative result confirms these critical ingress points are not currently
    hosting BRICKSTORM backdoors.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has compromised an edge appliance (Egnyte, Synology, or pfSense)
  using stolen credentials, escalated privileges via a sudo misconfiguration, and
  deployed the BRICKSTORM backdoor using DoH for command-and-control.
labels:
- hunt
- attack.t1059.004
- attack.t1071.004
- attack.t1078
- attack.t1090.003
- attack.t1133
- attack.t1505.003
- attack.t1548.003
name: VerdantBamboo Edge Appliance Backdoor and Pivot
parameters:
  c2_doh_ips:
    default:
    - 8.8.8.8
    - 8.8.4.4
    - 1.1.1.1
    description: Public DNS resolvers typically abused for DoH C2 channels.
    from:
      kind: article
      observed: '2026-06-04'
      ref: VERDANTBAMBOO-volexity
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-06-04'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: The specific appliances identified in the scoping step; paste them
      here to filter the rest of the hunt.
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux and FreeBSD appliances in hb_devices. The hunt assumes these
  devices are reporting telemetry; ensure they are within the scope of the current
  endpoint agent deployment.
references:
- name: "Volexity \u2014 VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall"
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: proxied-m365-access-anomalies
  reason: This hunt focuses on the appliance breach; session anomalies in M365 from
    proxied traffic require a separate hunt.
  relation: out-of-scope-alternative
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
  index: 1
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


# VerdantBamboo Edge Appliance Backdoor and Pivot

This hunt targets the activity of the VerdantBamboo (UNC5221) group as described in the BRICKSTORM campaign. It specifically looks for indicators of compromise on Linux and BSD-based edge appliances, including the abuse of 'sudo tee' for file writing, DNS-over-HTTPS (DoH) traffic to public resolvers (8.8.8.8) which serves as a C2 channel, and persistence through system crontabs. The hunt also examines VPN login anomalies that often precede the deployment of these implants.

## appliance-scoping
<!-- Identify Linux and BSD Appliances -->
Find Linux and BSD systems that match the platform profile of targeted storage and firewall appliances to define the hunt's strict scope.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to edge appliances or Linux servers. This
  list must be used to populate the 'scope_hosts' parameter for subsequent steps.
reads:
- hostname
- platform
- os_name
- ip_address
- time
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, platform, os_name, ip_address, time FROM hb_devices WHERE (LOWER(platform) IN ('linux', 'ubuntu', 'freebsd') OR LOWER(os_name) LIKE '%linux%' OR LOWER(os_name) LIKE '%bsd%') AND lifecycle_state = 'active' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-signals
<!-- Gather Evidence Across Multiple Surfaces -->
parallel:
- → vpn-login-anomalies
- → sudo-tee-misuse
- → doh-c2-activity
- → cron-persistence-anomalies
join: → triage-implants

## vpn-login-anomalies
<!-- VPN Authentication Anomalies -->
Identify logins to the scoped appliances using service accounts or administrative credentials.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Logins from unusual source IPs (assigned by the VPN) to service accounts
  like 'egnyteservice'.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, time FROM hb_auth_signin WHERE instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0 AND (LOWER(actor_user_name) = 'egnyteservice' OR LOWER(metadata_product) = 'vpn' OR LOWER(dst_endpoint_name) LIKE '%vpn%' OR LOWER(dst_endpoint_name) LIKE '%firewall%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## sudo-tee-misuse
<!-- Sudo Tee Privilege Escalation -->
Detect the use of 'sudo tee' to overwrite system configuration files on targeted appliances.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process using sudo and tee to write to sensitive directories like /etc/cron.d
  or /usr/sbin.
reads:
- device_hostname
- user_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND (LOWER(process_cmd_line) LIKE '%sudo %' AND LOWER(process_cmd_line) LIKE '% tee %') AND time >= datetime('now', '-{{lookback_days}} days')
```

## doh-c2-activity
<!-- DoH C2 Traffic to Public Resolvers -->
Identify historical HTTPS connections (log) to public DNS resolvers which may be DoH C2 traffic.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, c2_doh_ips=c2_doh_ips, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Persistent outbound TLS connections to 8.8.8.8 from an appliance server
  process without corresponding DNS traffic.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
- state_kind
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND instr(',' || '{{c2_doh_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND dst_endpoint_port = 443 AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port HAVING connection_count > 5
```

## cron-persistence-anomalies
<!-- Anomalous Script Execution in System Cron -->
Detect script executions defined in system-level cron directories on scoped appliances, a hallmark of BRICKSTORM persistence.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A job definition in /etc/cron.d/ executing an interpreter or script, particularly
  on an appliance where such entries are not standard.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_definition_path
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_definition_path, job_user_name FROM hb_scheduled_job WHERE instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND LOWER(job_definition_path) LIKE '%/etc/cron.d/%' AND (LOWER(job_cmd_line) LIKE '%/bin/sh%' OR LOWER(job_cmd_line) LIKE '%/bin/bash%' OR LOWER(job_cmd_line) LIKE '%python%' OR LOWER(job_cmd_line) LIKE '%/usr/bin/tee%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-implants
<!-- Weigh VerdantBamboo Evidence -->
```agent target=hunter
cite: required
context:
- vpn-login-anomalies
- sudo-tee-misuse
- doh-c2-activity
- cron-persistence-anomalies
max_iterations: 5
objective: Determine if any host shows overlapping indicators of the VerdantBamboo
  attack chain, focusing on 'sudo tee', cron-based persistence, and 8.8.8.8:443 DoH
  C2.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  specific rows and overlaps found.
tools:
- endpoint
- identity
- network
```

## decision-route
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host and includes evidence of persistence or C2" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-appliance-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Compromised Appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the appliance. Collect a memory capture and the identified persistence files before any reboot.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Forensics -->
```manual target=analyst
Review the cited rows. Search for internal SSH connections from these appliances to Synology NAS (T1021.004) or VMware infrastructure in hb_network_connection.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
If negative, verify edge appliances are updated to Storage Sync v13.13 and 'egnyteservice' credentials have been rotated with MFA enforced.
```
→ end
