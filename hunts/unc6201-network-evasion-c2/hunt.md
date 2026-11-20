---
analysis: A single detection rule would struggle to distinguish legitimate iptables
  administration from SPA redirection. This hunt baselines DoH activity against the
  fleet and correlates it with specific, rare network redirection commands to identify
  an active pivot.
blind_spots:
- id: missing-process-telemetry
  question: What iptables commands were executed by the web shell?
  requires: hb_process_activity with command-line logging on Linux
  risk: If iptables manipulation is performed via a direct API call or kernel module
    rather than the binary, this hunt will not see it.
  stage: stealthy-iptables-proxying
- id: no-esxi-hardware-telemetry
  question: Were Ghost NICs created on virtual machines?
  requires: vCenter/ESXi audit logs showing hardware configuration changes
  risk: The creation of temporary virtual network interfaces is not visible in standard
    endpoint process or network connection surfaces.
  stage: vmware-infrastructure-pivoting
coverage:
- stage: stealthy-iptables-proxying
  status: covered
  steps:
  - iptables-redirection-commands
- stage: c2-doh-communication
  status: covered
  steps:
  - dns-over-https-activity
- blind_spot: no-esxi-hardware-telemetry
  reason: No virtual machine hardware audit source is available in the hb_ surfaces
    to detect Ghost NIC creation.
  stage: vmware-infrastructure-pivoting
  status: not_visible
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: tomcat-manager-zero-day-exploit
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: webshell-war-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: boot-script-backdoor-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of zero-day vulnerabilities in edge appliances (Dell
    RecoverPoint) and vCenter by UNC6201 presents a critical risk of persistent, high-privileged
    access and stealthy network pivoting.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using iptables REDIRECT rules for Single Packet Authorization
  and DNS-over-HTTPS for command-and-control to hide ingress traffic and outbound
  beacons on compromised appliances.
labels:
- hunt
- attack.t1071
- attack.t1090.003
- attack.t1190
name: UNC6201 Network Evasion and C2
parameters:
  doh_domains:
    default:
    - dns.google
    - cloudflare-dns.com
    - dns.google.com
    - dns.nextdns.io
    description: Known DNS-over-HTTPS provider domains.
    from:
      kind: article
      observed: '2025-09-01'
      ref: unc6201-exploitation
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on; leave empty to hunt across
      the estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize internet-facing Linux appliances and hosts identified
  in the software inventory as Dell RecoverPoint or vCenter.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: unc6201-initial-access-webshells
  reason: Initial access via Tomcat Manager and SLAYSTYLE webshell persistence is
    handled in the companion hunt.
  relation: out-of-scope-alternative
- hunt: dell-recoverpoint-intrusion-persistence
  relation: follows
scenario:
  stages:
  - name: Tomcat Manager Zero-Day Exploitation
    observables:
    - CVE-2026-22769
    - HTTP PUT /manager/text/deploy?path=/
    - admin user authentication to Apache Tomcat Manager
    - /home/kos/tomcat9/tomcat-users.xml
    - /home/kos/auditlog/fapi_cl_audit_log.log
    slug: tomcat-manager-zero-day-exploit
    tactic: initial-access
    techniques:
    - T1190
    - T1133
  - name: SLAYSTYLE Web Shell Deployment
    observables:
    - Malicious WAR file upload to /var/lib/tomcat9
    - org.apache.catalina.startup.HostConfig.deployWAR
    - /var/cache/tomcat9/Catalina
    - java.io
    - Base64.getDecoder
    - Runtime.getRuntime().exec
    slug: webshell-war-persistence
    tactic: persistence
    techniques:
    - T1505.003
  - name: Backdoor Persistence via Boot Script
    observables:
    - Modification of /home/kos/kbox/src/installation/distribution/convert_hosts.sh
    - Execution via /etc/rc.local at boot
    - GRIMBOLT C# Native AOT binary packed with UPX
    - BRICKSTORM binary replacement
    slug: boot-script-backdoor-persistence
    tactic: persistence
    techniques:
    - T1505.003
  - name: Stealthy Proxying via IPTables
    observables:
    - iptables -I INPUT -i eth0 -p tcp --dport 443 -m string --hex-string
    - iptables REDIRECT --to-ports 10443
    - Monitoring port 443 for Single Packet Authorization (SPA)
    - Systemd Journal command recovery
    slug: stealthy-iptables-proxying
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: C2 via DNS-over-HTTPS
    observables:
    - DNS-over-HTTPS queries to Google, Cloudflare, and Amazon DNS services
    - C2 traffic associated with GRIMBOLT and BRICKSTORM
    slug: c2-doh-communication
    tactic: command-and-control
    techniques:
    - T1071
  - name: Lateral Movement via Ghost NICs
    observables:
    - Creation of temporary network ports (Ghost NICs) on virtual machines
    - Pivoting from ESXi servers to internal or SaaS infrastructure
    slug: vmware-infrastructure-pivoting
    tactic: lateral-movement
    techniques:
    - T1090.003
  summary: Suspected PRC-nexus actor UNC6201 exploited a zero-day (CVE-2026-22769)
    in Dell RecoverPoint for Virtual Machines using hardcoded Tomcat Manager credentials.
    They established persistent access via SLAYSTYLE web shells and backdoors, utilizing
    modified boot scripts and complex iptables rules for stealthy network proxying
    and Single Packet Authorization.
series:
  index: 2
  slug: unc6201-exploiting-a-dell-recoverpoint-zero-day
  title: UNC6201 exploiting a Dell RecoverPoint zero-day
  total: 2
severity: critical
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
tlp: clear
type: investigation
---


# UNC6201 Network Evasion and C2

This hunt identifies stealthy network proxying and evasive command-and-control patterns associated with UNC6201 activity. The hunt first scopes for vulnerable Dell RecoverPoint appliances and then fans out to look for specific iptables manipulation used for traffic redirection (SPA) and attempts to resolve known DNS-over-HTTPS providers. An agent weighs these network-level indicators to identify hosts being used as stealthy pivots.

## scope-vulnerable-appliances
<!-- Scope potentially vulnerable Dell appliances -->
Identify Dell RecoverPoint for Virtual Machines software in the inventory to narrow the focus to high-value targets.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames running Dell RecoverPoint software. Silence means no
  such software is managed or reported in inventory.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%recoverpoint%' OR LOWER(vendor_name) LIKE '%dell%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## network-evasion-fan-out
<!-- Search for proxy and C2 evidence -->
parallel:
- → iptables-redirection-commands
- → dns-over-https-activity
join: → triage-network-evasion

## iptables-redirection-commands
<!-- SPA and iptables redirection activity -->
Detect the use of iptables to establish Single Packet Authorization or port redirection patterns.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A process execution row showing iptables used to redirect traffic or match
  strings. Silence proves no such commands were captured by process monitoring.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%iptables%' OR LOWER(process_cmd_line) LIKE '%iptables%') AND (LOWER(process_cmd_line) LIKE '%redirect%' OR LOWER(process_cmd_line) LIKE '%--hex-string%' OR LOWER(process_cmd_line) LIKE '%--u32%' OR LOWER(process_cmd_line) LIKE '%-m u32%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-over-https-activity
<!-- DNS-over-HTTPS resolution patterns -->
Identify hosts resolving common DoH providers which may indicate encrypted C2 traffic.

```sqlite target=endpoint role=baseline params=(doh_domains=doh_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Lookup events for DoH domains. Rare lookups from appliances are suspicious;
  frequent lookups from browsers are baseline.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{doh_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-network-evasion
<!-- Evaluate network evasion evidence -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-appliances
- iptables-redirection-commands
- dns-over-https-activity
max_iterations: 3
objective: Determine if any host exhibits both iptables redirection commands and rare
  DoH resolution activity, suggesting a persistent pivot.
success_criteria: Verdicts for each examined host citing the specific iptables command
  or DNS query. You must explicitly filter the findings from iptables-redirection-commands
  and dns-over-https-activity to focus only on the hosts identified in scope-vulnerable-appliances.
tools:
- endpoint
```

## decide-on-isolation
<!-- Determine response action -->
if~: "the triage-network-evasion verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-triage-review
unavailable: → analyst-triage-review (blind_spot: missing-process-telemetry)
else: → analyst-triage-review

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified as malicious and verify that the iptables rules are preserved for forensic analysis.
```
→ analyst-triage-review

## analyst-triage-review
<!-- Review triage findings -->
```manual target=analyst
Verify the cited iptables commands. If malicious, perform a full disk image analysis focusing on the /var/log/tomcat9 and /home/kos directories.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record whether the iptables rules were legitimate or malicious. If malicious, ensure the host is remediated by applying the Dell RecoverPoint hotfix.
```
→ end
