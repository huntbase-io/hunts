---
analysis: A simple detection rule for 'iptables' would be too noisy in many Linux
  environments. This hunt uses stack-counting on non-standard ports (10443) and combines
  it with specific 'rcheck' and 'string' module usage in iptables to isolate malicious
  infrastructure manipulation from legitimate system administration.
blind_spots:
- id: limited-telemetry-on-appliances
  question: Can we see iptables modifications on locked-down appliances?
  requires: EDR/Auditd on proprietary Linux appliances
  risk: Many Dell or VMware appliances may not support standard endpoint telemetry
    agents, leaving a blind spot for process-level infrastructure manipulation.
  stage: stealthy-network-redirection
- id: spa-trigger-visibility
  question: Can we see the specific HEX string used to trigger the SPA redirection?
  requires: Full packet capture (PCAP) or HTTP activity with raw payload analysis
  risk: Single Packet Authorization occurs at the kernel level via iptables; unless
    traffic is captured and analyzed for the specific trigger string, the activation
    of the C2 port will appear as spontaneous traffic to an otherwise closed port.
  stage: stealthy-network-redirection
coverage:
- stage: stealthy-network-redirection
  status: covered
  steps:
  - detect-spa-configuration
  - rare-c2-port-connections
  - ghost-nic-creation-commands
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: exploit-hardcoded-credentials
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: webshell-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: boot-script-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: backdoor-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries (UNC6201) are leveraging kernel-level networking features
    (iptables) and virtualization layer manipulation to bypass standard perimeter
    security controls. This hunt addresses the exposure of critical virtualization
    infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Single Packet Authorization (SPA) via iptables to
  hide C2 listeners and creating temporary 'Ghost' network interfaces to pivot stealthily
  between virtualized segments.
labels:
- hunt
- attack.t1090.003
- attack.t1190
- attack.t1505.003
name: Stealthy Infrastructure Pivoting via SPA and Ghost NICs
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  spa_c2_port:
    default: '10443'
    description: The hidden port used for C2 after SPA trigger.
    type: string
  vulnerable_cve:
    default: CVE-2026-22769
    description: CVE associated with the initial access vector.
    type: string
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize Linux-based appliances, particularly Dell RecoverPoint
  and VMware vCenter/ESXi servers, as they are the primary targets for the identified
  TTPs.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: recoverpoint-zero-day-initial-access
  reason: Initial access and webshell deployment on RecoverPoint is handled by a separate
    hunt in this series.
  relation: out-of-scope-alternative
- hunt: dell-recoverpoint-persistence-execution
  relation: follows
scenario:
  stages:
  - name: Exploitation of Hardcoded Credentials
    observables:
    - admin
    - /home/kos/tomcat9/tomcat-users.xml
    - /manager/text/deploy
    - CVE-2026-22769
    slug: exploit-hardcoded-credentials
    tactic: initial-access
    techniques:
    - T1190
  - name: SLAYSTYLE Web Shell Deployment
    observables:
    - SLAYSTYLE
    - /var/lib/tomcat9
    - /var/cache/tomcat9/Catalina
    - org.apache.catalina.startup.hostconfig.deploywar
    - java.io
    - base64.getdecoder
    - runtime.getruntime
    slug: webshell-persistence
    tactic: persistence
    techniques:
    - T1505.003
  - name: Appliance Boot Script Persistence
    observables:
    - rc.local
    - convert_hosts.sh
    - /home/kos/kbox/src/installation/distribution/convert_hosts.sh
    slug: boot-script-persistence
    tactic: persistence
    techniques:
    - T1133
  - name: GRIMBOLT Backdoor Execution
    observables:
    - GRIMBOLT
    - BRICKSTORM
    - UPX
    - C#
    slug: backdoor-execution
    tactic: command-and-control
    techniques:
    - T1071
  - name: Single Packet Authorization Redirection
    observables:
    - iptables
    - port 443
    - port 10443
    - --syn -m recent
    - --seconds 300
    - Ghost NICs
    slug: stealthy-network-redirection
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: UNC6201 exploited a hardcoded credential vulnerability (CVE-2026-22769)
    in Dell RecoverPoint for Virtual Machines to deploy SLAYSTYLE web shells and GRIMBOLT
    backdoors. The actor maintained persistence via modified appliance boot scripts
    and leveraged novel VMware-centric techniques, including 'Ghost NICs' and iptables-based
    Single Packet Authorization, for stealthy lateral movement.
series:
  index: 3
  slug: unc6201-exploiting-a-dell-recoverpoint-zero-day
  title: UNC6201 exploiting a Dell RecoverPoint zero-day
  total: 3
severity: critical
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


# Stealthy Infrastructure Pivoting via SPA and Ghost NICs

This hunt focuses on the infrastructure manipulation tactics used by UNC6201. It looks for the specific iptables configuration patterns used for Single Packet Authorization—which allows a port to remain closed until a specific 'trigger' string is received—and searches for the creation of temporary network interfaces (Ghost NICs) on ESXi and Linux-based appliances. The hunt corroborates these behavioral signals with prevalence-based analysis of the non-standard port 10443.

## scope-to-affected-assets
<!-- Identify vulnerable or affected appliances -->
Scope the hunt to Dell RecoverPoint appliances or hosts with known vulnerability findings for the related CVE.

```sqlite target=endpoint role=scoping params=(vulnerable_cve=vulnerable_cve)
~~~yaml
expected: A list of host identifiers that are known to be vulnerable to the Dell zero-day.
  Silence means no vulnerable assets are recorded in the directory.
reads:
- affected_package_name
- affected_package_version
- cve_uid
- device_uid
- first_seen
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_uid, affected_package_name, affected_package_version, severity, first_seen FROM hb_vulnerability_finding WHERE cve_uid = '{{vulnerable_cve}}' AND status != 'suppressed'
```

## detect-spa-configuration
<!-- Detect iptables Single Packet Authorization (SPA) commands -->
Search for the specific iptables strings mentioned in the report used to implement SPA.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Process command lines matching the SPA configuration pattern. This is a
  high-fidelity indicator of network manipulation.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%iptables%' AND (LOWER(process_cmd_line) LIKE '%-m string%' OR LOWER(process_cmd_line) LIKE '%--hex-string%' OR LOWER(process_cmd_line) LIKE '%--rcheck%' OR LOWER(process_cmd_line) LIKE '%--seconds 300%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## infrastructure-pivot-parallel
<!-- Corroborate Network and Interface Activity -->
parallel:
- → rare-c2-port-connections
- → ghost-nic-creation-commands
join: → triage-infrastructure-activity

## rare-c2-port-connections
<!-- Prevalence of connections to C2 port 10443 -->
Identify hosts communicating on the non-standard C2 port mentioned in the report.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, spa_c2_port=spa_c2_port)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare outbound or inbound connections on port 10443. Clusters of single-host
  activity are high priority.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = CAST('{{spa_c2_port}}' AS INTEGER) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 5 ORDER BY host_count ASC
```

## ghost-nic-creation-commands
<!-- Detect 'Ghost NIC' creation commands -->
Search for process execution that manipulates virtual network interfaces on Linux or ESXi.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Commands creating new network interfaces. This should be cross-referenced
  with authorized change management windows.
reads:
- device_hostname
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%ip link add%' OR LOWER(process_cmd_line) LIKE '%ifconfig%add%' OR LOWER(process_cmd_line) LIKE '%esxcli%network%interface%add%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infrastructure-activity
<!-- Triage Infrastructure Manipulation -->
```agent target=hunter
cite: required
context:
- scope-to-affected-assets
- detect-spa-configuration
- rare-c2-port-connections
- ghost-nic-creation-commands
max_iterations: 4
objective: Determine if any host has unauthorized SPA configuration (iptables) or
  'Ghost NIC' creation that correlates with the rare C2 port 10443.
success_criteria: A verdict citing specific process command lines and network connection
  rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-close-out
unavailable: → analyst-close-out (blind_spot: limited-telemetry-on-appliances)
else: → analyst-close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised appliance and collect volatile network state (active iptables rules and interface lists) before remediation.
```
→ analyst-close-out

## analyst-close-out
<!-- Analyst Close-out -->
```manual target=analyst
Review all cited evidence. If activity is confirmed as unauthorized, initiate incident response procedures for lateral movement in VMware environments.
```
→ end
