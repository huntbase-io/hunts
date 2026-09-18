---
analysis: This is a hunt because SPA (Single Packet Authorization) is designed to
  be invisible to traditional port scanners and IDS rules. Only by corroborating endpoint-level
  iptables rule changes with live network listeners and suspicious process context
  can we detect this persistence mechanism.
blind_spots:
- id: limited-appliance-visibility
  question: whether iptables rules were changed and then immediately reverted
  requires: host-level iptables logging or persistent listener monitoring
  risk: A short-lived change to firewall rules might be missed if the process activity
    log is not continuous or if the adversary uses a shell script that clears its
    own tracks.
  stage: defense-evasion-spa-iptables
- id: missing-esxi-native-logs
  question: whether temporary network interfaces were created
  requires: vCenter or ESXi audit logs for NIC management
  risk: Endpoint surfaces can see traffic from a NIC but not the administrative creation
    of the 'Ghost NIC' itself.
  stage: lateral-movement-ghost-nics
coverage:
- stage: backdoor-execution-grimbolt
  status: covered
  steps:
  - grimbolt-execution-triage
- stage: defense-evasion-spa-iptables
  status: covered
  steps:
  - iptables-spa-rules
  - spa-port-listeners
- blind_spot: missing-esxi-native-logs
  reason: Creating temporary NICs on ESXi is a management-plane action not visible
    in normalized endpoint or network surfaces; requires ESXi-specific audit logs.
  stage: lateral-movement-ghost-nics
  status: not_visible
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: exploit-hardcoded-credentials
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: webshell-persistence-slaystyle
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: boot-script-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UNC6201 is a critical threat targeting edge appliances with high-impact
    vulnerabilities. A negative result confirming no SPA listeners or suspicious root-level
    backdoor execution provides significant security assurance for critical virtual
    infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has modified the firewall configuration of a Dell or VMware
  appliance to implement Single Packet Authorization (SPA) and is running a Native
  AOT-compiled backdoor from a web-server directory, potentially using a deleted binary.
labels:
- hunt
- attack.t1071
- attack.t1090.003
- attack.t1505.003
- attack.t1190
name: 'UNC6201: In-Memory Backdoor and Network Evasion'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty for the whole estate.
    type: list[host]
  spa_port:
    default: '10443'
    description: The port used for Single Packet Authorization redirection as reported
      in the article.
    type: number
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
rationale: Focus on perimeter-facing Dell RecoverPoint and VMware appliances. If scoping
  is empty, run behaviorally across all Linux-based servers.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: unc6201-initial-access-and-webshells
  reason: Initial access via CVE-2026-22769 and subsequent SLAYSTYLE web shells are
    covered in the precursor hunt of this series.
  relation: out-of-scope-alternative
- hunt: dell-recoverpoint-appliance-compromise
  relation: follows
scenario:
  stages:
  - name: Exploitation of Dell RecoverPoint Tomcat Manager
    observables:
    - CVE-2026-22769
    - admin
    - tomcat-users.xml
    - PUT /manager/text/deploy?path=/
    - /home/kos/auditlog/fapi_cl_audit_log.log
    - /manager/text/deploy
    slug: exploit-hardcoded-credentials
    tactic: initial-access
    techniques:
    - T1190
  - name: SLAYSTYLE Web Shell Deployment
    observables:
    - org.apache.catalina.startup.hostconfig.deploywar
    - java.io
    - base64.getdecoder
    - runtime.getruntime
    - /var/lib/tomcat9
    - /var/cache/tomcat9/Catalina
    - c.substring
    slug: webshell-persistence-slaystyle
    tactic: persistence
    techniques:
    - T1505.003
  - name: Boot Persistence via shell script
    observables:
    - convert_hosts.sh
    - rc.local
    - /home/kos/kbox/src/installation/distribution/convert_hosts.sh
    slug: boot-script-persistence
    tactic: persistence
    techniques:
    - T1133
  - name: GRIMBOLT Backdoor Execution
    observables:
    - GRIMBOLT
    - BRICKSTORM
    - Native AOT-compiled C# binary
    - UPX packed binary
    - /proc/self/exe
    slug: backdoor-execution-grimbolt
    tactic: execution
    techniques:
    - T1071
  - name: Network Evasion via iptables SPA
    observables:
    - iptables -I INPUT -i eth0 -p tcp --dport 443 -m string --hex-string
    - iptables -t nat -A IPT -p tcp -j REDIRECT --to-ports 10443
    - Port 10443
    - Single Packet Authorization
    slug: defense-evasion-spa-iptables
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: Network Pivoting via Ghost NICs
    observables:
    - Ghost NICs
    - Temporary network ports on virtual machines
    - ESXi
    slug: lateral-movement-ghost-nics
    tactic: lateral-movement
    techniques:
    - T1021
  summary: UNC6201 exploited a hardcoded credential vulnerability (CVE-2026-22769)
    in Dell RecoverPoint for Virtual Machines to deploy SLAYSTYLE web shells and GRIMBOLT
    backdoors. The actor maintained persistence via modified appliance boot scripts
    and used sophisticated network evasion, including iptables-based Single Packet
    Authorization (SPA) and Ghost NICs on ESXi, to pivot into internal and SaaS environments.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# UNC6201: In-Memory Backdoor and Network Evasion

This hunt targets the post-exploitation tradecraft of UNC6201 (Silk Typhoon), focusing on the stealthy persistence and network evasion techniques observed following the exploitation of CVE-2026-22769. It looks for behavioral markers of the GRIMBOLT backdoor, including Native AOT binaries running from sensitive Dell RecoverPoint paths (like /home/kos/) and the implementation of Single Packet Authorization (SPA) using iptables redirection to port 10443. The hunt corroborates firewall rule changes, active network listeners on the SPA port, and suspicious root-level process execution to identify compromised virtual infrastructure.

## scope-recoverpoint-appliances
<!-- Scope potentially affected Dell RecoverPoint appliances -->
Identify hosts running Dell software or vulnerable to CVE-2026-22769 to focus the behavioral hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hostnames of Dell appliances. Silence suggests no such software is indexed
  in the estate.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%recoverpoint%' OR LOWER(vendor_name) LIKE '%dell%')
```

## behavioral-parallel-check
<!-- Corroborate Network and Process Evidence -->
parallel:
- → iptables-spa-rules
- → spa-port-listeners
- → grimbolt-execution-triage
join: → triage-agent

## iptables-spa-rules
<!-- Search for IPTables SPA configuration -->
Identify process activity modifying firewall rules to include string matching or port redirection to 10443.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process executions showing iptables rules that mention port 10443 or hex-string
  matching. This is a durable signal of SPA tradecraft.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%iptables%' AND (LOWER(process_cmd_line) LIKE '%--hex-string%' OR LOWER(process_cmd_line) LIKE '%10443%' OR LOWER(process_cmd_line) LIKE '%redirect%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## spa-port-listeners
<!-- Active listeners on port 10443 -->
Find systems currently listening on the reported SPA port to identify active backdoors.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, spa_port=spa_port)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Any row indicates a process interacting with port 10443. Silence suggests
  the SPA listener is not currently active.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_port, COUNT(*) as count FROM hb_network_connection WHERE (dst_endpoint_port = {{spa_port}} OR src_endpoint_port = {{spa_port}}) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name, dst_endpoint_port
```

## grimbolt-execution-triage
<!-- Suspicious root processes in application paths -->
Identify GRIMBOLT or BRICKSTORM execution by looking for root processes in Dell/Tomcat directories, especially those no longer on disk.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process running from a Dell application path as root. High confidence
  if on_disk is 0, indicating the binary was deleted after launch.
reads:
- device_hostname
- process_path
- process_cmd_line
- on_disk
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, process_cmd_line, on_disk, user_name, time FROM hb_process_activity WHERE (process_path LIKE '%/home/kos/%' OR process_path LIKE '%/var/lib/tomcat9/%' OR process_path LIKE '%/var/cache/tomcat9/%') AND user_name = 'root' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Evaluate UNC6201 Indicators -->
```agent target=hunter
cite: required
context:
- scope-recoverpoint-appliances
- iptables-spa-rules
- spa-port-listeners
- grimbolt-execution-triage
max_iterations: 4
objective: Determine if any host shows signs of SPA redirection (iptables rules +
  port 10443 activity) and backdoor execution (root processes in app paths).
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  telemetry.
tools:
- endpoint
- network
```

## route-decision
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host showing both iptables changes and suspicious root processes" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-appliance-visibility)
else: → analyst-manual-review

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the binary from the application paths identified in the triage.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the iptables command lines and root process activity. If on_disk was 0, prioritize host-level forensics to recover deleted binaries.
```
→ end
