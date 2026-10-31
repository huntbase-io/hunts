---
analysis: This hunt correlates vulnerability status with rare file-system behavior
  and HTTP traffic patterns using a gated approach, allowing it to find intrusion
  even when specific web shell filenames rotate.
blind_spots:
- id: missing-vulnerability-telemetry
  question: whether an appliance is vulnerable before the scanner updates
  requires: hb_vulnerability_finding with CVE-2026-22769 coverage
  risk: A host may be exploited before it is flagged by vulnerability scanners, causing
    the gate to close prematurely.
  stage: tomcat-manager-zero-day-exploit
- id: insufficient-telemetry-for-verdict
  question: whether we can see the compilation of the malicious WAR file
  requires: hb_file_activity covering /var/cache/tomcat9
  risk: If endpoint auditing excludes the Tomcat cache directories, the deployment
    of SLAYSTYLE might remain invisible.
  stage: webshell-war-persistence
- id: appliance-audit-logs
  question: whether the specific deployment command succeeded
  requires: /home/kos/auditlog/fapi_cl_audit_log.log
  risk: Standard HTTP logs show the request but not the application-level success
    or error codes only found in the proprietary audit log.
  stage: tomcat-manager-zero-day-exploit
coverage:
- stage: tomcat-manager-zero-day-exploit
  status: covered
  steps:
  - vulnerable-appliances
  - http-exploitation
- stage: webshell-war-persistence
  status: covered
  steps:
  - rare-persistence-markers
- stage: boot-script-backdoor-persistence
  status: covered
  steps:
  - rare-persistence-markers
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: stealthy-iptables-proxying
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: c2-doh-communication
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: vmware-infrastructure-pivoting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Exploitation of a CVSS 10.0 zero-day in edge appliances allows root-level
    persistence that bypasses traditional OS security controls.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting hardcoded credentials (CVE-2026-22769) to deploy
  SLAYSTYLE web shells and persistent GRIMBOLT backdoors on Dell RecoverPoint for
  Virtual Machines appliances.
labels:
- hunt
- attack.t1190
- attack.t1133
- attack.t1505.003
- attack.t1071
name: Dell RecoverPoint Appliance Intrusion and Persistence
parameters:
  lookback_days:
    default: '30'
    description: Days of history to examine for exploitation and persistence markers.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on, typically derived from the
      scoping step.
    type: list[host]
  target_cve:
    default: CVE-2026-22769
    description: The specific Dell RecoverPoint vulnerability ID.
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on systems running Dell RecoverPoint software. If CVE telemetry is
  delayed, search hb_software_inventory for the RecoverPoint package name.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: vmware-infrastructure-pivoting
  reason: Compromised appliances are used as a beachhead to create Ghost NICs on the
    virtual infrastructure.
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
  index: 1
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Dell RecoverPoint Appliance Intrusion and Persistence

This hunt identifies compromised Dell RecoverPoint appliances using a gated flow. It begins by finding vulnerable assets through vulnerability scan data. If vulnerable hosts exist, the hunt fans out to search for HTTP exploitation attempts against the Apache Tomcat Manager and rare file-system markers. The hunt examines both web shell deployment in Tomcat cache directories and persistent backdoor entries in boot scripts.

## vulnerable-appliances
<!-- Identify vulnerable Dell RecoverPoint appliances -->
Find Dell RecoverPoint appliances currently reporting the hardcoded credential vulnerability and map them to hostnames.

```sqlite target=endpoint role=scoping params=(target_cve=target_cve)
~~~yaml
expected: A list of hostnames and device UIDs flagging CVE-2026-22769. Silence proves
  no vulnerable hosts are currently reporting.
reads:
- device_uid
- hostname
- provider
- cve_uid
silence: evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT d.hostname AS device_hostname, f.device_uid, f.affected_package_name, f.affected_package_version, f.severity, f.status, f.first_seen FROM hb_vulnerability_finding AS f JOIN hb_devices AS d ON f.device_uid = d.device_uid AND f.provider = d.provider WHERE f.cve_uid = '{{target_cve}}' AND f.status != 'suppressed'
```

## evaluate-exposure
<!-- Evaluate exposure level -->
```agent target=hunter
cite: required
context:
- vulnerable-appliances
max_iterations: 3
objective: Determine if any Dell RecoverPoint appliances are vulnerable and prioritize
  them for historical telemetry review.
success_criteria: A recommendation to fan out or close the hunt.
tools:
- endpoint
- web
```

## is-vulnerable
<!-- Should the hunt proceed to deep investigation? -->
if~: "vulnerable Dell RecoverPoint appliances were identified" (confidence: high, judge=hunter)
then: → fan-out
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: missing-vulnerability-telemetry)
else: → close-out

## fan-out
<!-- Fan out forensic queries -->
parallel:
- → http-exploitation
- → rare-persistence-markers
join: → triage-compromise

## http-exploitation
<!-- HTTP exploitation of Tomcat Manager -->
Identify PUT requests targeting the Tomcat Manager deployment endpoint via both text and HTML APIs.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PUT requests to the manager endpoint indicate attempt or success in deploying
  a malicious WAR file.
reads:
- device_hostname
- url_path
- url_query
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_full, http_method, src_endpoint_ip, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/manager/text/deploy%' OR LOWER(url_path) LIKE '%/manager/html/deploy%' OR LOWER(url_query) LIKE '%path=/%') AND http_method = 'PUT' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-persistence-markers
<!-- Rare persistence markers on Dell appliances -->
Identify rare WAR file deployments, boot script modifications, or audit log tampering across the entire fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A file path seen on only one or two appliances fleet-wide indicates a malicious
  artifact.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- file_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT file_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '/var/lib/tomcat9/%.war' OR LOWER(file_path) LIKE '/var/cache/tomcat9/catalina/%' OR LOWER(file_path) LIKE '%convert_hosts.sh' OR LOWER(file_path) LIKE '/home/kos/auditlog/fapi_cl_audit_log.log') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path HAVING host_count <= 2
```

## triage-compromise
<!-- Triage compromise per host -->
```agent target=hunter
cite: required
context:
- evaluate-exposure
- http-exploitation
- rare-persistence-markers
max_iterations: 6
objective: Determine if the vulnerable Dell appliances show conclusive signs of exploitation
  (HTTP PUT) or persistence (rare WARs/scripts).
success_criteria: A malicious | suspicious | benign verdict for every host listed
  in the results.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: insufficient-telemetry-for-verdict)
else: → close-out

## isolate-host
<!-- Isolate compromised appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the Dell RecoverPoint appliance from the network and revoke any service credentials used by Apache Tomcat.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Review the cited rows from the triage step. For compromised hosts, acquire a disk image for analysis of the fapi_cl_audit_log.log and the Tomcat WAR cache.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the final count of vulnerable vs. compromised appliances. If vulnerable appliances were found but no intrusion markers were present, notify the infrastructure team to prioritize patching.
```
→ end
