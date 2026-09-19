---
analysis: This hunt correlates Tomcat Manager exploitation with rare file system changes
  in protected directories and specific boot script modifications, providing the context
  an analyst needs to distinguish administrative maintenance from zero-day exploitation.
blind_spots:
- id: no-appliance-telemetry
  question: whether the appliance OS is reporting file and script telemetry
  requires: EDR agent enrollment for appliances
  risk: A compromised appliance that is not enrolled in telemetry will show zero activity,
    providing a false sense of security.
  stage: exploit-hardcoded-credentials
- id: http-payload-visibility
  question: whether the specific 'PUT' request path and user account are visible
  requires: SSL-terminating proxy or server-side HTTP logs
  risk: If traffic is encrypted and only captured as network flows, the URL path and
    actor_user_name will be missing.
  stage: exploit-hardcoded-credentials
coverage:
- stage: exploit-hardcoded-credentials
  status: covered
  steps:
  - tomcat-manager-exploitation
- stage: webshell-persistence-slaystyle
  status: covered
  steps:
  - rare-war-deployment
  - suspicious-java-scripts
- stage: boot-script-persistence
  status: covered
  steps:
  - boot-script-tampering
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: backdoor-execution-grimbolt
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: defense-evasion-spa-iptables
  status: out_of_scope
- reason: Belongs to another part of the 'UNC6201 exploiting a Dell RecoverPoint zero-day'
    series.
  stage: lateral-movement-ghost-nics
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Compromise of management appliances like Dell RecoverPoint provides
    unauthenticated root access to underlying infrastructure, enabling lateral movement
    into ESXi and vCenter environments.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting hardcoded credentials (CVE-2026-22769) in Dell
  RecoverPoint to deploy the SLAYSTYLE web shell and establish persistence via appliance-specific
  boot scripts.
labels:
- hunt
- attack.t1190
- attack.t1505.003
- attack.t1133
name: Dell RecoverPoint Appliance Compromise
parameters:
  boot_scripts:
    default:
    - /home/kos/kbox/src/installation/distribution/convert_hosts.sh
    - /etc/rc.local
    description: Appliance-specific boot scripts modified for persistence.
    from:
      kind: article
      observed: '2024-06-01'
      ref: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
    type: list[path]
  exploit_paths:
    default:
    - /manager/text/deploy
    - /manager/html/deploy
    description: Tomcat Manager deployment endpoints targeted in CVE-2026-22769 exploitation.
    from:
      kind: article
      observed: '2024-06-01'
      ref: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to target; leave empty to hunt across all discovered
      appliances.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all appliances running Dell RecoverPoint for VMs.
  CVE-2026-22769 affects versions prior to 6.0.3.1 HF1. Use hb_software_inventory
  to narrow down the estate.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: grimbolt-backdoor-execution
  reason: GRIMBOLT is the native AOT backdoor deployed as a second-stage payload after
    persistence is established.
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


# Dell RecoverPoint Appliance Compromise

This hunt identifies exploitation of the Dell RecoverPoint management interface and subsequent persistence. It focuses on the Apache Tomcat Manager exploitation used to deploy malicious WAR files, anomalous file activity in webapp directories, and modifications to critical boot scripts like convert_hosts.sh. The hunt leverages HTTP logs for initial access detection and file/script telemetry for persistence corroboration.

## find-recoverpoint-appliances
<!-- Locate Dell RecoverPoint Instances -->
Identify hosts running Dell RecoverPoint software or affected by CVE-2026-22769 to focus the hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to Dell RecoverPoint appliances. Silence means
  no appliances were found in inventory.
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

## tomcat-manager-exploitation
<!-- Tomcat Manager Exploitation Attempts -->
Find HTTP PUT requests to deployment endpoints often paired with hardcoded credentials in this campaign.

```sqlite target=web role=detection-candidate params=(exploit_paths=exploit_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Evidence of remote deployment via Tomcat Manager. Successful exploitation
  involves an 'admin' or hardcoded user account.
reads:
- device_hostname
- url_path
- url_query
- http_method
- actor_user_name
- src_endpoint_ip
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_path, url_query, http_method, actor_user_name, src_endpoint_ip, time FROM hb_http_activity WHERE http_method = 'PUT' AND instr(',' || '{{exploit_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-check-parallel
<!-- Persistence Check Parallel -->
parallel:
- → rare-war-deployment
- → suspicious-java-scripts
- → boot-script-tampering
join: → triage-compromise

## rare-war-deployment
<!-- Rare WAR Deployment and Cache Activity -->
Find anomalous file creation in Tomcat directories used by SLAYSTYLE and Tomcat Manager.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A file written to a Tomcat webapp or cache directory seen on very few hosts.
  Silence suggests standard application behavior.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- file_path
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT file_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '/var/lib/tomcat9/%' OR LOWER(file_path) LIKE '/var/cache/tomcat9/catalina/%') AND activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path HAVING host_count <= 2
```

## suspicious-java-scripts
<!-- Suspicious Java Script Logic -->
Identify execution of scripts containing code fragments associated with SLAYSTYLE command execution.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks performing shell execution or direct IO, which are rare for
  standard Tomcat manager operations. Silence does not rule out compiled WAR files.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%java.io%' OR LOWER(script_content) LIKE '%runtime.getruntime%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## boot-script-tampering
<!-- Boot Script Tampering -->
Detect modifications to the specific shell scripts used by UNC6201 for boot-time persistence.

```sqlite target=endpoint role=enrichment params=(boot_scripts=boot_scripts, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File updates to convert_hosts.sh or rc.local on an appliance. This is high-confidence
  evidence of persistence.
reads:
- device_hostname
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, activity_name, time FROM hb_file_activity WHERE instr(',' || '{{boot_scripts}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND activity_id IN (1, 3) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage Appliance Compromise -->
```agent target=hunter
cite: required
context:
- tomcat-manager-exploitation
- rare-war-deployment
- suspicious-java-scripts
- boot-script-tampering
max_iterations: 4
objective: Determine if any Dell RecoverPoint appliance was successfully compromised
  by UNC6201 based on the exploitation path and persistence evidence.
success_criteria: A verdict of malicious | suspicious | benign for each appliance,
  citing rows from at least two surfaces.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one appliance" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-appliance-telemetry)
else: → analyst-review

## isolate-appliance
<!-- Isolate Appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the Dell RecoverPoint appliance and initiate a forensic image capture for disk analysis of /home/kos and /var/lib/tomcat9.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the PUT requests in HTTP logs. Inspect the /home/kos/kbox/src/installation/distribution/convert_hosts.sh file for any unauthorized additions. Verify if any rare .war files were deployed to /var/lib/tomcat9/webapps.
```
→ close-out

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record all compromised appliances. If the detection-candidate query successfully found an intrusion, promote it to a standing rule.
```
→ end
