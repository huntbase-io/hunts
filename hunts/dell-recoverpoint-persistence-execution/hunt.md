---
analysis: A single detection rule might alert on any modification to rc.local, but
  this hunt correlates the modification with the specific appliance profile, calculates
  prevalence for binaries launched *from* those modifications, and uses an agent to
  weigh the totality of the evidence.
blind_spots:
- id: limited-endpoint-telemetry
  owner: Endpoint Security Team
  question: Are the rare binaries definitely Native AOT compiled or UPX-packed backdoors?
  remediation: Enable higher-verbosity logging for Linux appliances or use a tool
    that reports binary entropy and compiler markers.
  requires: detailed process memory maps or binary analysis
  risk: Legitimate but rare updates or custom scripts may be flagged as suspicious,
    leading to false positives.
  stage: backdoor-execution
- id: script-modification-method
  owner: Infrastructure Team
  question: What specific lines were added to the shell scripts?
  remediation: Deploy a FIM solution that captures 'before' and 'after' snapshots
    of configuration files.
  requires: file integrity monitoring (FIM) content diffs
  risk: A simple 'modified' flag doesn't show the malicious path; we must infer it
    from the subsequent execution query.
  stage: boot-script-persistence
coverage:
- stage: boot-script-persistence
  status: covered
  steps:
  - detect-script-modification
- stage: backdoor-execution
  status: covered
  steps:
  - identify-backdoor-execution
  - rare-binary-prevalence
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
  stage: stealthy-network-redirection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of high-CVSS zero-day vulnerabilities in edge appliances
    (like Dell RecoverPoint) often leads to persistent root access that bypasses traditional
    OS security controls. Verifying the integrity of boot scripts is a critical check
    for appliance health.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence on Dell RecoverPoint appliances
  by modifying the 'convert_hosts.sh' boot script to execute Native AOT-compiled backdoors
  like GRIMBOLT.
labels:
- hunt
- attack.t1133
- attack.t1071
- attack.t1546.004
- attack.t1059.004
name: Dell RecoverPoint appliance persistence and backdoor execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-policy
    type: number
  persistence_scripts:
    default:
    - /home/kos/kbox/src/installation/distribution/convert_hosts.sh
    - /etc/rc.local
    description: Boot scripts modified for persistence as reported in the article.
    from:
      kind: article
      observed: '2024-05-01'
      ref: UNC6201 Dell RecoverPoint
    type: list[path]
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
rationale: The hunt should be scoped specifically to appliances running Linux or the
  Dell RecoverPoint suite. If asset management is weak, broadening the scope to all
  Linux-based edge devices is recommended.
references:
- name: UNC6201 exploiting a Dell RecoverPoint zero-day
  url: https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day
related:
- hunt: recoverpoint-webshell-access
  reason: Webshell persistence via malicious WAR files (SLAYSTYLE) is handled in the
    first hunt of this series.
  relation: out-of-scope-alternative
- hunt: esxi-ghost-nic-redirection
  reason: The redirection of traffic and stealthy network pivoting (Ghost NICs) is
    covered in the third hunt of this series.
  relation: out-of-scope-alternative
- hunt: dell-recoverpoint-web-exploitation
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
  index: 2
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
tlp: clear
type: investigation
---


# Dell RecoverPoint appliance persistence and backdoor execution

This hunt targets the post-exploitation phase of the UNC6201 campaign against Dell RecoverPoint for Virtual Machines. It identifies the modification of critical appliance boot scripts (T1133) and the subsequent execution of rare binaries (GRIMBOLT/BRICKSTORM) that exhibit characteristics of native ahead-of-time (AOT) compilation. The hunt scopes to vulnerable or exposed appliances and then correlates file modifications with rare process activity.

## scope-recoverpoint-appliances
<!-- Identify Dell RecoverPoint appliances -->
Scope the hunt to systems that are vulnerable to CVE-2026-22769 or identified as Dell RecoverPoint software.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to Dell RecoverPoint appliances. These are
  the primary targets for the following behavioral checks.
reads:
- device_hostname
- package_name
- package_version
- device_uid
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, device_uid FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%recoverpoint%'
```

## detect-script-modification
<!-- Modifications to appliance boot scripts -->
Find file write or update events targeting the convert_hosts.sh script used by RecoverPoint at boot.

```sqlite target=endpoint role=detection-candidate params=(persistence_scripts=persistence_scripts, lookback_days=lookback_days)
~~~yaml
expected: Any write/update to these shell scripts on a RecoverPoint appliance is highly
  suspicious of persistence establishment. Silence suggests no tampering via the standard
  file surface.
reads:
- device_hostname
- file_path
- activity_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, activity_name, actor_user_name, time FROM hb_file_activity WHERE instr(',' || '{{persistence_scripts}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with execution and prevalence -->
parallel:
- → identify-backdoor-execution
- → rare-binary-prevalence
join: → triage-backdoor-activity

## identify-backdoor-execution
<!-- Backdoor execution lead -->
Identify processes launched by the modified scripts or with known malware strings in the command line.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A process being launched either by the persistence script or by the backdoors
  themselves.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%convert_hosts.sh%' OR LOWER(process_name) LIKE '%grimbolt%' OR LOWER(process_name) LIKE '%brickstorm%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-binary-prevalence
<!-- Prevalence of processes on appliances -->
Stack-count processes on these Linux appliances to find unique or rare binaries that could be the Native AOT backdoors.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries appearing on only one or two hosts. These should be manually
  compared against legitimate RecoverPoint binaries.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 2
```

## triage-backdoor-activity
<!-- Triage backdoor activity -->
```agent target=hunter
cite: required
context:
- scope-recoverpoint-appliances
- detect-script-modification
- identify-backdoor-execution
- rare-binary-prevalence
max_iterations: 4
objective: Determine if any Dell RecoverPoint hosts show evidence of persistence modification
  followed by execution of an anomalous binary.
success_criteria: A per-host verdict (malicious | suspicious | benign) citing file
  paths and process names.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious or suspicious for any host" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-endpoint-telemetry)
else: → close-hunt

## isolate-appliance
<!-- Isolate appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the Dell RecoverPoint appliance from the network and collect volatile memory for Native AOT binary extraction.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the modified 'convert_hosts.sh' scripts for injected paths. Verify if rare processes are compiled using .NET Native AOT.
```
→ end

## close-hunt
<!-- Close hunt -->
```manual target=analyst
Archive the hunt results. No evidence of UNC6201 appliance persistence found.
```
→ end
