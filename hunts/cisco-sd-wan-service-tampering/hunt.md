---
analysis: A static rule might fire on any write to /etc/sv, but this hunt provides
  the vital context of a specific filesystem remount (defense evasion) combined with
  fleet prevalence counting to distinguish targeted APT tampering from vendor firmware
  updates.
blind_spots:
- id: auditd-unconfigured
  owner: Cloud Infrastructure Team
  question: whether the remount command was executed
  remediation: Enable syscall auditing for 'mount' across the SD-WAN controller fleet.
  requires: hb_linux_audit with SYSCALL:mount monitoring
  risk: If auditd is not configured to log the mount syscall, the lead query will
    return zero rows, and the gate will close even if the controller is compromised.
  stage: defense-evasion-remount-rootfs
- id: overlay-fs-complexity
  question: what precise changes were made to the overlay when the remount occurred
  requires: Deep inspection of overlay filesystem changes
  risk: File activity logs might show the write, but the relationship between the
    remount and the write is temporal, not causal in the logs; an analyst must manually
    link them.
  stage: persistence-runit-service-tampering
coverage:
- reason: The peering authentication bypass occurs within the proprietary SD-WAN control
    plane; it does not leave standard authentication logs on the listed surfaces.
  stage: initial-access-cisco-auth-bypass
  status: not_visible
- stage: persistence-runit-service-tampering
  status: covered
  steps:
  - script-tampering
  - rare-scripts
- stage: defense-evasion-remount-rootfs
  status: covered
  steps:
  - lead-remount
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: execution-injection-ptrace
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: collection-in-process-hooking
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: exfiltration-in-band-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Cisco SD-WAN controllers are the trust anchor of the enterprise network.
    A compromise here allows an adversary to intercept all control traffic and extract
    data-plane encryption keys, rendering the network's confidentiality void.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a Cisco SD-WAN authentication bypass to establish
  persistence by modifying runit service scripts and remounting the root filesystem
  as executable to facilitate malware deployment.
labels:
- hunt
- attack.t1190
- attack.t1037
- attack.t1543
- attack.t1574.006
- attack.t1036.004
- collection
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: Cisco SD-WAN Controller Service Tampering
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for process and file activity.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on, typically those identified in the
      scoping lead.
    type: list[host]
  target_paths:
    default:
    - /etc/sv/sshd/run
    - /etc/sv/aaamgr/run
    - /etc/pam.d/sshd
    - /etc/pam.d/login
    description: Runit service scripts and PAM configurations targeted for tampering.
    from:
      kind: article
      observed: '2026-10-28'
      ref: uat-11473-keydrift
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/uat-11473-keydrift/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Cisco Catalyst SD-WAN Controller instances (vSmart, vManage, vBond).
  These typically run a specific Linux-based firmware. Remounting /rootfs.rw as executable
  is a rare administrative action.
references:
- name: 'Inside KeyDrift: Analyzing historical UAT-11473 activity on Cisco SD-WAN'
  url: https://blog.talosintelligence.com/uat-11473-keydrift/
related:
- hunt: keydrift-ptrace-injection
  reason: Once persistence is established via service tampering, the malware framework
    typically proceeds to inject into vdaemon using ptrace.
  relation: follows
scenario:
  stages:
  - name: Cisco SD-WAN Authentication Bypass
    observables:
    - CVE-2026-20127
    - Cisco SD-WAN Catalyst Controller
    slug: initial-access-cisco-auth-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Runit Service Launcher Modification
    observables:
    - /etc/sv/sshd/run
    - /etc/sv/aaamgr/run
    - deletion of writable-overlay PAM configurations
    - invocation of malicious run scripts before legitimate service start
    slug: persistence-runit-service-tampering
    tactic: persistence
    techniques:
    - T1037
    - T1543
  - name: Rootfs Executable Remounting
    observables:
    - remount /rootfs.rw as executable
    - mount -o remount,exec /rootfs.rw
    slug: defense-evasion-remount-rootfs
    tactic: defense-evasion
    techniques:
    - T1574.006
  - name: Process Injection and PID Enumeration
    observables:
    - conf_sshd script execution
    - rsshd injector execution
    - aaamgrd packed loader execution
    - ptrace system calls against vdaemon processes
    - /tmp/system-vdaemon
    - enumeration of vdaemon PIDs
    slug: execution-injection-ptrace
    tactic: execution
    techniques:
    - T1055.008
    - T1059.004
    - T1036.004
  - name: Control-Plane Interception Hooking
    observables:
    - libdssl.so (PolyFlame)
    - libcommon.so (LittleFilch)
    - hooking of SSL_read inside vdaemon
    - hooking of recvfrom, sendto, and dlopen in vdaemon
    - interposition of runtime-linker behavior
    slug: collection-in-process-hooking
    tactic: collection
    techniques:
    - T1574.006
  - name: Telemetry Staging and C2 Exfiltration
    observables:
    - /var/tmp/vdaemon.bin (RSA-encrypted telemetry)
    - /var/tmp/vdaemon.conf (Endpoint configuration)
    - UDP exfiltration in DTLS 1.2 style records
    - TinyShell command codes 0x100, 0x200, 0x300
    slug: exfiltration-in-band-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: UAT-11473 exploited an authentication bypass vulnerability (CVE-2026-20127)
    in Cisco SD-WAN Catalyst Controllers to gain unauthorized administrative access.
    The threat actor established persistence by modifying runit service scripts to
    launch the KeyDrift framework, which uses ptrace injection and runtime hooking
    to intercept sensitive control-plane keying material and exfiltrate it over UDP.
series:
  index: 1
  slug: inside-keydrift-analyzing-historical-uat-11473-activity-on-cisco-sd-wan
  title: 'Inside KeyDrift: Analyzing historical UAT-11473 activity on Cisco SD-WAN'
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
tlp: clear
type: investigation
---


# Cisco SD-WAN Controller Service Tampering

The adversary exploits a Cisco SD-WAN authentication bypass to modify runit service scripts and remount the root filesystem as executable. This hunt identifies the initial remounting of the /rootfs.rw filesystem, a mandatory step for the attacker to write to the underlying OS. If suspicious remounting is identified, the hunt fans out to examine modifications to runit service launchers and stack-counts these changes across the fleet to highlight rare, malicious patterns that deviate from standard Cisco firmware behavior. An agent weighs the combined evidence to identify compromised controllers before an analyst initiates containment.

## lead-remount
<!-- Remount rootfs as executable -->
Identify the critical defense evasion step where /rootfs.rw is remounted as executable to allow malicious scripts to run.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A mount syscall targeting /rootfs.rw with the 'exec' option. Silence indicates
  no such remounting was captured during the window.
reads:
- device_hostname
- process_path
- path_name
- raw_record
- time
- record_type
- syscall
silence: not_evidence_of_absence
source: hb_linux_audit
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_path, path_name, raw_record, time FROM hb_linux_audit WHERE record_type = 'SYSCALL' AND syscall = 'mount' AND (LOWER(raw_record) LIKE '%remount%' AND LOWER(raw_record) LIKE '%exec%' AND LOWER(raw_record) LIKE '%/rootfs.rw%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## gate-agent
<!-- Read remount lead -->
```agent target=hunter
cite: required
context:
- lead-remount
max_iterations: 3
objective: Evaluate the context of the mount syscall; determine if /rootfs.rw was
  remounted specifically with executable flags outside of a standard update window.
success_criteria: A verdict of suspicious or benign for every host found in the lead.
tools:
- endpoint
```

## gate-decision
<!-- Gate on remount verdict -->
if~: "the gate-agent verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → fan-out-tampering
indeterminate: → forensic-task
unavailable: → forensic-task (blind_spot: auditd-unconfigured)
else: → close-out-task

## fan-out-tampering
<!-- Corroborate service tampering -->
parallel:
- → script-tampering
- → rare-scripts
join: → triage-agent

## script-tampering
<!-- Runit script tampering -->
Detect modifications to the specific runit service scripts and PAM configurations described in the KeyDrift staging.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, target_paths=target_paths)
~~~yaml
expected: File writes or modifications to runit run scripts or PAM configuration files.
  Silence suggests no tampering occurred on those paths.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{target_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND activity_id IN (1, 3, 4, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-scripts
<!-- Rare runit script modifications -->
Stack-count all runit script modifications to highlight those unique to a small number of hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Runit script paths modified on only one or two hosts. Fleet-wide changes
  are likely legitimate firmware updates.
prevalence:
  by: device_hostname
  key:
  - script_path
  rare_below: 3
reads:
- file_path
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT LOWER(file_path) AS script_path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS write_events, MIN(time) AS first_seen FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(file_path) LIKE '/etc/sv/%/run' AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-agent
<!-- Triage compromised controller -->
```agent target=hunter
cite: required
context:
- gate-agent
- script-tampering
- rare-scripts
max_iterations: 5
objective: Determine if the sequence of remounting /rootfs.rw followed by modifications
  to service scripts indicates a KeyDrift infection. Use prevalence data to rule out
  legitimate maintenance.
success_criteria: A final verdict citing the alignment between the observed behavior
  and the UAT-11473 staging pattern.
tools:
- endpoint
```

## route-decision
<!-- Route on triage verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-action
indeterminate: → forensic-task
unavailable: → forensic-task
else: → close-out-task

## isolate-action
<!-- Isolate SD-WAN controller -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the controller and initiate incident response. Revoke any control-plane certificates associated with this instance and prepare for a re-image.
```
→ forensic-task

## forensic-task
<!-- Forensic review -->
```manual target=analyst
Retrieve the content of the modified scripts found in /etc/sv/. Verify if the host is vulnerable to CVE-2026-20127 by checking patch levels or hb_vulnerability_finding for the CVE ID.
```
→ close-out-task

## close-out-task
<!-- Close out -->
```manual target=analyst
Record the hosts examined and whether any evidence of service tampering was identified. Ensure tuning notes are added if legitimate maintenance caused noise.
```
→ end
