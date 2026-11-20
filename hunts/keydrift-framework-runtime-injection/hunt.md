---
analysis: This hunt uses a gated logic to justify deep behavioral analysis of ptrace
  syscalls and memory-resident modules that are too noisy for continuous rules but
  effectively reveal stealthy in-memory implants.
blind_spots:
- id: missing-file-telemetry
  question: whether staging files like vdaemon.conf existed but were deleted before
    collection
  requires: hb_file_activity coverage for /var/tmp and /tmp
  risk: KeyDrift deletes its configuration file immediately after reading, making
    it a transient lead.
  stage: exfiltration-in-band-c2
- id: missing-audit-telemetry
  question: whether injection occurred on hosts where syscall auditing is disabled
  requires: hb_linux_audit with ptrace syscall logging
  risk: If ptrace auditing is not enabled, the mechanism of injection is invisible,
    and the hunt relies solely on memory-map snapshots.
  stage: execution-injection-ptrace
coverage:
- stage: execution-injection-ptrace
  status: covered
  steps:
  - rare-ptrace-activity
- stage: collection-in-process-hooking
  status: covered
  steps:
  - rare-vdaemon-modules
- reason: Covered through detection of the encrypted staging telemetry file /var/tmp/vdaemon.bin.
  stage: exfiltration-in-band-c2
  status: covered
  steps:
  - lead-file-indicators
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: initial-access-cisco-auth-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: persistence-runit-service-tampering
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside KeyDrift: Analyzing historical
    UAT-11473 activity on Cisco SD-WAN'' series.'
  stage: defense-evasion-remount-rootfs
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The UAT-11473 KeyDrift framework allows persistent administrative-level
    access and automated exfiltration of SD-WAN control-plane keying material, which
    can compromise the entire network fabric.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using ptrace to inject malicious modules into the vdaemon
  process on a Cisco SD-WAN controller to intercept and exfiltrate control-plane keying
  material.
labels:
- hunt
- attack.t1055.008
- attack.t1574.006
- attack.t1059.004
- attack.t1036.004
- attack.t1041
- collection
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: KeyDrift Framework Runtime Injection and Hooking
parameters:
  indicator_files:
    default:
    - /tmp/system-vdaemon
    - /var/tmp/vdaemon.bin
    - /var/tmp/vdaemon.conf
    description: KeyDrift staging and configuration files observed in Talos research.
    from:
      kind: article
      observed: '2026-10-28'
      ref: https://blog.talosintelligence.com/uat-11473-keydrift/
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine for staging and injection behavior.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to scope the hunt to; empty means the whole estate.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: analyst-scope
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Scope this hunt to Cisco Catalyst SD-WAN Controller roles, specifically
  vSmart, vManage, and vBond instances where the vdaemon process resides. Start with
  controllers exposed to the internet.
references:
- name: "Cisco Talos \u2014 Inside KeyDrift: Analyzing historical UAT-11473 activity\
    \ on Cisco SD-WAN"
  url: https://blog.talosintelligence.com/uat-11473-keydrift/
related:
- hunt: keydrift-persistence-runit
  reason: The modification of runit service scripts for persistence on disk is handled
    by a separate hunt in this series.
  relation: out-of-scope-alternative
- hunt: cisco-sd-wan-service-tampering
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
  index: 2
  slug: inside-keydrift-analyzing-historical-uat-11473-activity-on-cisco-sd-wan
  title: 'Inside KeyDrift: Analyzing historical UAT-11473 activity on Cisco SD-WAN'
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


# KeyDrift Framework Runtime Injection and Hooking

This hunt targets the runtime behavior of the UAT-11473 KeyDrift framework. It begins with a lead query for high-fidelity staging files in /tmp and /var/tmp that indicate an active intrusion. If found, the hunt triggers a deep dive into Linux audit logs using prevalence to detect rare processes invoking ptrace and examines vdaemon process memory maps for rare shared objects. An agent correlates these behavioral signals to confirm that an adversary has established in-process collection of SD-WAN control traffic.

## lead-file-indicators
<!-- Search for KeyDrift staging files -->
Identify hosts where KeyDrift staging files or telemetry records exist in common temporary directories.

```sqlite target=endpoint role=triage params=(indicator_files=indicator_files, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows indicating the presence of /var/tmp/vdaemon.bin or /tmp/system-vdaemon.
  Silence suggests no such staging files were logged in the window.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{indicator_files}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess lead indicators -->
```agent target=hunter
cite: required
context:
- lead-file-indicators
max_iterations: 3
objective: Decide if the file activity observed on any host matches the KeyDrift framework
  staging behavior described in the article.
success_criteria: A malicious or suspicious verdict for any host where KeyDrift staging
  indicators were identified.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Deep investigation -->
if~: "the assess-lead verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → deep-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-telemetry)
else: → close-out

## deep-investigation
<!-- Deep behavioral investigation -->
parallel:
- → rare-ptrace-activity
- → rare-vdaemon-modules
join: → final-triage

## rare-ptrace-activity
<!-- Rare processes using ptrace syscall -->
Search for ptrace syscalls invoked by rare processes, which is the primary mechanism of PolyFlame injection into vdaemon.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes using ptrace. Legitimate diagnostic tools or debuggers are
  usually common across the fleet; injectors like rsshd will appear on few hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- syscall
- time
silence: not_evidence_of_absence
source: hb_linux_audit
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_linux_audit WHERE syscall = 'ptrace' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING hosts < 3
```

## rare-vdaemon-modules
<!-- Rare shared objects in vdaemon memory -->
Identify any rare shared objects loaded into the vdaemon process across the fleet to find the PolyFlame and LittleFilch modules.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Modules loaded into vdaemon on only one or two hosts. These indicate potential
  injected implants like libdssl.so or libcommon.so.
prevalence:
  by: device_hostname
  key:
  - module_path
  rare_below: 3
reads:
- device_hostname
- module_path
- process_name
- time
silence: evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT module_path, process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_module_activity WHERE LOWER(process_name) LIKE '%vdaemon%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY module_path, process_name HAVING hosts < 3
```

## final-triage
<!-- Final triage of KeyDrift activity -->
```agent target=hunter
cite: required
context:
- lead-file-indicators
- assess-lead
- rare-ptrace-activity
- rare-vdaemon-modules
max_iterations: 6
objective: Determine if the collective evidence from all queries confirms that the
  KeyDrift framework is active and intercepting traffic on the host.
success_criteria: A final assessment that identifies the host, the injector process,
  and the malicious shared objects found in memory.
tools:
- endpoint
```

## route-to-action
<!-- Route to action -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-audit-telemetry)
else: → close-out

## isolate-host
<!-- Isolate SD-WAN controller -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Capture a memory dump and disk image before any remediation, as PolyFlame is primarily memory-resident.
```
→ analyst-review

## analyst-review
<!-- Forensic review -->
```manual target=analyst
Review the cited ptrace activity and module loading. If vdaemon.bin was identified, attempt to recover the RSA-encrypted records for analysis of extracted keying material.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record what was examined and what was not visible. If no indicators were found, document the negative result as evidence of security for the controller estate.
```
→ end
