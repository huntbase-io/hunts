---
analysis: A static rule might catch one known .so filename; this hunt correlates vulnerability
  exposure with fleet-wide module rarity and dynamic loading from /tmp, providing
  the context to distinguish a complex modular framework from incidental software
  updates.
blind_spots:
- id: module-telemetry-gap
  owner: Endpoint Security Team
  question: Are we seeing dynamically loaded plugins that only exist in memory?
  remediation: Enable Linux auditd or eBPF-based module monitoring.
  requires: EDR with module load visibility (hb_module_activity)
  risk: If the ELF linker/loader loads modules without writing them to disk or if
    the EDR doesn't capture the load event, the modular nature of VoidLink stays hidden.
  stage: implant-execution-and-module-loading
- id: ebpf-rootkit-stealth
  owner: Platform Engineering
  question: Is the rootkit using eBPF programs rather than standard LKMs?
  remediation: Deploy eBPF-specific monitoring tools like Tetragon or Cilium.
  requires: Advanced kernel auditing (e.g., bpftool or custom osquery tables)
  risk: eBPF programs are not always visible in hb_module_activity, which typically
    lists loaded kernel modules via lsmod. Stealth eBPF persistence would bypass this
    hunt.
  stage: persistence-via-rootkit
coverage:
- stage: implant-execution-and-module-loading
  status: covered
  steps:
  - suspicious-shared-object-loads
  - unusual-process-execution-paths
  - triage-voidlink-activity
- stage: persistence-via-rootkit
  status: covered
  steps:
  - rare-linux-kernel-modules
  - triage-voidlink-activity
- reason: Belongs to another part of the 'VoidLink' series.
  stage: initial-access-vulnerability-or-creds
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: internal-discovery-and-p2p
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: c2-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VoidLink is a high-end framework targeting critical Linux infrastructure
    with 'compile-on-demand' plugins. Behavioral hunting for modular execution is
    the only reliable way to detect it before it shifts to P2P C2 and exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing VoidLink implants and modular plugins from user-writable
  paths and maintaining persistence via rare kernel modules or eBPF programs, likely
  following the exploitation of Java serialization vulnerabilities.
labels:
- hunt
- attack.t1204.002
- attack.t1574.002
- attack.t1014
- attack.t1547.006
name: VoidLink Modular Implant Execution and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  suspicious_linux_writable_paths:
    default:
    - /tmp/
    - /var/tmp/
    - /dev/shm/
    - /home/*/.local/share/
    - /var/www/html/
    description: Linux paths often used to host dropped implants or plugins.
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/voidlink/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with Linux-based cloud infrastructure and internal servers running
  Java or Dubbo. Focus on Class C networks if large-scale scanning is suspected.
references:
- name: "Cisco Talos \u2014 VoidLink"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-initial-access-and-creds
  reason: This hunt focuses on the execution phase after the initial Dubbo exploitation.
  relation: precedes
- hunt: voidlink-p2p-and-exfiltration
  reason: Once executed, the implant begins mesh networking and exfiltration.
  relation: follows
- hunt: voidlink-initial-access-dubbo-credentials
  relation: follows
scenario:
  stages:
  - name: Initial Access via Dubbo or Credentials
    observables:
    - Apache Dubbo
    - Java serialization vulnerabilities
    - Pre-obtained credentials
    slug: initial-access-vulnerability-or-creds
    tactic: initial-access
    techniques:
    - T1190
  - name: VoidLink Implant and Plugin Execution
    observables:
    - ZigLang implant binary
    - ELF linker and loader
    - C-based plugins
    - DLL sideloading (Windows)
    - Unix.Trojan.VoidLink ClamAV detection
    slug: implant-execution-and-module-loading
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: Kernel-Level Persistence and Evasion
    observables:
    - eBPF rootkit
    - Loadable Kernel Module (LKM)
    - Container privilege escalation
    - Sandbox escape
    slug: persistence-via-rootkit
    tactic: persistence
  - name: Lateral Movement and Internal Discovery
    observables:
    - FSCAN scanning tool
    - SOCKS server deployment
    - Scanning Class C networks
    - Kubernetes and Docker API enumeration
    slug: internal-discovery-and-p2p
    tactic: discovery
    techniques:
    - T1090
  - name: Command and Control via Mesh Network
    observables:
    - P2P mesh routing
    - Dead-letter queue routing
    - Obfuscated data exfiltration
    slug: c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
    - T1041
  summary: UAT-9921 leverages the VoidLink framework, a modular Linux-first implant
    management system, to compromise targets via Apache Dubbo Java serialization exploits
    or stolen credentials. Once deployed, the framework uses ZigLang-based implants
    with on-demand C plugins, eBPF rootkits, and P2P mesh communication to conduct
    stealthy lateral movement and cloud-aware reconnaissance.
series:
  index: 2
  slug: voidlink
  title: VoidLink
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
tlp: clear
type: investigation
---


# VoidLink Modular Implant Execution and Persistence

This hunt identifies the execution and persistence phases of the VoidLink modular framework (UAT-9921). VoidLink is a sophisticated, defense-contractor-grade implant framework that uses Zig and C to deploy plugins dynamically. It leverages rootkits (LKMs or eBPF) for stealth and persistence. The hunt begins by identifying infrastructure exposed to the Java serialization and Apache Dubbo vulnerabilities cited as UAT-9921's primary entry points. It then correlates that risk with behavioural evidence across multiple surfaces: rare kernel modules that may be custom rootkits, shared objects loaded from temporary Linux directories, and processes executing from non-standard paths. An agent then triages these signals per host to identify high-confidence modular implant activity.

## scoping-vulnerable-dubbo
<!-- Identify hosts with vulnerable serialization or Dubbo -->
Scope the hunt to hosts that may have been compromised via Java serialization vulnerabilities or the Apache Dubbo project, identifying the potential initial infection surface.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of cloud resources or devices currently exposed to the entry points
  used by UAT-9921. Silence means no known vulnerable Dubbo/serialization instances
  are reporting, but does not preclude zero-day access.
reads:
- resource_uid
- device_uid
- affected_package_name
- cve_uid
- title
- severity
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT resource_uid, device_uid, affected_package_name, cve_uid, title, severity FROM hb_vulnerability_finding WHERE (LOWER(affected_package_name) LIKE '%dubbo%' OR LOWER(title) LIKE '%serialization%') AND status != 'suppressed'
```

## parallel-implant-evidence
<!-- Gather Modular and Kernel Evidence -->
parallel:
- → rare-linux-kernel-modules
- → suspicious-shared-object-loads
- → unusual-process-execution-paths
join: → triage-voidlink-activity

## rare-linux-kernel-modules
<!-- Rare Linux Kernel Module (LKM) Loads -->
Detect potential VoidLink rootkits by finding Loadable Kernel Modules (.ko) that are unique to a small subset of the fleet.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A kernel module seen on 1-3 hosts. VoidLink uses LKMs for persistence; these
  are often custom and will not match fleet-wide standard modules.
prevalence:
  by: device_hostname
  key:
  - module_name
  rare_below: 3
reads:
- module_name
- module_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT module_name, module_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_module_activity WHERE LOWER(module_path) LIKE '%.ko' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY module_name, module_path HAVING hosts <= 3 ORDER BY hosts ASC
```

## suspicious-shared-object-loads
<!-- Suspicious Shared Object (.so) Loads -->
Identify VoidLink C-based plugins being loaded by an ELF linker/loader from temporary or user-writable paths on Linux.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Shared libraries loaded from non-standard system directories. VoidLink plugins
  are C-based and loaded dynamically.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE LOWER(module_path) LIKE '%.so' AND (LOWER(module_path) LIKE '/tmp/%' OR LOWER(module_path) LIKE '/var/tmp/%' OR LOWER(module_path) LIKE '/dev/shm/%' OR LOWER(module_path) LIKE '/home/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## unusual-process-execution-paths
<!-- Unusual Process Execution in Writable Paths -->
Find the main VoidLink ZigLang implant or plugins executing from standard staging paths like /tmp.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary executing from a global-writable directory. VoidLink is often dropped
  and executed immediately from these locations.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 2
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/var/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-voidlink-activity
<!-- Triage VoidLink Modular Activity -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-dubbo
- rare-linux-kernel-modules
- suspicious-shared-object-loads
- unusual-process-execution-paths
max_iterations: 4
objective: Identify hosts showing coordinated evidence of the VoidLink modular implant,
  focusing on the overlap between vulnerable Java infrastructure and unusual kernel/module
  loading.
success_criteria: A verdict for every suspicious host citing specific process names,
  module paths, and vulnerability context.
tools:
- endpoint
```

## verdict-decision
<!-- Route on Implant Verdict -->
if~: "The triage verdict is 'malicious' for at least one host." (confidence: high, judge=hunter)
then: → containment-isolation
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: module-telemetry-gap)
else: → analyst-forensic-review

## containment-isolation
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve forensic artifacts in /tmp and the kernel module list.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Forensic Review of Modular Components -->
```manual target=analyst
Review cited rare .ko and .so files. Check for 'compile-on-demand' artifacts in temp directories. Confirm if the host's Java applications were exploited.
```
→ close-out

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record what was examined and what was not visible. If rare but benign modules were found, update the prevalence baseline.
```
→ end
