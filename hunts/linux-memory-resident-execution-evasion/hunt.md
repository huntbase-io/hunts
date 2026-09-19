---
analysis: While a rule can alert on 'on_disk=0', this hunt uses fleet-wide prevalence
  and pivots across process and module loading surfaces to filter out container runtime
  noise and identify kernel-level evasion.
blind_spots:
- id: missing-ebpf-events
  question: Was the initial memfd_create syscall recorded?
  requires: Linux Kernel 5.10.16+ with eBPF enabled
  risk: On older kernels, the explicit syscall may not be logged, forcing the hunt
    to rely entirely on 'on_disk=0' or procfs path markers.
  stage: memfd-anonymous-execution
- id: snapshot-interval-gap
  question: Did a short-lived loader run and exit between inventory reads?
  requires: hb_process_activity snapshot frequency
  risk: If a loader creates a memfd, executes, and exits within seconds, a snapshot-based
    process inventory may miss it entirely.
  stage: deleted-binary-execution
coverage:
- stage: memfd-anonymous-execution
  status: covered
  steps:
  - detect-memory-resident-processes
  - rare-diskless-prevalence
- stage: deleted-binary-execution
  status: covered
  steps:
  - deleted-binary-evidence
- stage: fileless-kernel-module-load
  status: covered
  steps:
  - memory-module-evidence
- reason: Belongs to another part of the 'Linux Detection Engineering - Fileless Execution'
    series.
  stage: fenix-framework-staging
  status: out_of_scope
- reason: Belongs to another part of the 'Linux Detection Engineering - Fileless Execution'
    series.
  stage: interpreter-one-liner-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Fileless execution is a primary method for evading traditional EDRs
    that scan files at write/execute time. A negative hunt result provides assurance
    that no persistent implants are active in memory across the Linux estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing payloads through anonymous memory descriptors
  (memfd_create) or unlinking binaries immediately after launch to evade on-disk scanning
  and durable detection.
labels:
- hunt
- attack.t1620
- attack.t1059
- attack.t1070.004
- attack.t1547.006
name: Linux Memory-Resident Execution and Evasion
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers and high-uptime Linux instances where memory-resident
  persistence is most effective. Exclude ephemeral container hosts unless testing
  CI/CD staging.
references:
- name: "Elastic Security Labs \u2014 memfd_create Linux Fileless Execution"
  url: https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution
related:
- hunt: interpreter-one-liner-execution
  reason: This hunt focuses on ELF binary execution in memory; shell/python one-liners
    that never drop an ELF are handled by a sibling hunt.
  relation: out-of-scope-alternative
- hunt: linux-fileless-delivery-staging
  relation: follows
scenario:
  stages:
  - name: Staging of FENIX framework
    observables:
    - git clone https://github.com/elastic/FENIX.git
    - pip install -e .
    - make all
    - FENIX_BIN_DIR
    slug: fenix-framework-staging
    tactic: execution
    techniques:
    - T1059.004
    - T1105
  - name: Interpreter-backed fileless execution
    observables:
    - curl
    - wget
    - base64 -d
    - openssl
    - gzip -d
    - bash
    - python -c
    slug: interpreter-one-liner-execution
    tactic: execution
    techniques:
    - T1059.004
    - T1059.006
    - T1105
  - name: Anonymous memory-backed execution
    observables:
    - memfd_create
    - /proc/self/fd/
    - fexecve
    - execveat
    - MFD_CLOEXEC
    - MFD_ALLOW_SEALING
    slug: memfd-anonymous-execution
    tactic: execution
    techniques:
    - T1620
    - T1059
  - name: Deleted-file execution
    observables:
    - /proc/<pid>/exe
    - (deleted)
    - /tmp/payload
    - unlinking after execution
    slug: deleted-binary-execution
    tactic: defense-evasion
    techniques:
    - T1070.004
  - name: Memory-only kernel module load
    observables:
    - init_module
    - finit_module
    - memfd_create
    - loading module from file descriptor
    slug: fileless-kernel-module-load
    tactic: persistence
    techniques:
    - T1547.006
    - T1620
  summary: This scenario reproduces five distinct Linux fileless execution patterns
    used to minimize on-disk artifacts and bypass file-based security controls. The
    techniques involve the use of anonymous memory-backed file descriptors via memfd_create,
    interpreter-based one-liners, unlinked (deleted) executable execution, and in-memory
    kernel module loading.
series:
  index: 2
  slug: linux-detection-engineering-fileless-execution
  title: Linux Detection Engineering - Fileless Execution
  total: 2
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


# Linux Memory-Resident Execution and Evasion

This hunt identifies fileless execution patterns on Linux by detecting processes running without a corresponding binary on disk (on_disk = 0), identifying processes executing from '/proc' or 'memfd' paths, and finding kernel modules loaded from anonymous memory. It correlates this behavior with fleet-wide prevalence to distinguish legitimate administrative activity from malicious implants such as VoidLink.

## detect-memory-resident-processes
<!-- Identify Diskless or Descriptor-Based Processes -->
Find processes currently running where the binary is missing or the path indicates execution from an anonymous memory descriptor.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows naming processes running without disk artifacts. Legitimate container
  runtimes or updaters may appear, requiring prevalence analysis.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- on_disk
- pid
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, pid, time FROM hb_process_activity WHERE (on_disk = 0 OR LOWER(process_path) LIKE 'memfd:%' OR LOWER(process_path) LIKE '/proc/%/fd/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-evidence
<!-- Corroborate on multiple surfaces -->
parallel:
- → rare-diskless-prevalence
- → deleted-binary-evidence
- → memory-module-evidence
join: → triage-fileless-activity

## rare-diskless-prevalence
<!-- Prevalence of Diskless Binaries -->
Stack-count processes running from memory to highlight unique or rare binaries that differ from standard fleet-wide software.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A diskless process seen on only 1 or 2 hosts is a strong indicator of a
  targeted payload.
prevalence:
  by: device_hostname
  key:
  - process_path
  - process_cmd_line
  rare_below: 3
reads:
- process_path
- process_cmd_line
- device_hostname
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_path, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE on_disk = 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path, process_cmd_line HAVING hosts <= 3 ORDER BY hosts ASC
```

## deleted-binary-evidence
<!-- Processes from Unlinked Paths -->
Identify binaries that were deleted immediately after execution, leaving '(deleted)' markers in their path.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicating processes unlinked from disk, a common evasion tactic to
  prevent binary analysis.
reads:
- process_path
- process_name
- process_cmd_line
- device_hostname
- pid
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, pid, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%(deleted)%' OR LOWER(process_name) LIKE '%(deleted)%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## memory-module-evidence
<!-- Kernel Modules from Memory -->
Find loadable kernel modules (LKMs) sourced from memory or anonymous file descriptors rather than on-disk .ko files.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Kernel modules loaded from descriptors or memfd. This is a very high-confidence
  indicator of kernel-level fileless persistence.
reads:
- module_path
- device_hostname
- process_name
- pid
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, module_path, process_name, pid, time FROM hb_module_activity WHERE (LOWER(module_path) LIKE 'memfd:%' OR LOWER(module_path) LIKE '/proc/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-fileless-activity
<!-- Evaluate Fileless Evidence -->
```agent target=hunter
cite: required
context:
- detect-memory-resident-processes
- rare-diskless-prevalence
- deleted-binary-evidence
- memory-module-evidence
max_iterations: 4
objective: Determine if any host shows evidence of malicious fileless execution by
  weighing the 'on_disk=0' flag, rare prevalence, and memory-loaded modules.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  specific process PIDs and paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-ebpf-events)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Before a full reboot, attempt to dump the memory of the suspicious PID identified in triage to recover the ELF payload from memfd or procfs.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the triage results. Use the identified PID to inspect /proc/<pid>/fd/ to recover the memfd payload, or /proc/<pid>/exe if it was deleted. Document if the activity corresponds to a legitimate administrative process to tune the baseline.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record whether any malicious activity was found. If the results were negative, confirm that the relevant surfaces had adequate coverage for the Linux estate.
```
→ end
