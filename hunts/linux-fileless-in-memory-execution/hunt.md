---
analysis: A single rule for memfd_create may trigger high noise in development environments.
  This hunt pivots across DNS (staging), prevalence (unlinked binaries), and module
  activity to identify a complete, high-confidence intrusion chain that a single rule
  cannot resolve.
blind_spots:
- id: limited-kernel-telemetry
  question: whether the provider can observe finit_module calls on older kernels
  requires: eBPF-based syscall monitoring on Kernel 5.10+
  risk: Rootkits loaded on older kernels or through non-standard interfaces may not
    trigger hb_module_activity.
  stage: in-memory-kernel-module-load
- id: obfuscated-one-liners
  question: what code ran if the command line was base64 encoded or read from stdin
  requires: Deep script block inspection (hb_script_activity)
  risk: A loader that pipes encrypted content directly into an interpreter bypasses
    the process_cmd_line search.
  stage: interpreter-one-liners
coverage:
- stage: remote-payload-staging
  status: covered
  steps:
  - dns-staging-leads
- stage: memfd-fileless-execution
  status: covered
  steps:
  - memfd-behavioral-leads
- stage: interpreter-one-liners
  status: covered
  steps:
  - memfd-behavioral-leads
- stage: deleted-binary-execution
  status: covered
  steps:
  - deleted-binary-baseline
- stage: in-memory-kernel-module-load
  status: covered
  steps:
  - kernel-module-leads
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Fileless execution is the standard method for modern Linux rootkits
    and stealthy implants to bypass signature-based and file-scanning controls; a
    negative result over the fleet is a significant assurance of asset integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing malicious code on Linux hosts by staging payloads
  in memory-backed file descriptors, using interpreter one-liners, or running unlinked
  binaries to avoid on-disk detection.
labels:
- hunt
- attack.t1620
- attack.t1059.004
- attack.t1059.006
- attack.t1070.004
- attack.t1014
- attack.t1105
name: Linux Fileless and In-Memory Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-09-01'
      ref: hunt-designer
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific Linux hostnames; leave empty for the entire
      estate.
    from:
      kind: manual
      observed: '2024-09-01'
      ref: analyst-defined
    type: list[host]
  staging_domains:
    default:
    - github.com
    - pypi.org
    - files.pythonhosted.org
    - raw.githubusercontent.com
    description: Domains commonly used to stage loaders or download malicious PyPI
      packages.
    from:
      kind: article
      observed: '2024-09-01'
      ref: elastic-security-labs
    type: list[domain]
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
rationale: Start with public-facing Linux servers (DMZ) and development systems where
  tools like git and python are authorized. Focus the hunt on processes running with
  on_disk = 0 first, as these are the strongest indicators of evasion.
references:
- name: "Elastic Security Labs \u2014 Linux Detection Engineering \u2014 Fileless\
    \ Execution"
  url: https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution
related:
- hunt: linux-ebpf-rootkit-detection
  reason: This hunt focuses on the execution phase; rootkit detection focuses on the
    persistent hooks in the kernel.
  relation: alternative
scenario:
  stages:
  - name: Remote Payload Staging
    observables:
    - curl
    - wget
    - git clone https://github.com/elastic/FENIX.git
    - pip install sympy-dev
    - fenix.git
    - sympy-dev (PyPI)
    slug: remote-payload-staging
    tactic: initial-access
    techniques:
    - T1105
    - T1204.002
  - name: memfd_create Fileless Execution
    observables:
    - memfd_create
    - process.ext.memfd.name
    - /proc/self/fd/
    - MFD_CLOEXEC
    - MFD_ALLOW_SEALING
    - MFD_HUGETLB
    slug: memfd-fileless-execution
    tactic: execution
    techniques:
    - T1620
  - name: Interpreter One-Liner Execution
    observables:
    - python -c
    - bash -c
    - perl -e
    - base64 -d
    - openssl
    - gzip -d
    - curl ... | bash
    - sh one-liners
    slug: interpreter-one-liners
    tactic: execution
    techniques:
    - T1059.004
    - T1059.006
  - name: Execution of Unlinked Binaries
    observables:
    - /proc/<pid>/exe
    - (deleted)
    - on_disk = 0
    - unlinked payload in /tmp
    slug: deleted-binary-execution
    tactic: defense-evasion
    techniques:
    - T1070.004
  - name: In-Memory Kernel Module Loading
    observables:
    - init_module
    - finit_module
    - load_module event
    - memfd_create for module bytes
    slug: in-memory-kernel-module-load
    tactic: persistence
    techniques:
    - T1014
    - T1547.006
  summary: Adversaries utilize Linux fileless execution primitives such as memfd_create,
    interpreter one-liners, and unlinked binaries to execute malicious payloads while
    minimizing on-disk footprints. These techniques, often staged via remote downloads
    or malicious packages, enable in-memory execution of ELFs and kernel modules that
    complicate traditional file-based detection and inspection.
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


# Linux Fileless and In-Memory Execution

This hunt follows a phased flow to detect the lifecycle of Linux fileless execution. It starts by scoping to Linux assets and identifying early staging leads such as DNS resolutions to public repositories and the use of memfd_create primitives. It then pivots to verify high-confidence indicators of successful execution, including processes running from deleted binaries (stack-counted for prevalence) and the loading of kernel modules directly from memory or ephemeral paths.

## linux-host-inventory
<!-- Identify Linux host scope -->
Scope the hunt to Linux hosts by identifying systems with Linux-specific package management activity.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of Linux hosts to be used as a filter in subsequent steps.
reads:
- device_hostname
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE package_type IN ('deb', 'rpm', 'python') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## early-stage-leads
<!-- Early stage staging and primitives -->
parallel:
- → dns-staging-leads
- → memfd-behavioral-leads
join: → early-stage-agent

## dns-staging-leads
<!-- DNS staging to repositories -->
Find hosts resolving common staging domains, which may precede a fileless download.

```sqlite target=endpoint role=enrichment params=(staging_domains=staging_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions from tools like curl, git, or python to public code repositories.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{staging_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## memfd-behavioral-leads
<!-- Fileless execution behavioral patterns -->
Detect command-line indicators and process name patterns of fileless execution, including memfd_create strings and interpreter one-liners.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes named with memfd prefixes or command lines containing memory-backed
  execution primitives.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE 'memfd:%' OR LOWER(process_cmd_line) LIKE '%memfd:%' OR LOWER(process_cmd_line) LIKE '%memfd_create%' OR LOWER(process_cmd_line) LIKE '%/proc/self/fd/%' OR LOWER(process_cmd_line) LIKE '%python -c%' OR LOWER(process_cmd_line) LIKE '%bash -c%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-agent
<!-- Evaluate early-stage staging -->
```agent target=hunter
cite: required
context:
- dns-staging-leads
- memfd-behavioral-leads
max_iterations: 3
objective: Identify hosts where staging activity (DNS) aligns with fileless command-line
  primitives.
success_criteria: A per-host verdict citing the specific staging domains and command-line
  arguments found.
tools:
- endpoint
```

## follow-on-leads
<!-- Hunt for evasive persistence -->
parallel:
- → deleted-binary-baseline
- → kernel-module-leads
join: → follow-on-agent

## deleted-binary-baseline
<!-- Prevalence of unlinked binaries -->
Identify rare processes running from unlinked files by grouping on process name when on_disk is false.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes that were deleted after execution, grouped by their original
  identifier.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3
```

## kernel-module-leads
<!-- Anomalous kernel module loads -->
Detect kernel modules loaded from memory descriptors, suspicious temporary paths, or with missing paths.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Kernel module loads that do not originate from standard library paths or
  have null paths, suggesting rootkit activity.
reads:
- device_hostname
- module_name
- module_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, module_name, module_path, process_name, time FROM hb_module_activity WHERE (module_path LIKE '/proc/%' OR module_path LIKE '/dev/shm/%' OR module_path LIKE '/tmp/%' OR module_path IS NULL) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-agent
<!-- Correlate full fileless chain -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- deleted-binary-baseline
- kernel-module-leads
max_iterations: 4
objective: Determine if hosts with early-stage leads successfully transitioned to
  evasive execution states.
success_criteria: A final verdict identifying the compromised hosts and the specific
  fileless tradecraft observed across all stages.
tools:
- endpoint
```

## intrusion-decision
<!-- Route on fileless intrusion -->
if~: "the follow-on-agent identifies at least one host with staging activity and confirmed evasive execution (on_disk=0 or in-memory module load)" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: limited-kernel-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the process state for memory analysis.
```
→ forensic-review

## forensic-review
<!-- Forensic memory and procfs review -->
```manual target=analyst
Examine /proc/<pid>/fd/ for memory-backed file descriptors and /proc/<pid>/exe if on_disk was 0 to recover the executed binary.
```
→ end

## close-out
<!-- Hunt summary and close-out -->
```manual target=analyst
Record the examined hosts and findings. If the behavioral leads were high-fidelity, promote the memfd-behavioral-leads query to a permanent rule.
```
→ end
