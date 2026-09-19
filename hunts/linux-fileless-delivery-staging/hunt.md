---
analysis: A simple detection rule fires on 'curl | bash'; this hunt uses path-agnostic
  matching for utilities, stack-counts pipe usage across the fleet to find rare outliers,
  and corroborates with script content containing memfd and shared-memory primitives.
blind_spots:
- id: ebpf-kernel-limitation
  question: Can the agent observe memfd_create syscalls directly?
  remediation: Update Linux hosts to kernel 5.10.16 or higher for full eBPF telemetry.
  requires: Linux kernel 5.10.16+
  risk: Older kernels may not support eBPF-based event sourcing, making the initial
    anonymous file creation invisible at the kernel level.
- id: shell-script-logging
  question: What logic was executed inside the pipe chain?
  remediation: Enable script block auditing or eBPF-based script tracing for runtime
    interpreters.
  requires: Full script block logging for shell and python
  risk: Without script content logging, the analyst sees 'curl | bash' but cannot
    see the de-obfuscated payload it delivered.
  stage: interpreter-one-liner-execution
coverage:
- stage: fenix-framework-staging
  status: covered
  steps:
  - scoping-tools
  - framework-indicators
- stage: interpreter-one-liner-execution
  status: covered
  steps:
  - rare-pipe-execution
  - script-primitives
- reason: Belongs to another part of the 'Linux Detection Engineering - Fileless Execution'
    series.
  stage: memfd-anonymous-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Linux Detection Engineering - Fileless Execution'
    series.
  stage: deleted-binary-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Linux Detection Engineering - Fileless Execution'
    series.
  stage: fileless-kernel-module-load
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Fileless execution minimizes on-disk footprint, making the staging
    phase (pipes, frameworks) the most visible window for detection before the final
    payload is unlinked.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is acquiring the FENIX framework or using interpreter one-liners
  to download and pipe malicious payloads directly into memory-backed streams, avoiding
  on-disk persistence.
labels:
- hunt
- attack.t1059.004
- attack.t1059.006
- attack.t1105
name: Linux Fileless Delivery and Staging
parameters:
  downloader_bins:
    default:
    - curl
    - wget
    - git
    - pip
    description: Utilities frequently used to initiate fileless one-liners.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts from the scoping step.
    type: list[host]
  staging_indicators:
    default:
    - fenix
    - sympy-dev
    - fenix-loader
    description: Names of binaries or packages associated with fileless staging research.
    from:
      kind: article
      observed: '2026-09-01'
      ref: elastic-security-labs-memfd
    type: list[string]
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
rationale: Focus on servers with external connectivity and developer workstations
  that have 'git', 'make', or 'pip' installed. Widen to the full estate if no staging
  tools are inventoried.
references:
- name: "Elastic Security Labs \u2014 memfd_create Linux Fileless Execution"
  url: https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution
- name: FENIX Framework GitHub
  url: https://github.com/elastic/FENIX
related:
- hunt: linux-memfd-anonymous-execution
  reason: This hunt identifies the staging of tools; the follow-on hunt monitors for
    actual memfd execution and process behavior.
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
  index: 1
  slug: linux-detection-engineering-fileless-execution
  title: Linux Detection Engineering - Fileless Execution
  total: 2
severity: medium
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


# Linux Fileless Delivery and Staging

This hunt targets the initial delivery and staging phases of a Linux fileless intrusion. It identifies the acquisition of the FENIX framework or specific malicious PyPI packages and the use of interpreter one-liners (such as curl or wget piped to a shell) to execute code without durable binaries. By examining software inventory for staging tools, process activity for rare pipe chains using path-agnostic matching, and script contents for shared-memory or memfd_create primitives, the hunt detects the precursors to fileless ELF execution.

## scoping-tools
<!-- Scope to hosts with staging tools -->
Identify hosts that have the necessary utilities to initiate remote downloads or staging.

```sqlite target=endpoint role=scoping params=(downloader_bins=downloader_bins)
~~~yaml
expected: A list of hostnames with developer or download tools. Silence indicates
  these tools are not inventoried; the hunt will continue across all hosts.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE instr(',' || '{{downloader_bins}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## framework-indicators
<!-- Malicious framework and package indicators -->
Find path-agnostic matches for research-specific framework binaries or malicious packages like 'sympy-dev'.

```sqlite target=endpoint role=triage params=(staging_indicators=staging_indicators, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes identifying the FENIX framework or sympy-dev loader. Silence suggests
  no direct matches for known research tools were active.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/fenix' OR LOWER(process_name) LIKE '%/sympy-dev' OR LOWER(process_name) LIKE '%/fenix-loader' OR instr(',' || '{{staging_indicators}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-staging
<!-- Corroborate with pipes and script activity -->
parallel:
- → rare-pipe-execution
- → script-primitives
join: → triage-agent

## rare-pipe-execution
<!-- Rare interpreter pipe chains -->
Identify commands where a downloader pipes output directly into a shell, using path-agnostic matching for the utilities.

```sqlite target=endpoint role=detection-candidate params=(downloader_bins=downloader_bins, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare command lines like 'curl ... | bash'. Legitimate CI/CD pipelines are
  usually common across the fleet; outliers are high-interest.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_name
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) LIKE '%/git' OR LOWER(process_name) LIKE '%/pip' OR instr(',' || '{{downloader_bins}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (process_cmd_line LIKE '%|%bash%' OR process_cmd_line LIKE '%|%sh%' OR process_cmd_line LIKE '%|%python%' OR process_cmd_line LIKE '%|%perl%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_cmd_line HAVING hosts <= 3
```

## script-primitives
<!-- Script primitives for memory-backed files -->
Examine script contents for memfd_create, /proc/self/fd/ paths, or shared-memory staging areas used for runtime execution.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Python, Perl, or Shell scripts that manually allocate anonymous memory or
  use shared memory paths to stage payloads.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%memfd_create%' OR LOWER(script_content) LIKE '%/proc/self/fd/%' OR LOWER(script_content) LIKE '%/dev/shm/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage staging activity -->
```agent target=hunter
cite: required
context:
- framework-indicators
- rare-pipe-execution
- script-primitives
max_iterations: 4
objective: Determine if the FENIX framework or malicious one-liners are being staged
  for an intrusion, citing specific command lines and script primitives.
success_criteria: A verdict of malicious | suspicious | benign citing rows and hostnames.
tools:
- endpoint
```

## route-verdict
<!-- Route on triage verdict -->
if~: "The triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: shell-script-logging)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Staged fileless payloads are volatile; if the process is still running, capture a memory dump before rebooting.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited pipe chains and script content. Cross-reference with the user's role and standard deployment manifests. If this was a legitimate maintenance task, add the specific command line to a local exception list or tune the downloader_bins parameter.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the host coverage. If no staging was found but suspicion remains, run the follow-up hunt for active memfd execution.
```
→ end
