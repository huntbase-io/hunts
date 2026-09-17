---
analysis: "A single rule for unprivileged AF_ALG socket binding is often too noisy.\
  \ This hunt uses a behavioral sequence\u2014unprivileged file read, prevalence stacking,\
  \ and anomalous root transition\u2014to provide high-confidence signal."
blind_spots:
- id: missing-endpoint-telemetry
  question: Was an AF_ALG socket actually used to configure the AEAD pipeline?
  requires: Syscall tracing for AF_ALG socket and splice()
  risk: Standard surfaces see side effects only; the core mechanism is invisible without
    kernel syscall tracing.
  stage: crypto-socket-initialization
- id: volatile-memory-evidence
  question: Is the corruption still resident in memory?
  requires: In-memory page cache inspection
  risk: Corruption is volatile. If the kernel reclaims the page or the system reboots,
    the primary indicator is lost.
  stage: privilege-escalation-execution
coverage:
- blind_spot: missing-endpoint-telemetry
  reason: Standard surfaces do not capture AF_ALG socket family or specific setsockopt
    calls.
  stage: crypto-socket-initialization
  status: not_visible
- stage: sensitive-file-mapping
  status: covered
  steps:
  - unprivileged-sensitive-reads
  - rare-sensitive-access-stacking
- stage: privilege-escalation-execution
  status: covered
  steps:
  - suspicious-root-execution
- reason: Belongs to another part of the 'CVE-2026-31431 Copy-Fail exploit detection
    with agents' series.
  stage: vulnerability-identification
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: CVE-2026-31431 (Copy-Fail) bypasses all standard file integrity and
    write auditing by corrupting the page cache directly in kernel memory.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unprivileged actor is exploiting CVE-2026-31431 by using the Linux
  crypto subsystem to corrupt the in-memory page cache of sensitive system files,
  facilitating unauthorized privilege escalation to root.
labels:
- hunt
- attack.t1190
- attack.t1068
- attack.t1564
name: Kernel Page Cache Corruption Detection
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  sensitive_paths:
    default:
    - /etc/pam.d/
    - '%passwd'
    - '%su'
    - '%sudo'
    description: System paths and binaries targeted for page cache corruption to bypass
      authentication or escalate privileges.
    from:
      kind: article
      observed: '2026-05-01'
      ref: Datadog Security Labs
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://securitylabs.datadoghq.com/articles/cve-2026-31431-copy-fail-exploit-detection-with-agents/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value Linux servers and long-uptime systems where corrupted
  page cache pages are most likely to persist.
references:
- name: CVE-2026-31431 Copy-Fail exploit detection with agents
  url: https://securitylabs.datadoghq.com/articles/cve-2026-31431-copy-fail-exploit-detection-with-agents/
related:
- hunt: container-escape-via-page-cache
  reason: This hunt focuses on host-level privilege escalation; cross-namespace page
    cache corruption is a sibling hunt.
  relation: out-of-scope-alternative
- hunt: linux-copy-fail-exploit-detection
  relation: follows
scenario:
  stages:
  - name: Vulnerable Kernel Identification
    observables:
    - CVE-2026-31431
    - Linux kernel versions 4.14 through 6.19
    - Linux kernel version 7.0-rc
    slug: vulnerability-identification
    tactic: initial-access
    techniques:
    - T1190
  - name: AF_ALG Socket Setup
    observables:
    - socket(AF_ALG, SOCK_SEQPACKET, 0)
    - bind(AF_ALG, "authencesn(hmac(sha256),cbc(aes))")
    - setsockopt(SOL_ALG, ALG_SET_KEY)
    - setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 4)
    - process.euid != 0
    slug: crypto-socket-initialization
    tactic: execution
    techniques:
    - T1068
  - name: Target File Page Cache Mapping
    observables:
    - open("/usr/bin/su", O_RDONLY)
    - open("/etc/pam.d/*", O_RDONLY)
    - open("/etc/passwd", O_RDONLY)
    - os.pipe()
    - os.splice(target_fd, pipe_wr, ...)
    slug: sensitive-file-mapping
    tactic: defense-evasion
    techniques:
    - T1564
  - name: Privileged Execution of Corrupted Binary
    observables:
    - Execution of SUID binaries (e.g., /usr/bin/su)
    - Execution as root (euid 0) from an unprivileged parent process
    - Authentication bypass via modified PAM config
    slug: privilege-escalation-execution
    tactic: privilege-escalation
    techniques:
    - T1068
  summary: An unprivileged local user exploits CVE-2026-31431 by using AF_ALG crypto
    sockets and the splice syscall to corrupt the kernel page cache of sensitive system
    binaries or configuration files. This results in a controlled, in-memory modification
    of files like su or PAM configs, enabling the attacker to execute code as root
    without leaving a permanent on-disk audit trail or changing file metadata.
series:
  index: 2
  slug: cve-2026-31431-copy-fail-exploit-detection-with-agents
  title: CVE-2026-31431 Copy-Fail exploit detection with agents
  total: 2
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


# Kernel Page Cache Corruption Detection

This hunt identifies 'Copy-Fail' (CVE-2026-31431) exploitation, where an unprivileged user leverages AF_ALG sockets to write directly into the page cache of readable system files. Because the corruption occurs entirely in kernel memory without modifying the on-disk file, metadata-based FIM is blind to the write.

The hunt focuses on the distinctive behavioral chain: unprivileged processes performing read-only operations on sensitive binaries (e.g., /usr/bin/su) or PAM configurations, followed by a suspicious transition to root execution (euid 0) on the same host. We use prevalence stacking to isolate rare, targeted access patterns from normal system noise.

## linux-host-scope
<!-- Scope to Linux systems -->
Identify Linux hosts in the inventory that are susceptible to kernel-level vulnerabilities.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of Linux hostnames and kernel versions. Silence means no Linux systems
  are reporting inventory.
reads:
- device_hostname
- package_name
- package_version
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'linux' OR LOWER(package_name) = 'kernel') AND collected_at >= datetime('now', '-7 days')
```

## unprivileged-sensitive-reads
<!-- Unprivileged read access to sensitive files -->
Detect processes running as non-privileged users reading sensitive system binaries or configs, which is a precursor to the splicing phase of the exploit.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows showing unprivileged users accessing files they usually do not touch
  directly. This mimics the exploit's read phase.
reads:
- device_hostname
- process_name
- file_path
- actor_user_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, actor_user_name, time FROM hb_file_activity WHERE activity_id = 2 AND LOWER(actor_user_name) NOT IN ('root', 'system', 'bin', 'daemon') AND (LOWER(file_path) LIKE '%/bin/su' OR LOWER(file_path) LIKE '%/bin/sudo' OR LOWER(file_path) LIKE '%/etc/pam.d/%' OR LOWER(file_path) LIKE '%/etc/passwd' OR LOWER(file_path) LIKE '%/etc/security/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-exploitation
<!-- Corroborate access with prevalence and elevation -->
parallel:
- → rare-sensitive-access-stacking
- → suspicious-root-execution
join: → triage-verdict

## rare-sensitive-access-stacking
<!-- Stacking unprivileged sensitive access -->
Identify outlier hosts where unprivileged users are performing targeted reads on sensitive files.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary or config file being read by an unprivileged user on only one or
  two hosts in the fleet.
prevalence:
  by: device_hostname
  key:
  - file_path
  - actor_user_name
  rare_below: 3
reads:
- file_path
- actor_user_name
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT file_path, actor_user_name, COUNT(DISTINCT device_hostname) AS host_count FROM hb_file_activity WHERE activity_id = 2 AND LOWER(actor_user_name) NOT IN ('root', 'system', 'bin', 'daemon') AND (LOWER(file_path) LIKE '%/bin/su' OR LOWER(file_path) LIKE '%/etc/pam.d/%' OR LOWER(file_path) LIKE '%/etc/passwd') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path, actor_user_name HAVING host_count < 3
```

## suspicious-root-execution
<!-- Suspicious root execution from non-root parents -->
Corroborate the exploit's outcome: a process gaining root (euid 0) from an unprivileged parent without standard privilege escalation paths.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Processes launching as root from shell or user contexts without sudo.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- parent_process_name
- parent_process_cmd_line
- time
- activity_id
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, parent_process_name, parent_process_cmd_line, time FROM hb_process_activity WHERE activity_id = 1 AND LOWER(user_name) = 'root' AND LOWER(parent_process_name) NOT LIKE '%/systemd' AND LOWER(parent_process_name) NOT LIKE '%/init' AND LOWER(parent_process_name) NOT LIKE '%/kthreadd' AND LOWER(parent_process_name) NOT LIKE '%/sshd' AND LOWER(parent_process_name) NOT LIKE '%/containerd' AND LOWER(parent_process_name) NOT LIKE '%/dockerd' AND LOWER(parent_process_name) NOT LIKE '%sudo%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-verdict
<!-- Triage Copy-Fail exploitation sequence -->
```agent target=hunter
cite: required
context:
- unprivileged-sensitive-reads
- rare-sensitive-access-stacking
- suspicious-root-execution
max_iterations: 5
objective: 'Determine if any host shows the ''Copy-Fail'' exploit pattern: unprivileged
  read access to a sensitive binary or PAM config followed by a suspicious root transition
  from a non-standard parent on that same host.'
success_criteria: A host-by-host verdict citing specific file paths and the root execution
  details.
tools:
- endpoint
```

## route-decision
<!-- Route based on agent verdict -->
if~: "The triage verdict is malicious for at least one host, indicating privilege escalation following targeted file access." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host and preserve memory -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint from the network. Perform a memory acquisition before rebooting to capture the corrupted page cache.
```
→ analyst-review

## analyst-review
<!-- Forensic validation -->
```manual target=analyst
Review the cited rows. Confirm the unprivileged session and subsequent root launch. Look for secondary indicators like persistent shell creation.
```
→ close-out

## close-out
<!-- Close hunt and record baseline -->
```manual target=analyst
Record legitimate unprivileged file access patterns for tuning. Close the hunt.
```
→ end
