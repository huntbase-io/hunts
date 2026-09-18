---
analysis: A standard detection rule might alert on 'whoami' under PaperCut, but it
  would miss the subtle file artifacts and the coordinated log deletion behavior.
  This hunt pivots between three surfaces to build a contextual evidence chain that
  an agent can weigh, reducing the noise from legitimate administrative system profiling.
blind_spots:
- id: in-memory-execution
  owner: Endpoint Security
  question: Did the attacker use the Derby memory driver to execute bytecode without
    writing class files to disk?
  remediation: Deploy EDR with advanced Java runtime monitoring or instrument PaperCut
    with an APM agent.
  requires: hb_process_memory or Java agent instrumentation
  risk: If the attacker achieves execution purely in-memory via a malicious DB URL,
    file system monitoring (hb_file_activity) will not see the payload, and this hunt
    will rely solely on the process discovery signal.
  stage: class-loading-rce
- id: logic-bypass-visibility
  owner: Network Engineering
  question: Can we distinguish the bypass request from normal administrative traffic?
  remediation: Enable high-verbosity logging on WAFs/Reverse Proxies sitting in front
    of PaperCut servers.
  requires: hb_http_activity with full URI/component mapping
  risk: Initial access is a logic bypass within the Java application internals. Standard
    endpoint HTTP logging may not capture the specific administrative component targeting
    required to prove exploitation of CVE-2026-81578.
  stage: web-access-bypass
coverage:
- blind_spot: logic-bypass-visibility
  reason: Endpoint-level OCSF HTTP logging does not typically capture the application-layer
    component mismatch required to identify the access bypass.
  stage: web-access-bypass
  status: not_visible
- stage: class-loading-rce
  status: covered
  steps:
  - rare-artifact-creation
- stage: system-profiling
  status: covered
  steps:
  - papercut-discovery-activity
- stage: defense-evasion-cleanup
  status: covered
  steps:
  - papercut-log-evasion
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: PaperCut is a high-privilege application often running as SYSTEM/root.
    The reported vulnerabilities allow for unauthenticated remote code execution and
    are under active exploitation, making a negative result over the estate a critical
    business requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthenticated attacker is exploiting a logic flaw in PaperCut NG/MF
  to load malicious Java classes, resulting in system profiling commands being spawned
  from the application server process.
labels:
- hunt
- attack.t1190
- attack.t1203
- attack.t1106
- attack.t1033
- attack.t1082
- attack.t1057
- attack.t1083
- attack.t1070.004
name: PaperCut Pre-Auth RCE and System Discovery
parameters:
  encoded_payloads:
    default:
    - d2hvYW1pICYgdmVy
    - d2hvYW1pICYgdmVyICYgdGFza2xpc3Q=
    description: Base64 encoded discovery commands observed in the wild.
    from:
      kind: article
      observed: '2026-08-28'
      ref: huntress-papercut-zero-day
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-28'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; defaults to all hosts.
    from:
      kind: manual
      observed: '2026-08-28'
      ref: scoping-step
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/papercut-actively-exploited
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all PaperCut hosts via software inventory. Focus investigative
  depth on any server that is internet-exposed (port 9191/9192) or identified as vulnerable
  (CVE-2026-81578).
references:
- name: "Huntress \u2014 PaperCut Zero-Day: Active Exploitation and Pre-Auth RCE"
  url: https://www.huntress.com/blog/papercut-actively-exploited
related:
- hunt: papercut-log-forensics-derby
  reason: This hunt focuses on endpoint telemetry; a forensic hunt would focus specifically
    on parsing the Derby and Server logs for the 'memory:pwn' string if log deletion
    did not occur.
  relation: alternative
scenario:
  stages:
  - name: Unauthenticated Access Control Bypass
    observables:
    - CVE-2026-81578
    - Requests to PaperCut web management interface targeting administrative components
    - Exploitation of PaperCut NG or MF versions prior to 25.0.12.76497/25.0.12.76496
    slug: web-access-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Class Loading and RCE
    observables:
    - CVE-2026-82078
    - 'DB URL: jdbc:derby:memory:pwn'
    - 'File creation: lib/Udydn.class'
    - 'File creation: lib/Moo97.class'
    - pc-app.exe spawning charmap.exe
    - pc-app.exe spawning cmd.exe
    slug: class-loading-rce
    tactic: execution
    techniques:
    - T1203
    - T1106
  - name: System Profiling and Discovery
    observables:
    - 'Command: whoami & ver'
    - 'Command: whoami & ver & tasklist'
    - 'Base64 command: d2hvYW1pICYgdmVy'
    - 'Base64 command: d2hvYW1pICYgdmVyICYgdGFza2xpc3Q='
    - 'File creation: data/content/Udydn.out'
    - 'File creation: data/content/Udydn.cmd'
    slug: system-profiling
    tactic: discovery
    techniques:
    - T1033
    - T1082
    - T1057
    - T1083
  - name: Indicator Removal and Log Deletion
    observables:
    - Deletion of server.log
    - Deletion of Udydn.out
    - Java .class file self-deletion from server/lib/
    slug: defense-evasion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: Attackers chain an improper access control vulnerability (CVE-2026-81578)
    with an unsafe dynamic class-loading flaw (CVE-2026-82078) in PaperCut NG/MF to
    achieve pre-authentication RCE. Post-exploitation involves dropping malicious
    Java .class files in the application's library directory, executing system profiling
    commands via encoded strings, and deleting the server's activity logs to hide
    traces of the intrusion.
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


# PaperCut Pre-Auth RCE and System Discovery

This hunt targets the dual vulnerabilities (CVE-2026-81578 and CVE-2026-82078) in PaperCut NG and MF. It identifies vulnerable or exposed installations, then pivots to detect the execution of discovery tools (whoami, ver, tasklist) originating from the PaperCut process (pc-app.exe or java). It further corroborates these hits by searching for rare Java class files dropped in the application's library directory and the subsequent deletion of server logs, which is a reported evasion tactic used during active exploitation.

## scoping-papercut-hosts
<!-- Identify PaperCut installations -->
Identify hosts running PaperCut NG or MF to establish the target scope for behavioral analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running PaperCut software. These should be pasted into the
  'scope_hosts' parameter for subsequent steps.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%papercut%' OR LOWER(vendor_name) LIKE '%papercut%'
```

## papercut-discovery-activity
<!-- Discovery commands from PaperCut processes -->
Detect the primary post-exploitation indicator: profiling tools or encoded shell commands spawned directly from the PaperCut Application Server process.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, encoded_payloads=encoded_payloads)
~~~yaml
expected: Discovery commands running under the PaperCut service account. The presence
  of the base64 encoded strings is a high-fidelity indicator of exploitation.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%pc-app.exe%' OR LOWER(parent_process_name) LIKE '%java%') AND (LOWER(process_cmd_line) LIKE '%whoami%' OR LOWER(process_cmd_line) LIKE '%tasklist%' OR LOWER(process_cmd_line) LIKE '%ver%' OR instr(',' || '{{encoded_payloads}}' || ',', ',' || process_cmd_line || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-validation
<!-- Corroborate with artifacts and evasion -->
parallel:
- → rare-artifact-creation
- → papercut-log-evasion
join: → triage-papercut-compromise

## rare-artifact-creation
<!-- Rare file artifacts in PaperCut directories -->
Identify the malicious .class payloads or output files generated during profiling, using fleet-wide rarity as a filter.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Randomly named .class files (e.g., Udydn.class) or profile outputs (Udydn.out)
  present on a minimal number of PaperCut servers.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- file_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(file_name) AS name, file_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/server/lib/%' OR LOWER(file_path) LIKE '%\\server\\lib\\%' OR LOWER(file_path) LIKE '%/data/content/%' OR LOWER(file_path) LIKE '%\\data\content\\%') AND (LOWER(file_name) LIKE '%.class' OR LOWER(file_name) LIKE '%.out' OR LOWER(file_name) LIKE '%.cmd') AND activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY name, file_path HAVING hosts <= 3 ORDER BY hosts ASC
```

## papercut-log-evasion
<!-- PaperCut server log deletion -->
Corroborate the reported evasion tactic of the Application Server process deleting its own log file.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The server.log file being deleted by the PaperCut application process itself.
  Silence is expected in normal operations as log rotation typically renames files
  rather than deleting the active log.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 4 AND LOWER(file_name) = 'server.log' AND (LOWER(process_name) LIKE '%pc-app.exe%' OR LOWER(process_name) LIKE '%java%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-papercut-compromise
<!-- Triage PaperCut RCE indicators -->
```agent target=hunter
cite: required
context:
- scoping-papercut-hosts
- papercut-discovery-activity
- rare-artifact-creation
- papercut-log-evasion
max_iterations: 4
objective: Determine if the PaperCut Application Server has been compromised via the
  reported pre-auth RCE chain, citing evidence from process and file surfaces.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows for any non-benign results.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host, particularly where discovery commands were spawned from PaperCut processes." (confidence: high, judge=hunter)
then: → contain-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: in-memory-execution)
else: → close-out

## contain-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture the 'server/logs' directory and any files matching the anomalous pattern in 'server/lib' for forensic analysis before remediation.
```
→ analyst-review

## analyst-review
<!-- Analyst review and forensic deep-dive -->
```manual target=analyst
Review the cited rows for anomalous .class files. Check 'derby.log' for irregular database names like 'memory:pwn' or 'jdbc:derby:memory'. Confirm whether the identified hosts are running unpatched versions (v23 or below, or older builds of v24/v25).
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hosts examined. If negative, verify that PaperCut servers are scheduled for patching to Release 3 or newer to mitigate the underlying vulnerabilities.
```
→ end
