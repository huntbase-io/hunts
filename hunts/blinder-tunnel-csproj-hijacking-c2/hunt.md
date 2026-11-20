---
analysis: A standard rule might flag MSBuild, but this hunt connects staged binary
  renaming, rare execution from AppData, and GitHub C2 in a phased story that requires
  an analyst to weigh correlated evidence.
blind_spots:
- id: config-content-visibility
  question: Whether the config file contains the specific ETW-disabling XML tags
  requires: Endpoint telemetry with file content inspection
  risk: The hunt detects file creation but cannot verify malicious content without
    manual review.
  stage: stage-t1574-002
- id: github-api-uri
  question: Whether GitHub connections target specific malicious repositories versus
    general usage
  requires: Network proxy logs with full URI granularity
  risk: GitHub is common in developer environments; without URI-level logs, process
    context is the only discriminator.
  stage: stage-t1041
coverage:
- stage: stage-t1041
  status: covered
  steps:
  - github-api-c2
- reason: The campaign uses social engineering phishing lures rather than exploitation
    of public-facing applications.
  stage: stage-t1190
  status: out_of_scope
- reason: Malicious code delivery occurs via a weaponized archive in phishing, not
    a hijacked software update stream.
  stage: stage-t1195-002
  status: out_of_scope
- reason: Initial phishing delivery via email or external communication is not visible
    on the provided endpoint surfaces.
  stage: stage-t1566
  status: not_visible
- stage: stage-t1572
  status: covered
  steps:
  - chisel-execution
- stage: stage-t1574-002
  status: covered
  steps:
  - msbuild-file-staging
  - runtime-broker-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Blinder Tunnel campaign targets critical infrastructure via engineers.
    Identifying staged execution-hijack files early prevents the establishment of
    persistent tunneling bridges.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has delivered a weaponized Visual Studio project that uses
  MSBuild to stage malicious binaries into a local appdata path and initiate an AppDomainManager
  hijack for command-and-control.
labels:
- hunt
- attack.t1574.002
- attack.t1041
- attack.t1572
- attack.t1195.002
- attack.t1566
name: Blinder Tunnel .csproj Hijacking and C2
parameters:
  github_domains:
    default:
    - github.com
    - api.github.com
    - raw.githubusercontent.com
    description: GitHub domains used for C2 communication and payload retrieval.
    from:
      kind: article
      observed: '2026-10-06'
      ref: unit42-blinder-tunnel
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to hunt across
      the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers and workstations with developer tools like Visual Studio
  or MSBuild. Widen if MSBuild activity is observed on hosts not labeled as developer
  workstations.
references:
- name: "Unit 42 \u2014 Blinder Tunnel Campaign Targets Iraqi Infrastructure"
  url: https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
related:
- hunt: github-api-malware-delivery
  reason: This hunt focuses on the .csproj infection chain; general GitHub abuse for
    delivery is a broader topic.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: T1041
    slug: stage-t1041
    tactic: unknown
    techniques:
    - T1041
  - name: T1190
    slug: stage-t1190
    tactic: unknown
    techniques:
    - T1190
  - name: T1195.002
    slug: stage-t1195-002
    tactic: unknown
    techniques:
    - T1195.002
  - name: T1566
    slug: stage-t1566
    tactic: unknown
    techniques:
    - T1566
  - name: T1572
    slug: stage-t1572
    tactic: unknown
    techniques:
    - T1572
  - name: T1574.002
    slug: stage-t1574-002
    tactic: unknown
    techniques:
    - T1574.002
  summary: Blinder Tunnel Campaign Targets Iraqi Infrastructure
severity: medium
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Blinder Tunnel .csproj Hijacking and C2

The adversary targets software engineers with weaponized Visual Studio projects to gain a foothold in critical infrastructure. This hunt starts by finding developer workstations where MSBuild has been manipulated to create files in non-standard subdirectories of the Local AppData folder. It analyzes the execution of renamed binaries from these directories and correlates them with follow-on GitHub API traffic or Chisel tunneling. An agent weighs these phased results, and an analyst confirms the suppression of event tracing.

## developer-workstation-scoping
<!-- Identify developer workstations -->
Focus the hunt on hosts with Visual Studio or MSBuild, as these are the primary targets for weaponized project files.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to software engineers or developers. Silence
  means the estate lacks standard developer tooling.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-07'
~~~
SELECT DISTINCT device_hostname, package_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%visual studio%' OR LOWER(package_name) LIKE '%msbuild%'
```

## early-stage-parallel
<!-- Parallel: Staging and Rare Execution -->
parallel:
- → msbuild-file-staging
- → runtime-broker-prevalence
join: → early-stage-triage

## msbuild-file-staging
<!-- MSBuild writing to AppData subfolders -->
Identify instances where msbuild.exe creates files in the non-standard RuntimeBrokers path as specified in the report.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of RuntimeBroker.exe, RuntimeBroker.exe.config, or RuntimeBroker.dll
  in a local appdata folder by MSBuild.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-07'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(process_name) LIKE '%msbuild.exe' AND LOWER(file_path) LIKE '%\microsoft\runtimebrokers\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## runtime-broker-prevalence
<!-- Rare RuntimeBroker execution from AppData -->
Identify the execution of RuntimeBroker.exe from the non-standard Local AppData path used by the hijack.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary named RuntimeBroker.exe running from a user's Local AppData folder.
  Silence suggests no such hijack has occurred.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 5
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-07'
~~~
SELECT process_path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS run_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\microsoft\runtimebrokers\runtimebroker.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path HAVING host_count <= 5 ORDER BY host_count ASC
```

## early-stage-triage
<!-- Early Stage Triage -->
```agent target=hunter
cite: required
context:
- msbuild-file-staging
- runtime-broker-prevalence
max_iterations: 3
objective: Identify hosts where MSBuild staged files in the RuntimeBrokers path followed
  by execution of RuntimeBroker.exe from that same location.
success_criteria: A list of compromised hosts with a verdict of suspicious or malicious.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Parallel: C2 and Tunneling -->
parallel:
- → github-api-c2
- → chisel-execution
join: → follow-on-triage

## github-api-c2
<!-- Network connections to GitHub API -->
Identify process-led connections to GitHub domains from the suspected hijacked process.

```sqlite target=network role=enrichment params=(github_domains=github_domains, lookback_days=lookback_days)
~~~yaml
expected: The suspicious RuntimeBroker process communicating with GitHub API domains.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-07'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, time FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%\microsoft\runtimebrokers\%' OR LOWER(process_name) = 'runtimebroker.exe') AND instr(',' || '{{github_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## chisel-execution
<!-- Chisel execution and command lines -->
Search for the open-source Chisel tunneling tool used for persistent access.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Processes executing with Chisel-specific tunneling arguments. Silence means
  no active tunneling bridge was observed.
reads:
- device_hostname
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-07'
~~~
SELECT device_hostname, process_path, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%chisel%' OR LOWER(process_cmd_line) LIKE '%chisel%' OR LOWER(process_cmd_line) LIKE '%client %:% %R:%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Follow-on Analysis -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- github-api-c2
- chisel-execution
max_iterations: 5
objective: Determine if hosts with suspicious RuntimeBroker execution also exhibit
  GitHub-based C2 or Chisel tunneling.
success_criteria: A verdict of malicious citing the progression from staging to network
  persistence.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: config-content-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host. Collect contents of the %LOCALAPPDATA%\Microsoft\RuntimeBrokers directory for analysis.
```
→ remediation-review

## remediation-review
<!-- Remediation and analyst review -->
```manual target=analyst
Review cited rows. Confirm presence of RuntimeBroker.exe.config and verify if the etwEnable flag is disabled. Examine user downloads for Dubai Airport recruitment archives.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document hosts examined, results of file/process checks, and any evidence of C2 activity.
```
→ end
