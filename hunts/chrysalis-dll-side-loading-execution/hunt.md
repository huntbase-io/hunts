---
analysis: A static rule for log.dll is easily bypassed. This hunt uses structural
  directory comparison and fleet-wide rarity to identify the core behavior of side-loading
  regardless of the DLL filename.
blind_spots:
- id: missing-module-visibility
  question: whether a module was loaded into the service process from its local folder
  requires: hb_module_activity with Sysmon EID 7
  risk: Without module load events, a side-load appears as a normal service execution,
    leaving the intrusion completely invisible.
  stage: dll-side-loading-bluetooth
- id: system32-noise
  question: if the service intentionally loads legitimate modules from non-standard
    paths
  requires: precise directory filtering
  risk: Excluding System32 is necessary but may still produce false positives if the
    application regularly uses its own path for shared libraries.
  stage: dll-side-loading-bluetooth
coverage:
- stage: dll-side-loading-bluetooth
  status: covered
  steps:
  - scoping-hosts
  - rare-module-load
- stage: malicious-loader-execution
  status: covered
  steps:
  - malicious-hash-check
  - triage-agent
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Side-loading bypasses traditional binary reputation checks and path-based
    execution policies by piggybacking on a trusted, signed service binary.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has achieved code execution by placing a malicious DLL in
  the same directory as a legitimate Bluetooth service, exploiting the search order
  to side-load code and bypass standard system directory protections.
labels:
- hunt
- attack.t1574.002
name: Chrysalis DLL Side-Loading and Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_hashes:
    default:
    - 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    description: Known-malicious hashes from the research, including the EICAR test
      hash.
    from:
      kind: article
      observed: '2026-08-04'
      ref: Elastic Security Labs
    type: list[hash]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the scope.
    type: list[host]
  service_name:
    default: bluetoothservice.exe
    description: The legitimate executable targeted for side-loading.
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on the Windows hosts named srv-win-defend-01 or similar. Ensure the
  environment has Sysmon EID 7 enabled for module load visibility.
references:
- name: "Elastic Security Labs \u2014 Benchmarking the Agentic SOC"
  url: https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc
related:
- hunt: unusual-dll-loads-by-system-services
  reason: This hunt is specific to the Chrysalis campaign; a broader hunt would cover
    all services loading from non-system directories.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: DLL Side-loading via Bluetooth Service
    observables:
    - BluetoothService.exe
    - log.dll
    - srv-win-defend-01
    slug: dll-side-loading-bluetooth
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Malicious Loader Execution
    observables:
    - log.dll
    - EICAR test file hash
    slug: malicious-loader-execution
    tactic: execution
    techniques:
    - T1574.002
  summary: The Chrysalis campaign involves a DLL side-loading attack on a Windows
    host where a legitimate Bluetooth service loads a malicious DLL. The malicious
    loader carries an EICAR test hash, enabling the evaluation of agentic SOC tools
    for alert triage, threat hunting, and automated incident response.
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


# Chrysalis DLL Side-Loading and Execution

This hunt identifies the Chrysalis side-loading pattern by searching for instances where BluetoothService.exe loads a module from its own application directory rather than a standard system path. It uses a funnel approach to scope the investigation to hosts running the target service, then fans out to compare module directory proximity and known malicious hash activity. An agent then evaluates the structural evidence of the side-load—prioritizing directory proximity over the filename—to determine the final verdict.

## scoping-hosts
<!-- Scope hosts running the service -->
Identify hosts where the targeted Bluetooth service is active to focus the hunt.

```sqlite target=endpoint role=scoping params=(service_name=service_name, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts where the Bluetooth service is running. If empty, the service
  is not active in the scope.
reads:
- device_hostname
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, process_path, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%{{service_name}}' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## side-loading-fan-out
<!-- Fan-out for behavioral and indicator evidence -->
parallel:
- → rare-module-load
- → malicious-hash-check
join: → triage-agent

## rare-module-load
<!-- Analyze directory-proximity module loads -->
Find modules loaded from the same directory as the service, excluding standard Windows system paths.

```sqlite target=endpoint role=detection-candidate params=(service_name=service_name, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A module loaded from the same application folder as BluetoothService.exe.
  Rarity across the fleet increases suspicion.
prevalence:
  by: device_hostname
  key:
  - module_name
  - module_path
  rare_below: 3
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
SELECT device_hostname, process_name, module_path, module_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_module_activity WHERE LOWER(process_name) LIKE '%{{service_name}}' AND REPLACE(LOWER(module_path), LOWER(module_name), '') = REPLACE(LOWER(process_name), LOWER('{{service_name}}'), '') AND LOWER(module_path) NOT LIKE 'c:\windows\system32\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING hosts <= 3
```

## malicious-hash-check
<!-- Enrich with known malicious hashes -->
Check if any files touched on the scoped hosts match reported malicious indicators like the EICAR test hash.

```sqlite target=endpoint role=enrichment params=(malicious_hashes=malicious_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File activity matching known malicious hashes. This confirms the presence
  of the expected loader.
reads:
- device_hostname
- file_hash_sha256
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, file_hash_sha256, time FROM hb_file_activity WHERE instr(',' || '{{malicious_hashes}}' || ',', ',' || LOWER(file_hash_sha256) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze side-loading evidence -->
```agent target=hunter
cite: required
context:
- scoping-hosts
- rare-module-load
- malicious-hash-check
max_iterations: 4
objective: Determine if BluetoothService.exe has been subverted via side-loading.
  Prioritize the 'directory proximity' of the DLL to the executable as the primary
  evidence; treat the specific filename (e.g. log.dll) as secondary. Corroborate with
  any matching malicious hashes found in the environment.
success_criteria: A verdict for every host that identifies the specific file and justifies
  the side-loading conclusion.
tools:
- endpoint
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on directory-proximity loading" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-task
unavailable: → forensic-task (blind_spot: missing-module-visibility)
else: → documentation-task

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the directory containing the suspected side-loaded DLL for forensic collection.
```
→ forensic-task

## forensic-task
<!-- Forensic verification -->
```manual target=analyst
Manually verify the directory content for BluetoothService.exe. Confirm whether an unauthorized DLL exists in the same folder and extract its hash for cross-referencing.
```
→ documentation-task

## documentation-task
<!-- Documentation and close out -->
```manual target=analyst
Log the examined hosts and findings. If a side-load was confirmed, recommend a detection rule for directory-proximity module loads from non-system paths.
```
→ end
