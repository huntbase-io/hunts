---
analysis: A single detection rule might catch the specific 'printf xAxd' string, but
  this hunt combines package presence, rare parent-child relationships for build tools,
  and file-system artifacts into a single decision that covers both Android and iOS
  vectors.
blind_spots:
- id: missing-process-telemetry
  question: Was the 'printf' command executed?
  requires: hb_process_activity with command line arguments
  risk: If the endpoint agent does not capture full command lines for short-lived
    shell processes, the primary marker for the Gradle hook will be missed.
  stage: obfuscated-build-execution
- id: ephemeral-tmp-files
  question: Did the /tmp/.out file exist and then get deleted?
  requires: hb_file_activity real-time monitoring
  risk: Malicious build rules may delete their temporary artifacts immediately after
    execution, leaving no trace for snapshots.
  stage: obfuscated-build-execution
coverage:
- stage: obfuscated-build-execution
  status: covered
  steps:
  - obfuscated-shell-execution
  - suspicious-build-artifacts
  - rare-build-children
- reason: Handled in sibling hunt focusing on package management logs and pubspec.lock.
  stage: supply-chain-ingestion
  status: out_of_scope
- reason: Handled in sibling hunt focusing on registry and file changes to project
    metadata.
  stage: build-file-tampering
  status: out_of_scope
- reason: Handled in sibling hunt focusing on the .ru C2 domains and network connections.
  stage: c2-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Supply chain attacks in the Flutter ecosystem are a new and emerging
    threat. This hunt provides assurance that current build pipelines haven't been
    weaponized by the reported malicious packages, protecting sensitive credentials
    and signing keys.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing code during the build phase of a Flutter project
  by using obfuscated shell commands (printf/tr/sh) or malicious Xcode build rules
  to bypass static source analysis.
labels:
- hunt
- attack.t1204.002
- attack.t1059.004
- attack.t1195.001
name: Obfuscated Build Process Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of process and script history to examine.
    type: number
  target_packages:
    default:
    - universal_file_viewer
    - surveyjs_flutter
    description: Specific malicious packages identified in the report.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.ossprey.com/blog/pub-dev-compromise
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.ossprey.com/blog/pub-dev-compromise
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize CI/CD runners and developer workstations where
  Flutter/Dart packages are routinely built. The initial scoping query targets these
  environments.
references:
- name: 'pub.dev compromise: malicious Dart/Flutter packages'
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: supply-chain-ingestion-pub-dev
  reason: This hunt focuses on the execution phase; ingestion (downloading the package)
    is handled by a separate sibling hunt.
  relation: out-of-scope-alternative
- hunt: build-file-tampering-flutter
  reason: Detecting the modification of Gradle/Xcode project files on disk is out
    of scope here.
  relation: out-of-scope-alternative
- hunt: vulnerable-package-file-activity-pub-dev
  relation: follows
scenario:
  stages:
  - name: Malicious Package Ingestion
    observables:
    - universal_file_viewer version 0.1.5
    - universal_file_viewer version 0.1.6
    - surveyjs_flutter version 0.1.1
    - surveyjs_flutter version 0.1.2
    - surveyjs_flutter version 0.1.3
    - pubspec.lock
    slug: supply-chain-ingestion
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Native Build Script Injection
    observables:
    - example/android/app/build.gradle.kts
    - example/ios/Runner.xcodeproj/project.pbxproj
    - PBXBuildRule
    - A3EA261 build setting
    - zero-byte README.md in platform subdirectories
    - com.apple.compilers.proxy.script
    slug: build-file-tampering
    tactic: persistence
    techniques:
    - T1195.002
  - name: Build-Time Code Execution
    observables:
    - printf xAxd | tr -d A
    - printf bdase64 | tr -d d
    - sh execution during gradle build
    - sh execution via PBXBuildRule
    - /tmp/${INPUT_FILE_BASE}.out
    slug: obfuscated-build-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1059.004
  - name: C2 Domain Communication
    observables:
    - .ru TLD domains
    - POST /a
    - body containing p=xcode_rule
    - body containing p=gradle
    - body containing p=xcode_phase
    slug: c2-exfiltration
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  summary: A supply chain attack on the pub.dev registry where legitimate Flutter
    packages were weaponised by injecting malicious code into native Gradle and Xcode
    build files. The malware executes during the build process on developer or CI
    machines, fetching and executing remote shell scripts from attacker-controlled
    domains to compromise credentials and environment secrets.
series:
  index: 2
  slug: pub-dev-compromise-malicious-dart-flutter-packages
  title: 'pub.dev compromise: malicious Dart/Flutter packages'
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


# Obfuscated Build Process Execution

This hunt targets the execution phase of the pub.dev supply chain compromise. It looks for the characteristic 'printf | tr | sh' obfuscation pattern used in Gradle build hooks and the creation of temporary artifacts in /tmp associated with malicious Xcode PBXBuildRules. By examining process lineage and script content, we can identify build-time RCE even when the initial package ingestion was trusted.

## identify-flutter-dev-hosts
<!-- Identify Flutter development hosts -->
Scope the hunt to hosts that have the affected packages installed or are known Flutter development environments.

```sqlite target=endpoint role=scoping params=(target_packages=target_packages)
~~~yaml
expected: A list of hostnames potentially at risk. Silence indicates no development
  environment matches, suggesting low exposure.
reads:
- device_hostname
- install_path
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (instr(',' || '{{target_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%flutter%' OR LOWER(package_name) LIKE '%dart%')
```

## build-execution-patterns
<!-- Examine execution patterns -->
parallel:
- → obfuscated-shell-execution
- → suspicious-build-artifacts
- → rare-build-children
join: → triage-build-execution

## obfuscated-shell-execution
<!-- Obfuscated shell execution (printf | tr | sh) -->
Identify the characteristic 'printf | tr | sh' pattern used to hide xxd or base64 decoders during Gradle builds.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process command line containing 'printf' piped into 'tr' and then 'sh'.
  This is a high-fidelity indicator of the reported Gradle hook.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%printf%|%tr%|%sh%' OR LOWER(process_cmd_line) LIKE '%printf%|%tr%|%bash%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-build-artifacts
<!-- Suspicious /tmp artifacts from build rules -->
Find artifacts in /tmp that follow the naming convention ${INPUT_FILE_BASE}.out used by the malicious Xcode build rules.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Creation of .out files in /tmp by build-related processes, specifically
  targeting the artifacts of the PBXBuildRule exploit.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '/tmp/%.out' AND (LOWER(process_name) LIKE '%xcode%' OR LOWER(process_name) LIKE '%sh%' OR LOWER(process_name) LIKE '%bash%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-build-children
<!-- Rare processes spawned by build tools -->
Baseline normal build behavior to find rare shell execution or network tools spawned by Java (Gradle) or Xcode.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Rare shell commands or network fetches originating from Gradle or Xcode.
  Normal builds have frequent, repeated commands; one-off fetches are suspicious.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_cmd_line) as cmd, COUNT(DISTINCT device_hostname) as host_count FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%java%' OR LOWER(parent_process_name) LIKE '%xcode%') AND (LOWER(process_name) LIKE '%sh' OR LOWER(process_name) LIKE '%bash' OR LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING host_count < 3
```

## triage-build-execution
<!-- Triage build execution evidence -->
```agent target=hunter
cite: required
context:
- identify-flutter-dev-hosts
- obfuscated-shell-execution
- suspicious-build-artifacts
- rare-build-children
max_iterations: 3
objective: Determine if the observed process and file activity constitutes malicious
  build-time execution associated with the pub.dev compromise.
success_criteria: Confirm RCE by finding the obfuscated command pattern on a host
  where an affected package is also present.
tools:
- endpoint
```

## decision-route
<!-- Decision on Build Compromise -->
if~: "The triage verdict is malicious and finds the printf/tr/sh pattern on a host with a target package." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: missing-process-telemetry)
else: → close-hunt

## isolate-host
<!-- Isolate Host and Revoke Credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all CI/CD tokens and cloud credentials stored on this machine, as they are considered compromised by the build-time RCE.
```
→ analyst-triage

## analyst-triage
<!-- Detailed Analyst Triage -->
```manual target=analyst
Inspect the file system for the zero-byte README.md files mentioned in the report and check hb_script_activity for decoded base64/xxd output.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
Record the absence of build-time RCE markers across the Flutter development estate.
```
→ end
