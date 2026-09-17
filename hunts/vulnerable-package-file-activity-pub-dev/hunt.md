---
analysis: A simple rule might find a specific package, but this hunt uses three surfaces
  to confirm ingestion, looks for the behavioral fingerprint of the injection (suspicious
  README location), and stack-counts process activity on lockfiles to find the injector
  itself across the entire developer fleet.
blind_spots:
- id: file-content-visibility
  question: What specifically was written to the build files?
  requires: hb_script_activity or endpoint forensics
  risk: The hunt knows a file was modified, but cannot read the 'A3EA261' string or
    'printf' obfuscation from the file activity log alone.
  stage: build-file-tampering
- id: file-activity-logging-gap
  question: Did the package execute its injection script?
  requires: EDR logging on all developer endpoints
  risk: If file-system activity for the user's home directory (where pub caches live)
    is not logged, the tampering stage will be invisible.
  stage: build-file-tampering
coverage:
- stage: supply-chain-ingestion
  status: covered
  steps:
  - check-for-infected-packages
  - pubspec-lock-prevalence
- stage: build-file-tampering
  status: covered
  steps:
  - suspicious-platform-readme-creation
  - native-build-script-tampering
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: obfuscated-build-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
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
  justification: Software supply chain attacks on developer workstations provide high-privilege
    access to internal codebases and cloud environments. A negative result confirms
    that these specific malicious packages have not touched the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries have compromised developer workstations by distributing infected
  Flutter packages that modify native build configuration files to achieve persistence
  and code execution.
labels:
- hunt
- attack.t1195.002
- attack.t1204.002
name: 'Vulnerable Package and File Activity: pub.dev Compromise'
parameters:
  lookback_days:
    default: '30'
    description: Days of history to examine, covering the window since August 12th.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: incident-report
    type: number
  malicious_packages:
    default:
    - universal_file_viewer
    - surveyjs_flutter
    description: Names of the compromised packages.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-blog
    type: list[string]
  vulnerable_versions:
    default:
    - 0.1.1
    - 0.1.2
    - 0.1.3
    - 0.1.5
    - 0.1.6
    description: Affected versions of the packages.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-blog
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
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize machines belonging to mobile development teams and CI/CD runners.
  Focus on systems where platform is darwin or linux, as these are the primary targets
  for Flutter build tampering.
references:
- name: 'pub.dev compromise: malicious Dart/Flutter packages'
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: obfuscated-build-execution-pub-dev
  reason: This hunt finds the artifacts; the next hunt finds the shell execution and
    C2 activity that results from them.
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
  index: 1
  slug: pub-dev-compromise-malicious-dart-flutter-packages
  title: 'pub.dev compromise: malicious Dart/Flutter packages'
  total: 3
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


# Vulnerable Package and File Activity: pub.dev Compromise

This hunt identifies the presence of malicious Flutter packages (universal_file_viewer and surveyjs_flutter) and looks for characteristic tampering of native build files. It focuses on the ingestion and tampering stages where malicious packages land on a filesystem and immediately rewrite Gradle or Xcode project files. The hunt pivots from package inventory to file-system activity to find zero-byte README files and modifications to build scripts that are outside of standard developer workflows.

## check-for-infected-packages
<!-- Inventory check for infected packages -->
Identify hosts that have the specific malicious packages and versions installed in their local environments or CI caches.

```sqlite target=endpoint role=scoping params=(malicious_packages=malicious_packages, vulnerable_versions=vulnerable_versions)
~~~yaml
expected: Rows containing the device name and version. Silence means no enrolled host
  has these versions in their inventory, providing high confidence of absence if inventory
  coverage is broad.
reads:
- device_hostname
- package_name
- package_version
- install_path
- vendor_name
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path, vendor_name FROM hb_software_inventory WHERE instr(',' || '{{malicious_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 AND instr(',' || '{{vulnerable_versions}}' || ',', ',' || package_version || ',') > 0
```

## parallel-verification
<!-- Verify file artifacts and prevalence -->
parallel:
- → suspicious-platform-readme-creation
- → native-build-script-tampering
- → pubspec-lock-prevalence
join: → triage-evidence

## suspicious-platform-readme-creation
<!-- Suspicious README creation in platform directories -->
The attack creates zero-byte README.md files in ios/ or macos/ subdirectories to trigger custom Xcode build rules.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: README.md files in platform-specific folders where they do not belong. This
  is a high-fidelity behavioral indicator.
reads:
- device_hostname
- file_path
- process_name
- time
- activity_id
- file_name
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'readme.md' AND (LOWER(file_path) LIKE '%/ios/%' OR LOWER(file_path) LIKE '%/macos/%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## native-build-script-tampering
<!-- Tampering of native build scripts -->
Identify writes to critical build configuration files that occurred during the vulnerability window by non-standard processes.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: File modification events on build scripts. Filtering standard tools highlights
  anomalous injectors.
reads:
- device_hostname
- file_name
- file_path
- process_name
- parent_process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_name, file_path, process_name, parent_process_name, time FROM hb_file_activity WHERE (LOWER(file_name) IN ('build.gradle.kts', 'project.pbxproj', 'pubspec.lock')) AND activity_id IN (1, 3) AND LOWER(process_name) NOT IN ('flutter', 'dart', 'git', 'xcodebuild', 'xcode') AND time >= datetime('now', '-{{lookback_days}} days')
```

## pubspec-lock-prevalence
<!-- Rare processes modifying pubspec.lock -->
Identify anomalous processes modifying package lockfiles, which might indicate an automated injector or shell script rewriting dependencies.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare processes that touched pubspec.lock. Standard tools should
  be fleet-wide; a custom injector will be rare.
prevalence:
  by: device_hostname
  key:
  - process
  rare_below: 3
reads:
- process_name
- device_hostname
- time
- file_name
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_name) AS process, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_name) = 'pubspec.lock' AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING host_count <= 2
```

## triage-evidence
<!-- Triage build tampering and package presence -->
```agent target=hunter
cite: required
context:
- check-for-infected-packages
- suspicious-platform-readme-creation
- native-build-script-tampering
- pubspec-lock-prevalence
max_iterations: 4
objective: Determine if any host with the malicious packages also shows evidence of
  native build script tampering or the characteristic zero-byte README files.
success_criteria: A verdict of infected if package presence and file artifacts coincide;
  high-risk if package presence is found but file artifacts are missing.
tools:
- endpoint
```

## decision-route
<!-- Route on infection verdict -->
if~: "The triage verdict for any host is 'infected' or 'high-risk'." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: file-activity-logging-gap)
else: → close-out

## isolate-host
<!-- Isolate high-risk machine -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture a forensic image and collect the build.gradle.kts and project.pbxproj files for manual inspection of hidden payloads.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual inspection of build files -->
```manual target=analyst
Examine the files cited by the agent. Look for 'PBXBuildRule' claiming '*.md' and the 'A3EA261' build setting in Xcode projects, or the printf/xxd obfuscated hooks in Gradle files. Rotate all credentials (SSH, AWS, Git) used on this machine.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the findings. If clean, no further action is required until the next periodic run. If infected, ensure credentials have been rotated.
```
→ end
