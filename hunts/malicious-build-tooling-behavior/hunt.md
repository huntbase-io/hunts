---
analysis: A simple detection rule might catch 'printf | tr', but this hunt pivots
  between the development ecosystem context (Flutter/Dart), the resulting file-system
  artifacts (.bak, misplaced READMEs), and the execution patterns, providing the context
  an analyst needs to distinguish between a legitimate build script and a supply chain
  injector.
blind_spots:
- id: limited-file-content-visibility
  owner: Endpoint Security
  question: Does the .pbxproj file contain the A3EA261 marker?
  remediation: Enable script block logging and ensure EDR captures full command-line
    arguments and file write events.
  requires: Deep file content inspection or EDR-captured file write buffers.
  risk: If the marker is only present inside a file and never used as a command-line
    argument or captured in script activity, we can only see that the file was modified,
    not why.
  stage: build-time-injection-xcode
coverage:
- stage: build-time-injection-gradle
  status: covered
  steps:
  - obfuscated-build-scripts
  - gradle-injection-remnants
- stage: build-time-injection-xcode
  status: covered
  steps:
  - xcode-misplaced-files
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: malicious-package-distribution
  status: out_of_scope
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: c2-script-retrieval
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt addresses a critical supply chain risk where legitimate
    developer environments are weaponized. Finding these indicators on a build machine
    protects against the theft of signing keys and production secrets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised the build environment by injecting malicious
  hooks into Gradle or Xcode configuration files, resulting in obfuscated shell execution
  during the project compilation phase.
labels:
- hunt
- attack.t1204.002
- attack.t1195.001
- attack.t1059.004
name: Malicious Build Tooling Behavior
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  xcode_marker:
    default: A3EA261
    description: Malicious build setting identifier found in Xcode projects.
    type: string
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
rationale: We focus on developer workstations and CI runners by filtering on the presence
  of Flutter or Dart SDKs in software inventory. This narrows the scope from the entire
  fleet to the assets that actually execute the targeted build scripts.
references:
- name: "OSSPREY \u2014 pub.dev compromise: malicious Dart/Flutter packages"
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: malicious-package-distribution
  reason: This hunt looks for the behavior of the injector; the distribution hunt
    looks for the presence of the malicious packages themselves.
  relation: precedes
- hunt: c2-script-retrieval
  reason: The build hooks eventually fetch C2 scripts; that behavior is covered in
    a separate network-focused hunt.
  relation: follows
- hunt: flutter-dependency-inventory-scan
  relation: follows
scenario:
  stages:
  - name: Malicious Package Publication
    observables:
    - universal_file_viewer versions 0.1.5, 0.1.6
    - surveyjs_flutter versions 0.1.1, 0.1.2, 0.1.3
    - pubspec.lock contains affected versions
    - publisher elvynforge.xyz
    slug: malicious-package-distribution
    tactic: initial-access
    techniques:
    - T1195
  - name: Gradle Build-Time Execution
    observables:
    - build.gradle.kts
    - printf xAxd | tr -d A
    - printf bdase64 | tr -d d
    - sh
    - build.gradle.bak
    slug: build-time-injection-gradle
    tactic: execution
    techniques:
    - T1204.002
  - name: Xcode Build-Rule Execution
    observables:
    - project.pbxproj
    - A3EA261 build setting
    - com.apple.compilers.proxy.script compiler spec
    - zero-byte README.md in platform subdirectories
    - PBXShellScriptBuildPhase with p=xcode_phase
    slug: build-time-injection-xcode
    tactic: execution
    techniques:
    - T1204.002
  - name: Command and Control Callback
    observables:
    - .ru domains
    - POST to /a
    - p=gradle
    - p=xcode_rule
    - p=xcode_phase
    slug: c2-script-retrieval
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: A supply chain compromise targeting the Dart/Flutter ecosystem where a
    legitimate maintainer's account was used to publish malicious versions of universal_file_viewer
    and surveyjs_flutter. These packages contained build-time hooks in Gradle and
    Xcode configuration files that executed obfuscated shell commands to fetch and
    run remote scripts, targeting developer and CI environment credentials.
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


# Malicious Build Tooling Behavior

This hunt targets the secondary stage of the pub.dev supply chain compromise where a developer's environment is used to inject malicious code into native build files (Gradle and Xcode). We look for the footprint of the injector, specifically the creation of backup files (.bak) during automated editing, the presence of anomalous README files used as Xcode build triggers, and the execution of obfuscated shell commands using printf/tr piping—a technique used to bypass simple string-based script scanners.

## flutter-dev-scoping
<!-- Identify Flutter/Dart Development Hosts -->
Identify hosts that have Flutter or Dart SDKs installed, narrowing the hunt to developer and CI machines likely to run these build scripts.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or build runners. Silence suggests
  no Flutter/Dart development is occurring in the visible estate.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%flutter%' OR LOWER(package_name) LIKE '%dart%') AND asset_scope = 'endpoint'
```

## detect-malicious-build-behavior
<!-- Detect Malicious Build Behavior -->
parallel:
- → obfuscated-build-scripts
- → gradle-injection-remnants
- → xcode-misplaced-files
join: → triage-build-activity

## obfuscated-build-scripts
<!-- Obfuscated Build Script Execution -->
Find the execution of scripts that use printf and tr to reconstruct 'xxd' or 'base64', a core indicator of the pub.dev injector.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A script block containing the specific obfuscation patterns mentioned in
  the report. This is a very high-fidelity signal for this specific injector.
reads:
- device_hostname
- actor_user_name
- script_path
- script_content
- time
silence: evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, actor_user_name, script_path, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%printf%tr%sh%' OR LOWER(script_content) LIKE '%xAxd%' OR LOWER(script_content) LIKE '%bdase64%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## gradle-injection-remnants
<!-- Gradle Injection Artifacts (.bak files) -->
Identify the artifact of the automated script that rewrote the Gradle files—specifically the .bak files left behind.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Creation or presence of a .bak file sibling to a build.gradle file. This
  indicates an automated modification occurred.
reads:
- device_hostname
- file_path
- activity_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, activity_name, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%.gradle.bak' AND time >= datetime('now', '-{{lookback_days}} days')
```

## xcode-misplaced-files
<!-- Misplaced READMEs in Xcode Platforms -->
Identify the creation of README.md files inside ios/ or macos/ subdirectories, which the report identifies as the trigger for the malicious PBXBuildRule.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: README.md files appearing in platform folders where they do not typically
  belong. A rare path across the fleet suggests a malicious injection.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/ios/readme.md' OR LOWER(file_path) LIKE '%/macos/readme.md') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path
```

## triage-build-activity
<!-- Triage Build Activity Evidence -->
```agent target=hunter
cite: required
context:
- flutter-dev-scoping
- obfuscated-build-scripts
- gradle-injection-remnants
- xcode-misplaced-files
max_iterations: 4
objective: Determine if the script activity (printf|tr) correlates with the presence
  of .bak files or misplaced README files on the same developer hosts. Pay special
  attention to the {{xcode_marker}} setting if mentioned in any file content or process
  logs.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  host, citing the specific script content or file paths.
tools:
- endpoint
```

## decision-route
<!-- Route on Triage Verdict -->
if~: "The triage verdict is malicious for at least one developer or CI machine." (confidence: high, judge=hunter)
then: → isolate-dev-machine
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-file-content-visibility)
else: → close-hunt

## isolate-dev-machine
<!-- Isolate Developer Machine -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any local AWS/GCP/GitHub credentials, and capture the .gradle and .pbxproj files for forensic analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the script contents and file paths identified by the agent. Check for the specific marker {{xcode_marker}} in project files. Validate if these are legitimate automated build processes used by the development team.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
Record the findings and note any hosts where Flutter development was confirmed but no indicators of compromise were seen.
```
→ end
