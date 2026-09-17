---
analysis: This is a hunt because it uses prevalence baselining to discover 'rare'
  packages within the specific ecosystem, rather than relying on a static list of
  known-bad indicators that attackers easily rotate. It pivots into internal GitHub
  package data to identify mirrors, a level of contextual cross-surface correlation
  that a simple rule cannot achieve.
blind_spots:
- id: limited-package-visibility
  question: Are malicious packages present in hidden or user-profile directories not
    scanned by standard inventory?
  requires: hb_software_inventory capturing sub-directories of user-level pub caches
    (~/.pub-cache)
  risk: A developer may have downloaded the package locally but not yet built a project
    that exposes it to the OS-level software list, leaving the malicious files resident
    on disk but invisible.
  stage: malicious-package-distribution
- id: transitive-dependency-blindness
  question: Is the malicious package a transitive dependency of an internally developed
    library?
  requires: recursive lockfile parsing for all projects
  risk: Software inventory might only report direct dependencies or installed binaries;
    a transitive dependency buried in a lockfile might only be seen when the build
    executes.
  stage: malicious-package-distribution
coverage:
- stage: malicious-package-distribution
  status: covered
  steps:
  - scoping-flutter-hosts
  - rare-dart-packages
  - github-mirror-anomaly-check
- reason: This behavioral stage is covered in the sibling hunt 'flutter-build-time-injection-behavior'.
  stage: build-time-injection-gradle
  status: out_of_scope
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: build-time-injection-xcode
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
  justification: The pub.dev registry compromise targets high-value developer workstations
    and automated build pipelines. Identifying these packages before they execute
    build scripts is critical for preventing secret theft and supply chain injection
    into production applications.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has introduced malicious Dart/Flutter packages into the environment,
  detectable as rare, recently added dependencies in local developer toolchains or
  internal package mirrors.
labels:
- hunt
- attack.t1195
name: Flutter Dependency Inventory Scan
parameters:
  lookback_days:
    default: '30'
    description: Days of inventory history to examine (covers the month of August/September
      activity).
    type: number
  malicious_packages:
    default:
    - universal_file_viewer
    - surveyjs_flutter
    description: Names of the confirmed affected packages used for enrichment.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-pub-dev-compromise
    type: list[string]
  malicious_versions:
    default:
    - 0.1.1
    - 0.1.2
    - 0.1.3
    - 0.1.5
    - 0.1.6
    description: Specific versions confirmed to be infected used for enrichment.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-pub-dev-compromise
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
rationale: The hunt targets any host with Dart or Flutter toolsets. The timeframe
  is critical, starting from August 12, 2026, when the first infected package was
  published.
references:
- name: 'pub.dev compromise: malicious Dart/Flutter packages'
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: flutter-build-time-injection-behavior
  reason: This hunt focuses on inventory (at rest); a sibling hunt is needed to detect
    the behavior of the Gradle/Xcode script execution.
  relation: sibling
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
  index: 1
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
  github:
    category: siem
    huntbase:
      product: github
    name: github
  hunter:
    agent: true
    name: Hunt agent
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Flutter Dependency Inventory Scan

This hunt identifies potential supply chain compromises in the Flutter ecosystem. Instead of relying solely on hardcoded blocklists, it baselines the prevalence of all Dart and Flutter packages across the fleet to highlight rare or suspicious additions. It further corroborates these findings by examining internal GitHub repositories for mirrored packages that mimic popular libraries but exhibit anomalies in visibility and creation timing. This proactive approach identifies targeted development environments before malicious build-time code executes, focusing on the infrastructure that powers the software delivery lifecycle.

## scoping-flutter-hosts
<!-- Identify Flutter development hosts -->
Scope the hunt to hosts that have any Dart or Flutter related packages installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely to be developer or build machines. Silence indicates
  no Flutter ecosystem presence.
reads:
- device_hostname
- device_uid
- package_name
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, device_uid FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%flutter%' OR LOWER(package_name) LIKE '%dart%' OR package_type IN ('pub', 'dart', 'flutter'))
```

## rare-dart-packages
<!-- Rare Dart/Flutter packages in ecosystem -->
Identify low-prevalence packages within the Dart ecosystem that may represent targeted supply chain attacks.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Packages appearing on only a few hosts. Malicious versions 0.1.1-0.1.6 of
  the target packages should appear here if present.
prevalence:
  by: device_hostname
  key:
  - package_name
  - package_version
  rare_below: 5
reads:
- collected_at
- device_hostname
- package_name
- package_type
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT package_name, package_version, vendor_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(collected_at) AS first_seen FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%flutter%' OR LOWER(package_name) LIKE '%dart%' OR package_type IN ('pub', 'dart', 'flutter')) AND collected_at >= datetime('now', '-{{lookback_days}} days') GROUP BY package_name, package_version HAVING host_count <= 5 ORDER BY host_count ASC
```

## parallel-corroboration
<!-- Corroborate with internal mirrors and inventory -->
parallel:
- → detailed-inventory-enrichment
- → github-mirror-anomaly-check
join: → triage-affected-assets

## detailed-inventory-enrichment
<!-- Detailed host inventory details -->
Provide the triage agent with specific paths and versions for every Flutter-related package on scoped hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
expected: Context for specific package locations.
reads:
- collected_at
- device_hostname
- install_path
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, install_path, vendor_name, collected_at FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%flutter%' OR LOWER(package_name) LIKE '%dart%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## github-mirror-anomaly-check
<!-- GitHub private mirror anomalies -->
Check for private internal GitHub packages that mirror popular Flutter libraries but have unusual creation dates.

```sqlite target=github role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Private internal packages mimicking public names, created during the window
  of the report. This suggests internal propagation of a malicious package.
reads:
- created_at
- name
- organization
- repository_full_name
- visibility
silence: not_evidence_of_absence
source: github_package
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT name, repository_full_name, organization, visibility, created_at FROM github_package WHERE (LOWER(name) LIKE '%flutter%' OR LOWER(name) LIKE '%dart%' OR LOWER(name) LIKE '%universal_file%' OR LOWER(name) LIKE '%surveyjs%') AND visibility = 'private' AND created_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-affected-assets
<!-- Triage affected assets -->
```agent target=hunter
cite: required
context:
- rare-dart-packages
- detailed-inventory-enrichment
- github-mirror-anomaly-check
max_iterations: 4
objective: Identify hosts where rare packages match the known malicious list ({{malicious_packages}},
  {{malicious_versions}}). Additionally, flag hosts using internal GitHub packages
  that mirror these names but were created recently. Citing inventory rows is required
  for all verdicts.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- github
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for any host or identifies a recently created internal mirror for a known-malicious package." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-package-visibility)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Preserve the .pub-cache and all local project directories for deep inspection of Vector 1 (Gradle) and Vector 2 (Xcode) artifacts.
```
→ revoke-secrets

## revoke-secrets
<!-- Revoke CI/CD and developer secrets -->
```action target=identity
~~~yaml
approval: required
~~~
Rotate or revoke all CI/CD tokens, SSH keys, and cloud provider credentials associated with the affected hosts and repositories.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Examine the pubspec.lock files for identified hosts. Check for the presence of zero-byte README.md files in the ios/ and macos/ subdirectories of active projects, and inspect build.gradle.kts for hex-encoded strings as identified in the research.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the results. If no compromise is found, update the 'known good' package list to include the identified rare libraries to reduce future noise.
```
→ end
