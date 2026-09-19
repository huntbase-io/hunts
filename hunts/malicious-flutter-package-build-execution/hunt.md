---
analysis: A simple rule for elvynforge.xyz is noisy; the hunt correlates the resolution
  specifically back to the 'gradle' or 'xcode' build process and the local presence
  of specific package versions, providing a behavioral context rules lack.
blind_spots:
- id: limited-process-attribution
  question: Which process initiated the C2 callback if network activity is only visible
    at the firewall level?
  requires: hb_network_connection with process_name
  risk: Without endpoint process context, it is difficult to distinguish malicious
    build-time execution from unrelated traffic.
  stage: c2-obfuscated-callback
- id: user-level-pub-cache
  question: Are malicious packages present in the local cache but not yet used in
    a build?
  requires: Inventory scan of ~/.pub-cache/
  risk: Malicious versions sitting in the cache are a 'latent' threat that inventory
    scans of system paths will miss.
  stage: initial-access-malicious-dependency
coverage:
- stage: initial-access-malicious-dependency
  status: covered
  steps:
  - identify-malicious-package-presence
  - github-package-mirror-check
- stage: c2-obfuscated-callback
  status: covered
  steps:
  - c2-dns-callback
  - build-process-network-callback
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: execution-build-tooling-hook
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The compromise of pub.dev packages allows for the exfiltration of
    high-value CI secrets and developer credentials via native build hooks. A negative
    result across the build estate is a critical assurance.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised a Flutter package maintainer to inject build-time
  RCE, resulting in developer or CI machines downloading malicious dependencies and
  beaconing to C2 during the build process.
labels:
- hunt
- attack.t1195
- attack.t1090.003
- attack.t1190
- attack.t1204.002
name: Malicious Flutter Package Build Execution
parameters:
  build_files:
    default:
    - build.gradle
    - project.pbxproj
    - build.gradle.kts
    - binding.gyp
    - build.rs
    description: Sensitive build configuration files targeted by the injector.
    type: list[string]
  build_tools:
    default:
    - gradle
    - xcodebuild
    - dart
    - flutter
    - sh
    - bash
    - python
    description: Processes expected to initiate build-time activity.
    type: list[string]
  c2_domains:
    default:
    - elvynforge.xyz
    description: C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-pub-dev
    type: list[domain]
  lookback_days:
    default: '30'
    description: Days of history to examine.
    type: number
  malicious_packages:
    default:
    - universal_file_viewer
    - surveyjs_flutter
    description: Infected package names from the report.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-pub-dev
    type: list[string]
  malicious_versions:
    default:
    - 0.1.5
    - 0.1.6
    - 0.1.1
    - 0.1.2
    - 0.1.3
    description: Compromised versions associated with the report.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-pub-dev
    type: list[string]
  scope_hosts:
    default: []
    description: Limit to CI runners or developer subnets.
    type: list[host]
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
rationale: Target CI runners and macOS/Linux workstations where Flutter development
  occurs. Start with hosts appearing in hb_software_inventory.
references:
- name: "OSSPREY \u2014 pub.dev compromise: malicious Dart/Flutter packages"
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: npm-pypi-supply-chain-generic
  reason: This hunt is specifically tuned for Flutter/Xcode/Gradle artifacts; generic
    hunts may miss these native hooks.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious Dependency Injection
    observables:
    - universal_file_viewer versions 0.1.5, 0.1.6
    - surveyjs_flutter versions 0.1.1, 0.1.2, 0.1.3
    - pubspec.lock
    slug: initial-access-malicious-dependency
    tactic: initial-access
    techniques:
    - T1195
  - name: Build-Time Hook Execution
    observables:
    - build.gradle.kts
    - project.pbxproj
    - printf xAxd | tr -d A
    - printf bdase64 | tr -d d
    - PBXBuildRule with filePatterns = "*.md"
    - Build setting A3EA261
    slug: execution-build-tooling-hook
    tactic: execution
    techniques:
    - T1204.002
  - name: Obfuscated C2 Communication
    observables:
    - elvynforge.xyz
    - HTTP POST to /a
    - POST body p=gradle_hook
    - POST body p=xcode_rule
    slug: c2-obfuscated-callback
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: A supply chain attack targeting the pub.dev ecosystem weaponized legitimate
    Flutter packages to inject malicious build-time hooks for Android and Apple platforms.
    The malware executes during development or CI builds, using obfuscated Gradle
    and Xcode build rules to fetch and execute remote shell scripts from C2 infrastructure.
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
  github:
    category: siem
    huntbase:
      product: github
    name: github
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


# Malicious Flutter Package Build Execution

This hunt targets a supply chain attack involving the pub.dev ecosystem. Malicious code was injected into legitimate Flutter packages (universal_file_viewer and surveyjs_flutter) specifically targeting build files like build.gradle and Xcode project files. This allows execution on developer machines and CI runners where high-value secrets reside. The hunt identifies affected package versions in local inventory, monitors for unauthorized build file modifications, and corroborates through DNS and HTTP activity filtered by build-system process attribution.

## identify-malicious-package-presence
<!-- Find malicious package versions in inventory -->
Identify hosts that have specifically compromised versions of the targeted Flutter packages.

```sqlite target=endpoint role=scoping params=(malicious_packages=malicious_packages, malicious_versions=malicious_versions, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts with malicious package versions in their inventory. Silence suggests
  no managed installation of these versions.
reads:
- device_hostname
- package_name
- package_version
- install_path
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, install_path, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{malicious_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0) AND (instr(',' || '{{malicious_versions}}' || ',', ',' || package_version || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## unauthorized-build-file-modifications
<!-- Unauthorized modifications to sensitive build files -->
Search for modifications to build configuration files occurring outside of expected version control patterns or by rare processes.

```sqlite target=endpoint role=baseline params=(build_files=build_files, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process modifying build files. Legitimate CI tools or editors should
  be high frequency; injector activity is additive and rare.
prevalence:
  by: device_hostname
  key:
  - process_name
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, process_name, COUNT(*) AS modifications, MIN(time) AS first_mod FROM hb_file_activity WHERE instr(',' || '{{build_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND activity_id IN (1, 3, 5) AND LOWER(process_name) NOT LIKE '%git%' AND LOWER(process_name) NOT LIKE '%vscode%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, file_name, process_name HAVING modifications < 10
```

## corroboration-stream
<!-- Corroborate Network and Mirror Signals -->
parallel:
- → c2-dns-callback
- → build-process-network-callback
- → github-package-mirror-check
join: → triage-malicious-builds

## c2-dns-callback
<!-- C2 DNS activity for known domains -->
Identify resolution attempts to the elvynforge.xyz domain.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries to elvynforge.xyz. If from a build process, it confirms the
  RCE execution.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## build-process-network-callback
<!-- C2 Network connections from build tools -->
Incorporate process attribution to filter for traffic originating from build tools to the C2 infrastructure.

```sqlite target=network role=detection-candidate params=(c2_domains=c2_domains, build_tools=build_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Network connections from build tools (gradle, xcodebuild) to elvynforge.xyz.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_ip) || ',') > 0) AND (instr(',' || '{{build_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## github-package-mirror-check
<!-- Check internal GitHub mirrors for packages -->
Verify if internal repositories have mirrored the malicious versions.

```sqlite target=github role=baseline params=(malicious_packages=malicious_packages)
~~~yaml
expected: The presence of compromised package names in the internal GitHub. Versions
  should be checked manually if hits occur.
reads:
- name
- package_type
- repository_full_name
- organization
- updated_at
silence: evidence_of_absence
source: github_package
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT name, package_type, repository_full_name, organization, updated_at FROM github_package WHERE (instr(',' || '{{malicious_packages}}' || ',', ',' || LOWER(name) || ',') > 0)
```

## triage-malicious-builds
<!-- Triage build-time compromise -->
```agent target=hunter
cite: required
context:
- identify-malicious-package-presence
- unauthorized-build-file-modifications
- c2-dns-callback
- build-process-network-callback
- github-package-mirror-check
max_iterations: 4
objective: Confirm which hosts have malicious packages AND corroborating network/file
  activity. Focus on the 'gradle' or 'xcodebuild' process context for network callbacks.
success_criteria: A per-host verdict of malicious | suspicious with cited rows.
tools:
- endpoint
- github
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on process-attributed network callbacks" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-process-attribution)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any GitHub or Cloud tokens stored on it, and investigate the ~/.pub-cache/ for malicious artifacts.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the matches between software inventory, unauthorized file mods, and process-attributed network activity. Confirm if the 'gradle' or 'xcodebuild' process initiated the elvynforge.xyz DNS/Network resolution.
```
→ end
