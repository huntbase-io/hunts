---
analysis: This hunt is superior to a single rule because it pivots between host inventory
  and behavioural prevalence. A single rule targeting the rotating C2 domains would
  fail as the attacker updates their infrastructure, but the hunt identifies the durable
  pattern of obfuscated shell execution originating from build tools.
blind_spots:
- id: ci-runner-ephemerality
  owner: Cloud Infrastructure
  question: whether ephemeral CI runners executed the build and terminated before
    inventory was captured
  remediation: Implement real-time package monitoring or log pubspec.lock file touches.
  requires: hb_software_inventory snapshot persistence
  risk: A malicious build could execute on a short-lived runner, exfiltrate credentials,
    and disappear without being recorded in the inventory surface.
  stage: initial-access-supply-chain-registry
- id: xcode-project-file-visibility
  owner: Security Engineering
  question: whether the malicious PBXBuildRule exists in the project configuration
    without the script executing
  remediation: Deploy a scanner to audit project.pbxproj files for unauthorized script
    build phases.
  requires: hb_file_activity with file content inspection
  risk: We can only see the execution of the script, not the latent build configuration
    itself, via current behavioral surfaces.
  stage: execution-native-build-injection
- id: no-dns-logging
  owner: Endpoint Engineering
  question: whether the C2 callback occurred on hosts missing DNS telemetry
  remediation: Ensure the endpoint agent is deployed with network monitoring to all
    developer machines.
  requires: hb_dns_activity from developer hosts
  risk: We rely on DNS to confirm the rotating .ru domains; if telemetry is missing,
    we may miss the callback confirmation.
  stage: c2-rotating-domain-callback
coverage:
- stage: initial-access-supply-chain-registry
  status: covered
  steps:
  - find-affected-packages
- stage: execution-native-build-injection
  status: covered
  steps:
  - rare-process-baseline
  - build-script-activity
- stage: c2-rotating-domain-callback
  status: covered
  steps:
  - c2-dns-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Supply chain attacks against trusted maintainers bypass reputation-based
    filters; confirming the absence of these malicious build hooks protects high-value
    credentials in development pipelines.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised developer and CI environments by injecting
  malicious Flutter packages that execute obfuscated shell scripts during native Android
  or iOS builds.
labels:
- hunt
- attack.t1195
- attack.t1190
- attack.t1204.002
- attack.t1090.003
name: Flutter Supply Chain Build Execution
parameters:
  affected_packages:
    default:
    - universal_file_viewer
    - surveyjs_flutter
    description: Names of the compromised Flutter packages.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-blog
    type: list[string]
  c2_domains:
    default:
    - elvynforge.xyz
    description: Known C2 domains; the hunt also looks for generic .ru TLD traffic
      from build processes.
    from:
      kind: article
      observed: '2026-09-08'
      ref: ossprey-blog
    type: list[domain]
  lookback_days:
    default: '30'
    description: Days of history to examine, covering the known activity window.
    from:
      kind: article
      observed: '2026-08-12'
      ref: ossprey-blog
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts from the lead query to focus the behavioral
      analysis.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: scoping-output
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus initial analysis on developer VLANs and CI/CD runners. While the
  download count was low, transitive dependencies mean these packages could appear
  in unexpected projects.
references:
- name: "OSSPREY \u2014 pub.dev compromise: malicious Dart/Flutter packages"
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: dependency-confusion-npm-pypi
  reason: This hunt focuses specifically on the Flutter/Dart build-time injection;
    NPM confusion is a separate sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious Flutter package ingestion
    observables:
    - universal_file_viewer version 0.1.5
    - universal_file_viewer version 0.1.6
    - surveyjs_flutter version 0.1.1
    - surveyjs_flutter version 0.1.2
    - surveyjs_flutter version 0.1.3
    - pubspec.lock
    - pub.dev
    slug: initial-access-supply-chain-registry
    tactic: initial-access
    techniques:
    - T1195
    - T1190
  - name: Build-time code execution
    observables:
    - build.gradle.kts
    - project.pbxproj
    - example/android/app/build.gradle.kts
    - example/ios/Runner.xcodeproj/project.pbxproj
    - PBXBuildRule with filePatterns = "*.md"
    - build setting A3EA261
    - printf xAxd | tr -d A
    - printf bdase64 | tr -d d
    - sh
    slug: execution-native-build-injection
    tactic: execution
    techniques:
    - T1204.002
  - name: C2 payload download
    observables:
    - elvynforge.xyz
    - POST /a
    - body p=xcode_phase
    - body p=gradle
    - body p=xcode_rule
    - rotating .ru domains
    slug: c2-rotating-domain-callback
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Legitimate Flutter packages on the pub.dev registry were compromised after
    a maintainer's development environment was infected, leading to the injection
    of malicious code into native build files. This code executes during build-time
    on developer or CI machines to download and execute shell scripts from remote
    C2 domains, targeting sensitive credentials and secrets.
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


# Flutter Supply Chain Build Execution

This hunt targets a specific supply chain attack on the pub.dev ecosystem where malicious code was injected into native build files (Gradle and Xcode). The attack occurs at build time rather than runtime, making it invisible to standard application-level monitoring. The hunt first identifies hosts with the affected package versions, then fans out to look for characteristic obfuscated shell script execution, rare build-process activity, and C2 callbacks to rotating domains. An agent weighs the inventory, behavioral, and network evidence to determine if a host was compromised.

## find-affected-packages
<!-- Identify hosts with malicious package versions -->
Find developer workstations or CI runners that have downloaded the specific compromised versions of the target packages.

```sqlite target=endpoint role=scoping params=(affected_packages=affected_packages)
~~~yaml
expected: Hosts and paths where the packages are present. Silence means the specific
  versions were not detected in current inventory.
reads:
- device_hostname
- package_name
- package_version
- install_path
- provider
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, install_path, provider FROM hb_software_inventory WHERE instr(',' || '{{affected_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 AND (package_version IN ('0.1.1', '0.1.2', '0.1.3', '0.1.5', '0.1.6'))
```

## assess-lead-scope
<!-- Assess lead scope -->
```agent target=hunter
cite: required
context:
- find-affected-packages
max_iterations: 3
objective: Determine if any hosts in the environment have the specific malicious Flutter
  package versions present.
success_criteria: A list of hostnames requiring deep inspection.
tools:
- endpoint
```

## gate-on-discovery
<!-- Gate on discovery -->
if~: "the assess-lead-scope agent identifies at least one host with a malicious package version" (confidence: high, judge=hunter)
then: → deep-inspection-fanout
indeterminate: → remediation-tasks
unavailable: → remediation-tasks (blind_spot: ci-runner-ephemerality)
else: → close-out

## deep-inspection-fanout
<!-- Deep inspection fan-out -->
parallel:
- → rare-process-baseline
- → build-script-activity
- → c2-dns-activity
join: → final-triage

## rare-process-baseline
<!-- Stack-count rare shell-spawned processes -->
Identify rare child processes spawned by shell interpreters on developer hosts, which may indicate build-time injection.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small set of processes; unexpected binaries spawned from shells during
  builds are highlights.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(parent_process_name) IN ('sh', 'zsh', 'bash') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path HAVING host_count <= 3
```

## build-script-activity
<!-- Detect obfuscated build scripts -->
Find the specific obfuscation pattern (printf/tr/sh) used in the Gradle and Xcode build-time injections.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row containing the obfuscated shell command evaluated by sh. This is high-confidence
  evidence of the reported injection.
reads:
- device_hostname
- process_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%printf%tr%sh%' OR LOWER(script_content) LIKE '%a3ea261%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-activity
<!-- Match C2 network activity -->
Check for DNS callbacks to the known C2 domain or rotating .ru domains from processes involved in the build.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolutions for the named domain or .ru TLDs from shell or developer
  tools. Silence means the domain has rotated or no callback occurred.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.ru') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final triage -->
```agent target=hunter
cite: required
context:
- assess-lead-scope
- rare-process-baseline
- build-script-activity
- c2-dns-activity
max_iterations: 5
objective: Determine if any host with the malicious packages also exhibits behavioral
  or network evidence of the build-time compromise.
success_criteria: A verdict citing script execution or C2 callbacks on a host with
  affected packages.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → remediation-tasks
unavailable: → remediation-tasks (blind_spot: no-dns-logging)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any CI secrets or cloud credentials stored on the machine.
```
→ remediation-tasks

## remediation-tasks
<!-- Remediation tasks -->
```manual target=analyst
Manually inspect the pubspec.lock files on the identified hosts. Review the full text of any scripts captured in hb_script_activity. Rotate all credentials that were active on the machine during the identified lookback window.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document which hosts were inspected and whether additional forensic collection is required. Record any tuning notes if the obfuscated script check caught benign developer activity.
```
→ end
