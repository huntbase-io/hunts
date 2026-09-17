---
analysis: A standard detection rule might fire on any .ru domain lookup, but this
  hunt correlates the presence of compromised packages with specific HTTP POST behavioral
  patterns and fleet-wide DNS rarity to reduce false positives and confirm an active
  supply chain callback.
blind_spots:
- id: network-log-retention-gap
  question: Did the compromise occur before the current retention window?
  requires: Extended retention for hb_http_activity and hb_dns_activity
  risk: Malicious activity occurring early in the month (Aug 12) may not be visible
    if logs have rolled over.
  stage: c2-script-retrieval
- id: encrypted-c2-payloads
  question: Is the '/a' path visible if traffic is encrypted via HTTPS?
  requires: TLS Inspection or endpoint-based HTTP interception
  risk: If the C2 uses HTTPS and no decryption is in place, only DNS and raw socket
    traffic to .ru domains will be visible, while the behavioral 'POST /a' indicator
    will be missed.
  stage: c2-script-retrieval
coverage:
- stage: c2-script-retrieval
  status: covered
  steps:
  - rare-ru-dns-lookups
  - http-post-callback-behavior
  - outbound-ru-connections
  - triage-c2-activity
- reason: Covered in a separate hunt in the series.
  stage: malicious-package-distribution
  status: out_of_scope
- reason: Covered in a separate hunt in the series.
  stage: build-time-injection-gradle
  status: out_of_scope
- reason: Covered in a separate hunt in the series.
  stage: build-time-injection-xcode
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt protects the integrity of the software development lifecycle
    by identifying active compromises in CI/CD pipelines and developer environments.
    Supply chain attacks on registries like pub.dev represent a direct risk to company
    intellectual property and production credentials.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Developer workstations or CI runners are beaconing to rotating .ru domains
  via POST requests to the /a path, indicating the execution of a malicious Flutter
  package's build-time downloader.
labels:
- hunt
- attack.t1090.003
- attack.t1195
- attack.t1190
name: 'Pub.dev Compromise: C2 Callbacks'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_path:
    default: /a
    description: The HTTP path observed in the report for script retrieval.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.ossprey.com/blog/pub-dev-compromise
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
rationale: The hunt should start with CI/CD runners and developer workstations that
  show signs of Flutter/Dart activity. The 'affected-software-inventory' step provides
  the initial list of hosts. The lookback period is set to 14 days by default to capture
  the peak period of the rotating C2 activity reported.
references:
- name: "OSSPREY \u2014 pub.dev compromise: malicious Dart/Flutter packages"
  url: https://www.ossprey.com/blog/pub-dev-compromise
- name: "JAMF \u2014 3CX Supply Chain Attack (Context on Flutter Weaponization)"
  url: https://www.jamf.com/blog/3cx-supply-chain-attack/
related:
- hunt: malicious-package-distribution
  reason: This hunt focuses on the C2 stage; the distribution of packages is covered
    in the companion hunt.
  relation: out-of-scope-alternative
- hunt: build-time-injection-gradle
  reason: Focuses on the specific disk and file-level modifications made to Gradle
    build files.
  relation: out-of-scope-alternative
- hunt: malicious-build-tooling-behavior
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
  index: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Pub.dev Compromise: C2 Callbacks

This hunt focuses on the network-level aftermath of the pub.dev supply chain compromise. Malicious Flutter packages (universal_file_viewer and surveyjs_flutter) were found to inject code into Gradle and Xcode build scripts. This code downloads an additional stage of malware by making HTTP POST requests to a rotating set of .ru domains. By examining DNS queries, HTTP metadata, and outbound network connections, we can identify compromised environments that have executed these build-time hooks. This hunt uses a parallel approach to correlate prevalence-based DNS signals with specific HTTP behavioral indicators.

## affected-software-inventory
<!-- Find hosts with malicious Flutter packages -->
Scope the hunt to hosts that have resolved or installed the specific compromised versions of the Dart/Flutter packages.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows indicating specific hosts where these package versions are present.
  Silence means the specific versions were not detected in the current software inventory.
reads:
- device_hostname
- package_name
- package_version
- provider
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, provider FROM hb_software_inventory WHERE (LOWER(package_name) = 'universal_file_viewer' AND package_version IN ('0.1.5', '0.1.6')) OR (LOWER(package_name) = 'surveyjs_flutter' AND package_version IN ('0.1.1', '0.1.2', '0.1.3'))
```

## c2-evidence-gathering
<!-- Collect C2 evidence in parallel -->
parallel:
- → rare-ru-dns-lookups
- → http-post-callback-behavior
- → outbound-ru-connections
join: → triage-c2-activity

## rare-ru-dns-lookups
<!-- Stack-count .ru DNS lookups -->
Identify rare .ru domains queried by the fleet, which is indicative of the rotating C2 infra mentioned in the report.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of .ru domains queried by only a few hosts. High-prevalence domains
  are likely generic Russian web services and can be ignored.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.ru' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING hosts <= 3 ORDER BY hosts ASC, lookups DESC
```

## http-post-callback-behavior
<!-- HTTP POST callbacks to the /a path -->
Directly identify the specific HTTP behavioral pattern (POST /a) described as the malware's second-stage downloader.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, malicious_path=malicious_path)
~~~yaml
expected: Instances where a process (likely java or xcodebuild) sends a POST request
  to '/a'.
reads:
- device_hostname
- url_full
- user_agent
- src_endpoint_ip
- time
- http_method
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_full, user_agent, src_endpoint_ip, time FROM hb_http_activity WHERE LOWER(http_method) = 'post' AND LOWER(url_path) = '{{malicious_path}}' AND time >= datetime('now', '-{{lookback_days}} days')
```

## outbound-ru-connections
<!-- Raw network connections to .ru TLDs -->
Identify direct IP/socket connections to Russian infrastructure originating from developer build processes.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Build tools (Java/Gradle, Xcode, Dart) establishing outbound connections
  to .ru domains or suspicious IPs.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
- severity_id
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(dst_endpoint_hostname) LIKE '%.ru' OR (severity_id >= 2 AND dst_endpoint_port IN (80, 443))) AND (LOWER(process_name) LIKE '%java%' OR LOWER(process_name) LIKE '%xcode%' OR LOWER(process_name) LIKE '%dart%' OR LOWER(process_name) LIKE '%flutter%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-c2-activity
<!-- Triage C2 Activity -->
```agent target=hunter
cite: required
context:
- affected-software-inventory
- rare-ru-dns-lookups
- http-post-callback-behavior
- outbound-ru-connections
max_iterations: 4
objective: Identify hosts where the combination of affected software presence and
  network activity confirms a supply chain callback event.
success_criteria: A verdict for every host found in the initial scoping step, citing
  specific evidence from the parallel queries.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for one or more hosts" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: network-log-retention-gap)
else: → close-hunt

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke all CI/CD secrets associated with the runner, and rotate any credentials stored on the developer machine.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the DNS lookups and HTTP POST activity cited by the agent. Verify if the .ru domains are truly suspicious or part of legitimate developer activity.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
No malicious activity detected. Record the hosts examined and the specific package versions identified during the scoping step.
```
→ end
