---
analysis: A standard detection rule might alert on any connection to a .ru domain,
  but this hunt correlates the 'build activity' behavior (file changes) with 'rare
  outbound' events specifically from development tools. This behavioral layering reduces
  the noise inherent in developer environments and identifies exfiltration even if
  the attacker rotates TLDs or endpoints.
blind_spots:
- id: missing-http-request-bodies
  owner: Infrastructure Engineering
  question: Does the HTTP POST contain the 'p=gradle' or 'p=xcode_rule' payload strings?
  remediation: Enable request body inspection for outbound developer traffic on corporate
    proxies.
  requires: hb_http_activity with request_body support
  risk: We can identify the POST destination and path, but cannot confirm the internal
    exfiltration format without body inspection.
  stage: c2-exfiltration
- id: no-process-to-network-mapping-cloud
  owner: Cloud Operations
  question: Which specific process on a cloud build runner initiated the outbound
    connection?
  remediation: Ensure all ephemeral build runners are deployed with short-lived endpoint
    monitoring agents.
  requires: Endpoint agents on CI/CD runners
  risk: Flow logs in cloud environments (VPC Flow Logs) do not capture process metadata;
    if agents are missing on runners, we lose the 'dart/java/xcodebuild' process context.
  stage: c2-exfiltration
coverage:
- stage: c2-exfiltration
  status: covered
  steps:
  - rare-dns-lookups-from-build-processes
  - rare-http-posts-by-build-tools
  - rare-outbound-network-events
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: supply-chain-ingestion
  status: out_of_scope
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: build-file-tampering
  status: out_of_scope
- reason: 'Belongs to another part of the ''pub.dev compromise: malicious Dart/Flutter
    packages'' series.'
  stage: obfuscated-build-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Developer workstations and build runners are high-value targets containing
    cloud and code-signing credentials. Detecting anomalous build-time network traffic
    is a critical control against supply chain compromise that bypasses code-level
    review.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established C2 communication from developer workstations
  by injecting malicious network-fetching logic into Flutter build-time components
  (Gradle, Xcode), manifesting as rare outbound connections from build tools.
labels:
- hunt
- attack.t1071.001
- attack.t1090.003
- attack.t1195
- attack.t1204.002
name: Outbound Build-Time Network Traffic
parameters:
  build_tool_processes:
    default:
    - dart
    - java
    - xcodebuild
    - sh
    - bash
    - curl
    - wget
    description: Processes associated with Flutter/Dart build environments and shell
      execution.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of log history to examine.
    type: number
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
rationale: We scope the hunt to 'active developer environments' by identifying hosts
  where pubspec or gradle files are frequently modified. This focuses our network
  analysis on high-risk machines without requiring a static list of IP addresses.
references:
- name: 'pub.dev compromise: malicious Dart/Flutter packages'
  url: https://www.ossprey.com/blog/pub-dev-compromise
related:
- hunt: build-file-tampering-flutter
  reason: Tampering of files like build.gradle is a prerequisite for this network
    behavior but is covered in a dedicated persistence/tampering hunt.
  relation: out-of-scope-alternative
- hunt: obfuscated-build-execution
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


# Outbound Build-Time Network Traffic

This hunt targets the network exfiltration and second-stage retrieval phase of the pub.dev supply chain compromise. Rather than searching only for known indicators, it identifies active development environments by file activity and then stack-counts outbound network behavior from build tools (Dart, Java/Gradle, Xcodebuild). We look for rare DNS lookups, rare HTTP POST requests, and low-prevalence IP/Host connections that deviate from standard developer traffic patterns.

## scope-active-build-environments
<!-- Identify active development environments -->
Find hosts where build configuration files (pubspec, gradle, pbxproj) are being modified, identifying systems actively performing builds.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts with activity on Flutter/Xcode build files. This narrows our hunt
  to the 'dev environment' population.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_name, file_path, process_name, COUNT(*) as activity_count, MIN(time) as first_active, MAX(time) as last_active FROM hb_file_activity WHERE (LOWER(file_name) IN ('pubspec.lock', 'build.gradle', 'build.gradle.kts', 'project.pbxproj')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, file_name, file_path, process_name
```

## gather-telemetry
<!-- Gather build-time network evidence -->
parallel:
- → rare-dns-lookups-from-build-processes
- → rare-http-posts-by-build-tools
- → rare-outbound-network-events
join: → triage-outbound-activity

## rare-dns-lookups-from-build-processes
<!-- Rare DNS lookups from build tools -->
Broadly identify low-prevalence external domains queried by build tools, moving beyond hardcoded TLDs.

```sqlite target=endpoint role=baseline params=(build_tool_processes=build_tool_processes, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Low-volume external DNS queries from build processes. Legitimate dependencies
  usually have higher lookup counts across the fleet.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{build_tool_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND query_hostname NOT LIKE '%.local' AND query_hostname NOT LIKE '%.internal' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname HAVING lookup_count < 50
```

## rare-http-posts-by-build-tools
<!-- Rare HTTP POSTs by build tools -->
Generalize the search for HTTP POST exfiltration from build tools to any external endpoint.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Unusual POST requests from a developer workstation to external sites. The
  agent will correlate these with the scoped build tools and file activity.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  - url_path
  rare_below: 3
reads:
- device_hostname
- url_hostname
- url_path
- http_method
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, user_agent, COUNT(*) as request_count FROM hb_http_activity WHERE http_method = 'POST' AND url_hostname NOT LIKE '%.internal' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path, http_method, user_agent HAVING request_count < 20
```

## rare-outbound-network-events
<!-- Rare outbound network connections -->
Narrow the network search to the intersection of build tools and rare destination IP/Host pairs to manage volume.

```sqlite target=network role=enrichment params=(build_tool_processes=build_tool_processes, lookback_days=lookback_days)
~~~yaml
expected: A small set of outbound connections from shell or build tools to external
  IPs that are not seen across the rest of the fleet.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 4
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as connection_count FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{build_tool_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.16.%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip HAVING connection_count < 30
```

## triage-outbound-activity
<!-- Triage build-time exfiltration -->
```agent target=hunter
cite: required
context:
- scope-active-build-environments
- rare-dns-lookups-from-build-processes
- rare-http-posts-by-build-tools
- rare-outbound-network-events
max_iterations: 5
objective: Identify hosts that exhibit both 'active build activity' (Step 1) and 'rare
  outbound network/DNS/HTTP traffic' (Steps 3, 4, 5) originating from build tools.
  Determine if the destinations match the .ru TLD or /a endpoint patterns described
  in the research.
success_criteria: A verdict of malicious (rare outbound from dev tools to suspicious
  domains), suspicious (rare traffic from build tools without known C2 hits), or benign.
tools:
- endpoint
- network
- web
```

## decision-on-verdict
<!-- Route on triage result -->
if~: "the triage identifies at least one host as malicious or suspicious due to rare outbound connections to suspicious TLDs or endpoints from build processes" (confidence: high, judge=hunter)
then: → isolate-workstation
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-http-request-bodies)
else: → close-out

## isolate-workstation
<!-- Isolate workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Coordinate with the user to rotate all developer-related credentials, including SSH keys, GitHub tokens, and AWS secrets.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual analyst review -->
```manual target=analyst
Examine the full process tree and network history for the flagged host. Determine if the rare outbound traffic coincides with Flutter build commands and whether other sensitive files (~/.ssh/*) were accessed by the same process tree.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record all identified malicious domains and IPs. If valid exfiltration was found, promote the 'rare outbound from build processes' query to a permanent detection rule.
```
→ end
