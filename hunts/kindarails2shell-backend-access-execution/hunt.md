---
analysis: A simple detection rule for /etc/passwd access might be too noisy. This
  hunt specifically pivots from a scoped set of vulnerable Rails processes to identify
  unusual file access patterns and rare child processes, correlating two distinct
  stages of a complex exploit chain.
blind_spots:
- id: no-file-telemetry
  question: Was the Rails process reading sensitive files via the matload loader?
  requires: hb_file_activity with read events
  risk: Without file read telemetry, we cannot distinguish between a failed exploit
    attempt and a successful arbitrary file disclosure.
  stage: arbitrary-file-read
- id: short-retention
  question: Did exploitation occur outside the 14-day lookback window?
  requires: 30+ day telemetry retention
  risk: The vulnerability was disclosed on July 29, 2026. If the lookback window is
    too short, we may miss historical exploitation attempts.
coverage:
- stage: arbitrary-file-read
  status: covered
  steps:
  - sensitive-file-access
- stage: rce-via-chain-builder
  status: covered
  steps:
  - suspicious-rails-children
  - rare-child-processes
- reason: Belongs to another part of the 'KindaRails2Shell technical analysis (CVE-2026-66066)'
    series.
  stage: vulnerability-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'KindaRails2Shell technical analysis (CVE-2026-66066)'
    series.
  stage: direct-upload-spoofing
  status: out_of_scope
- reason: Belongs to another part of the 'KindaRails2Shell technical analysis (CVE-2026-66066)'
    series.
  stage: variation-key-replay
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of CVE-2026-66066 allows unauthenticated attackers to
    read any file accessible to the Rails process, which typically includes the master.key
    used to sign session cookies. This leads directly to full account takeover or
    remote code execution, making this a critical risk.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting CVE-2026-66066 to read sensitive configuration
  files or execute arbitrary commands by submitting crafted image uploads to a Rails
  application using the libvips processor.
labels:
- hunt
- attack.t1190
name: KindaRails2Shell Backend Access and Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of telemetry to examine.
    type: number
  sensitive_paths:
    default:
    - /etc/passwd
    - /etc/shadow
    - .env
    - config/master.key
    - config/database.yml
    - credentials.yml.enc
    description: Target files typically sought by attackers via arbitrary file read.
    type: list[path]
  shell_interpreters:
    default:
    - sh
    - bash
    - dash
    - zsh
    - python
    - python3
    - perl
    - ruby
    - node
    description: Interpreters commonly used as second-stage execution payloads.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing web servers running Ruby on Rails. This hunt identifies
  Action Pack/Rails packages in the hb_software_inventory to narrow the scope.
references:
- name: 'Rapid7: KindaRails2Shell Technical Analysis (CVE-2026-66066)'
  url: https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066/
related:
- hunt: direct-upload-spoofing-detection
  reason: This hunt focuses on backend impact; detecting the initial direct-upload
    spoofing belongs on the HTTP request surface.
  relation: out-of-scope-alternative
- hunt: active-storage-web-exploitation-cve-2026-66066
  relation: follows
scenario:
  stages:
  - name: Identification of Vulnerable Rails Services
    observables:
    - Rails versions 6.0.6.1, 6.1.7.10, 7.2.3.1, 8.0.5, 8.1.3
    - Active Storage configured with Vips
    - config.active_support.message_serializer = :json
    slug: vulnerability-discovery
    tactic: discovery
    techniques:
    - T1190
  - name: Malicious Blob Registration
    observables:
    - POST /rails/active_storage/direct_uploads
    - 'content_type: image/png'
    - 'params.expect(blob: [:filename, :byte_size, :checksum, :content_type, metadata:
      {}])'
    slug: direct-upload-spoofing
    tactic: initial-access
    techniques:
    - T1190
  - name: Exploit Trigger via Key Replay
    observables:
    - GET /rails/active_storage/representations/proxy/
    - variation_key parameter replayed from genuine application URLs
    - signed_blob_id of the spoofed MAT/HDF5 file
    - 'ActiveStorage.verifier.verify(key, purpose: :variation)'
    slug: variation-key-replay
    tactic: initial-access
    techniques:
    - T1190
  - name: File Disclosure via matload
    observables:
    - libvips selecting matload decoder
    - MATLAB 5.0 file header prefix
    - libmatio reading MAT_FT_MAT73 (0x0200)
    - HDF5 external storage reading /etc/passwd
    - HDF5 external storage reading config/master.key
    - HDF5 external storage reading .env
    slug: arbitrary-file-read
    tactic: collection
    techniques:
    - T1190
  - name: Remote Code Execution via ImageProcessing
    observables:
    - Kernel#spawn execution
    - Kernel#eval execution
    - ImageProcessing Vips transformation bypassing validate_transformation
    - JSON-compatible Hash/Array/String values in signed variation
    slug: rce-via-chain-builder
    tactic: execution
    techniques:
    - T1190
  summary: Attackers exploit a vulnerability in Ruby on Rails Active Storage (CVE-2026-66066)
    by uploading a crafted MAT/HDF5 file via a direct-upload endpoint while spoofing
    the content-type as an image. By replaying a valid variation key, they trigger
    libvips processing which uses HDF5 external storage to read arbitrary local files,
    such as Rails secrets, and returns them to the attacker rendered as image pixels.
series:
  index: 2
  slug: kindarails2shell-technical-analysis-cve-2026-66066
  title: KindaRails2Shell technical analysis (CVE-2026-66066)
  total: 2
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


# KindaRails2Shell Backend Access and Execution

This hunt targets the backend manifestations of the KindaRails2Shell vulnerability. It specifically looks for the Ruby/Rails process accessing sensitive filesystem paths (like master.key or /etc/passwd) which occurs when libvips's matload loader is tricked into using HDF5 external storage. Additionally, it monitors for unusual child processes spawned by the Rails application, which indicates the successful use of the ImageProcessing chain-builder RCE vector. By correlating file access anomalies with suspicious process trees, we can identify active exploitation even if the initial HTTP request was obfuscated or not captured.

## vulnerable-hosts-scoping
<!-- Identify potentially vulnerable Rails hosts -->
Identify hosts running vulnerable versions of Action Pack / Rails based on software inventory.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running Rails in the affected version ranges. Silence
  indicates no such packages are inventoried.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE package_name IN ('rails', 'actionpack', 'action_pack') AND (package_version LIKE '7.2.%' OR package_version LIKE '8.0.%' OR package_version LIKE '8.1.%')
```

## detective-parallel
<!-- Parallel evidence gathering -->
parallel:
- → sensitive-file-access
- → suspicious-rails-children
- → rare-child-processes
join: → triage-verdict

## sensitive-file-access
<!-- Rails process accessing sensitive files -->
Identify instances where the Ruby/Rails process reads files it should not access during normal web request handling, indicating file disclosure.

```sqlite target=endpoint role=detection-candidate params=(sensitive_paths=sensitive_paths, lookback_days=lookback_days)
~~~yaml
expected: Rows showing Rails processes reading credentials, environment variables,
  or system files. Silence suggests no such access was captured.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(process_name) LIKE '%ruby%' OR LOWER(process_name) LIKE '%rails%') AND (instr(',' || '{{sensitive_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR LOWER(file_name) = 'master.key') AND activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-rails-children
<!-- Unusual child processes of Rails -->
Detect RCE by finding shell interpreters or network tools spawned by the Rails application process.

```sqlite target=endpoint role=triage params=(shell_interpreters=shell_interpreters, lookback_days=lookback_days)
~~~yaml
expected: A list of shell executions triggered by Rails. Benign hits might include
  legitimate maintenance tasks if not properly scoped.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%ruby%' OR LOWER(parent_process_name) LIKE '%rails%') AND (instr(',' || '{{shell_interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-child-processes
<!-- Baseline: Rare Rails child processes -->
Apply stack-counting to identify rare binaries spawned by Rails that may not be in the pre-defined shell list.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous binaries seen on only a few hosts. High host_count entries are
  likely standard app behavior.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%ruby%' OR LOWER(parent_process_name) LIKE '%rails%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 2 ORDER BY host_count ASC
```

## triage-verdict
<!-- Agent Triage: Correlate File Read and RCE -->
```agent target=hunter
cite: required
context:
- sensitive-file-access
- suspicious-rails-children
- rare-child-processes
max_iterations: 5
objective: Determine per host if the Rails process has been compromised to read backend
  secrets or execute arbitrary commands via libvips/ImageProcessing loaders.
success_criteria: A verdict of malicious, suspicious, or benign for each host with
  findings, citing specific file paths or process command lines.
tools:
- endpoint
```

## route-verdict
<!-- Route on Triage Results -->
if~: "The triage verdict is malicious for at least one host based on suspicious child processes or unauthorized access to Rails secrets." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and preserve memory/disk for forensic analysis. Pay special attention to rotating any secrets stored in 'master.key' or '.env' as they are likely compromised.
```
→ analyst-review

## analyst-review
<!-- Manual Verification and IR -->
```manual target=analyst
Verify the command lines and file access logs. If exploitation is confirmed, initiate the Incident Response protocol for credential rotation, as the attacker likely accessed Rails secrets used for session encryption.
```
→ end

## close-out
<!-- Hunt Completion -->
```manual target=analyst
Document the hosts scanned and the versions found. If many vulnerable hosts were identified but no activity was seen, recommend prioritizing patching for CVE-2026-66066.
```
→ end
