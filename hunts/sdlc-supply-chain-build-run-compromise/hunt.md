---
analysis: 'While a rule can flag a specific package version, this hunt pivots from
  the vulnerability to the behavior: asking if a package manager spawned a foreign
  runtime, and if that runtime then performed memory-scraping operations. This context
  is too complex for a single detection rule without high false positives.'
blind_spots:
- id: short-lived-telemetry
  owner: Cloud Security
  question: Are we missing telemetry from runners that are destroyed immediately after
    a build?
  remediation: Enforce log streaming to a central store before runner termination.
  requires: Persistent logging for ephemeral CI/CD runners
  risk: Attackers can perform credential theft in seconds; if the host is destroyed
    before telemetry is ingested, the activity is invisible.
  stage: malicious-package-execution
- id: script-fragmentation
  owner: Endpoint Engineering
  question: Can we detect markers if the malicious logic is split across many script
    blocks?
  remediation: Implement block-reconstruction logic for PowerShell/Shell scripts.
  requires: hb_script_activity reconstruction
  risk: A worm that splits its payload into many small fragments may avoid detection
    by substring matching on individual blocks.
  stage: runner-memory-credential-theft
coverage:
- stage: vulnerable-upstream-contribution
  status: covered
  steps:
  - scope-vulnerable-packages
  - enrich-with-cve-findings
- stage: malicious-package-execution
  status: covered
  steps:
  - suspicious-hook-execution
- stage: runner-memory-credential-theft
  status: covered
  steps:
  - script-memory-markers
  - credential-file-access
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: ide-tool-config-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: automated-propagation-and-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SDLC supply chain attacks execute during the build phase where traditional
    production security controls are absent. A hunt that correlates software inventory
    with build-time behavior is essential to stop downstream propagation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised an upstream dependency or build tool to execute
  malicious code during the CI/CD process, leveraging lifecycle hooks to steal OIDC
  tokens and developer credentials.
labels:
- hunt
- attack.t1195.002
- attack.t1584.005
- attack.t1059.007
- attack.t1204.002
- attack.t1105
- attack.t1003
- attack.t1552
name: 'SDLC Supply Chain: Build & Run Compromise'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  memory_markers:
    default:
    - ctypes
    - ptrace
    - /proc/self/mem
    - oidc
    description: Keywords in scripts indicative of memory scraping or token theft.
    from:
      kind: article
      observed: '2026-08-21'
      ref: unit42-sdlc-supply-chain
    type: list[string]
  package_managers:
    default:
    - npm
    - pip
    - cargo
    - mvn
    - go
    description: Common package manager processes.
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt.
    type: list[host]
  suspicious_runtimes:
    default:
    - bun
    - python
    - node
    - sh
    - bash
    description: Processes often used in malicious hooks.
    type: list[string]
  target_cve:
    default:
    - CVE-2024-3094
    description: Target CVE IDs associated with supply chain vulnerabilities.
    from:
      kind: article
      observed: '2024-03-29'
      ref: unit42-sdlc-supply-chain
    type: list[string]
  vulnerable_versions:
    default:
    - 5.6.0
    - 5.6.1
    description: Known compromised versions of xz/liblzma.
    from:
      kind: article
      observed: '2024-03-29'
      ref: unit42-sdlc-supply-chain
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/sdlc-supply-chain/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts identified as having vulnerable xz versions. Prioritize
  assets with names containing 'runner', 'build', or 'dev'.
references:
- name: "Unit 42 \u2014 Securing the Overlooked Corners of the SDLC Supply Chain"
  url: https://unit42.paloaltonetworks.com/sdlc-supply-chain/
related:
- hunt: ide-tool-config-persistence
  reason: Persistence in IDE configs (VS Code tasks.json) occurs after initial build
    compromise and is handled in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious Upstream Contribution
    observables:
    - liblzma version 5.6.0
    - liblzma version 5.6.1
    - CVE-2024-3094
    - malicious tarballs
    - OpenSSL zero-day
    slug: vulnerable-upstream-contribution
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Malicious Package Hook Execution
    observables:
    - npm install
    - package.json preinstall script
    - Bun runtime download
    - 727 KB obfuscated payload
    slug: malicious-package-execution
    tactic: execution
    techniques:
    - T1584.005
    - T1059.007
    - T1204.002
    - T1105
  - name: CI/CD Runner Memory Scraping
    observables:
    - Python script reading process memory
    - GitHub Actions runners
    - OpenID Connect (OIDC) tokens
    - .git-credentials
    slug: runner-memory-credential-theft
    tactic: credential-access
    techniques:
    - T1003
    - T1552
  - name: Developer Tool Persistence
    observables:
    - .vscode/tasks.json
    - Claude Code configuration
    - VS Code extensions
    slug: ide-tool-config-persistence
    tactic: persistence
    techniques:
    - T1543
    - T1505
  - name: Automated Propagation and C2
    observables:
    - Ethereum blockchain transactions
    - GitHub API calls
    - npm token usage
    - rogue code repositories
    slug: automated-propagation-and-c2
    tactic: c2
    techniques:
    - T1102
    - T1078
  summary: Attackers are targeting the software supply chain by embedding backdoors
    in foundational libraries and deploying autonomous worms like ChainDrop that hijack
    npm preinstall hooks. These attacks exploit the high privileges of developer tools
    to steal OIDC tokens from CI/CD runner memory, establish persistent backdoors
    in IDE configurations, and propagate via stolen credentials using blockchain-based
    command and control.
series:
  index: 1
  slug: connecting-the-dots-securing-the-overlooked-corners-of-the-software-development-lifecycle-sdlc-s
  title: 'Connecting the Dots: Securing the Overlooked Corners of the Software Development
    Lifecycle (SDLC) Supply Chain'
  total: 2
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


# SDLC Supply Chain: Build & Run Compromise

Supply chain attacks are increasingly targeting the 'digital factory'—the CI/CD pipelines and developer environments—rather than the production application code. This hunt investigates the transition from vulnerable software (like the XZ Utils backdoor CVE-2024-3094) to active execution and credential harvesting.

We start by identifying assets with vulnerable package versions or known supply chain CVEs. We then look for anomalous process behavior, specifically package managers spawning out-of-ecosystem runtimes (like Bun or standalone Python) which is characteristic of the ChainDrop worm. Finally, we corroborate this by searching for memory-scraping logic in script blocks and unauthorized access to local credential stores (.git-credentials, .npmrc), which are prime targets for automated propagation.

## scope-vulnerable-packages
<!-- Scope by vulnerable package versions -->
Identify hosts where the vulnerable XZ Utils or liblzma packages are installed based on the research.

```sqlite target=endpoint role=scoping params=(vulnerable_versions=vulnerable_versions)
~~~yaml
expected: A list of hostnames potentially at risk. No rows means these specific versions
  aren't detected in inventory.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) IN ('xz', 'liblzma') AND instr(',' || '{{vulnerable_versions}}' || ',', ',' || package_version || ',') > 0
```

## enrich-with-cve-findings
<!-- Enrich with scanner CVE findings -->
Cross-reference inventory with official vulnerability scanner findings for the target CVE to see where it has already been flagged.

```sqlite target=endpoint role=enrichment params=(target_cve=target_cve)
~~~yaml
expected: Specific resource IDs (like container images or instances) flagged for the
  supply chain CVE.
reads:
- resource_uid
- cve_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT resource_uid, cve_uid, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cve}}' || ',', ',' || cve_uid || ',') > 0
```

## parallel-behavior-check
<!-- Analyze behavior for compromise indicators -->
parallel:
- → suspicious-hook-execution
- → script-memory-markers
- → credential-file-access
join: → triage-agent

## suspicious-hook-execution
<!-- Suspicious package manager child processes -->
Identify instances where a package manager spawns an unexpected runtime, which is a common pattern for 'preinstall' hook exploitation.

```sqlite target=endpoint role=detection-candidate params=(package_managers=package_managers, suspicious_runtimes=suspicious_runtimes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare parent->child relationship on a build runner or dev machine. Legitimate
  installs are common; rare 'bun' or 'python' launches from 'npm' are suspicious.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  - process_name
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, COUNT(*) as exec_count, MIN(time) as first_seen FROM hb_process_activity WHERE instr(',' || '{{package_managers}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND (instr(',' || '{{suspicious_runtimes}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%preinstall%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING exec_count <= 5
```

## script-memory-markers
<!-- Script content with memory markers -->
Detect script blocks containing indicators of memory scraping or OIDC token theft, as seen in the ChainDrop worm.

```sqlite target=endpoint role=baseline params=(memory_markers=memory_markers, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing Python 'ctypes' logic or OIDC keywords. Silence
  means no such scripts were executed within the window.
reads:
- device_hostname
- actor_user_name
- script_path
- script_content
- time
silence: evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, script_path, script_content, time FROM hb_script_activity WHERE ( (instr(LOWER(script_content), 'ctypes') > 0 AND instr('{{memory_markers}}', 'ctypes') > 0) OR (instr(LOWER(script_content), 'ptrace') > 0 AND instr('{{memory_markers}}', 'ptrace') > 0) OR (instr(LOWER(script_content), 'oidc') > 0 AND instr('{{memory_markers}}', 'oidc') > 0) OR (instr(LOWER(script_content), '/proc/self/mem') > 0 AND instr('{{memory_markers}}', '/proc/self/mem') > 0) ) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## credential-file-access
<!-- Access to sensitive SDLC credentials -->
Identify suspicious runtimes reading local Git or NPM credentials during the build window.

```sqlite target=endpoint role=enrichment params=(suspicious_runtimes=suspicious_runtimes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A suspicious runtime (e.g. Bun or standalone Python) reading a developer's
  secret file.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.git-credentials%' OR LOWER(file_path) LIKE '%.npmrc%' OR LOWER(file_path) LIKE '%.env%') AND activity_name IN ('Read', 'Open') AND instr(',' || '{{suspicious_runtimes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage SDLC activity -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-packages
- enrich-with-cve-findings
- suspicious-hook-execution
- script-memory-markers
- credential-file-access
max_iterations: 5
objective: Determine if a package installation or build process has been subverted
  on any host by analyzing process lineage, script content, and file access patterns.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  rare process chains or script markers found.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one build host or runner" (confidence: high, judge=hunter)
then: → contain-compromised-host
indeterminate: → analyst-close-out
unavailable: → analyst-close-out (blind_spot: short-lived-telemetry)
else: → analyst-close-out

## contain-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke all OIDC tokens issued to this runner, and rotate any .git-credentials or .npmrc secrets found on the machine.
```
→ analyst-close-out

## analyst-close-out
<!-- Analyst review and close-out -->
```manual target=analyst
Review the cited rows. If the activity is part of a legitimate but unusual build utility, record the command line or script hash for tuning the suspicious-hook detection rule.
```
→ end
