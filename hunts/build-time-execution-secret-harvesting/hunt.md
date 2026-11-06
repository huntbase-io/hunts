---
analysis: A simple detection rule for 'npm install' or 'preinstall' is too noisy for
  developer environments. This hunt stacks child processes across the fleet to find
  rare hooks and correlates that rarity with credential file access, providing the
  context an analyst needs to judge a supply chain compromise.
blind_spots:
- id: missing-memory-telemetry
  question: Was a script reading the memory of the GitHub runner process directly?
  requires: Process memory access telemetry (CrossProcessHandle)
  risk: Harvesters like ChainDrop can read OIDC tokens directly from memory without
    touching sensitive configuration files on disk, bypassing file-based detection.
  stage: cicd-secret-memory-scraping
- id: ephemeral-runner-logs
  question: Did the telemetry reach the platform before the ephemeral build host was
    destroyed?
  requires: Centralized, real-time telemetry forwarding for ephemeral CI/CD runners
  risk: Short-lived CI/CD runners may execute a hook and be terminated before the
    agent can flush its event buffer, leading to missed execution signals.
  stage: malicious-npm-hook-execution
coverage:
- stage: malicious-npm-hook-execution
  status: covered
  steps:
  - rare-build-child-processes
- stage: payload-delivery-bun-runtime
  status: covered
  steps:
  - rare-build-child-processes
  - triage-sdlc-exposure
- blind_spot: missing-memory-telemetry
  reason: Memory-based scraping is not visible on standard process or file surfaces;
    partially addressed by monitoring sensitive file access instead.
  stage: cicd-secret-memory-scraping
  status: not_visible
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: developer-tool-backdooring
  status: out_of_scope
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: blockchain-based-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''Connecting the Dots: Securing the Overlooked
    Corners of the Software Development Lifecycle (SDLC) Supply Chain'' series.'
  stage: automated-worm-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Build-time supply chain attacks bypass production SBOMs and runtime
    security. A negative result verifies that authorized developer systems are not
    executing rare, unauthorized setup hooks that harvest secrets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised a software dependency to execute malicious
  code during the build phase, subsequently harvesting cloud and developer credentials
  from the environment's configuration files.
labels:
- hunt
- attack.t1195.002
- attack.t1059.003
- attack.t1105
- attack.t1059.007
- attack.t1003
- attack.t1528
- attack.t1552.004
name: Build-Time Execution and Secret Harvesting
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-21'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on (e.g. known CI/CD runners);
      leave empty for the whole estate.
    from:
      kind: manual
      observed: '2026-08-21'
      ref: analyst-scoping
    type: list[host]
  sensitive_paths:
    default:
    - /home/runner/.npmrc
    - /root/.npmrc
    - /home/runner/.aws/credentials
    - /root/.aws/credentials
    - /home/runner/.ssh/id_rsa
    - /root/.ssh/id_rsa
    - tasks.json
    - .git-credentials
    description: Specific credential and configuration file paths commonly targeted
      by harvesters.
    from:
      kind: article
      observed: '2026-08-21'
      ref: unit42-sdlc
    type: list[path]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes using software inventory to find hosts where development
  tools are installed. Focus the lookback on recent dependency updates or pipeline
  runs.
references:
- name: "Unit 42 \u2014 Connecting the Dots: Securing the Overlooked Corners of the\
    \ SDLC Supply Chain"
  url: https://unit42.paloaltonetworks.com/sdlc-supply-chain/
related:
- hunt: developer-tool-configuration-tampering
  reason: This hunt focuses on build-time execution and harvesting; persistence via
    backdooring VS Code or Claude Code configurations belongs to a separate investigation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious npm preinstall hook execution
    observables:
    - npm install
    - preinstall scripts in package.json
    - npm hooks
    slug: malicious-npm-hook-execution
    tactic: execution
    techniques:
    - T1195.002
    - T1059.003
  - name: Payload delivery via Bun runtime
    observables:
    - Bun runtime download
    - 727 KB obfuscated payload
    - Background payload launch
    slug: payload-delivery-bun-runtime
    tactic: execution
    techniques:
    - T1105
    - T1059.007
  - name: CI/CD and endpoint secret harvesting
    observables:
    - Python script reading live process memory
    - GitHub Actions runner memory scraping
    - OpenID Connect (OIDC) tokens
    - Local developer credentials sweep
    slug: cicd-secret-memory-scraping
    tactic: credential-access
    techniques:
    - T1003
    - T1528
    - T1552.004
  - name: Persistence via developer tool configuration
    observables:
    - VS Code tasks.json modification
    - Claude Code cross-linked hooks
    slug: developer-tool-backdooring
    tactic: persistence
    techniques:
    - T1546
  - name: Blockchain command and control
    observables:
    - Ethereum blockchain transactions
    - Dynamic C2 infrastructure
    slug: blockchain-based-c2
    tactic: command-and-control
    techniques:
    - T1102
  - name: Automated package propagation
    observables:
    - Stolen npm tokens
    - Stolen GitHub tokens
    - Republishing infected packages (keyv, cacheable-request)
    - Creation of rogue repositories
    slug: automated-worm-propagation
    tactic: lateral-movement
    techniques:
    - T1534
    - T1195.002
  summary: Attackers target the software supply chain by poisoning package dependencies
    with malicious preinstall hooks that execute during development and build processes.
    The ChainDrop worm specifically scrapes CI/CD runner memory for OIDC tokens and
    local credentials to establish persistence in developer tools like VS Code and
    automatically propagate by infecting and republishing additional packages.
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Build-Time Execution and Secret Harvesting

Attackers are increasingly targeting the software build process rather than the application code. This hunt identifies the initial execution of malicious lifecycle hooks (like npm preinstall), the delivery of unauthorized runtimes like Bun, and the subsequent harvesting of sensitive credentials. By scoping to development environments and stacking rare child processes spawned by package managers, we identify anomalous behaviors that static bill-of-materials scans miss.

## find-sdlc-environments
<!-- Identify development and build hosts -->
Scope the hunt to systems where package managers or runtimes are present, representing the SDLC attack surface.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames with development tools. Silence indicates no such software
  is inventoried, making the hunt non-applicable.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%npm%' OR LOWER(package_name) LIKE '%node%' OR LOWER(package_name) LIKE '%bun%' OR LOWER(package_name) LIKE '%python%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-build-child-processes
<!-- Stack-count rare build child processes -->
Identify anomalous processes spawned by package managers, which can reveal malicious lifecycle hooks or secondary payloads.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines involving 'preinstall' scripts or rare secondary runtimes
  seen on very few hosts. Silence suggests no unusual hook execution occurred.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%npm%' OR LOWER(parent_process_name) LIKE '%node%' OR LOWER(parent_process_name) LIKE '%bun%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 3 ORDER BY hosts ASC
```

## secret-file-access
<!-- Credential and configuration file access -->
Find file activity targeting sensitive paths by developer tools or their child processes.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_paths=sensitive_paths)
~~~yaml
expected: Access to .npmrc, .aws/credentials, or tasks.json by non-standard processes.
  Silence means no direct file-level harvesting was observed.
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE instr(',' || '{{sensitive_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-sdlc-exposure
<!-- Weigh SDLC build-time evidence -->
```agent target=hunter
cite: required
context:
- find-sdlc-environments
- rare-build-child-processes
- secret-file-access
max_iterations: 4
objective: Determine if the rare child processes spawned by npm, node, or bun indicate
  a malicious build-time execution event and whether those processes accessed sensitive
  credentials.
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows
  and linking process rarity to credential access.
tools:
- endpoint
```

## route-exposure
<!-- Route on SDLC verdict -->
if~: "The triage verdict identifies malicious lifecycle hooks or unauthorized secret harvesting on any developer host." (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: missing-memory-telemetry)
else: → close-out

## remediation-review
<!-- Credential rotation and hook review -->
```manual target=analyst
For any host with suspicious activity, rotate all local developer credentials (SSH, AWS, npm) and OIDC tokens. Review the package.json of the affected project to identify the malicious dependency. Consider implementing --ignore-scripts policy.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the baseline of common preinstall hooks used in your business to reduce noise for future hunts. Document any coverage gaps found during the process.
```
→ end
