---
analysis: A simple file detection can find the .pth hook, but this hunt correlates
  inventory status with the unusual behavioral pattern of cross-process environment
  reading to confirm that a package was not just installed but was actively used to
  steal secrets.
blind_spots:
- id: auditd-not-configured
  question: Are all environment variable reads via the proc filesystem being logged?
  requires: hb_linux_audit specifically monitoring /proc syscalls
  risk: The harvesting behavior might be invisible if the audit configuration does
    not capture reads to /proc/*/environ.
  stage: credential-access-secret-harvesting
- id: ephemeral-containers
  question: Did the package run in a container that was destroyed before a scan?
  requires: real-time package inventory for container lifecycles
  risk: Build-and-destroy CI/CD nodes may install and run the stealer, perform the
    theft, and terminate before the inventory surface records their presence.
  stage: initial-access-malicious-pypi-package
coverage:
- stage: initial-access-malicious-pypi-package
  status: covered
  steps:
  - package-inventory-scoping
- stage: persistence-python-pth-hook
  status: covered
  steps:
  - malicious-file-hooks
- stage: execution-background-stealer-fork
  status: covered
  steps:
  - python-stealer-processes
- stage: credential-access-secret-harvesting
  status: covered
  steps:
  - harvesting-behavior
- reason: Belongs to another part of the 'We caught the agent-framework PyPI compromise
    six minutes after it published' series.
  stage: exfiltration-to-webhook-site
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The agent-framework PyPI compromise reached nearly 200,000 monthly
    downloads; its automated credential harvesting can lead to total Azure or GitHub
    subscription takeover from a single infected build node.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has installed a compromised version of the agent-framework
  package which persists via a .pth hook and harvests cloud credentials by reading
  environment variables from the /proc filesystem and local configuration files.
labels:
- hunt
- attack.t1195.002
- attack.t1546
- attack.t1059.006
- attack.t1555
- attack.t1003
- attack.t1528
- credential access
- execution
- exfiltration
- initial access
- persistence
name: Malicious Python Package Persistence and Secret Theft
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_versions:
    default:
    - 1.26.1
    - 1.26.2
    description: The specific compromised versions of agent-framework.
    from:
      kind: article
      observed: '2026-11-18'
      ref: elastic-security-labs
    type: list[string]
  persistence_files:
    default:
    - agent_framework_meta.pth
    - _telemetry.py
    - af_runtime_diag.pth
    - af_runtime_diag.py
    description: Filenames used by the .pth hook and telemetry loader.
    from:
      kind: article
      observed: '2026-11-18'
      ref: elastic-security-labs
    type: list[path]
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty for the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target build agents, developer laptops, and CI/CD runners where Python
  development activity is frequent. Use the initial scoping step to limit the analysis
  to hosts where the specific malicious versions are present.
references:
- name: "Elastic Security Labs \u2014 We caught the agent-framework PyPI compromise\
    \ six minutes after it published"
  url: https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
related:
- hunt: exfiltration-to-webhook-site
  reason: This hunt focuses on the on-host lifecycle (installation, persistence, and
    harvesting); exfiltration behavior is a network-centric sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious PyPI package installation
    observables:
    - agent-framework==1.26.1
    - agent-framework==1.26.2
    - d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110
    - 3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9
    slug: initial-access-malicious-pypi-package
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Persistence via Python .pth hook
    observables:
    - agent_framework_meta.pth
    - af_runtime_diag.pth
    - _telemetry.py
    - af_runtime_diag.py
    - 21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e
    - 325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93
    slug: persistence-python-pth-hook
    tactic: persistence
    techniques:
    - T1546
  - name: Background stealer execution
    observables:
    - os.fork()
    - os.setsid()
    - _AF_TEL
    - threading.Thread
    - t.daemon = True
    slug: execution-background-stealer-fork
    tactic: execution
    techniques:
    - T1059.006
  - name: Credential harvesting from disk and memory
    observables:
    - ~/.azure
    - /proc/*/environ
    - pip.conf
    - .npmrc
    - .git-credentials
    - config.json
    - SYSTEM_ACCESSTOKEN
    - IDENTITY_HEADER
    slug: credential-access-secret-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1003
    - T1528
  - name: Network exfiltration to webhook.site
    observables:
    - webhook.site
    - af-runtime-diagnostics/1
    - runtime-diagnostics/1
    - d381fd80-ec62-42ad-8f5c-d1b15103c9bb
    slug: exfiltration-to-webhook-site
    tactic: exfiltration
    techniques:
    - T1041
  summary: The agent-framework PyPI package (versions 1.26.1 and 1.26.2) was compromised
    to include a persistent credential stealer triggered by a .pth startup hook. The
    malware executes in the background of any Python process to harvest cloud tokens,
    environment variables, and configuration files from the filesystem and process
    memory for exfiltration to webhook.site.
series:
  index: 1
  slug: we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
  title: We caught the agent-framework PyPI compromise six minutes after it published
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


# Malicious Python Package Persistence and Secret Theft

This hunt identifies hosts impacted by the agent-framework supply-chain compromise. The malicious versions (1.26.1 and 1.26.2) use a .pth startup hook to execute a credential stealer every time any Python script starts. The stealer forks a background process to harvest environment variables from up to 300 running processes and searches for Azure, AWS, and GitHub credential caches on disk. We trace the lifecycle from package installation and hook creation to active secret harvesting behavior.

## package-inventory-scoping
<!-- Scope compromised package inventory -->
Identify hosts that have the malicious versions of the agent-framework package installed.

```sqlite target=endpoint role=scoping params=(malicious_versions=malicious_versions)
~~~yaml
expected: A list of hostnames where the malicious package is present in the software
  inventory. None means no hosts are reporting the specific versions.
reads:
- device_hostname
- install_path
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) = 'agent-framework' AND instr(',' || '{{malicious_versions}}' || ',', ',' || package_version || ',') > 0
```

## parallel-early-evidence
<!-- Identify early-stage persistence and execution -->
parallel:
- → malicious-file-hooks
- → python-stealer-processes
join: → agent-infection-triage

## malicious-file-hooks
<!-- Find malicious persistence hooks -->
Detect the creation or presence of the .pth hook files that trigger the stealer.

```sqlite target=endpoint role=detection-candidate params=(persistence_files=persistence_files, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: File activity rows naming the malicious .pth or .py files. This is the primary
  indicator of persistence.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE instr(',' || '{{persistence_files}}' || ',', ',' || file_name || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## python-stealer-processes
<!-- Search for stealer background execution -->
Identify Python processes that show behavior consistent with the detached stealer (e.g., _AF_TEL marker).

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes referencing the malicious telemetry modules in their command line.
  This proves the hook was active.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%_telemetry%' OR LOWER(process_cmd_line) LIKE '%agent_framework_meta%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-infection-triage
<!-- Triage host infection status -->
```agent target=hunter
cite: required
context:
- package-inventory-scoping
- malicious-file-hooks
- python-stealer-processes
max_iterations: 3
objective: Identify hosts that have the malicious package installed AND show evidence
  of persistence hooks or telemetry process execution.
success_criteria: A verdict of infected | clean per host citing the specific file
  or process activity found.
tools:
- endpoint
```

## harvesting-behavior
<!-- Detect environment harvesting via /proc -->
Detect the unusual behavior of a Python process reading environment files from other processes.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Python processes reading multiple proc environment files. This is rare and
  indicative of the stealer's harvesting phase.
prevalence:
  by: device_hostname
  key:
  - process_path
  - path_name
  rare_below: 3
reads:
- device_hostname
- path_name
- process_path
- syscall
- time
silence: not_evidence_of_absence
source: hb_linux_audit
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_path, path_name, COUNT(DISTINCT device_hostname) AS hosts, time FROM hb_linux_audit WHERE path_name LIKE '/proc/%/environ' AND syscall = 'open' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path, path_name HAVING hosts <= 3
```

## agent-theft-analysis
<!-- Analyze active secret theft -->
```agent target=hunter
cite: required
context:
- agent-infection-triage
- harvesting-behavior
max_iterations: 4
objective: Determine if the infected hosts identified earlier are actively harvesting
  secrets, citing the specific proc reads or file access patterns.
success_criteria: A final verdict of malicious-theft | suspicious | clean per host.
tools:
- endpoint
```

## decision-route
<!-- Route based on theft verdict -->
if~: "the agent-theft-analysis verdict is malicious-theft for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: auditd-not-configured)
else: → analyst-manual-review

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to stop further token exfiltration. Collect a memory dump if possible to preserve process environment variables.
```
→ task-remediate-secrets

## analyst-manual-review
<!-- Manual analyst review -->
```manual target=analyst
Review the cited rows from the theft analysis agent. Inspect the host for the presence of the .pth hook files and rotate any identities associated with the host's build environment.
```
→ task-close-out

## task-remediate-secrets
<!-- Remediate and rotate secrets -->
```manual target=analyst
Uninstall the malicious agent-framework package and pin to version 1.26.0. Rotate all secrets stored on the host, including Azure CLI caches, .npmrc tokens, and GitHub OIDC federated credentials.
```
→ task-close-out

## task-close-out
<!-- Close out hunt -->
```manual target=analyst
Record what was found, which hosts were impacted, and whether any evidence suggests the stolen secrets were used for lateral movement in the cloud.
```
→ end
