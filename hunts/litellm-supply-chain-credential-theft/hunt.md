---
analysis: "A standard detection rule for the LiteLLM version is necessary but noisy.\
  \ This hunt provides the behavioral context\u2014stack-counting Python credential\
  \ access and finding hidden payload markers\u2014to confirm exploitation versus\
  \ mere installation."
blind_spots:
- id: missing-file-telemetry
  owner: Endpoint Security Engineering
  question: whether the Python process successfully read the content of the credential
    files
  remediation: Enable file-level audit logging for ~/.aws, ~/.ssh, and ~/.kube directories.
  requires: Detailed file read auditing (e.g. Linux auditd or Sysmon EventID 1) for
    non-binary configuration files.
  risk: If only file creation or execution is logged, the hunt identifies presence
    and markers but cannot confirm the theft of secrets.
  stage: credential-harvesting
- id: ephemeral-environments
  owner: Cloud/DevOps Team
  question: whether a CI agent or short-lived build worker was infected and destroyed
    before a scan
  remediation: Integrate software composition analysis (SCA) into the CI pipeline
    to block builds containing known malicious versions.
  requires: Real-time or event-driven software inventory for short-lived containers.
  risk: Supply chain compromise often targets ephemeral build environments that traditional
    snapshot-based inventory may not capture.
  stage: malicious-package-distribution
coverage:
- stage: malicious-package-distribution
  status: covered
  steps:
  - scope-litellm-install
- stage: credential-harvesting
  status: covered
  steps:
  - rare-python-file-access
  - malicious-marker-activity
- reason: 'Belongs to another part of the ''Inside the LiteLLM 1.107.0 supply chain
    compromise: Credential theft through Python startup hooks'' series.'
  stage: python-startup-hook-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the LiteLLM 1.107.0 supply chain
    compromise: Credential theft through Python startup hooks'' series.'
  stage: remote-code-loader-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the LiteLLM 1.107.0 supply chain
    compromise: Credential theft through Python startup hooks'' series.'
  stage: data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Supply chain attacks on core AI libraries like LiteLLM bypass perimeter
    defenses by using trusted package mirrors and CI/CD pipelines. Protecting developer
    secrets is critical to preventing follow-on cloud intrusions.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has distributed a compromised version of LiteLLM (1.107.0)
  that uses Python startup hooks to execute a credential harvester upon any Python
  invocation, targeting cloud, SSH, and browser secrets.
labels:
- hunt
- attack.t1195.002
- attack.t1083
- attack.t1555
- credential access
- execution
- exfiltration
- initial access
- persistence
name: LiteLLM 1.107.0 Supply Chain Compromise and Credential Harvesting
parameters:
  litellm_version:
    default: 1.107.0
    description: The specific compromised version of LiteLLM to hunt for.
    from:
      kind: article
      observed: '2026-10-23'
      ref: msrc-blog-litellm
    type: string
  lookback_days:
    default: '14'
    description: Number of days of file activity history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts from the scoping step to focus the hunt; leave
      empty to run fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize developer workstations, CI/CD runners, and AI gateway servers.
  These environments are most likely to contain both the LiteLLM package and high-value
  long-lived credentials.
references:
- name: "Microsoft Security Blog \u2014 Inside the LiteLLM 1.107.0 supply chain compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
related:
- hunt: python-startup-hook-persistence
  reason: This hunt focuses on initial package presence and credential harvesting;
    the mechanics of startup persistence are handled in the sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Compromised Package Distribution
    observables:
    - litellm==1.107.0
    - Berri-AI/litellm (lookalike repository)
    slug: malicious-package-distribution
    tactic: initial-access
    techniques:
    - T1195
  - name: Python Startup Hook Persistence
    observables:
    - cook.pth
    - cook.py
    - sitecustomize.py
    - litellm-1.107.0.data/purelib/
    slug: python-startup-hook-persistence
    tactic: persistence
    techniques:
    - T1574
  - name: Credential and Sensitive Data Collection
    observables:
    - PRIVCOLLECT_ACTIVE environment variable
    - /tmp/.pc_once_72129118c59f5636c0bb
    - .aws/credentials
    - .azure/accessTokens.json
    - .kube/config
    - .ssh/id_rsa
    - Prisma database queries against LiteLLM proxy
    slug: credential-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1083
  - name: Remote Code Loader Execution
    observables:
    - /tmp/remote_code_loader.lock
    - GitHub domain.txt lookup
    - HTTP GET /codepy
    slug: remote-code-loader-execution
    tactic: execution
    techniques:
    - T1059.006
  - name: Encrypted Data Exfiltration
    observables:
    - .pc_e_ temporary directories
    - data.bin
    - key.bin
    - hdr.json
    - www.litellm.dev/healthcheck
    - X-SHA256 HTTP header
    - application/octet-stream
    slug: data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: The LiteLLM 1.107.0 supply chain compromise involved a malicious package
    release that deployed Python startup hooks (.pth files and sitecustomize.py) to
    achieve automatic execution. Once activated, the payload harvested a wide range
    of credentials from cloud providers, developer tools, and browsers, while maintaining
    a remote code loader to execute additional instructions from attacker-controlled
    infrastructure.
series:
  index: 1
  slug: inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks
  title: 'Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through
    Python startup hooks'
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


# LiteLLM 1.107.0 Supply Chain Compromise and Credential Harvesting

This hunt targets the LiteLLM 1.107.0 supply chain compromise, where malicious code was distributed via PyPI. The adversary uses Python startup hooks to execute the PRIVCOLLECT harvester. The hunt identifies installed copies of the compromised package and searches for evidence of unauthorized access to cloud, SSH, and browser credentials. An agent triages findings from software inventory and file activity to confirm active exploitation, and an analyst rotates compromised secrets.

## scope-litellm-install
<!-- Scope LiteLLM 1.107.0 installations -->
Identify all hosts where the compromised LiteLLM version is currently installed.

```sqlite target=endpoint role=scoping params=(litellm_version=litellm_version)
~~~yaml
expected: A list of hostnames and paths where the compromised version exists. Silence
  means the package was not detected on any enrolled host.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) = 'litellm' AND package_version = '{{litellm_version}}'
```

## parallel-behavior
<!-- Parallel behavioral analysis -->
parallel:
- → rare-python-file-access
- → malicious-marker-activity
join: → triage-compromise

## rare-python-file-access
<!-- Rare Python file access to credentials -->
Use stack-counting to identify Python processes accessing sensitive paths.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A Python process reading cloud or SSH secrets on only a few hosts. Rarity
  combined with the presence of the LiteLLM package is highly suspicious.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT LOWER(file_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS events FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.aws/credentials%' OR LOWER(file_path) LIKE '%.aws\\credentials%' OR LOWER(file_path) LIKE '%/.ssh/id_%' OR LOWER(file_path) LIKE '%.ssh\\id_%' OR LOWER(file_path) LIKE '%/.kube/config%' OR LOWER(file_path) LIKE '%.kube\\config%') AND LOWER(process_name) LIKE '%python%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY path HAVING hosts <= 3 ORDER BY hosts ASC
```

## malicious-marker-activity
<!-- Malicious marker and staging activity -->
Identify specific markers of the PRIVCOLLECT payload.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of the .pc_once marker or .pc_e temporary directories. These are
  high-fidelity indicators of the malicious collector running.
reads:
- device_hostname
- process_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.pc_once_%' OR LOWER(file_path) LIKE '%.pc_once_%' OR LOWER(file_path) LIKE '%/.pc_e_%' OR LOWER(file_path) LIKE '%.pc_e_%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-compromise
<!-- Triage compromise evidence -->
```agent target=hunter
cite: required
context:
- scope-litellm-install
- rare-python-file-access
- malicious-marker-activity
max_iterations: 4
objective: Determine if any host with the LiteLLM 1.107.0 package shows behavioral
  evidence of the PRIVCOLLECT credential harvester.
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows
  and paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host showing both markers and rare credential access" (confidence: high, judge=hunter)
then: → contain-and-rebuild
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: missing-file-telemetry)
else: → close-out

## contain-and-rebuild
<!-- Contain and rebuild environment -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Terminate all running Python processes immediately. Wipe the affected Python environment (site-packages) and rebuild from a verified clean LiteLLM version (1.107.1 or later). Ensure cook.pth, cook.py, and sitecustomize.py are removed.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Review the file access paths from the prevalence step. Confirm if the 'python' process involved matches the installation directory of LiteLLM. Rotate every secret stored in the identified files (AWS keys, SSH keys, etc.) for confirmed malicious hosts.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the total number of hosts where the package was found and how many showed behavioral evidence. Document evidence of absence for hosts that had the package but no markers.
```
→ end
