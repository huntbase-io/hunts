---
analysis: 'This hunt correlates a supply-chain installation with its behavioral consequences:
  processes that are usually local-only (like Python) initiating lookups to configuration
  sources and staging files. A single rule on the C2 domain may fail as infrastructure
  rotates, while this hunt focuses on the persistent behavioral indicators of the
  payload''s lifecycle.'
blind_spots:
- id: transient-artifact-deletion
  question: whether malicious staging files were created and then deleted
  requires: hb_file_activity with deletion records
  risk: The payload attempts to remove its temporary staging files and directories
    (.pc_e_*) after upload, which may leave no persistent on-disk evidence.
  stage: remote-code-loader-execution
- id: short-lived-processes
  question: whether exfiltration attempts occurred in short-lived processes
  requires: hb_dns_activity with high-frequency capture
  risk: A Python process that starts, initiates a thread, and exits quickly may not
    be captured by snapshot-based telemetry or may exit before the collector finishes
    its upload.
  stage: data-exfiltration
coverage:
- stage: remote-code-loader-execution
  status: covered
  steps:
  - dns-to-c2-infrastructure
  - staging-and-loader-artifacts
- stage: data-exfiltration
  status: covered
  steps:
  - dns-to-c2-infrastructure
  - staging-and-loader-artifacts
- reason: Handled by the distribution-focused hunt in this series.
  stage: malicious-package-distribution
  status: out_of_scope
- reason: Handled by the persistence-focused hunt in this series.
  stage: python-startup-hook-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the LiteLLM 1.107.0 supply chain
    compromise: Credential theft through Python startup hooks'' series.'
  stage: credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Supply chain compromises like LiteLLM facilitate direct credential
    theft and provide a remote execution path; identifying where the payload successfully
    exfiltrated data is critical for immediate credential revocation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using malicious Python startup hooks in a compromised
  package to execute a remote code loader and exfiltrate credentials from developer
  and production environments.
labels:
- hunt
- attack.t1041
- attack.t1059.006
- attack.t1195.002
- credential access
- execution
- exfiltration
- initial access
- persistence
name: LiteLLM Remote Code Loading and Exfiltration
parameters:
  c2_domains:
    default:
    - www.litellm.dev
    - litellm.dev
    - raw.githubusercontent.com
    description: Known domains used for exfiltration and loader configuration.
    from:
      kind: article
      observed: '2026-10-23'
      ref: msrc-blog-litellm
    type: list[domain]
  exfil_artifacts:
    default:
    - data.bin
    - key.bin
    - hdr.json
    - remote_code_loader.lock
    description: Specific filenames used by the exfiltration and loader components.
    from:
      kind: article
      observed: '2026-10-23'
      ref: msrc-blog-litellm
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts to scope; leave empty to hunt across the entire estate.
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations, CI/CD runners, and production gateway
  hosts identified by the software inventory scan.
references:
- name: 'MSRC Blog: Inside the LiteLLM 1.107.0 supply chain compromise'
  url: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
related:
- hunt: litellm-installation-and-startup-persistence
  reason: A sibling hunt that focuses on identifying the distribution and the initial
    persistence hooks.
  relation: precedes
- hunt: litellm-supply-chain-credential-theft
  relation: follows
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
  index: 2
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


# LiteLLM Remote Code Loading and Exfiltration

This hunt identifies the second-stage behavior of the LiteLLM 1.107.0 supply chain compromise. It focuses on the activation of the remote code loader and the exfiltration of encrypted credential archives. The hunt correlates the presence of the compromised software version with network telemetry from DNS lookups and the creation of transient staging artifacts or lock files on the file system.

## identify-vulnerable-installations
<!-- Identify LiteLLM 1.107.0 installations -->
Locate hosts with the compromised version of LiteLLM to focus the hunt on the most likely points of compromise.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running the compromised package. Silence means the specific
  version was not found in the current inventory snapshot.
reads:
- device_hostname
- package_name
- package_version
- install_path
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, package_name, package_version, install_path, collected_at FROM hb_software_inventory WHERE LOWER(package_name) = 'litellm' AND package_version = '1.107.0'
```

## corroborate-activity
<!-- Corroborate loader and exfiltration activity -->
parallel:
- → dns-to-c2-infrastructure
- → staging-and-loader-artifacts
join: → triage-signals

## dns-to-c2-infrastructure
<!-- Python DNS lookups to C2 infrastructure -->
Identify Python processes resolving the exfiltration domain or the loader configuration source.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Python or pip processes communicating with the domains named in the report.
  Silence means no such resolutions were logged within the window.
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
verified_at: '2026-10-24'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND (LOWER(process_name) LIKE '%python%' OR LOWER(process_name) LIKE '%pip%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## staging-and-loader-artifacts
<!-- Malicious staging and loader artifacts -->
Find transient files used to stage exfiltrated data or the lock file used by the remote loader.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, exfil_artifacts=exfil_artifacts)
~~~yaml
expected: The presence of staging files (data.bin, key.bin, hdr.json) or the loader
  lock file on disk. Silence is expected if the payload successfully cleaned up or
  never activated.
reads:
- device_hostname
- process_name
- file_path
- file_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-24'
~~~
SELECT device_hostname, process_name, file_path, file_name, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/.pc_e_%' OR instr(',' || '{{exfil_artifacts}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-signals
<!-- Triage compromise signals -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-installations
- dns-to-c2-infrastructure
- staging-and-loader-artifacts
max_iterations: 5
objective: Determine if any host in scope reached the exfiltration or remote code
  loading stages. Correlate the presence of LiteLLM 1.107.0 with the timing of Python
  DNS requests to C2 domains and the creation of staging file artifacts.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  DNS and file rows that align with the presence of the compromised package.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on activity verdict -->
if~: "the triage-signals verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: transient-artifact-deletion)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not use local Python tools for investigation; perform all forensic collection from a known-clean environment.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited DNS resolutions and file activity. Check for HTTP POST activity to litellm.dev in proxy logs if available. Verify the content of site-packages for unauthorized .pth or .py files.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record every host where successful exfiltration or loader activity was suspected. Coordinate the rotation of all secrets accessible to the affected systems and ensure affected Python environments are purged.
```
→ end
