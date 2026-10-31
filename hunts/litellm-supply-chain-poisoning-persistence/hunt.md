---
analysis: A static rule for package versions is bypassed by renaming. This hunt uses
  prevalence counting across .pth files and correlates it with specific Python-based
  file access behavioral patterns, providing a cross-surface signal that simple version
  checks miss.
blind_spots:
- id: no-process-telemetry
  question: whether the installation occurred on a host without process logging
  requires: hb_process_activity with command-line auditing
  risk: A host that installs the package but does not report process history will
    be missed by the lead query.
  stage: malicious-dependency-installation
- id: insufficient-file-logs
  question: whether the RAT accessed secrets not in the standard searched paths
  requires: hb_file_activity with activity_id = 2 (Read) auditing for sensitive directories
  risk: If the RAT targets non-standard secret locations, the behavior will be invisible.
  stage: credential-theft-and-rat-c2
coverage:
- stage: malicious-dependency-installation
  status: covered
  steps:
  - litellm-install-lead
  - litellm-inventory-check
- stage: python-startup-persistence
  status: covered
  steps:
  - pth-persistence-prevalence
- stage: credential-theft-and-rat-c2
  status: covered
  steps:
  - python-credential-theft
- reason: Belongs to another part of the 'Lessons from Cybersecurity Black Week' series.
  stage: rce-vulnerability-exposure
  status: out_of_scope
- reason: Belongs to another part of the 'Lessons from Cybersecurity Black Week' series.
  stage: memory-safety-exploitation-crashes
  status: out_of_scope
- reason: Belongs to another part of the 'Lessons from Cybersecurity Black Week' series.
  stage: compromised-certificate-trust
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The LiteLLM supply chain compromise allows for unauthenticated RCE
    and credential theft at scale. Verifying the integrity of Python environments
    is critical for preventing unauthorized cloud access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has installed a poisoned version of the LiteLLM library to
  establish persistence via Python startup files and exfiltrate host credentials.
labels:
- hunt
- attack.t1195.002
- attack.t1574.013
- attack.t1555
- credential access
- execution
- initial access
- persistence
name: LiteLLM Supply Chain Poisoning and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for installation and behavior.
    from:
      kind: manual
      observed: '2026-10-21'
      ref: incident-window
    type: number
  malicious_version:
    default: 1.107.0
    description: The specific compromised version of LiteLLM.
    from:
      kind: article
      observed: '2026-10-21'
      ref: https://www.welivesecurity.com/en/business-security/lessons-cybersecurity-black-week/
    type: string
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on after the scoping step.
    from:
      kind: manual
      observed: '2026-10-28'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/lessons-cybersecurity-black-week/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developers and CI/CD runners where LiteLLM is likely used. ephemeral
  build agents are high priority.
references:
- name: "ESET Research \u2014 Lessons from Cybersecurity Black Week"
  url: https://www.welivesecurity.com/en/business-security/lessons-cybersecurity-black-week/
related:
- hunt: python-startup-hijack-general
  reason: This hunt is specific to the LiteLLM incident; a broader hunt for all .pth
    hijacks is a sibling.
  relation: out-of-scope-alternative
- hunt: cybersecurity-black-week-vulnerability-trust-audit
  relation: follows
scenario:
  stages:
  - name: Vulnerable Service Exposure
    observables:
    - PHP versions 5.4 through 8.5.11
    - GitLab CE/EE versions 7.0 to 19.5
    - Node.js 24.22.0
    - Linux kernel KSMBD SMB Direct (ZDI-CAN-33549, ZDI-CAN-33774)
    - CVE-2026-109618
    - CVE-2026-109619
    - CVE-2026-110264
    - CVE-2026-111497
    slug: rce-vulnerability-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Memory Safety Exploitation
    observables:
    - PHP out-of-memory (OOM) errors
    - Node.js Brotli decoder crashes
    - GitLab integer overflow during regex compilation
    - Application Error 1000
    - Exception code c0000005
    slug: memory-safety-exploitation-crashes
    tactic: execution
    techniques:
    - T1203
  - name: Supply Chain Poisoning
    observables:
    - litellm==1.107.0
    - 'Docker tags: v1.107.0, latest, main-latest, main-stable'
    - Malicious images pushed to official container registries
    slug: malicious-dependency-installation
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Python Startup Hijack
    observables:
    - .pth files created in Python site-packages
    - Abuse of Python startup mechanisms
    slug: python-startup-persistence
    tactic: persistence
    techniques:
    - T1574.013
  - name: Credential Theft and RAT Activity
    observables:
    - Credential stealer payload
    - Remote Access Trojan (RAT) execution
    - Outbound C2 connections from Python processes
    - Access to sensitive local secret stores
    slug: credential-theft-and-rat-c2
    tactic: credential-access
    techniques:
    - T1555
    - T1071.001
  - name: Intermediate CA Trust Compromise
    observables:
    - eMudhra/emSign intermediate CAs with insecure private keys
    - certifi < 2026.10.19
    - pip < 26.2.2
    - uv < 0.13.4
    slug: compromised-certificate-trust
    tactic: initial-access
    techniques:
    - T1553.004
  summary: A barrage of critical vulnerabilities in October 2026 including PHP2Shell,
    Node2Shell, and GitLab RCE enabled unauthenticated remote code execution, while
    a supply-chain compromise of the LiteLLM package facilitated persistent credential
    theft. Attackers poisoned LiteLLM's PyPI and Docker distributions with a payload
    that hijacks Python startup via .pth files and establishes a remote access trojan
    (RAT).
series:
  index: 2
  slug: lessons-from-cybersecurity-black-week
  title: Lessons from Cybersecurity Black Week
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


# LiteLLM Supply Chain Poisoning and Persistence

This hunt targets the Cybersecurity Black Week compromise of the LiteLLM library (v1.107.0). It follows a gated flow, starting with a lead query that identifies the malicious package installation in process history to capture activity on ephemeral hosts. If the lead is positive, the hunt fans out to find rare Python persistence (.pth files) and sensitive credential access across the fleet. An agent then correlates these signals to confirm a compromise and trigger containment.

## litellm-install-lead
<!-- Detect malicious LiteLLM installation events -->
Identify hosts that attempted to install the compromised version of LiteLLM, including ephemeral hosts.

```sqlite target=endpoint role=scoping params=(malicious_version=malicious_version, lookback_days=lookback_days)
~~~yaml
expected: Rows showing pip or python commands installing the malicious version. Silence
  means no recorded installation events in the window.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%pip%install%litellm%{{malicious_version}}%' OR LOWER(process_cmd_line) LIKE '%litellm-{{malicious_version}}%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess lead evidence -->
```agent target=hunter
cite: required
context:
- litellm-install-lead
max_iterations: 3
objective: Identify hosts that have LiteLLM version 1.107.0 installation activity
  in their process logs.
success_criteria: A verdict naming the affected hosts.
tools:
- endpoint
```

## gate-on-install
<!-- Gate on installation activity -->
if~: "the agent confirms at least one host has activity relating to version 1.107.0 of LiteLLM" (confidence: high, judge=hunter)
then: → deep-dive
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-telemetry)
else: → close-out

## deep-dive
<!-- Examine behavior and persistence -->
parallel:
- → pth-persistence-prevalence
- → litellm-inventory-check
- → python-credential-theft
join: → final-triage

## pth-persistence-prevalence
<!-- Rare .pth file persistence -->
Stack-count .pth file creations to find rare startup hijacks and attribute them to a process.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare .pth files created on one or two hosts. Persistent malicious startup
  files will stand out from common library files.
prevalence:
  by: device_hostname
  key:
  - file_name
  - file_path
  rare_below: 5
reads:
- file_name
- file_path
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT file_name, file_path, process_name, process_cmd_line, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_file_activity WHERE LOWER(file_name) LIKE '%.pth' AND (LOWER(file_path) LIKE '%site-packages%' OR LOWER(file_path) LIKE '%dist-packages%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, file_path, process_name, process_cmd_line HAVING host_count < 5
```

## litellm-inventory-check
<!-- Check current package inventory -->
Confirm if the malicious version is currently installed on any disk in the fleet.

```sqlite target=endpoint role=enrichment params=(malicious_version=malicious_version, scope_hosts=scope_hosts)
~~~yaml
expected: A snapshot of hosts with the vulnerable version currently installed.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) = 'litellm' AND package_version = '{{malicious_version}}' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## python-credential-theft
<!-- Python credential file access -->
Find Python processes reading sensitive local secret stores.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Reads of cloud or SSH credentials by a Python interpreter. Legitimate tools
  may exist, but those matching the scope hosts are high risk.
reads:
- device_hostname
- process_name
- process_cmd_line
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, file_path, time FROM hb_file_activity WHERE activity_id = 2 AND LOWER(process_name) LIKE '%python%' AND (LOWER(file_path) LIKE '%/.aws/credentials' OR LOWER(file_path) LIKE '%/.ssh/id_%' OR LOWER(file_path) LIKE '%/config.json' OR LOWER(file_path) LIKE '%/.dockercfg' OR LOWER(file_path) LIKE '%/.npmrc') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Triage compromise and impact -->
```agent target=hunter
cite: required
context:
- assess-lead
- pth-persistence-prevalence
- litellm-inventory-check
- python-credential-theft
max_iterations: 6
objective: Determine if the compromised LiteLLM package has achieved persistence or
  attempted credential theft on the affected hosts.
success_criteria: A per-host verdict of malicious | suspicious | benign.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host, showing both package presence and either persistence (.pth) or credential access" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-file-logs)
else: → close-out

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate the supply-chain incident response protocol, specifically focusing on credential rotation.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the identified .pth files and the Python processes that read sensitive files. Confirm if LiteLLM was the primary actor and determine which cloud or SSH credentials were leaked.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the absence of malicious LiteLLM versions or the containment of any hits. Ensure all containers and virtual environments are updated to 1.107.1 or higher.
```
→ end
