---
analysis: A single rule on shell spawns by the git user is prone to false positives
  from legitimate hooks. This hunt correlates software version, delivery patterns,
  and execution prevalence using a phased approach and AI triage to reduce noise and
  provide a high-confidence verdict.
blind_spots:
- id: agent-visibility-gap
  owner: IT Operations
  question: whether the GitLab instance is enrolled in monitoring
  remediation: Ensure all GitLab infrastructure is enrolled in the central EDR/monitoring
    system.
  requires: hb_process_activity from an endpoint agent
  risk: A host without an agent provides no telemetry for the execution phase, leaving
    a critical blind spot in the detection chain.
- id: http-body-inspection
  owner: DevSecOps
  question: whether the .gitlab-ci.yml specifically contained the overflow regex
  remediation: Enable repository audit logging within GitLab for configuration changes.
  requires: Application layer logging of .gitlab-ci.yml content
  risk: Surface logs show the file was modified but not the content, requiring the
    agent to infer maliciousness from the subsequent RCE behavior.
  stage: malicious-config-delivery
coverage:
- stage: vulnerable-software-identification
  status: covered
  steps:
  - vulnerable-gitlab-instances
- stage: malicious-config-delivery
  status: covered
  steps:
  - config-file-changes
  - project-creation-traffic
- stage: regex-compiler-exploitation
  status: covered
  steps:
  - rce-behavior-prevalence
- stage: rce-command-execution
  status: covered
  steps:
  - rce-behavior-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: CVE-2026-97229 is a critical CVSS 10.0 unauthenticated RCE. This
    hunt provides the necessary business assurance that the critical integer overflow
    has not been triggered on the self-managed GitLab estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker exploited CVE-2026-97229 by planting a malicious .gitlab-ci.yml
  in a repository, causing an integer overflow in the Ruby Onigmo engine that executes
  arbitrary commands as the git user.
labels:
- hunt
- attack.t1190
- attack.t1059
- execution
- initial access
name: GitLab CI/CD Regex Compiler RCE Detection
parameters:
  git_user:
    default: git
    description: The operating system account that the GitLab service runs as.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: standard-deployment
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine for file and process activity.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Limit hunting to these hosts; leave empty to hunt across the entire
      estate.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-97229-critical-unauthenticated-remote-code-execution-in-gitlab
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus exclusively on self-managed GitLab Community and Enterprise editions.
  GitLab.com is out of scope.
references:
- name: "Rapid7 \u2014 CVE-2026-97229: Critical Unauthenticated Remote Code Execution\
    \ in GitLab"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-97229-critical-unauthenticated-remote-code-execution-in-gitlab
related:
- hunt: gitlab-malicious-registration-monitor
  reason: This hunt focuses on the RCE behavior; monitoring for anomalous spikes in
    new user registrations is a separate sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Vulnerable GitLab Instance Detection
    observables:
    - GitLab CE/EE versions 19.2 before 19.2.8
    - GitLab CE/EE versions 19.3 before 19.3.5
    - GitLab CE/EE versions 19.4 before 19.4.2
    - CVE-2026-97229
    slug: vulnerable-software-identification
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious CI/CD Configuration Delivery
    observables:
    - .gitlab-ci.yml
    - repository path containing UTF-8 characters
    - unauthenticated creation of public projects
    slug: malicious-config-delivery
    tactic: initial-access
    techniques:
    - T1190
  - name: Regex Engine Control-Flow Hijack
    observables:
    - Ruby Onigmo VM operations
    - GitLab application worker processes
    slug: regex-compiler-exploitation
    tactic: execution
    techniques:
    - T1190
    - T1059
  - name: Command Execution as git User
    observables:
    - operating system commands executed as the git user
    - shell processes spawned by Ruby GitLab workers
    slug: rce-command-execution
    tactic: execution
    techniques:
    - T1059
  summary: An attacker exploits an integer overflow in GitLab's CI/CD regular expression
    compiler (CVE-2026-97229) by committing a malicious configuration file and a repository
    path containing UTF-8 characters to a public project. This triggers a control-flow
    hijack in the Onigmo regex engine when evaluating the crafted expression, allowing
    unauthenticated remote code execution as the 'git' user on unpatched self-managed
    instances.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# GitLab CI/CD Regex Compiler RCE Detection

This hunt covers the entire lifecycle of CVE-2026-97229 exploitation on self-managed GitLab instances. It begins by scoping the estate to vulnerable 19.2, 19.3, and 19.4 version branches. The hunt then moves through a phased flow: first identifying delivery evidence via configuration file writes and suspicious web activity, followed by a search for the successful execution phase where the GitLab worker process spawns rare shell or utility processes under the git account. An agent weighs the delivery and execution evidence together per host to provide a final verdict.

## vulnerable-gitlab-instances
<!-- Identify vulnerable GitLab instances -->
Narrow the hunt to self-managed GitLab servers running the affected 19.2, 19.3, or 19.4 branches.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running vulnerable versions. Silence means the estate is
  patched or does not run self-managed GitLab.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%gitlab-ce%' OR LOWER(package_name) LIKE '%gitlab-ee%') AND (package_version LIKE '19.2.%' OR package_version LIKE '19.3.%' OR package_version LIKE '19.4.%')
```

## parallel-delivery
<!-- Examine delivery evidence -->
parallel:
- → config-file-changes
- → project-creation-traffic
join: → early-delivery-read

## config-file-changes
<!-- Malicious CI/CD configuration writes -->
Find recent writes to the .gitlab-ci.yml file, which is the primary delivery mechanism for the exploit.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A hit identifies the timestamp and actor behind a configuration change.
  Normal DevOps activity will create noise here.
reads:
- actor_user_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, file_path, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%.gitlab-ci.yml' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## project-creation-traffic
<!-- Suspicious project management traffic -->
Identify HTTP requests indicating a new project or IDE session, preceding the planting of the exploit.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows show IPs initiating project setup. High volumes from external or unknown
  IPs warrant closer inspection.
reads:
- device_hostname
- src_endpoint_ip
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/projects/new%' OR LOWER(url_path) LIKE '%/-/ide/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-delivery-read
<!-- Assess delivery risk -->
```agent target=hunter
cite: required
context:
- vulnerable-gitlab-instances
- config-file-changes
- project-creation-traffic
max_iterations: 3
objective: Identify hosts showing a vulnerable version branch combined with recent
  .gitlab-ci.yml writes or project creation events.
success_criteria: A per-host risk assessment focused on delivery indicators.
tools:
- endpoint
- web
```

## rce-behavior-prevalence
<!-- Rare processes spawned by GitLab workers -->
Identify successful RCE by stack-counting rare shell and utility processes spawned by the Ruby application workers.

```sqlite target=endpoint role=detection-candidate params=(git_user=git_user, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare shell command or network utility spawned by a GitLab worker is a
  high-fidelity indicator of successful RCE. Silence proves the absence of this specific
  behavior on the GitLab hosts during the window.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT LOWER(process_cmd_line) AS cmd, GROUP_CONCAT(DISTINCT device_hostname) AS hosts, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(user_name) = LOWER('{{git_user}}') AND (LOWER(parent_process_name) LIKE '%ruby%' OR LOWER(parent_process_name) LIKE '%sidekiq%' OR LOWER(parent_process_name) LIKE '%bundle%') AND (LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) = 'sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) = 'bash' OR LOWER(process_name) LIKE '%/python%' OR LOWER(process_name) = 'python' OR LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) = 'curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) = 'wget') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING host_count <= 3
```

## final-exploit-chain-read
<!-- Review the complete exploit chain -->
```agent target=hunter
cite: required
context:
- early-delivery-read
- rce-behavior-prevalence
max_iterations: 4
objective: 'Determine if any host shows the complete chain: vulnerable software, delivery
  indicators, and rare RCE-like process behavior.'
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the strength of the chain.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the final-exploit-chain-read verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: agent-visibility-gap)
else: → analyst-forensic-review

## isolate-and-remediate
<!-- Isolate and remediate -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the GitLab server from the network. Stop the GitLab service. Collect a forensic image. Upgrade GitLab to a fixed version (19.4.2+) before returning it to service.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the process activity on the GitLab server. Inspect /var/log/gitlab/gitlab-rails/production.log and sidekiq.log for the project path and the UTF-8 characters that triggered the overflow. Identify the source IP of the unauthenticated project creation.
```
→ close-out-report

## close-out-report
<!-- Close out report -->
```manual target=analyst
Record the list of vulnerable vs patched hosts. Log the malicious projects identified. Update the vulnerability management records for CVE-2026-97229.
```
→ end
