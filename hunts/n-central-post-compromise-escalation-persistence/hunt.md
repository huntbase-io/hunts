---
analysis: This is a hunt because it correlates vulnerability state with specific,
  reported escalation tradecraft like syslog-ng tampering and applies fleet-wide baselines
  to account creation.
blind_spots:
- id: missing-linux-audit-ipc
  question: Whether insecure IPC channels (CVE-2026-91000) were exploited
  requires: hb_linux_audit with socket/ipc syscalls
  risk: Exploitation of insecure IPC channels may not produce discrete file or process
    launch events detectable in standard process telemetry until after root is achieved.
  stage: privilege-escalation-to-root
- id: app-level-session-logging
  question: Whether session-handling weaknesses were used to disclose ProductAdmin
    credentials
  requires: N-central application access logs or hb_http_activity with request body
  risk: Disclosure of credentials through session weaknesses occurs within the application
    logic and is invisible to host-level process and file monitoring.
  stage: credential-and-session-disclosure
coverage:
- stage: privilege-escalation-to-root
  status: covered
  steps:
  - syslog-ng-tampering
- stage: unauthorized-account-creation
  status: covered
  steps:
  - account-creation-prevalence
- blind_spot: app-level-session-logging
  reason: Internal session-handling disclosure is an application logic weakness not
    visible in host-level process or standard HTTP path logging.
  stage: credential-and-session-disclosure
  status: not_visible
- reason: Belongs to another part of the 'Critical vulnerabilities in N-able N-central
    prompt hosted shutdown' series.
  stage: n-central-exposure-and-scanning
  status: out_of_scope
- reason: Belongs to another part of the 'Critical vulnerabilities in N-able N-central
    prompt hosted shutdown' series.
  stage: unauthenticated-rce-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: N-central is an RMM platform with significant administrative reach;
    a compromise allows for immediate lateral movement to all managed endpoints.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited N-central vulnerabilities to gain a beachhead
  as the nable service account and is now attempting to escalate to root by tampering
  with syslog configurations or creating unauthorized local accounts.
labels:
- hunt
- attack.t1068
- attack.t1548
- attack.t1136.001
- attack.t1555
- attack.t1190
- credential access
- execution
- initial access
- persistence
- privilege escalation
name: Post-Compromise Escalation and Persistence on N-central
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for post-exploitation activity.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames of N-central appliances to focus on; leave empty
      to hunt across the entire estate.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: analyst-defined
    type: list[host]
  vulnerable_build_threshold:
    default: 2026.4.1.26
    description: The build version that includes the fix; versions lower than this
      are considered vulnerable.
    from:
      kind: article
      observed: '2026-11-10'
      ref: Rapid7 N-central advisory
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers identified as N-central appliances. Prioritize those running
  versions below 2026.4.1.26.
references:
- name: "Rapid7 \u2014 Critical Vulnerabilities in N-able N-central"
  url: https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown
related:
- hunt: n-central-unauthenticated-rce-exploitation
  reason: This hunt focuses on post-exploitation; initial exploitation via XXE/SSRF
    is handled separately.
  relation: out-of-scope-alternative
- hunt: n-central-initial-exploitation-able2shell
  relation: follows
scenario:
  stages:
  - name: N-central Exposure and Vulnerability Scanning
    observables:
    - N-able N-central instances before version 2026.4.1 (build 2026.4.1.26)
    - N-central Appliance 2026.4.0.31
    - HTTP scanning activity targeting N-central management interfaces
    slug: n-central-exposure-and-scanning
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthenticated RCE via Web Vulnerabilities
    observables:
    - XML external entity (XXE) payloads in HTTP requests
    - OGNL injection strings in web parameters
    - Path traversal sequences (../) in file-repository upload paths
    - Administrator viewing malicious MMS3 patch metadata
    slug: unauthenticated-rce-exploitation
    tactic: execution
    techniques:
    - T1190
    - T1203
  - name: Local Privilege Escalation to Root
    observables:
    - Modification of nable-writable syslog-ng configuration files
    - Exploitation of insecure IPC channels
    - nable service account spawning shell with root privileges
    slug: privilege-escalation-to-root
    tactic: privilege-escalation
    techniques:
    - T1068
    - T1548
  - name: Unauthorized Account Creation for Persistence
    observables:
    - New local user accounts created on the N-central appliance
    - Unauthorized administrative account creation
    slug: unauthorized-account-creation
    tactic: persistence
    techniques:
    - T1136.001
  - name: Credential and Session Disclosure
    observables:
    - Access to ProductAdmin credentials
    - Exploitation of session-handling weaknesses to disclose credentials
    slug: credential-and-session-disclosure
    tactic: credential-access
    techniques:
    - T1555
  summary: The Able2Shell disclosure identifies 33 vulnerabilities in the N-able N-central
    RMM platform, enabling unauthenticated remote code execution (RCE) via XXE, OGNL
    injection, and path traversal. Once initial access is gained, attackers can escalate
    privileges to root through insecure IPC or syslog-ng configurations and maintain
    persistence via unauthorized account creation, putting downstream managed environments
    at risk.
series:
  index: 2
  slug: critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown
  title: Critical vulnerabilities in N-able N-central prompt hosted shutdown
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


# Post-Compromise Escalation and Persistence on N-central

This hunt focuses on the 'Able2Shell' post-exploitation lifecycle on N-able N-central appliances. It follows an exposure flow, identifying vulnerable N-central instances and then examining host-telemetry for privilege escalation and persistence tradecraft described in recent research. The hunt specifically monitors the nable service account for anomalous file modifications and shell execution, alongside auditing new local account creations that could indicate an attacker establishing a long-term presence on the RMM server.

## scoping-vulnerable-n-central
<!-- Identify vulnerable N-central instances -->
Identify hosts running N-central versions prior to the 2026.4.1.26 hotfix to scope the hunt to potentially exposed appliances.

```sqlite target=endpoint role=scoping params=(vulnerable_build_threshold=vulnerable_build_threshold)
~~~yaml
expected: A list of hostnames running outdated N-central software. None means the
  estate is already patched or N-central is not present.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (instr(LOWER(package_name), 'n-central') > 0 OR instr(LOWER(package_name), 'ncentral') > 0) AND package_version < '{{vulnerable_build_threshold}}'
```

## account-creation-prevalence
<!-- Prevalence of local account creation -->
Identify unauthorized account creation on appliances, which is a reported persistence method in the Able2Shell disclosure.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Newly created user accounts on N-central appliances. Unexpected usernames
  should be scrutinized for correlation with vulnerability disclosure dates.
prevalence:
  by: device_hostname
  key:
  - user_name
  rare_below: 2
reads:
- device_hostname
- user_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, user_name, activity_name, COUNT(*) as changes, MIN(time) as first_seen FROM hb_account_change WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name ORDER BY changes ASC
```

## syslog-ng-tampering
<!-- Syslog-ng configuration modification -->
Detect the LPE mechanism where the nable user account modifies syslog-ng configuration to gain root privileges.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The nable service account modifying the syslog-ng configuration file, which
  is anomalous for this account context.
reads:
- device_hostname
- actor_user_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, actor_user_name, file_path, process_name, time FROM hb_file_activity WHERE instr(LOWER(file_path), 'syslog-ng.conf') > 0 AND LOWER(actor_user_name) = 'nable' AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-weigh-evidence
<!-- Assess post-exploitation evidence -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-n-central
- account-creation-prevalence
- syslog-ng-tampering
max_iterations: 3
objective: Decide whether the observed file modifications and account changes on vulnerable
  N-central hosts indicate an active compromise or unauthorized post-exploitation
  activity.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows for any anomaly.
tools:
- endpoint
```

## decision-route-on-verdict
<!-- Route based on compromise verdict -->
if~: "the agent verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → task-remediation-review
indeterminate: → task-remediation-review
unavailable: → task-remediation-review (blind_spot: missing-linux-audit-ipc)
else: → task-close-out

## task-remediation-review
<!-- Remediation and Incident Response Review -->
```manual target=analyst
1. For hosts with malicious or suspicious verdicts, verify if the account creation or syslog modification was unauthorized.
2. Ensure all identified vulnerable N-central instances are upgraded to build 2026.4.1.26 or higher immediately.
3. Validate that Agents and Probes are scheduled for updates following the server patch.
```
→ task-close-out

## task-close-out
<!-- Close out hunt -->
```manual target=analyst
Record the count of vulnerable vs patched hosts. Document any blind spots encountered, such as missing process-start telemetry for short-lived IPC exploitation.
```
→ end
