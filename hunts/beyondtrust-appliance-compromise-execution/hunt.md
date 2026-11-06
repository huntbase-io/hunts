---
analysis: A simple vulnerability alert does not indicate if exploitation has occurred;
  this hunt correlates the presence of the software with the behavioral signals of
  script drops and rare shell execution to distinguish unpatched systems from active
  compromises.
blind_spots:
- id: no-appliance-telemetry
  question: Whether the appliance was compromised but did not report file or process
    activity
  requires: Endpoint telemetry on the appliance OS
  risk: A closed appliance without an agent will not report the behavioral activity
    this hunt relies on, leading to a false negative.
  stage: execution-unauthorized-scripts
- id: no-http-logs
  question: The specific exploit path used for the authentication bypass
  requires: hb_http_activity or appliance web logs
  risk: Without HTTP-level logs, the initial bypass is only visible via its behavioral
    aftermath (files and processes).
  stage: initial-access-beyondtrust-bypass
coverage:
- stage: initial-access-beyondtrust-bypass
  status: covered
  steps:
  - identify-affected-appliances
  - unrecognized-script-creation
- stage: execution-unauthorized-scripts
  status: covered
  steps:
  - rare-shell-execution
  - unrecognized-script-creation
- reason: Belongs to another part of the 'CISA Urges Patching Critical Vulnerability
    in BeyondTrust Remote Support' series.
  stage: persistence-account-manipulation
  status: out_of_scope
- reason: Belongs to another part of the 'CISA Urges Patching Critical Vulnerability
    in BeyondTrust Remote Support' series.
  stage: lateral-movement-privileged-sessions
  status: out_of_scope
- reason: Belongs to another part of the 'CISA Urges Patching Critical Vulnerability
    in BeyondTrust Remote Support' series.
  stage: defense-evasion-log-tampering
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: BeyondTrust CVE-2026-102764 is a critical authentication bypass in
    the CISA KEV catalog. Compromised appliances provide attackers with persistent,
    privileged remote access to the internal network.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited CVE-2026-102764 to bypass authentication on
  a BeyondTrust Remote Support appliance, resulting in unauthorized file operations
  and the execution of unrecognized scripts.
labels:
- hunt
- attack.t1190
- attack.t1059
- defense evasion
- execution
- initial access
- lateral movement
- persistence
name: BeyondTrust Appliance Compromise and Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioral activity.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames of suspected appliances to narrow the search; leave
      empty to hunt across the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-critical-vulnerability-beyondtrust-remote-support
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on self-hosted BeyondTrust/Bomgar appliances. Use software inventory
  to find these devices regardless of whether they have an active vulnerability finding,
  as the bypass is widely exploited.
references:
- name: "CISA \u2014 CISA Urges Patching Critical Vulnerability in BeyondTrust Remote\
    \ Support"
  url: https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-critical-vulnerability-beyondtrust-remote-support
related:
- hunt: beyondtrust-persistence-manipulation
  reason: This hunt focuses on initial access and script execution; persistence through
    session-policy changes is handled elsewhere.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: BeyondTrust Remote Support Authentication Bypass
    observables:
    - BeyondTrust Remote Support (formerly Bomgar) versions 26.2.3 and earlier
    - CVE-2026-102764
    - Unauthorized file operations on the B Series appliance
    slug: initial-access-beyondtrust-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Execution of Unrecognized Scripts
    observables:
    - Unrecognized script files on the appliance
    slug: execution-unauthorized-scripts
    tactic: execution
    techniques:
    - T1059
  - name: Account and MFA Manipulation
    observables:
    - Unauthorized account changes
    - Permission or session-policy modifications
    - New MFA registrations on privileged accounts
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1098
    - T1556.006
  - name: Unrecognized Privileged Sessions
    observables:
    - Unrecognized privileged or administrative sessions
    slug: lateral-movement-privileged-sessions
    tactic: lateral-movement
    techniques:
    - T1078
    - T1021
  - name: Detection Evasion via Log Tampering
    observables:
    - Unexpected gaps in logs
    - Unexpected gaps in log forwarding
    slug: defense-evasion-log-tampering
    tactic: defense-evasion
    techniques:
    - T1562.002
  summary: Threat actors are exploiting a critical authentication bypass in BeyondTrust
    Remote Support (CVE-2026-102764) to gain initial access and perform unauthorized
    file operations on vulnerable appliances. Post-exploitation, attackers execute
    unauthorized scripts, establish persistence through account and MFA manipulation,
    and move laterally using unrecognized privileged sessions while tampering with
    log forwarding to evade detection.
series:
  index: 1
  slug: cisa-urges-patching-critical-vulnerability-in-beyondtrust-remote-support
  title: CISA Urges Patching Critical Vulnerability in BeyondTrust Remote Support
  total: 2
severity: critical
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


# BeyondTrust Appliance Compromise and Execution

This hunt targets the exploitation of BeyondTrust Remote Support (formerly Bomgar) appliances. It first identifies affected appliances in the estate, then fans out to search for the outcomes of the authentication bypass: the creation of unrecognized script files and the execution of rare shells or interpreters. By combining inventory scoping with behavioral activity, the hunt identifies compromised appliances even when network-level exploitation logs are missing.

## identify-affected-appliances
<!-- Identify BeyondTrust Remote Support appliances -->
Use software inventory to find these devices regardless of whether they have an active vulnerability finding, to define the search scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Silence means no matching software packages are found in the inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%beyondtrust%' OR LOWER(package_name) LIKE '%bomgar%'
```

## corroborate-activity
<!-- Corroborate file and process activity -->
parallel:
- → rare-shell-execution
- → unrecognized-script-creation
join: → triage-exploitation

## rare-shell-execution
<!-- Rare shell and interpreter execution -->
The query stack-counts the execution of shells and interpreters on appliances so that one-host sessions stand out from fleet-wide activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A shell or interpreter path seen on very few hosts. Silence suggests no
  unusual shell sessions occurred during the window.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT LOWER(process_path) AS shell_path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS run_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (on_disk = 0 OR (LOWER(process_path) LIKE '%/sh' OR LOWER(process_path) LIKE '%/bash' OR LOWER(process_path) LIKE '%/python%' OR LOWER(process_path) LIKE '%/perl' OR LOWER(process_path) LIKE '%/php')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY shell_path HAVING host_count <= 3 ORDER BY host_count ASC, run_count ASC
```

## unrecognized-script-creation
<!-- Unrecognized script file creation -->
Find scripts dropped during exploitation.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Silence means no script creation was recorded.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%.sh' OR LOWER(file_path) LIKE '%.py' OR LOWER(file_path) LIKE '%.pl' OR LOWER(file_path) LIKE '%.php') AND (LOWER(file_path) LIKE '/tmp/%' OR LOWER(file_path) LIKE '/var/tmp/%' OR LOWER(file_path) LIKE '/dev/shm/%' OR LOWER(file_path) LIKE '%/www/%' OR LOWER(file_path) LIKE '%/html/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-exploitation
<!-- Triage exploitation evidence -->
```agent target=hunter
cite: required
context:
- identify-affected-appliances
- rare-shell-execution
- unrecognized-script-creation
max_iterations: 4
objective: Determine if any BeyondTrust appliance shows signs of active exploitation
  based on script drops and rare shell execution.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  scripts or process rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → manual-forensic-review
unavailable: → manual-forensic-review (blind_spot: no-appliance-telemetry)
else: → close-out

## isolate-appliance
<!-- Isolate appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified appliance host. Revoke all active support sessions and rotate credentials.
```
→ manual-forensic-review

## manual-forensic-review
<!-- Manual forensic review -->
```manual target=analyst
Review appliance syslog and web logs if available. Examine the dropped scripts and their contents to understand the attacker's intent.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts examined, the presence of vulnerable software, and any suspicious file or process activity found.
```
→ end
