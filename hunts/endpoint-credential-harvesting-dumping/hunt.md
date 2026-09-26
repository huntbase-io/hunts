---
analysis: Standard detections alert on static strings like mimikatz.exe. This hunt
  instead looks for any rare binary running from a user-writable path that touches
  browser profiles or invokes registry save commands, catching renamed or custom tools.
blind_spots:
- id: no-file-access-telemetry
  question: Are browser profiles being accessed on hosts where file telemetry is disabled?
  requires: hb_file_activity with process context
  risk: An attacker could harvest browser credentials without being detected by file
    activity queries, leaving only process-based indicators.
  stage: infostealer-browser-harvesting
- id: reflective-loading-blind-spot
  question: Is the attacker using reflective loading to dump memory without command-line
    artifacts?
  requires: hb_module_activity and memory scanning
  risk: Advanced dumping techniques that avoid standard tools or common command-line
    strings like minidump will not be captured by process-based lead queries.
  stage: lsass-memory-dumping
coverage:
- stage: infostealer-browser-harvesting
  status: covered
  steps:
  - lead-process-analysis
  - browser-file-access
- stage: lsass-memory-dumping
  status: covered
  steps:
  - lead-process-analysis
- stage: registry-hive-extraction
  status: covered
  steps:
  - lead-process-analysis
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: external-auth-spraying
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: credential-stuffing-attempts
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: account-takeover-anomalies
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Endpoint credential harvesting is the precursor to lateral movement
    and ransomware; identifying these behaviors allows for eviction before the adversary
    expands their reach.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is harvesting credentials from local browser stores, LSASS
  memory, or Registry hives to facilitate lateral movement, indicated by rare processes
  in user-writable paths performing sensitive file or memory access.
labels:
- hunt
- attack.t1003.001
- attack.t1003
- attack.t1555
- attack.t1078
name: Endpoint Credential Harvesting and Dumping
parameters:
  harvesting_targets:
    default:
    - cookies
    - login data
    - web data
    - local state
    - key4.db
    - logins.json
    description: Common filenames for browser credential and session stores.
    from:
      kind: article
      observed: '2024-09-10'
      ref: huntress-cred-theft
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for harvesting behavior.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for the
      entire estate.
    from:
      kind: manual
      observed: '2024-09-10'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/credential-theft-expanding-your-reach
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and workstations belonging to IT administrators or developers,
  as these are higher-value targets for credential harvesting.
references:
- name: "Huntress \u2014 Credential Theft: How Attackers Steal & Use Stolen Credentials"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: cloud-identity-anomaly-hunt
  reason: This hunt focuses on the endpoint harvest phase; cloud credential abuse
    is covered separately.
  relation: out-of-scope-alternative
- hunt: identity-authentication-account-abuse
  relation: follows
scenario:
  stages:
  - name: Password Spraying and Brute Force
    observables:
    - Single common password tested against many accounts
    - Iterative password guessing against a single account
    - Spikes in authentication failures (activity_id 5)
    - Logins from unfamiliar IP addresses or geographic locations
    slug: external-auth-spraying
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110
  - name: Credential Stuffing
    observables:
    - Authentication attempts using username/password pairs leaked in previous third-party
      breaches
    - High volume of failed login attempts across diverse accounts
    slug: credential-stuffing-attempts
    tactic: credential-access
    techniques:
    - T1110.004
  - name: Infostealer Data Collection
    observables:
    - Access to browser profile directories (e.g., AppData\Local\Google\Chrome\User
      Data)
    - Reading of 'Cookies' and 'Login Data' SQLite databases
    - Exfiltration of harvested credentials to external C2 nodes
    - Processes running from Temp or Downloads directories
    slug: infostealer-browser-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: LSASS Credential Dumping
    observables:
    - procdump -ma lsass.exe
    - rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
    - Execution of Mimikatz or similar tools
    - Creation of .dmp files containing LSASS memory
    slug: lsass-memory-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Registry Hive Extraction
    observables:
    - reg.exe save HKLM\SAM
    - reg.exe save HKLM\SYSTEM
    - reg.exe save HKLM\SECURITY
    - esentutl.exe /y /vss /d
    - Access to %SystemRoot%\System32\config
    slug: registry-hive-extraction
    tactic: credential-access
    techniques:
    - T1003
  - name: Valid Account Abuse and Impossible Travel
    observables:
    - Impossible travel (logins from distant locations in rapid succession)
    - Logins that bypass MFA using stolen session tokens
    - Unauthorized privilege changes or administrative role assignments
    - MFA enrollments for new/unrecognized devices
    slug: account-takeover-anomalies
    tactic: initial-access
    techniques:
    - T1078
  summary: This campaign involves the unauthorized acquisition of credentials via
    phishing, brute force, and infostealers to impersonate legitimate users. Attackers
    then perform credential dumping on compromised endpoints to harvest cached passwords
    and hashes, enabling lateral movement and full account takeover.
series:
  index: 2
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  total: 2
severity: medium
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


# Endpoint Credential Harvesting and Dumping

This hunt identifies the transition from initial execution to credential theft on Windows endpoints. It specifically targets infostealer behavior and standard credential dumping techniques. The hunt finds processes running from user-writable paths like Temp or Downloads and correlates them with access to browser credential stores and the use of LSASS or Registry dumping commands. By evaluating process rarity across the fleet alongside these behaviors, the hunt distinguishes between legitimate administrative tasks and malicious harvesting.

## lead-process-analysis
<!-- Identify suspicious process origins and dumping commands -->
Find processes executing from user-writable paths, those using command-line arguments typical of credential dumping, or processes not present on disk.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts and processes. Matches for LSASS or Registry saves are high-priority;
  matches from Temp paths require rarity analysis.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_cmd_line) LIKE '%lsass%' OR LOWER(process_cmd_line) LIKE '%comsvcs.dll%minidump%' OR (LOWER(process_name) = 'reg.exe' AND LOWER(process_cmd_line) LIKE '%save%') OR on_disk = 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with prevalence and behavior -->
parallel:
- → rare-process-baseline
- → browser-file-access
join: → agent-triage

## rare-process-baseline
<!-- Determine suspicious process prevalence -->
Stack-count the processes found in suspicious paths to identify rare binaries that deviate from the fleet baseline.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries seen on fewer than 5 hosts. Fleet-wide updaters are excluded,
  leaving transient or adversary-controlled tools.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\downloads\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count < 5 ORDER BY host_count ASC
```

## browser-file-access
<!-- Detect access to browser credential stores -->
Identify processes interacting with sensitive browser databases that contain cookies and passwords.

```sqlite target=endpoint role=enrichment params=(harvesting_targets=harvesting_targets, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any non-browser process reading these files is a high-confidence indicator
  of harvesting.
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
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, file_name, activity_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{harvesting_targets}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND NOT (LOWER(process_name) LIKE '%\\chrome.exe' OR LOWER(process_name) LIKE '%\\msedge.exe' OR LOWER(process_name) LIKE '%\\firefox.exe')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Weigh harvesting evidence -->
```agent target=hunter
cite: required
context:
- lead-process-analysis
- rare-process-baseline
- browser-file-access
max_iterations: 4
objective: Identify hosts where unauthorized processes are performing credential dumping
  or browser harvesting by correlating process origins, command lines, fleet rarity,
  and sensitive file access.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing the
  specific process and activity rows.
tools:
- endpoint
```

## decision-route
<!-- Route on harvesting verdict -->
if~: "the agent-triage verdict is malicious for at least one host based on rare processes accessing browser credentials or dumping memory" (confidence: high, judge=hunter)
then: → containment-action
indeterminate: → credential-review-task
unavailable: → credential-review-task (blind_spot: no-file-access-telemetry)
else: → close-out-task

## containment-action
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke all active session tokens for users logged into this machine in the identity provider.
```
→ credential-review-task

## credential-review-task
<!-- Credential reset and investigation -->
```manual target=analyst
Review the cited rows. Confirm the suspicious process activity and force password resets for all accounts identified in the harvesting session. Check hb_network_connection for data exfiltration patterns.
```
→ close-out-task

## close-out-task
<!-- Close out -->
```manual target=analyst
Record what was found, what was blocked, and whether any binaries should be promoted to the permanent blocklist.
```
→ end
