---
analysis: This hunt pivots from an evasion lead to two different kinds of impact (credential
  theft and high-velocity encryption). A single rule cannot easily correlate stealthy
  binary execution with mass file modification while excluding administrative noise
  across multiple surfaces.
blind_spots:
- id: missing-endpoint-telemetry
  question: Can we see mass encryption if it happens on an unmonitored disk or network
    mount?
  requires: hb_file_activity on all drives
  risk: An adversary could encrypt shared network drives from a machine without an
    agent, or on a drive excluded from monitoring, causing the encryption check to
    return zero rows.
  stage: ransomware-data-encryption
- id: in-memory-theft
  question: Are credentials stolen directly from memory without touching the browser
    files?
  requires: hb_process_activity showing handle access to LSASS
  risk: Sophisticated infostealers that read from memory (LSASS) rather than files
    will not be identified by the credential-access-check.
  stage: credential-theft-infostealers
coverage:
- stage: evasive-execution-and-rmm
  status: covered
  steps:
  - lolbas-execution-lead
- stage: credential-theft-infostealers
  status: covered
  steps:
  - credential-access-check
- stage: ransomware-data-encryption
  status: covered
  steps:
  - ransomware-activity-check
- reason: Belongs to another part of the 'When confusion reigns, trusted vendors must
    guide their SMB customers' series.
  stage: inbound-application-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'When confusion reigns, trusted vendors must
    guide their SMB customers' series.
  stage: phishing-and-email-compromise
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SMBs are frequent targets for destructive ransomware and credential
    theft. A negative result across the estate confirms that these high-impact post-compromise
    behaviors are not active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using signed system binaries to proxy execution of infostealers
  or ransomware, transitioning from stealthy credential harvesting to mass file encryption.
labels:
- hunt
- attack.t1218
- attack.t1555
- attack.t1078
- attack.t1486
- credential access
- defense evasion
- impact
- initial access
name: Post-Compromise Evasion and Ransomware Impact
parameters:
  credential_filenames:
    default:
    - login data
    - cookies
    - history
    - credentials
    - masterkey
    - key3.db
    - key4.db
    description: Specific filenames associated with browser and system credential
      stores.
    from:
      kind: article
      observed: '2024-11-02'
      ref: infostealer-mechanics
    type: list[string]
  lolbas_paths:
    default:
    - c:\windows\system32\mshta.exe
    - c:\windows\syswow64\mshta.exe
    - c:\windows\system32\certutil.exe
    - c:\windows\system32\regsvr32.exe
    - c:\windows\system32\rundll32.exe
    description: Full paths to common binaries used for system binary proxy execution.
    from:
      kind: article
      observed: '2024-11-02'
      ref: lolbas-project
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-02'
      ref: hunt-standard-lookback
    type: number
  ransom_note_filenames:
    default:
    - readme.txt
    - decrypt.txt
    - how_to_back.txt
    - ransom.txt
    - instruction.txt
    description: Common file names for ransomware instructions.
    from:
      kind: article
      observed: '2024-11-02'
      ref: ransomware-trends-2024
    type: list[string]
  scope_hosts:
    default: []
    description: Hosts identified in the lead step; populate this to scope the corroboration
      queries.
    from:
      kind: manual
      observed: '2024-11-02'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/business-security/when-confusion-reigns-trusted-vendors-guide-smb-customers/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations and file servers. Workstations are the primary beachhead
  for LOLBAS and infostealers, while file servers provide visibility into mass encryption
  impact.
references:
- name: "ESET \u2014 When confusion reigns, trusted vendors must guide their SMB customers"
  url: https://www.welivesecurity.com/en/business-security/when-confusion-reigns-trusted-vendors-guide-smb-customers/
related:
- hunt: phishing-and-email-compromise-triage
  reason: Initial access via phishing is a precursor to these behaviors but is handled
    by its own hunt.
  relation: out-of-scope-alternative
- hunt: initial-access-external-apps-phishing
  relation: follows
scenario:
  stages:
  - name: Public-Facing Application Exploitation
    observables:
    - Exploitation of web servers
    - AI-discovered zero-day exploits
    - Manipulation of software update or delivery mechanisms
    - Anomalous HTTP requests targeting vulnerabilities
    slug: inbound-application-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1195
  - name: Phishing and Business Email Compromise
    observables:
    - Emails containing malicious attachments
    - Phishing links delivered via email
    - Unauthorized access to business email accounts
    slug: phishing-and-email-compromise
    tactic: initial-access
    techniques:
    - T1566
  - name: Living off the Land and Unsanctioned RMM
    observables:
    - Execution via signed Microsoft binaries (LOLBAS)
    - Unsanctioned remote monitoring and management (RMM) software
    - Use of 'safe-looking' administrative tools for malicious activity
    slug: evasive-execution-and-rmm
    tactic: defense-evasion
    techniques:
    - T1218
  - name: Infostealers and Credential Harvest
    observables:
    - Infostealer malware execution
    - Searching for credentials in password stores
    - Abuse of compromised valid accounts for session access
    slug: credential-theft-infostealers
    tactic: credential-access
    techniques:
    - T1555
    - T1078
  - name: Data Encryption for Impact
    observables:
    - Deployment of ransomware binaries
    - Mass file encryption on local or remote drives
    - Creation of ransom notes
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Adversaries target SMBs as a pathway into larger supply chains, using phishing
    and exploitation of public-facing applications for initial access. Post-compromise,
    they utilize 'living off the land' techniques and unsanctioned remote monitoring
    and management (RMM) tools to steal credentials and deploy ransomware.
series:
  index: 2
  slug: when-confusion-reigns-trusted-vendors-must-guide-their-smb-customers
  title: When confusion reigns, trusted vendors must guide their SMB customers
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


# Post-Compromise Evasion and Ransomware Impact

This hunt identifies the progression from defense evasion to destructive impact. It begins by identifying LOLBAS binaries performing suspicious network requests. The hunt then fans out to investigate whether these specific hosts show signs of credential theft or high-velocity file encryption. By scoping the impact queries to the suspicious hosts identified in the lead, the hunt distinguishes malicious activity from fleet-wide background noise and administrative maintenance.

## lolbas-execution-lead
<!-- Suspicious System Binary Proxy Execution -->
Find instances of signed Microsoft binaries being used to execute code or fetch content, which often precedes credential theft or ransomware deployment.

```sqlite target=endpoint role=detection-candidate params=(lolbas_paths=lolbas_paths, lookback_days=lookback_days)
~~~yaml
expected: Trusted binaries behaving as downloaders. Silence suggests no obvious LOLBAS
  abuse in this window.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
- process_path
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE instr(',' || '{{lolbas_paths}}' || ',', ',' || LOWER(process_path) || ',') > 0 AND (LOWER(process_cmd_line) LIKE '%http%' OR LOWER(process_cmd_line) LIKE '%ftp%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## impact-analysis
<!-- Analyze Post-Compromise Impact -->
parallel:
- → credential-access-check
- → ransomware-activity-check
join: → intrusion-triage

## credential-access-check
<!-- Access to Credential Stores -->
Identify processes reading browser password and session stores, limited to suspicious hosts to ensure findings are actionable.

```sqlite target=endpoint role=enrichment params=(credential_filenames=credential_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Anomalous processes accessing sensitive credential files. Silence suggests
  no secondary file impact on those machines.
reads:
- device_hostname
- process_name
- file_name
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, process_name, file_name, file_path, time FROM hb_file_activity WHERE activity_id IN (2, 14) AND instr(',' || '{{credential_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransomware-activity-check
<!-- Mass File Activity and Ransom Notes -->
Find high-velocity file modifications or ransom note creation scoped to the suspicious hosts.

```sqlite target=endpoint role=baseline params=(ransom_note_filenames=ransom_note_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process touching many unique files or dropping a ransom note. Silence
  indicates no active mass encryption.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- process_name
- file_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-03'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) AS file_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (activity_id IN (1, 3, 5) OR instr(',' || '{{ransom_note_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_count > 500 OR MAX(CASE WHEN instr(',' || '{{ransom_note_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 THEN 1 ELSE 0 END) = 1
```

## intrusion-triage
<!-- Triage Intrusion Evidence -->
```agent target=hunter
cite: required
context:
- lolbas-execution-lead
- credential-access-check
- ransomware-activity-check
max_iterations: 6
objective: Determine if the observed LOLBAS execution on any host correlates with
  credential theft or mass encryption findings. Ignore traffic to legitimate Microsoft
  domains.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  specific binary and the file impact rows.
tools:
- endpoint
```

## verdict-routing
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host involving both a LOLBAS binary and either credential access or mass file activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: missing-endpoint-telemetry)
else: → analyst-forensic-review

## isolate-host
<!-- Isolate Malicious Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR and revoke all active sessions for users associated with the host.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the agent's citations. Examine the process tree of the identified LOLBAS binary and check for SMB activity from the same process to determine if encryption occurred on network shares.
```
→ close-out

## close-out
<!-- Remediation and Close Out -->
```manual target=analyst
Document the findings. If benign admin noise was found, record those parent processes for future exclusions.
```
→ end
