---
analysis: A simple detection rule may catch the comsvcs.dll string, but it cannot
  weigh the prevalence of a binary against the vulnerability status and volumetric
  file modification density of a single host over time.
blind_spots:
- id: incomplete-agent-coverage
  question: Are we seeing all potential endpoint compromises?
  requires: Complete endpoint agent deployment
  risk: Hosts without an agent contribute no process or file activity telemetry, rendering
    the hunt blind to their status.
- id: non-windows-harvesting
  question: Are credentials being harvested on non-Windows endpoints?
  requires: hb_module_activity on Linux/macOS
  risk: The comsvcs.dll technique is Windows-specific; credential dumping on Linux
    (e.g., /etc/shadow access) is not captured by this specific query.
  stage: local-credential-dumping
coverage:
- stage: exploitation-of-vulnerable-applications
  status: covered
  steps:
  - identify-vulnerable-exposed-hosts
- stage: infostealer-harvesting
  status: covered
  steps:
  - rare-user-path-binaries
- stage: local-credential-dumping
  status: covered
  steps:
  - lsass-dumping-via-comsvcs
- stage: impact-and-ransomware-encryption
  status: covered
  steps:
  - high-volume-file-modification
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: phishing-and-aitm-token-theft
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: brute-force-and-spraying
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: identity-abuse-and-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Credential harvesting and ransomware are the most frequent causes
    of high-impact data breaches. Validating the integrity of vulnerable internet-facing
    hosts against these behaviors provides critical risk reduction.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited an internet-facing vulnerability (T1190) and
  is now using local credential dumping or infostealers to harvest credentials before
  initiating a high-volume ransomware encryption event.
labels:
- hunt
- attack.t1190
- attack.t1555
- attack.t1003
- attack.t1003.001
- attack.t1486
name: Endpoint Credential Harvesting and Host Impact
parameters:
  lookback_days:
    default: '14'
    description: Days of endpoint and activity history to examine.
    type: number
  min_file_actions:
    default: '1000'
    description: Minimum number of file modifications/renames in a 30-minute window
      to flag as suspicious.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty to run
      fleet-wide.
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
rationale: The hunt prioritizes hosts identified as internet-exposed and vulnerable.
  If the scoping step returns no results, the subsequent activity queries run estate-wide
  to find opportunistic attacks on unprofiled assets.
references:
- name: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: phishing-and-aitm-token-theft
  reason: This hunt focuses on endpoint-based harvesting; credential theft via phishing/AitM
    requires identity and cloud auth log analysis.
  relation: out-of-scope-alternative
- hunt: identity-plane-authentication-account-abuse
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - Internet-accessible open sockets
    - exposed database services (SQL)
    - unpatched software vulnerabilities
    - misconfigured web servers
    slug: exploitation-of-vulnerable-applications
    tactic: initial-access
    techniques:
    - T1190
  - name: Phishing and AitM Token Theft
    observables:
    - Phishing emails masquerading as Docusign
    - fake login pages capturing usernames and passwords
    - adversary-in-the-middle interception of authentication tokens
    - proxying sessions to bypass MFA
    slug: phishing-and-aitm-token-theft
    tactic: initial-access
    techniques:
    - T1566
    - T1090.003
  - name: Brute Force and Password Spraying
    observables:
    - Spikes in failed login attempts
    - testing common passwords (e.g., Password01) across multiple accounts
    - credential stuffing using data from previous breach dumps
    slug: brute-force-and-spraying
    tactic: credential-access
    techniques:
    - T1110
    - T1110.003
    - T1110.004
  - name: Infostealer Credential Harvesting
    observables:
    - Collection of saved browser passwords
    - theft of browser cookies and session tokens
    - harvesting of autofill data from endpoints
    - infostealer execution disguised as fake downloads or ads
    slug: infostealer-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Local Credential Dumping
    observables:
    - Use of Mimikatz to extract password hashes
    - procdump -ma lsass.exe
    - rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
    - copying SAM, SECURITY, and SYSTEM Registry hives to capture hashes
    slug: local-credential-dumping
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  - name: Abuse of Valid Accounts for Lateral Movement
    observables:
    - Logins from unfamiliar locations
    - impossible travel (logins from two distant locations in a short timeframe)
    - unrequested privilege changes
    - use of legitimate employee credentials to reach internal applications
    slug: identity-abuse-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Impact and Ransomware Encryption
    observables:
    - Encryption of files and data
    - ransomware notes
    - business email compromise involving fraudulent wire transfers
    slug: impact-and-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors use phishing, adversary-in-the-middle (AitM) attacks, and
    infostealers to obtain valid credentials and session tokens. These stolen identities
    fuel lateral movement, privilege escalation, and credential dumping to achieve
    high-impact outcomes like business email compromise and ransomware.
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


# Endpoint Credential Harvesting and Host Impact

This hunt identifies the host-level progression of a credential-theft campaign. It begins by correlating vulnerabilities with internet exposure, then branches to investigate three distinct endpoint behaviors: rare binaries executing from user-writable paths (infostealers), the use of comsvcs.dll for LSASS memory dumping, and volumetric file modification activity characteristic of ransomware encryption. By joining these disparate signals, the hunt identifies high-confidence host compromises that individual detection rules may miss.

## identify-vulnerable-exposed-hosts
<!-- Identify Vulnerable and Exposed Hosts -->
Correlate critical vulnerabilities with known internet-facing assets to identify the highest-risk targets for initial exploitation.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts that are both internet-exposed and carry critical vulnerabilities.
  Silence indicates no currently known overlap between exposed assets and unpatched
  findings.
reads:
- device_uid
- hostname
- cve_uid
- affected_package_name
- domain_or_ip
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT v.device_uid, d.hostname AS device_hostname, v.cve_uid, v.affected_package_name, e.domain_or_ip AS exposed_as FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid AND v.provider = d.provider JOIN hb_exposed_assets e ON (d.ip_address = e.ip_address OR d.hostname = e.domain_or_ip) WHERE v.severity_id >= 4 AND v.status != 'suppressed' AND v.collected_at >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate Endpoint Activity -->
parallel:
- → rare-user-path-binaries
- → lsass-dumping-via-comsvcs
- → high-volume-file-modification
join: → triage-impact

## rare-user-path-binaries
<!-- Rare Binaries in User-Writable Paths -->
Detect infostealers by identifying rare processes executing from paths where users have write permissions, focusing on hosts identified in the scoping step.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries running from user paths that are unique to one or two hosts across
  the estate.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\appdata\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY process_path, process_name HAVING hosts < 3 ORDER BY hosts ASC
```

## lsass-dumping-via-comsvcs
<!-- LSASS Memory Dumping via Comsvcs -->
Detect the use of rundll32 and comsvcs.dll to dump LSASS memory, a built-in method for credential harvesting.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A specific command line execution. Zero rows indicates this specific technique
  was not observed on the monitored estate.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%comsvcs.dll%minidump%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## high-volume-file-modification
<!-- High-Volume File Activity in 30m Buckets -->
Identify potential ransomware encryption by finding bursts of file modifications and renames within short windows.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, min_file_actions=min_file_actions)
~~~yaml
expected: Spikes of file activity that exceed normal user background noise, suggesting
  automated encryption.
reads:
- device_hostname
- actor_user_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, (unixepoch(time) / 1800) AS time_bucket_30m, COUNT(*) AS activity_count FROM hb_file_activity WHERE activity_id IN (3, 5) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, actor_user_name, time_bucket_30m HAVING activity_count > {{min_file_actions}}
```

## triage-impact
<!-- Triage Scoping and Activity Evidence -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-exposed-hosts
- rare-user-path-binaries
- lsass-dumping-via-comsvcs
- high-volume-file-modification
max_iterations: 4
objective: Determine if any host shows a sequence of compromise from vulnerability
  to credential harvesting or ransomware impact.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing relevant
  rows from the scoped and behavior steps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "The triage verdict is malicious for any host exhibiting LSASS dumping or high-volume file modifications." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-agent-coverage)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all active session tokens for the actor_user_name identified in the high-volume-file-modification step.
```
→ analyst-review

## analyst-review
<!-- Analyst Investigation -->
```manual target=analyst
Review the process and file activity. For rare binaries, check if they are unsigned or signed by unusual subjects. Confirm if the file modifications target sensitive data or common document types.
```
→ end

## close-out
<!-- Close Out and Record Gaps -->
```manual target=analyst
Log the examined hosts. Note any high-severity vulnerabilities for patching even if no active exploitation was found.
```
→ end
