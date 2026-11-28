---
analysis: "Detecting every new Okta login location creates significant noise. This\
  \ hunt solves that by pivoting to cross-surface behavioral impact\u2014bulk cloud\
  \ API reads and ransomware command-line markers\u2014to confirm intent."
blind_spots:
- id: limited-endpoint-visibility
  question: whether ransomware markers exist on hosts without EDR coverage
  requires: hb_process_activity with command line support on all hosts
  risk: A host without process logging could perform mass encryption without being
    detected by the behavioral query.
  stage: impact-data-theft-and-encryption
- id: vishing-visibility
  question: the initial vishing call that enabled the credential theft
  requires: corporate VOIP or phone logs
  risk: The hunt can see the successful takeover login but lacks visibility into the
    social engineering attempt that preceded it.
  stage: credential-access-sso-takeover
coverage:
- stage: credential-access-sso-takeover
  status: covered
  steps:
  - okta-mfa-less-logons
- stage: impact-data-theft-and-encryption
  status: covered
  steps:
  - bulk-data-access
  - ransomware-behavioral-markers
- reason: Belongs to another part of the 'The story behind the intelligence' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'The story behind the intelligence' series.
  stage: execution-infostealer-malware
  status: out_of_scope
- reason: Belongs to another part of the 'The story behind the intelligence' series.
  stage: credential-access-browser-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The theft of millions of patient records through vishing-driven SSO
    takeover is a confirmed high-impact threat; verifying the integrity of MFA-less
    sessions is a business requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed SSO protections using stolen credentials and
  is now performing bulk data exfiltration or deploying ransomware across the environment.
labels:
- hunt
- attack.t1555
- attack.t1486
- attack.t1566
name: SSO Takeover and Data Impact
parameters:
  impact_markers:
    default:
    - vssadmin.exe
    - wbadmin.exe
    - bcdedit.exe
    - cipher.exe
    description: Process names associated with shadow copy deletion or volume modification
      during ransomware impact.
    from:
      kind: article
      observed: '2026-09-03'
      ref: talos-beers-with-talos
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the lead query to focus the search;
      leave empty to scan the entire estate.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: hunt-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the initial lead query on successful Okta sign-ins. If results are
  sparse, widen the scope to include failed logins with status_detail indicating MFA
  was required but not completed.
references:
- name: "Cisco Talos \u2014 The story behind the intelligence"
  url: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
related:
- hunt: infostealer-browser-artifact-cleanup
  reason: Identifying the initial infostealer malware that harvested the credentials
    is the focus of a separate hunt.
  relation: out-of-scope-alternative
- hunt: infostealer-execution-browser-credential-harvesting
  relation: follows
scenario:
  stages:
  - name: Vishing and Phishing Kits
    observables:
    - vishing calls to employees
    - obfuscated JavaScript phishing kits
    - content.js
    - malicious unofficial downloads
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Infostealer and Tool Execution
    observables:
    - VID001.exe
    - NetGuard.exe
    - SECOH-QAD.exe
    - sample.exe
    - d4aa3e7010220ad1b458fac17039c274_62_Exe.exe
    - w32.9f1f11a708-100.sbx.tg
    - win.dropper.miner
    slug: execution-infostealer-malware
    tactic: execution
    techniques:
    - T1566
  - name: Browser Credential and Cookie Harvesting
    observables:
    - saved browser passwords
    - browser login cookies
    - credentials for local applications
    slug: credential-access-browser-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Okta SSO Account Takeover
    observables:
    - stolen credentials used for Okta single sign-on accounts
    - unauthorized Okta session established
    slug: credential-access-sso-takeover
    tactic: credential-access
    techniques:
    - T1555
  - name: Data Exfiltration and Ransomware
    observables:
    - 284 million patient records stolen
    - Azim sucks text string in ransomware code
    - unauthorized file encryption
    slug: impact-data-theft-and-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors such as ShinyHunters leverage vishing and obfuscated JavaScript
    phishing kits to harvest credentials and session cookies from employees. These
    stolen identities are then utilized to bypass Okta SSO protections, enabling large-scale
    data exfiltration and the deployment of infostealers or ransomware.
series:
  index: 2
  slug: the-story-behind-the-intelligence
  title: The story behind the intelligence
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# SSO Takeover and Data Impact

This hunt investigates the critical sequence from identity compromise to high-impact data operations. It starts by identifying successful Okta sign-ins that occurred without MFA, establishing a baseline of potentially compromised accounts and the hosts used for access. The hunt then branches into two parallel investigations of adversary intent: mass data access in cloud environments and the presence of ransomware-specific process markers on the identified hosts. An agent evaluates the combined evidence to determine if the sign-ins correlate with malicious impact, specifically looking for actor-specific strings like azim sucks and bulk record theft.

## okta-mfa-less-logons
<!-- Identify MFA-less Okta sign-ins -->
Identify successful Okta logins where MFA was not utilized, establishing a lead for potential account takeover using stolen credentials.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames and usernames that successfully authenticated without
  MFA. Silence means every successful Okta login during the window recorded an MFA
  check.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- event_type
- mfa
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, event_type, mfa, time FROM hb_auth_signin WHERE provider = 'okta' AND status_id = 1 AND (mfa IS NULL OR mfa = 'false' OR mfa = 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## impact-parallel
<!-- Investigate parallel impact vectors -->
parallel:
- → bulk-data-access
- → ransomware-behavioral-markers
join: → triage-agent

## bulk-data-access
<!-- Detect bulk cloud read operations -->
Find users performing an unusually high volume of read operations, which is indicative of automated exfiltration following an SSO takeover.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific accounts making thousands of read requests in a short window. Silence
  indicates no mass-read behavior was recorded.
prevalence:
  by: api_operation
  key:
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- api_operation
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT actor_user_name, api_operation, COUNT(*) AS call_count, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation HAVING call_count > 1000 ORDER BY call_count DESC
```

## ransomware-behavioral-markers
<!-- Ransomware behavioral markers -->
Identify process execution that matches common ransomware patterns or contains actor-specific strings on the scoped hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, impact_markers=impact_markers)
~~~yaml
expected: Rows containing ransomware utility execution or the specific azim sucks
  string. Silence suggests no such markers were observed on the specified hosts.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{impact_markers}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%azim%sucks%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh sign-in and impact evidence -->
```agent target=hunter
cite: required
context:
- okta-mfa-less-logons
- bulk-data-access
- ransomware-behavioral-markers
max_iterations: 4
objective: Determine if any host or user account from the lead query is responsible
  for the bulk cloud reads or endpoint ransomware markers.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing the
  exact rows from all context steps.
tools:
- endpoint
- identity
```

## response-decision
<!-- Route on triage verdict -->
if~: "the triage-agent verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: limited-endpoint-visibility)
else: → close-out-hunt

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and revoke the associated Okta session and user credentials.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the specific S3 buckets or mailbox objects accessed in the bulk-data-access query and verify the integrity of the process binaries that emitted ransomware markers.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Summarize the number of MFA-less logins analyzed and identify any regions or accounts missing hb_cloud_api_activity coverage.
```
→ end
