---
analysis: 'While static rules alert on the malware hashes, this hunt pivots into the
  behavioral aftermath: non-browser processes accessing SQLite files in browser profiles
  and rare processes communicating with ''sbx.tg'' domains. It connects the execution
  to the behavioral context of credential theft.'
blind_spots:
- id: no-process-visibility
  owner: Infrastructure
  question: whether the infostealer ran on unmanaged or legacy systems
  remediation: Audit device inventory against hb_devices and enroll missing endpoints.
  requires: an endpoint agent on every host
  risk: A negative result only covers the enrolled estate; unmanaged servers may remain
    infected.
  stage: execution-infostealer-malware
- id: obfuscated-js-visibility
  owner: Detection Engineering
  question: what the specific commands inside the obfuscated content.js script were
  remediation: Enable PowerShell script block logging and ensure script content is
    captured in hb_script_activity.
  requires: hb_script_activity with de-obfuscation
  risk: The hunt finds the script drop, but cannot observe the in-memory execution
    of its payload.
  stage: initial-access-social-engineering
coverage:
- stage: initial-access-social-engineering
  status: covered
  steps:
  - phishing-kit-indicators
- stage: execution-infostealer-malware
  status: covered
  steps:
  - lead-indicator-execution
  - c2-dns-activity
- stage: credential-access-browser-harvesting
  status: covered
  steps:
  - credential-file-access
- reason: Belongs to another part of the 'The story behind the intelligence' series.
  stage: credential-access-sso-takeover
  status: out_of_scope
- reason: Belongs to another part of the 'The story behind the intelligence' series.
  stage: impact-data-theft-and-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Infostealers are a high-risk precursor to enterprise data breaches.
    A negative result across the enrolled estate provides assurance that current campaigns
    targeting browser credentials have not gained a foothold.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has successfully phished a user and executed an infostealer,
  which is now harvesting browser credentials and cookies from local SQLite databases
  for exfiltration.
labels:
- hunt
- attack.t1566
- attack.t1555
- attack.t1486
name: Infostealer execution and browser credential harvesting
parameters:
  c2_domains:
    default:
    - w32.9f1f11a708-100.sbx.tg
    - w32.228c316455-95.sbx.tg
    - 95.sbx.tg
    - w32.c4dd71e347-95.sbx.tg
    - w32.38d053135d-95.sbx.tg
    description: Sandbox-associated C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
    type: list[domain]
  infostealer_filenames:
    default:
    - VID001.exe
    - NetGuard.exe
    - SECOH-QAD.exe
    - sample.exe
    - content.js
    description: Known filenames associated with malicious infostealer and phishing
      kit drops.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
    type: list[path]
  infostealer_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 228c316455d5ed69232adcbe9acd033092f200014cfa7ed40d6c382f07b19b82
    - a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91
    - c4dd71e347a076ba24bdd2d0ee532ef991c1ef25a2431a19f850942ba2ab16b2
    - 38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    description: Infostealer SHA256 hashes identified by Talos telemetry.
    from:
      kind: article
      observed: '2026-09-03'
      ref: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of history to examine for process, file, and network activity.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the investigation based on the scoping
      step.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: hunt-standard
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying all hosts with browser installations using
  software inventory, then narrows the scope to these hosts for behavioral queries.
  This focuses the investigation on potential targets for credential harvesting.
references:
- name: "Talos \u2014 The story behind the intelligence"
  url: https://blog.talosintelligence.com/the-story-behind-the-intelligence/
related:
- hunt: sso-session-cookie-reuse
  reason: This hunt finds the harvesting of cookies; the sibling hunt looks for their
    use in Okta or Azure AD sign-ins.
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
  index: 1
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
tlp: clear
type: investigation
---


# Infostealer execution and browser credential harvesting

This hunt targets the endpoint-centric phase of infostealer campaigns, where initial malware execution leads to local credential theft. It uses a gated flow: first identifying systems with vulnerable browser targets, then looking for known malware execution. If confirmed, it expands to behavioral queries that identify rare processes accessing browser login data or communicating with sandbox-associated C2 infrastructure. This sequence identifies the activity before stolen session cookies are used to bypass MFA in subsequent SSO takeovers.

## scoping-browsers
<!-- Find hosts with browser installations -->
Identify hosts that serve as primary targets for infostealer harvesting by locating Chrome and Edge installations.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with installed browsers. Silence means no browsers are inventoried,
  which is unlikely in an enterprise environment.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%'
```

## lead-indicator-execution
<!-- Lead infostealer hash execution -->
Identify hosts where known malicious binaries from the Talos report have executed.

```sqlite target=endpoint role=triage params=(infostealer_hashes=infostealer_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows mapping known malicious hashes to execution on specific hosts. Silence
  means these specific variants did not run.
reads:
- device_hostname
- process_name
- process_path
- process_hash_sha256
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_path, process_hash_sha256, user_name, time FROM hb_process_activity WHERE instr(',' || '{{infostealer_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-gatekeeper
<!-- Evaluate lead evidence -->
```agent target=hunter
cite: required
context:
- lead-indicator-execution
max_iterations: 3
objective: Review the lead-indicator-execution results and decide if any malicious
  hashes executed on the estate.
success_criteria: A verdict of malicious or suspicious for at least one host.
tools:
- endpoint
```

## gate-decision
<!-- Gate the behavioral investigation -->
if~: "the lead-gatekeeper verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → behavioral-fan-out
indeterminate: → close-out
unavailable: → close-out
else: → close-out

## behavioral-fan-out
<!-- Behavioral evidence fan-out -->
parallel:
- → credential-file-access
- → c2-dns-activity
- → phishing-kit-indicators
join: → combined-triage

## credential-file-access
<!-- Rare processes reading browser stores -->
Identify processes other than the browser itself reading sensitive SQLite databases containing passwords and session cookies.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process (like a dropped executable or script) reading browser database
  files. Normal browser use generates high access counts; rare processes with low
  counts stand out.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_path, COUNT(*) AS access_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\\user data\\default\\login data%' OR LOWER(file_path) LIKE '%\\user data\\default\\cookies%') AND activity_id = 2 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path HAVING access_count < 15
```

## c2-dns-activity
<!-- DNS activity to sandbox domains -->
Identify network communication with the sandbox-derived C2 domains named in the report.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries for sandbox-generated domains (e.g., w32.c4dd...sbx.tg). Silence
  says nothing if indicators have rotated.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.sbx.tg') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## phishing-kit-indicators
<!-- Phishing kit file drops -->
Search for the presence of the content.js phishing script or other dropped files mentioned in the Talos research.

```sqlite target=endpoint role=enrichment params=(infostealer_filenames=infostealer_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The creation of files like content.js in user profiles, typically preceding
  the harvesting phase.
reads:
- device_hostname
- file_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_name, file_path, actor_user_name, time FROM hb_file_activity WHERE instr(',' || '{{infostealer_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## combined-triage
<!-- Combined behavioral triage -->
```agent target=hunter
cite: required
context:
- lead-gatekeeper
- credential-file-access
- c2-dns-activity
- phishing-kit-indicators
max_iterations: 6
objective: Determine if the evidence supports an active infostealer infection currently
  harvesting credentials on any host.
success_criteria: Verdicts (malicious | suspicious | benign) with specific citations
  for every identified host.
tools:
- endpoint
```

## route-verdict
<!-- Route on final verdict -->
if~: "the combined-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate a password reset for the logged-in user to invalidate potentially harvested session cookies.
```
→ analyst-review

## analyst-review
<!-- Post-hunt analyst review -->
```manual target=analyst
Review the cited evidence of browser store access and DNS activity. If confirmed, identify any secondary payloads or lateral movement attempts and update the C2 indicator list.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record that zero matches were found for the specific infostealer variants and behavioral patterns during the examination period.
```
→ end
