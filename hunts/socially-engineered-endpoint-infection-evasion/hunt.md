---
analysis: A simple detection rule for these hashes is easily defeated by the attacker
  re-building the trojanised installer. This hunt correlates the specific lure behavior
  (parents, paths) with subsequent kernel-level evasion and credential theft patterns
  across multiple surfaces.
blind_spots:
- id: edr-blinding-gap
  question: Did the driver successfully terminate the security agent?
  requires: Endpoint telemetry persistence
  risk: A host that reports the initial lure execution and then stops all telemetry
    is likely blinded, creating a critical blind spot.
  stage: defense-evasion-edr-killer
- id: external-lure-blindness
  question: What was the content of the initial social engineering lure?
  requires: Social media logs
  risk: Internal telemetry cannot see the conversation on social media; we only see
    the resulting malware execution.
  stage: social-engineering-elicitation
coverage:
- blind_spot: external-lure-blindness
  reason: Initial social media messaging occurs off-network and is not captured in
    internal telemetry.
  stage: social-engineering-elicitation
  status: not_visible
- stage: trojanised-software-execution
  status: covered
  steps:
  - scope-potential-infections
  - lure-execution-behavior
  - file-drops-by-lure
- stage: defense-evasion-edr-killer
  status: covered
  steps:
  - edr-killer-driver-loads
- stage: credential-access-infostealer
  status: covered
  steps:
  - browser-credential-theft
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: command-and-control-autonomous-ai
  status: out_of_scope
- reason: Belongs to another part of the 'Trust and the enticing consultancy offer'
    series.
  stage: impact-ransomware-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Professional social engineering lures are effective at bypassing
    technical perimeters; a phased hunt that connects human-initiated execution with
    advanced evasion and theft is required to protect high-access personnel.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker uses social engineering lures such as consultancy offers to
  trick users into running trojanised software that installs an EDR killer and steals
  credentials.
labels:
- hunt
- attack.t1566
- attack.t1204
- attack.t1562.001
- attack.t1555
- attack.t1071
name: Socially Engineered Endpoint Infection and Evasion
parameters:
  known_browsers:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    description: Legitimate browser processes to exclude from file-read monitoring.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for lure execution and follow-on activity.
    type: number
  lure_filenames:
    default:
    - sample.exe
    - secoh-qad.exe
    - f_000bc7.exe
    - kmsauto.exe
    - content.js
    description: Filenames of lures reported in the Talos article.
    from:
      kind: article
      observed: '2026-09-24'
      ref: talos
    type: list[string]
  malicious_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    - 540080fea97d88ed902c5e4f9a026b4fcd32ab263706c520e00728f1a29578b8
    - cfa1997682e4ed41bc691ba848d845abbe0b75ec97e640c2b015b4d1624a108a
    - 38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55
    description: Hashes of reported trojanised software from the dossier.
    from:
      kind: article
      observed: '2026-09-24'
      ref: talos
    type: list[hash]
  scope_hosts:
    default: []
    description: Filter results to these hosts; leave empty to hunt across the entire
      estate.
    type: list[host]
  sensitive_files:
    default:
    - login data
    - cookies
    - web data
    - local state
    description: Browser data files targeted by the Rapuncel infostealer.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: common-browser-paths
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize technical staff, project leads, and personnel with external
  social media presence (e.g., speakers, researchers) who are high-value targets for
  consultancy lures.
references:
- name: "Talos \u2014 Trust and the enticing consultancy offer"
  url: https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/
related:
- hunt: autonomous-ai-malware-analysis
  reason: The dossier mentions CLOSEDQUORUM, which represents a separate autonomous
    AI C2 phase follow-on to initial infection.
  relation: follows
scenario:
  stages:
  - name: Consultancy and Job Lure
    observables:
    - Social media messages offering $300/hour for consultancy
    - Sparse consultant profiles with no employer footprint
    - Fake job offers requiring candidate software installation
    slug: social-engineering-elicitation
    tactic: initial-access
    techniques:
    - T1566
  - name: Execution of Trojanised Installer
    observables:
    - Fake LastPass Authenticator installers
    - SECOH-QAD.exe
    - KMSAuto.exe
    - sample.exe
    - f_000bc7.exe
    - content.js
    - Distribution via GitHub repositories
    slug: trojanised-software-execution
    tactic: execution
    techniques:
    - T1204
    - T1566
  - name: Kernel-Level Security Evasion
    observables:
    - Rapuncel kernel-level EDR killer payload
    - Disabling of remote access and alarms
    slug: defense-evasion-edr-killer
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Rapuncel Infostealing
    observables:
    - Rapuncel stealer searching for credentials
    - Accessing protected systems via found credentials
    slug: credential-access-infostealer
    tactic: credential-access
    techniques:
    - T1555
  - name: Autonomous AI-Driven C2
    observables:
    - CLOSEDQUORUM malware binary
    - Delegation of actions to LLM panels via API calls
    - Autonomous C2 decision making
    slug: command-and-control-autonomous-ai
    tactic: command-and-control
    techniques:
    - T1071
  - name: Data Encryption and Impact
    observables:
    - Qilin ransomware incidents
    - The Gentlemen leak-site listings
    - Encryption of files and manipulation of pumping cycles in utility systems
    slug: impact-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: This social engineering campaign targets technical professionals with fake
    consultancy and job offers to distribute trojanised software via platforms like
    GitHub. Successful infections deploy kernel-level EDR killers and 'Rapuncel' infostealers,
    while advanced variants utilize 'CLOSEDQUORUM' for autonomous AI-driven command-and-control
    before final ransomware deployment.
series:
  index: 1
  slug: trust-and-the-enticing-consultancy-offer
  title: Trust and the enticing consultancy offer
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


# Socially Engineered Endpoint Infection and Evasion

This hunt follows the attack chain from the initial human-targeted social engineering lure to the execution of local payloads. It identifies the execution of reported trojanised software, correlates it with the loading of unsigned kernel drivers designed to disable security software, and detects unauthorized access to browser credential stores. By using a phased approach, the hunt connects the initial lure to subsequent high-impact evasion and theft behaviors.

## scope-potential-infections
<!-- Scope potentially infected hosts -->
Identify hosts that have executed binaries matching reported hashes or original filenames.

```sqlite target=endpoint role=scoping params=(malicious_hashes=malicious_hashes, lure_filenames=lure_filenames, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts that executed known indicators. Silence proves that these
  specific lures did not run.
reads:
- device_hostname
- process_original_file_name
- process_hash_sha256
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_original_file_name, process_hash_sha256, COUNT(*) as execution_count FROM hb_process_activity WHERE (instr(',' || '{{malicious_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR instr(',' || '{{lure_filenames}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## initial-infection-fanout
<!-- Fan-out initial infection investigation -->
parallel:
- → lure-execution-behavior
- → file-drops-by-lure
join: → early-stage-read

## lure-execution-behavior
<!-- Lure execution behavior -->
Examine the launch context of the reported lures, including parents and command lines.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, malicious_hashes=malicious_hashes, lure_filenames=lure_filenames, lookback_days=lookback_days)
~~~yaml
expected: Execution events where parents like browser or messaging apps suggest social
  engineering delivery.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- parent_process_name
- process_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, process_hash_sha256, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{malicious_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR instr(',' || '{{lure_filenames}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-drops-by-lure
<!-- File drops by lure processes -->
Identify secondary payloads or scripts dropped by the initial lure binary.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lure_filenames=lure_filenames, lookback_days=lookback_days)
~~~yaml
expected: Creation of new files by processes matching the lure list, indicating installer
  or dropper behavior.
reads:
- device_hostname
- file_path
- file_name
- process_name
- file_hash_sha256
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, file_name, process_name, file_hash_sha256, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{lure_filenames}}' || ',', ',' || REPLACE(LOWER(process_name), RTRIM(LOWER(process_name), REPLACE(LOWER(process_name), '\', '')), '') || ',') > 0 AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-read
<!-- Early stage read -->
```agent target=hunter
cite: required
context:
- scope-potential-infections
- lure-execution-behavior
- file-drops-by-lure
max_iterations: 3
objective: Determine if the execution of reported lures is confirmed on the scoped
  hosts.
success_criteria: A verdict citing specific process and file events.
tools:
- endpoint
```

## follow-on-activity-fanout
<!-- Fan-out follow-on detection -->
parallel:
- → edr-killer-driver-loads
- → browser-credential-theft
join: → follow-on-read

## edr-killer-driver-loads
<!-- EDR killer driver loads -->
Find unsigned or suspicious drivers loading, characteristic of the Rapuncel payload.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Loads of unsigned drivers; these are highly anomalous and used to blind
  security agents.
reads:
- device_hostname
- driver_path
- driver_signature_status
- driver_signed
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, driver_path, driver_signature_status, driver_signature_subject, time FROM hb_kernel_extension_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (driver_signed = 'false' OR driver_signature_status != 'Valid') AND time >= datetime('now', '-{{lookback_days}} days')
```

## browser-credential-theft
<!-- Browser credential theft -->
Detect unauthorized access to browser data files by non-browser processes.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, sensitive_files=sensitive_files, known_browsers=known_browsers, lookback_days=lookback_days)
~~~yaml
expected: Non-browser processes reading sensitive Login Data or Cookies files.
reads:
- device_hostname
- file_path
- file_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{sensitive_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND NOT (instr(',' || '{{known_browsers}}' || ',', ',' || REPLACE(LOWER(process_name), RTRIM(LOWER(process_name), REPLACE(LOWER(process_name), '\', '')), '') || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-read
<!-- Follow-on read -->
```agent target=hunter
cite: required
context:
- early-stage-read
- edr-killer-driver-loads
- browser-credential-theft
max_iterations: 4
objective: Assess the relationship between initial infection (from early-stage-read)
  and the observed driver loads or credential access events.
success_criteria: A final verdict identifying compromised hosts with multiple stage
  hits.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the verdict is malicious for at least one host demonstrating multiple stages of the attack chain" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: edr-blinding-gap)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the user's manager of a potential social engineering incident.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the process and kernel driver evidence. Interview the user to confirm the social media lure source and timing.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Log the negative results and confirm if any scoped hosts failed to report telemetry during the window.
```
→ end
