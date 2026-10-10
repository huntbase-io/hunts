---
analysis: 'A single rule on a trojan hash might be dismissed as a False Positive or
  PUAs. This hunt correlates the initial access with two critical follow-on behaviors:
  kernel driver tampering (BYOVD) and mass file encryption. The analyst weighs these
  across three different telemetry surfaces to confirm a high-confidence intrusion.'
blind_spots:
- id: telemetry-gap-impairment
  question: whether the adversary successfully disabled logging before the encryption
    phase began
  requires: EDR driver-load telemetry and kernel activity logs
  risk: A successful BYOVD attack may blind the EDR agent, meaning the ransomware
    impact results would be empty even if encryption occurred.
  stage: kernel-driver-edr-impairment
- id: entropy-analysis-limitation
  question: whether a domain is algorithmically generated (DGA) or highly entropic
  requires: native entropy-calculating query functions
  risk: DNS detection relies on length and known patterns; true DGA or high-entropy
    domains might be missed without a specialized analysis surface.
  stage: trojanized-utility-execution
coverage:
- stage: trojanized-utility-execution
  status: covered
  steps:
  - scoping-by-process
  - file-drops-persistence
- stage: ai-analysis-evasion-obfuscation
  status: covered
  steps:
  - early-triage-agent
- stage: kernel-driver-edr-impairment
  status: covered
  steps:
  - byovd-driver-load
- stage: ransomware-data-encryption
  status: covered
  steps:
  - ransomware-impact
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: citrix-netscaler-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Making sure the checks get printed' series.
  stage: lawful-access-identity-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The MANTLEMAZE and Warlock ransomware chain uses sophisticated AI-evasion
    and kernel-impairment techniques that bypass traditional single-point detections.
    This phased hunt ensures that even if one stage is evasive, the correlation of
    the full attack lifecycle provides a definitive result.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained access via trojanized software containing AI-analysis
  evasion code, then loaded vulnerable drivers to disable security tools before executing
  ransomware.
labels:
- hunt
- attack.t1195.002
- attack.t1027
- attack.t1562.001
- attack.t1068
- attack.t1486
- defense evasion
- execution
- impact
- initial access
name: Trojanized Utilities and Kernel EDR Impairment
parameters:
  c2_domains:
    default:
    - w32.9f1f11a708-100.sbx.tg
    - w32.fed979f93b-95.sbx.tg
    - w32.9896a6fcb9-95.sbx.tg
    - pulsebrowser.29kh.in12.talos
    - w32.58d6fec4ba-95.sbx.tg
    description: Malicious domains used for C2 or infrastructure associated with the
      campaign.
    from:
      kind: article
      observed: '2026-10-08'
      ref: talos-making-sure-checks-printed
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-25'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Restrict the hunt to these hostnames; leave empty to hunt across
      the entire estate.
    from:
      kind: manual
      observed: '2024-10-25'
      ref: analyst-defined
    type: list[host]
  trojan_hashes:
    default:
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    - 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f
    - 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
    description: SHA256 hashes of trojanized utilities and MANTLEMAZE samples.
    from:
      kind: article
      observed: '2026-10-08'
      ref: talos-making-sure-checks-printed
    type: list[hash]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/making-sure-the-checks-get-printed/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying any host running the reported hashes or processes
  matching the trojan names. Also include a wide behavioral scoop for processes running
  from user folders with non-system integrity, as these are common staging areas for
  trojanized utilities.
references:
- name: "Cisco Talos \u2014 Making sure the checks get printed"
  url: https://blog.talosintelligence.com/making-sure-the-checks-get-printed/
related:
- hunt: citrix-netscaler-zero-day-exploitation
  reason: Initial access via Citrix CVE-2026-88779 is a network appliance intrusion
    and is handled in a separate hunt.
  relation: out-of-scope-alternative
- hunt: perimeter-identity-abuse-hunt
  relation: follows
scenario:
  stages:
  - name: Citrix NetScaler Vulnerability Exploitation
    observables:
    - CVE-2026-88779
    - Memory overflow in Citrix NetScaler
    slug: citrix-netscaler-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Abuse of Lawful Identity Access
    observables:
    - Abuse of Danish company lawful access to CPR system
    slug: lawful-access-identity-abuse
    tactic: initial-access
    techniques:
    - T1078
  - name: Trojanised Software Execution
    observables:
    - KMSAuto Net.exe
    - SECOH-QAD.exe
    - PulseBrowser.29kh.in12.Talos
    - 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
    - fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
    - 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
    - 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
    slug: trojanized-utility-execution
    tactic: execution
    techniques:
    - T1195
  - name: AI-Analysis Evasion (A3)
    observables:
    - Plaintext imperative language instructions in binaries
    - Template spraying designed to trick LLMs
    - Instructions telling AI to ignore files
    slug: ai-analysis-evasion-obfuscation
    tactic: defense-evasion
    techniques:
    - T1027
  - name: Kernel driver EDR Impairment
    observables:
    - Abusing vulnerable drivers to disable EDR from kernel space
    - MANTLEMAZE driver abuse
    slug: kernel-driver-edr-impairment
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1068
  - name: Ransomware Encryption
    observables:
    - Warlock ransomware activity
    - Encryption of water utility and telecom systems
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Mantlemaze and other threat actors are employing 'AI-Analysis Evasion'
    (A3) by embedding natural-language instructions in malware to trick automated
    scrutiny, often pairing it with kernel-level driver abuse to disable EDR. These
    techniques are observed alongside high-impact threats including vulnerabilities
    in Citrix NetScaler and ransomware attacks by groups like Warlock.
series:
  index: 2
  slug: making-sure-the-checks-get-printed
  title: Making sure the checks get printed
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


# Trojanized Utilities and Kernel EDR Impairment

This hunt identifies the full lifecycle of an endpoint intrusion starting with trojanized utility execution, such as KMSAuto or PulseBrowser, which incorporates A3 (AI-Analysis Evasion) techniques. It follows the chain from initial access to kernel-level defense evasion using BYOVD (Bring Your Own Vulnerable Driver) and concludes with mass file encryption indicative of Warlock ransomware. The phased approach ensures that later impact signals are analyzed in the context of the initial beachhead.

## scoping-by-process
<!-- Scope by trojanized utility execution -->
Identify initial beachheads by matching malicious processes by hash, original filename, or behavioral traits in user-writable paths.

```sqlite target=endpoint role=scoping params=(trojan_hashes=trojan_hashes, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts running reported malware or suspicious, unnamed binaries
  from user folders. Results define the scope for the rest of the hunt.
reads:
- device_hostname
- integrity_level
- process_hash_sha256
- process_name
- process_original_file_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_hash_sha256, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{trojan_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0 OR LOWER(process_original_file_name) IN ('kmsauto net.exe', 'secoh-qad.exe', 'sample.exe', 'f_003914.exe') OR (LOWER(process_name) LIKE '%\kmsauto net.exe' OR LOWER(process_name) LIKE '%\secoh-qad.exe' OR LOWER(process_name) LIKE '%\sample.exe') OR ( (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\downloads\%') AND integrity_level != 'System' AND (process_original_file_name IS NULL OR process_original_file_name = '') ) ) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-initial-evidence
<!-- Gather initial intrusion evidence -->
parallel:
- → dns-to-c2
- → file-drops-persistence
join: → early-triage-agent

## dns-to-c2
<!-- DNS queries to C2 or high-entropy domains -->
Detect network beacons to known malicious domains or anomalous high-entropy domains on scoped hosts.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS resolutions for reported C2 domains or long, complex hostnames which
  may represent DGA or C2 rotation. Silence suggests the beaconing infrastructure
  has rotated.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookups, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LENGTH(query_hostname) > 24 AND LOWER(query_hostname) NOT LIKE '%.local%' AND LOWER(query_hostname) NOT LIKE '%.internal%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## file-drops-persistence
<!-- Persistent file drops on scoped hosts -->
Identify filesystem artifacts matching the reported malware hashes on the scoped hosts.

```sqlite target=endpoint role=enrichment params=(trojan_hashes=trojan_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Confirmed presence of reported trojanized files on disk. Silence means the
  samples were run in-memory or using different hashes.
reads:
- device_hostname
- file_hash_sha256
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, file_path, file_hash_sha256, process_name, time FROM hb_file_activity WHERE instr(',' || '{{trojan_hashes}}' || ',', ',' || LOWER(file_hash_sha256) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage-agent
<!-- Early-stage beachhead triage -->
```agent target=hunter
cite: required
context:
- scoping-by-process
- dns-to-c2
- file-drops-persistence
max_iterations: 3
objective: Determine if the scoped hosts are confirmed beachheads. Specifically look
  for evidence of A3 evasion, such as binaries that have been flagged by AV but show
  execution, or unusual process trees originating from the trojanized utilities.
success_criteria: A per-host verdict citing specific rows from the process and DNS
  results.
tools:
- endpoint
```

## parallel-impact
<!-- Hunt for post-exploitation defense evasion and impact -->
parallel:
- → byovd-driver-load
- → ransomware-impact
join: → follow-on-triage-agent

## byovd-driver-load
<!-- Kernel EDR impairment via BYOVD -->
Identify rare driver loads across the fleet that may represent the use of vulnerable drivers to disable security agents.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts loading rare drivers. Fleet-wide rarity is a strong indicator
  of manual BYOVD tampering to impair security tools.
prevalence:
  by: device_hostname
  key:
  - driver_path
  rare_below: 3
reads:
- device_hostname
- driver_path
- driver_signature_subject
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, driver_path, driver_signature_subject, COUNT(*) as loads, MIN(time) as first_seen FROM hb_kernel_extension_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING COUNT(DISTINCT device_hostname) <= 3
```

## ransomware-impact
<!-- High-volume file encryption (Impact) -->
Identify mass file modification activity indicative of ransomware encryption, grouping by file extension.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A process modifying over 1000 files, likely with a consistent extension.
  This distinguishes ransomware from typical application updates or temporary file
  cleanup.
reads:
- activity_id
- device_hostname
- file_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, process_name, SUBSTR(file_name, INSTR(file_name, '.') + 1) as extension, COUNT(*) as file_count, MIN(time) as first_op FROM hb_file_activity WHERE activity_id IN (4, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING file_count > 1000
```

## follow-on-triage-agent
<!-- Complete attack chain assessment -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- byovd-driver-load
- ransomware-impact
max_iterations: 6
objective: Evaluate the full attack chain. Confirm whether hosts with a confirmed
  beachhead (from Agent 1) have subsequently loaded rare drivers and performed mass
  file encryption.
success_criteria: A per-host verdict of malicious | suspicious, citing drivers and
  file counts.
tools:
- endpoint
```

## route-decision
<!-- Route on verdict -->
if~: "the follow-on-triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: telemetry-gap-impairment)
else: → closure

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active credentials or administrative sessions that were active on the host at the time of the trojan execution.
```
→ analyst-review

## analyst-review
<!-- Forensic analyst review -->
```manual target=analyst
Review the binaries found on the scoped hosts for imperative language instructions meant to deceive AI analysts. Identify the vulnerable driver and verify whether its use corresponds to a known MANTLEMAZE variant.
```
→ closure

## closure
<!-- Hunt closure and detection tuning -->
```manual target=analyst
Record the hunt findings. If the ransomware-impact query correctly identified an intrusion, promote it to a standing detection rule. If A3 evasion was identified, ensure future analysis pipelines treat extracted sample text as evidence only.
```
→ end
