---
analysis: A simple detection rule for 'vssadmin delete shadows' fires on every routine
  maintenance script. This hunt provides context by correlating PsExec movement, rare
  recon tools, and the VSS event over a 14-day window, allowing an analyst to see
  the intrusion timeline rather than an isolated, potentially benign event.
blind_spots:
- id: vss-api-evasion
  question: whether the attacker manipulated shadow copies via direct API calls
  requires: VSS provider COM/API monitoring
  risk: An attacker using a custom tool to call the VSS API directly would bypass
    the process-name-based detection of vssadmin.exe and diskshadow.exe.
  stage: inhibit-recovery-vss
- id: ntds-copy-transparency
  question: whether ntds.dit was copied from a mounted shadow volume
  requires: hb_file_activity with volume mount monitoring
  risk: Many EDRs do not record file access events within temporary shadow volume
    mount points, making the actual theft of the database invisible even if the VSS
    creation is seen.
  stage: credential-access-ntds
coverage:
- stage: lateral-movement-psexec
  status: covered
  steps:
  - psexec-activity
- stage: reconnaissance-discovery
  status: covered
  steps:
  - recon-prevalence
- stage: credential-access-ntds
  status: covered
  steps:
  - vss-abuse-commands
- stage: inhibit-recovery-vss
  status: covered
  steps:
  - vss-abuse-commands
- reason: Bulk file encryption is an after-effect; this hunt aims to find the precursors
    (VSS inhibition) before encryption starts.
  stage: ransomware-impact
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: VSS manipulation is a critical precursor to both AD-wide credential
    theft and ransomware encryption. Because VSS activity is noisy, a multi-stage
    hunt that correlates lateral movement with shadow copy abuse is necessary to identify
    targeted intrusions while minimizing false positives from backup software.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has moved laterally into the environment and is abusing Volume
  Shadow Copy Service utilities to either steal the Active Directory database or inhibit
  system recovery before a ransomware event.
labels:
- hunt
- attack.t1021.001
- attack.t1021.002
- attack.t1003.003
- attack.t1490
- attack.t1486
name: VSS Manipulation and Lateral Movement Correlation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  psexec_names:
    default:
    - psexec.exe
    - psexesvc.exe
    description: Filenames associated with PsExec remote execution.
    type: list[string]
  recon_names:
    default:
    - qwinsta.exe
    - query.exe
    - nslookup.exe
    description: Tools for RDP session enumeration and DNS discovery.
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for the
      entire estate.
    type: list[host]
  vss_names:
    default:
    - vssadmin.exe
    - diskshadow.exe
    description: Utilities used to manipulate volume shadow copies.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/vss-abuse-explained
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on domain controllers and high-value servers first. Admin workstations
  will naturally show high recon tool usage; prioritize servers where VSS manipulation
  is not part of the standard backup workflow.
references:
- name: "Huntress \u2014 How Attackers Abuse VSS, and How Huntress Detects It"
  url: https://www.huntress.com/blog/vss-abuse-explained
related:
- hunt: ntds-dit-theft-via-esentutl
  reason: Attackers may use esentutl.exe or other native tools to copy the AD database;
    this hunt focuses exclusively on the VSS abuse path.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Lateral Movement via PsExec
    observables:
    - psexec.exe
    - SYSTEM-level command shell processes
    - cmd.exe
    slug: lateral-movement-psexec
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: Internal Reconnaissance
    observables:
    - Enumeration of active Remote Desktop sessions
    - DNS enumeration commands
    - Reconnaissance against additional hosts
    - qwinsta
    - query user
    slug: reconnaissance-discovery
    tactic: discovery
    techniques:
    - T1021.001
    - T1018
  - name: NTDS.dit Extraction via VSS
    observables:
    - vssadmin create shadow
    - ntds.dit
    - Active Directory database extraction from shadow copy
    slug: credential-access-ntds
    tactic: credential-access
    techniques:
    - T1003.003
  - name: Inhibit System Recovery
    observables:
    - vssadmin delete shadows /all /quiet
    - Shadow copy deletion via VSSAdmin
    slug: inhibit-recovery-vss
    tactic: impact
    techniques:
    - T1490
  - name: Data Encryption
    observables:
    - Bulk file encryption
    - Ransomware detonation
    slug: ransomware-impact
    tactic: impact
    techniques:
    - T1486
  summary: Attackers leverage Volume Shadow Copy (VSS) to extract sensitive files
    like the Active Directory database (ntds.dit) and delete local backups prior to
    ransomware deployment. Effective detection requires correlating these VSS activities
    with lateral movement via PsExec and internal reconnaissance.
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


# VSS Manipulation and Lateral Movement Correlation

This hunt identifies the progression from lateral movement (PsExec) and internal reconnaissance to the abuse of VSS utilities (vssadmin, diskshadow). While VSS activity is often part of routine backup or RMM workflows, this hunt correlates it with precursor activity—remote service installation and session enumeration—to distinguish malicious intent. By phasing the analysis, we first identify high-risk hosts exhibiting lateral movement and then examine them for subsequent credential theft or recovery inhibition.

## identify-servers
<!-- Identify domain controllers and servers -->
Scope the hunt to Windows server infrastructure where ntds.dit or volume backups are most critical.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames belonging to the server estate. Silence means no Windows
  servers were found in the inventory.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%server%' OR LOWER(package_name) LIKE '%active directory%') AND LOWER(vendor_name) LIKE '%microsoft%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## precursor-fan-out
<!-- Identify lateral movement and recon precursors -->
parallel:
- → psexec-activity
- → recon-prevalence
join: → early-stage-triage

## psexec-activity
<!-- PsExec remote execution activity -->
Find instances of PsExec service installation or execution, common for moving to domain controllers.

```sqlite target=endpoint role=baseline params=(psexec_names=psexec_names, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Process starts for psexesvc.exe or psexec.exe. Benign admin use is common,
  but should be rare on non-admin hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{psexec_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## recon-prevalence
<!-- Prevalence of reconnaissance tools -->
Stack-count the use of enumeration tools like qwinsta or nslookup to find outliers that deviate from standard admin hygiene.

```sqlite target=endpoint role=baseline params=(recon_names=recon_names, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of hosts using recon tools rarely. High host counts likely indicate
  standard RMM inventory tasks.
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
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, GROUP_CONCAT(DISTINCT device_hostname) AS hosts FROM hb_process_activity WHERE instr(',' || '{{recon_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 5
```

## early-stage-triage
<!-- Evaluate early-stage precursors -->
```agent target=hunter
cite: required
context:
- psexec-activity
- recon-prevalence
max_iterations: 3
objective: Summarize hosts where PsExec and rare reconnaissance tools (qwinsta/nslookup)
  were used in the same time window. Flag these as 'high-risk targets' for the next
  phase.
success_criteria: A per-host assessment of precursor activity.
tools:
- endpoint
```

## vss-abuse-commands
<!-- VSS utility abuse commands -->
Detect explicit commands to create shadow copies (credential theft) or delete them (ransomware impact).

```sqlite target=endpoint role=detection-candidate params=(vss_names=vss_names, lookback_days=lookback_days)
~~~yaml
expected: Command lines using vssadmin or diskshadow to manipulate snapshots. Silence
  does not prove absence if the attacker uses custom API calls.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{vss_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(process_cmd_line) LIKE '%shadow%' AND (LOWER(process_cmd_line) LIKE '%create%' OR LOWER(process_cmd_line) LIKE '%delete%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## intrusion-chain-agent
<!-- Correlate intrusion chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- vss-abuse-commands
max_iterations: 5
objective: Review the high-risk hosts from the first agent and determine if the VSS
  commands observed in 'vss-abuse-commands' occur within the same session or shortly
  after the lateral movement/recon. Cite the specific timeline per host.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## routing-decision
<!-- Route based on verdict -->
if~: "the intrusion-chain-agent reports a malicious or suspicious sequence on at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: vss-api-evasion)
else: → hunt-closure

## isolate-endpoint
<!-- Isolate high-risk endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately and preserve evidence for manual review.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Manual analyst review -->
```manual target=analyst
Examine the hosts identified by the agent. Review process lineage starting from PsExec to VSS commands. Check for concurrent file activity on C:\Windows\NTDS\ntds.dit or C:\Windows\System32\config\SAM.
```
→ end

## hunt-closure
<!-- Hunt closure and documentation -->
```manual target=analyst
Record the hosts that were scoped and the observed baseline for VSS activity. Note any routine scripts that caused noise for exclusion in future runs.
```
→ end
