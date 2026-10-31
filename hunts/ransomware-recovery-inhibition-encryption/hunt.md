---
analysis: This hunt correlates recovery inhibition across process and script surfaces
  with fleet-wide file activity baselining, providing the context needed to distinguish
  a live intrusion from administrative backup maintenance.
blind_spots:
- id: no-vss-api-telemetry
  question: Was the shadow copy deletion performed using direct API calls rather than
    command-line tools?
  requires: Direct VSS API monitoring via EDR
  risk: Adversaries using custom binaries to call VSS APIs directly will not be caught
    by command-line based queries.
  stage: inhibit-recovery-vss-deletion
- id: event-truncation
  question: Did the endpoint sensor truncate high-volume rename events during the
    encryption phase?
  requires: High-fidelity file modification logging
  risk: Mass encryption generates thousands of events; sensor-level truncation can
    mask the scale of the impact.
  stage: impact-data-encryption
coverage:
- stage: inhibit-recovery-vss-deletion
  status: covered
  steps:
  - vss-deletion-lead
  - scripted-shadow-deletion
- stage: impact-data-encryption
  status: covered
  steps:
  - ransom-note-creation
  - mass-encryption-baseline
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Ransomware recovery depends on VSS integrity; identifying its disruption
    confirms a critical disruption of disaster recovery processes.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is inhibiting system recovery by deleting volume shadow copies
  using standard tools or scripts before performing mass file encryption with rare
  extensions.
labels:
- hunt
- attack.t1486
- attack.t1490
- impact
name: Ransomware Recovery Inhibition and Encryption
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  ransom_notes:
    default:
    - readme.txt
    - decrypt.txt
    - restore_files.txt
    - how_to_decrypt.html
    description: Common filenames for ransom notes.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: common-ransom-notes
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the investigation.
    type: list[host]
  vss_tools:
    default:
    - vssadmin.exe
    - wmic.exe
    - powershell.exe
    - pwsh.exe
    description: Binary names of tools used to delete shadow copies.
    from:
      kind: article
      observed: '2026-10-14'
      ref: huntress-vss
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/microsoft-vss-limits-and-best-practices
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on file servers and database servers where VSS snapshots are critical
  for recovery. Start with any host showing vssadmin or wmic deletion activity.
references:
- name: 'Microsoft VSS: Still Essential, But Not the Whole Story'
  url: https://www.huntress.com/blog/microsoft-vss-limits-and-best-practices
related:
- hunt: ransomware-exfiltration-detection
  reason: Data exfiltration typically precedes encryption and requires network/cloud
    telemetry analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: VSS Snapshot Deletion
    observables:
    - vssadmin.exe delete shadows /all /quiet
    - wmic.exe shadowcopy delete
    - powershell.exe -Command Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete()
      }
    - Execution of vssadmin.exe with administrative privileges
    slug: inhibit-recovery-vss-deletion
    tactic: impact
    techniques:
    - T1490
  - name: Data Encryption for Impact
    observables:
    - High volume of file modification events
    - Creation of ransom notes (e.g., .txt, .html files in multiple directories)
    - Renaming of files to include ransomware-specific extensions
    - Modification of files on SQL Server or Active Directory database volumes
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Ransomware operators frequently target the Windows Volume Shadow Copy Service
    (VSS) to delete local snapshots before or during the encryption process. By inhibiting
    system recovery, adversaries ensure that victims cannot use 'Previous Versions'
    or other local restore points to recover data, thereby increasing the likelihood
    of ransom payment.
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


# Ransomware Recovery Inhibition and Encryption

This hunt identifies the destructive impact phase of a ransomware intrusion by looking for recovery inhibition and data encryption. It lead-scopes the estate for the use of VSS-manipulation tools, then fans out to corroborate this with scripted shadow copy deletion, the creation of known ransom-note filenames, and fleet-wide anomalous file rename activity. An agent evaluates the combined evidence to distinguish between legitimate administrative maintenance and a live ransomware event.

## vss-deletion-lead
<!-- Lead: VSS Snapshot Deletion Command -->
Identify execution of tools known to delete shadow copies by matching binary names and looking for deletion keywords in the command line.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, vss_tools=vss_tools, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing specific hosts and processes attempting shadow copy deletion.
  Silence suggests no obvious recovery inhibition via command line tools.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_original_file_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{vss_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{vss_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (instr(LOWER(process_cmd_line), 'delete') > 0 AND instr(LOWER(process_cmd_line), 'shadow') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-evidence
<!-- Corroborate Recovery Inhibition and Impact -->
parallel:
- → scripted-shadow-deletion
- → ransom-note-creation
- → mass-encryption-baseline
join: → agent-triage

## scripted-shadow-deletion
<!-- Scripted WMI Shadow Copy Deletion -->
Find programmatic shadow copy deletion in script blocks that might bypass process monitoring.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks calling the WMI Delete method on shadow objects. Silence proof
  of absence depends on script block logging coverage.
reads:
- device_hostname
- script_name
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, script_name, script_content, actor_user_name, time FROM hb_script_activity WHERE (instr(LOWER(script_content), 'win32_shadowcopy') > 0 AND instr(LOWER(script_content), '.delete()') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransom-note-creation
<!-- Ransom Note Creation -->
Find creation of files matching a known list of ransom-note names.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ransom_notes=ransom_notes)
~~~yaml
expected: Creation of files like readme.txt or decrypt.txt in multiple directories.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{ransom_notes}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mass-encryption-baseline
<!-- Mass Renames to Rare Extensions -->
Stack-count file renames to identify anomalous volume of extensions that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A high volume of renames to a single extension that is not common across
  the fleet.
prevalence:
  by: device_hostname
  key:
  - extension
  rare_below: 3
reads:
- device_hostname
- file_name
- activity_id
- time
- process_name
- actor_user_name
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, actor_user_name AS user_name, LOWER(SUBSTR(file_name, INSTR(file_name, '.') + 1)) AS extension, COUNT(*) AS event_count, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 5 AND file_name LIKE '%.%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name, user_name, extension HAVING event_count > 500
```

## agent-triage
<!-- Evaluate Evidence Triage -->
```agent target=hunter
cite: required
context:
- vss-deletion-lead
- scripted-shadow-deletion
- ransom-note-creation
- mass-encryption-baseline
max_iterations: 6
objective: Identify hosts where shadow deletion was followed by ransom note creation
  or mass file renames with rare extensions, specifically examining if the same process
  is responsible for both deletion and encryption.
success_criteria: A verdict per host citing specific rows and indicators.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the agent-triage verdict is malicious for at least one host showing both recovery inhibition and impact indicators" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-vss-api-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately and initiate incident response protocols for confirmed ransomware.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited evidence. Confirm if the 'rare extensions' are known encryption markers and if the process performing them is unauthorized. Check if deletion was part of scheduled backup maintenance.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document absence of malicious recovery inhibition. Record benign administrative VSS manipulation for tuning.
```
→ end
