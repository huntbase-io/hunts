---
analysis: A simple rule might alert on finger.exe usage, but this hunt correlates
  explorer.exe parentage, caretaker obfuscation, and fleet-wide rarity into a single
  decision, reducing false positives from legitimate administrator activity.
blind_spots:
- id: no-process-visibility
  question: Can we see explorer.exe spawning cmd.exe?
  requires: hb_process_activity with parent process tracking
  risk: Without parent process lineage, the lead query cannot distinguish user-pasted
    commands from standard system activity.
  stage: social-engineering-run-dialog
- id: no-dns-logging
  question: Did the finger.exe cradle reach the C2?
  requires: hb_dns_activity
  risk: If DNS logging is missing, we cannot confirm if the Social Engineering attempt
    successfully retrieved its payload.
  stage: lolbin-payload-retrieval
coverage:
- stage: social-engineering-run-dialog
  status: covered
  steps:
  - identify-obfuscated-launchers
  - rare-explorer-children
- stage: lolbin-payload-retrieval
  status: covered
  steps:
  - dns-c2-lookups
- reason: General hb_ surfaces do not track specific file-level access to browser
    sqlite databases required for high-fidelity credential theft detection.
  stage: credential-access-theft
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ClickFix attacks bypass file-based defenses by utilizing user interaction
    to execute signed system binaries. Confirming the absence of this behavior ensures
    the estate is resilient to this high-velocity social engineering campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using social engineering to trick users into pasting obfuscated
  commands into the Windows Run dialog, using explorer.exe to launch downloaders like
  finger.exe for payload retrieval.
labels:
- hunt
- attack.t1204.002
- attack.t1059.001
- attack.t1218
- attack.t1105
- attack.t1555
- command and control
- credential access
- execution
name: ClickFix Run-Dialog Social Engineering and LOLBIN Execution
parameters:
  c2_domains:
    default:
    - linkeders.net
    - finger.linkeders.net
    description: C2 domains observed in ClickFix campaigns.
    from:
      kind: article
      observed: '2024-10-05'
      ref: huntress-clickfix-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for process and network events.
    from:
      kind: manual
      observed: '2024-10-05'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2024-10-05'
      ref: hunt-standard
    type: list[host]
  social_eng_strings:
    default:
    - push the enter key
    - en_t_e_r_ k_e_y
    description: Strings used in social engineering padding to scroll real commands
      out of view.
    from:
      kind: article
      observed: '2024-10-05'
      ref: huntress-clickfix-blog
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fix-for-clickfix
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope focuses on Windows endpoints where users interact with the Run dialog.
  Explorer.exe parentage is the primary scoping mechanism within behavioral telemetry.
references:
- name: "Huntress \u2014 How Huntress Detects and Responds to a ClickFix Attack"
  url: https://www.huntress.com/blog/fix-for-clickfix
related:
- hunt: infostealer-post-execution-behavior
  reason: This hunt focuses on the initial access; follow-on behavior like browser
    credential theft is covered in the infostealer hunt.
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Run Dialog
    observables:
    - explorer.exe spawning cmd.exe
    - Process command line containing cmd.exe /c start "" /min
    - Caret obfuscation in command line (e.g., s^t^a^r^t, f^^i^^n^^g^^e^^r)
    - Social engineering strings in command line (e.g., ---P_u_s_h----t_h_e----_E_n_t_e_r_----k_e_y--)
    - Command line containing 'for /f' loops to execute captured text
    slug: social-engineering-run-dialog
    tactic: execution
    techniques:
    - T1204.002
    - T1059.003
  - name: LOLBIN Payload Retrieval
    observables:
    - finger.exe fetching data from linkeders.net
    - finger.exe fetching data from finger.linkeders.net
    - Network connection to port 79
    - finger.exe used within a 'for' loop to capture and execute output
    slug: lolbin-payload-retrieval
    tactic: command-and-control
    techniques:
    - T1218
    - T1105
  - name: Infostealer Credential Access
    observables:
    - Access to browser credential stores
    - Execution of infostealer payloads (stage two)
    slug: credential-access-theft
    tactic: credential-access
    techniques:
    - T1555
  summary: ClickFix is a social engineering campaign that tricks users into pasting
    obfuscated commands into the Windows Run dialog, which are then executed by explorer.exe.
    These commands leverage native LOLBINs like finger.exe to download and execute
    follow-on payloads such as infostealers without writing files to disk.
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


# ClickFix Run-Dialog Social Engineering and LOLBIN Execution

ClickFix attacks bypass traditional file-based defenses by delivering commands directly into the user interactive session via the Windows Run dialog. The command usually contains caret obfuscation to defeat string matching and uses built-in Microsoft binaries like finger.exe to fetch and execute a remote payload. This hunt identifies the specific explorer.exe to cmd.exe or LOLBIN process relationship, detects the obfuscated command patterns, and stack-counts rare explorer children to separate legitimate activity from the attack.

## scoping-windows-inventory
<!-- Scope to Windows endpoints -->
Identify Windows systems which are the primary target for ClickFix social engineering via the Run dialog.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running Windows. This list is used to scope subsequent
  behavioral queries.
reads:
- device_hostname
- vendor_name
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-06'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(vendor_name) LIKE '%microsoft%' AND LOWER(package_name) LIKE '%windows%'
```

## identify-obfuscated-launchers
<!-- Identify explorer-spawned obfuscated shells -->
Find instances where explorer.exe spawns cmd.exe or LOLBINs with caretaker obfuscation, finger usage, or social engineering strings.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days, social_eng_strings=social_eng_strings)
~~~yaml
expected: A shell or system binary launched by explorer.exe containing caret characters,
  for-loops, or the social engineering padding. This is the primary lead.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
- parent_process_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-06'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\explorer.exe' AND (process_cmd_line LIKE '%^%' OR LOWER(process_cmd_line) LIKE '%finger%' OR LOWER(process_cmd_line) LIKE '%for /f%' OR instr(',' || '{{social_eng_strings}}' || ',', ',' || LOWER(process_cmd_line) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-launcher-logic
<!-- Evaluate launcher suspiciousness -->
```agent target=hunter
cite: required
context:
- identify-obfuscated-launchers
max_iterations: 3
objective: Determine if the command lines in identify-obfuscated-launchers contain
  caretaker obfuscation, for/f loops used for execution, or long strings of dashes/social
  engineering instructions.
success_criteria: A per-host verdict of suspicious | malicious | benign citing the
  command line rows.
tools:
- endpoint
```

## gate-on-suspicion
<!-- Gate on lead suspicion -->
if~: "the evaluate-launcher-logic verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-corroboration
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-process-visibility)
else: → close-out-negative

## parallel-corroboration
<!-- Corroborate with prevalence and network -->
parallel:
- → rare-explorer-children
- → dns-c2-lookups
join: → triage-full-chain

## rare-explorer-children
<!-- Rare processes spawned by explorer -->
Stack-count children of explorer.exe to find anomalous launchers across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The binary name used in the ClickFix attack appearing on very few hosts
  compared to standard Windows activity.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-06'
~~~
SELECT LOWER(process_name) AS binary, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS launches FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\explorer.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3 ORDER BY hosts ASC
```

## dns-c2-lookups
<!-- DNS resolutions to ClickFix infrastructure -->
Search for DNS lookups to domains associated with ClickFix payload delivery.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: A hostname resolving linkeders infrastructure shortly after the explorer
  launcher event.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-06'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-chain
<!-- Triage ClickFix intrusion chain -->
```agent target=hunter
cite: required
context:
- evaluate-launcher-logic
- rare-explorer-children
- dns-c2-lookups
max_iterations: 6
objective: 'Confirm if any host shows the complete ClickFix chain: explorer.exe spawning
  an obfuscated command, that command being rare in the environment, and follow-on
  DNS activity to linkeders infrastructure.'
success_criteria: A final malicious verdict per host with a summary of the evidence
  chain and timing correlation.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage-full-chain verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-intrusion
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-dns-logging)
else: → close-out-negative

## contain-intrusion
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all active web and application sessions for the affected user, as infostealer payloads often harvest session tokens.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic remediation -->
```manual target=analyst
Review the full process tree around the identified launcher. Look for randomly named executables or scripts in %APPDATA% or %TEMP% that may represent the infostealer stage. Confirm browser profiles are intact and force user password resets.
```
→ close-out-negative

## close-out-negative
<!-- Close out hunt -->
```manual target=analyst
Record the examined scope and findings. If ClickFix was not found, note that no users executed obfuscated cradles via explorer.exe in the lookback period.
```
→ end
