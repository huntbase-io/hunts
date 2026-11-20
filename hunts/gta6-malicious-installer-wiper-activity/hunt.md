---
analysis: A single detection rule on vssadmin or bcdedit lacks the context of the
  social engineering lure. This hunt connects the fake installer lead to rare binaries
  and final wiper impact, providing a complete behavioral chain that simple rules
  cannot synthesize.
blind_spots:
- id: no-process-telemetry
  question: whether the connectivity check batch file was executed
  requires: hb_process_activity with command-line logging
  risk: Without command lines, the hunt relies on installer filenames which can be
    easily randomized, missing behavioral staging leads.
  stage: initial-access-seo-poisoning
- id: no-file-telemetry
  question: whether the read_it.txt note was created
  requires: hb_file_activity with file creation events
  risk: Missing file creation events means we cannot confirm successful wiper impact
    versus a blocked or failed execution.
  stage: wiper-impact-and-recovery-inhibition
- id: ephemeral-staging-scripts
  question: whether staging scripts like P3usMXh1h4.bat were deleted
  requires: hb_file_activity deletion logging
  risk: The malware often deletes its own staging files; short telemetry retention
    may lose the evidence of deployment before the hunt runs.
  stage: fake-installer-deployment
coverage:
- stage: initial-access-seo-poisoning
  status: covered
  steps:
  - installer-execution-lead
- stage: fake-installer-deployment
  status: covered
  steps:
  - installer-execution-lead
  - rare-binaries-in-temp
- stage: wiper-impact-and-recovery-inhibition
  status: covered
  steps:
  - wiper-impact-evidence
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: rat-c2-and-tunneling
  status: out_of_scope
- reason: Belongs to another part of the 'Grand Theft Auto VI hype leads to malware'
    series.
  stage: infostealer-credential-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Wiper activity causes permanent data loss and significant business
    disruption. Identifying the staging of these threats during high-interest campaigns
    like the GTA6 hype cycle protects assets from irreversible damage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is exploiting GTA6 hype to deploy a fake installer that stages
  multiple RATs and executes a destructive wiper masquerading as ransomware.
labels:
- hunt
- attack.t1190
- attack.t1486
- attack.t1490
name: GTA6 Malicious Installer and Chaos Wiper Activity
parameters:
  installer_names:
    default:
    - gta6installer.exe
    - licensechecker.exe
    - rockstargames.exe
    - rockstargamescrashfixer.exe
    - rockstarservices.exe
    - license.exe
    - adminapp.exe
    - gta6.exe
    description: Filenames associated with the fake GTA6 installers and launchers.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6-malware
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-retention
    type: number
  ransom_note_name:
    default: read_it.txt
    description: The ransom note filename dropped by the Chaos wiper.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-gta6-malware
    type: string
  scope_hosts:
    default: []
    description: Limit the hunt to these hostnames; leave empty for the full estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/fake-gta6-download-malware-analysis
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to Windows endpoints using software inventory. Focus on
  hosts where users have administrative privileges, as the wiper requires them to
  run its destructive payload.
references:
- name: "Huntress \u2014 Grand Theft Auto VI hype leads to malware"
  url: https://www.huntress.com/blog/fake-gta6-download-malware-analysis
related:
- hunt: rat-c2-and-tunneling
  reason: Network-based detection of NJRAT and DCRAT C2 to AWS and ngrok is handled
    in a separate network-focused hunt.
  relation: out-of-scope-alternative
- hunt: infostealer-credential-theft
  reason: The collection of browser credentials and Discord tokens by Mercurial Grabber
    is tracked in an identity-focused hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access via SEO Poisoning
    observables:
    - gta6installer.exe
    - https://clck.ru/34uJnp
    - Large ISO files masquerading as GTA6
    slug: initial-access-seo-poisoning
    tactic: initial-access
    techniques:
    - T1190
  - name: Fake Installer Execution and Staging
    observables:
    - '%TEMP%\checkinternetconnection.bat'
    - '%TEMP%\find.vbs'
    - '%TEMP%\licensechecker.exe'
    - '%TEMP%\rockstar.exe'
    - '%TEMP%\steam.exe'
    - '%TEMP%\rockstargames.exe'
    - '%TEMP%\YandexPackLoader.exe'
    - C:\Windows\System32\drivers\etc\hosts
    - WScript.exe find.vbs
    slug: fake-installer-deployment
    tactic: execution
  - name: RAT Command and Control with Tunneling
    observables:
    - 7.tcp.eu.ngrok.io:12684
    - 35.157.111.131
    - 3.68.56.232
    - 3.67.15.169
    - a0700877.xsph.ru
    - 141.8.197.42
    - any.ran.exe
    - UserOOBEBroker.exe
    slug: rat-c2-and-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: Infostealer Collection and Exfiltration
    observables:
    - adminapp.exe
    - Mercurial Grabber
    - https://discord.com/api/webhooks/995445114254139543/NmpxQmuBCD6sm3UkVvupGtx-Y0M_A86oJHp00O-l8F4jakfVhqFXzMBoy1uBDdj2rBLc
    slug: infostealer-credential-theft
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  - name: Wiper Impact and Recovery Inhibition
    observables:
    - gta6.exe
    - '%USERPROFILE%\AppData\Roaming\svchost.exe'
    - vssadmin.exe delete shadows /all /quiet
    - bcdedit /set {default} recoveryenabled No
    - read_it.txt
    - YOU HAVE BEEN HACKED BY THE ASHA HACKER TEAM!
    slug: wiper-impact-and-recovery-inhibition
    tactic: impact
    techniques:
    - T1486
    - T1490
  summary: Threat actors are exploiting Grand Theft Auto VI hype by distributing malicious
    ISO files via SEO poisoning and gaming forums. The infection chain uses a fake
    installer to deploy a variety of malware including NJRAT, DCRAT, Mercurial Grabber,
    and Chaos ransomware, which acts as a wiper to destroy user data while inhibiting
    system recovery.
series:
  index: 1
  slug: grand-theft-auto-vi-hype-leads-to-malware
  title: Grand Theft Auto VI hype leads to malware
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


# GTA6 Malicious Installer and Chaos Wiper Activity

This hunt identifies the deployment of fake GTA6 installers and the subsequent impact of the Chaos wiper family. It uses a gated flow to first find behavioral leads—like the execution of connectivity-check scripts or known malicious filenames—before fanning out to confirm the presence of rare staged binaries in user temp folders and the creation of ransom notes. This multi-surface synthesis distinguishes successful destructive infections from blocked attempts.

## scope-windows-hosts
<!-- Scope to Windows hosts -->
Identify Windows systems in the estate that are the target of this malware campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames to focus the behavioral queries.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%windows%' AND LOWER(vendor_name) LIKE '%microsoft%'
```

## installer-execution-lead
<!-- Detect installer execution lead -->
Find the initial execution of the fake GTA6 installer or its connectivity-check script.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, installer_names=installer_names, lookback_days=lookback_days)
~~~yaml
expected: Processes matching the reported filenames or the specific batch script lead.
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
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{installer_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%checkinternetconnection.bat%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate installer lead -->
```agent target=hunter
cite: required
context:
- installer-execution-lead
max_iterations: 3
objective: Determine if the identified process execution matches the fake GTA6 installer
  behavior reported by Huntress.
success_criteria: A verdict citing specific rows for each host.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on installer lead -->
if~: "the evaluate-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-impact
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-process-telemetry)
else: → close-out

## corroborate-impact
<!-- Corroborate staging and wiper impact -->
parallel:
- → rare-binaries-in-temp
- → wiper-impact-evidence
join: → triage-synthesis

## rare-binaries-in-temp
<!-- Rare binaries in user temp folders -->
Identify RATs and secondary payloads staged in writable user directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of binaries that are rare across the fleet and executing from temporary
  paths.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 4
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\appdata\roaming\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING host_count <= 3 ORDER BY host_count ASC
```

## wiper-impact-evidence
<!-- Chaos wiper impact evidence -->
Locate the read_it.txt ransom note to confirm successful destructive activity.

```sqlite target=endpoint role=triage params=(ransom_note_name=ransom_note_name, lookback_days=lookback_days)
~~~yaml
expected: Evidence of ransom note creation across multiple user directories.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) = LOWER('{{ransom_note_name}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-synthesis
<!-- Synthesize infection verdict -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- rare-binaries-in-temp
- wiper-impact-evidence
max_iterations: 5
objective: Determine if the host is actively compromised by the fake GTA6 payloads
  and whether wiper destruction has occurred.
success_criteria: A malicious verdict for any host where the installer lead is followed
  by rare temp binaries or wiper artifacts.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the triage-synthesis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-file-telemetry)
else: → close-out

## isolate-endpoint
<!-- Isolate infected endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. The Chaos wiper irreversibly overwrites files larger than 200MB. Recovery requires reimaging and restoring from backups.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the cited telemetry. Check for vssadmin.exe execution or desktop wallpaper changes to SpongeBob if process command lines are available. Verify the user who ran the installer and assess for potential lateral movement.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the number of successful compromises versus blocked attempts. Note any blind spots where staging scripts were deleted before collection.
```
→ end
