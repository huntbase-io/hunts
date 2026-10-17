---
analysis: This hunt pivots across file activity, scheduled jobs, module loads, and
  DNS resolutions. It uses stack-counting to identify rare browser preference tampering
  that a single rule would miss without fleet-wide context.
blind_spots:
- id: no-module-telemetry
  owner: Endpoint Engineering
  question: whether the unsigned SentinelAgentCore.dll was loaded
  remediation: Enable Sysmon Event ID 7 or ensure EDR library load events are captured.
  requires: hb_module_activity load events
  risk: Without module load events, the primary defense evasion mechanism is invisible,
    forcing reliance on file forgery outcomes.
  stage: dll-sideloading-sentinelone
- id: ephemeral-loader-files
  owner: Detection Engineering
  question: whether the popup script was deleted before collection
  remediation: Configure file activity logging for user profile directories.
  requires: hb_file_activity create events
  risk: The malware deletes its temporary loader scripts immediately; if file creation
    logs have short retention, the lead is lost.
  stage: initial-javascript-loader-execution
coverage:
- stage: initial-javascript-loader-execution
  status: covered
  steps:
  - js-loader-files
- stage: scheduled-task-persistence
  status: covered
  steps:
  - persistence-task
- stage: ethereum-dead-drop-resolution
  status: covered
  steps:
  - c2-dns-resolution
- stage: dll-sideloading-sentinelone
  status: covered
  steps:
  - sentinel-sideloading
- stage: browser-extension-forgery
  status: covered
  steps:
  - browser-forgery-prevalence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: KREMLIN is an active 15-month campaign targeting financial institutions
    via sophisticated browser forgery; detecting it protects banking sessions and
    identifies persistent compromises.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-stage JavaScript loaders to install a persistent
  Node.js task that sideloads malware via SentinelOne to forge browser integrity checks
  and install malicious extensions.
labels:
- hunt
- attack.t1047
- attack.t1053.005
- attack.t1059.001
- attack.t1176
name: KREMLIN Loader and Malicious Browser Extension Forgery
parameters:
  c2_domains:
    default:
    - connection.upgradeonline.site
    - granderevolucao.store
    - archive.org
    - ia601808.us.archive.org
    description: C2 and payload delivery domains observed in the campaign.
    from:
      kind: article
      observed: '2026-09-14'
      ref: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
    type: list[domain]
  known_browsers:
    default:
    - chrome.exe
    - msedge.exe
    - explorer.exe
    - systemsettings.exe
    description: Legitimate processes that typically modify browser preference files.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_task_name:
    default: MicrosoftNodeRuntimeUpdater
    description: The name of the scheduled task created for persistence.
    from:
      kind: article
      observed: '2026-09-14'
      ref: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
    type: string
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with Windows hosts having Chrome or Edge installed. If inventory
  is missing, prioritize hosts with DNS lookups to archive.org or attacker domains.
references:
- name: "Elastic Security Labs \u2014 The extension you never installed: KREMLIN forges\
    \ Chrome's own integrity checks to steal banking sessions"
  url: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
related:
- hunt: browser-extension-sideloading-generic
  reason: This hunt is specifically tuned to the KREMLIN infection chain and its unique
    SentinelOne sideloading technique.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: JavaScript Loader and Sandbox Evasion
    observables:
    - popup_*.js
    - shell.Popup
    - wmic process get
    - certutil -decode
    - connection.upgradeonline.site/api/log_loader
    slug: initial-javascript-loader-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: Node.js Runtime Persistence
    observables:
    - MicrosoftNodeRuntimeUpdater
    - conhost.exe --headless node.exe
    - items.json
    slug: scheduled-task-persistence
    tactic: persistence
    techniques:
    - T1053.005
  - name: Blockchain Config and Payload Retrieval
    observables:
    - '0xCD7360A83E5cdbBbbbcEB0e78748babA6740d07b'
    - archive.org/download/hotelmoskva/hotelmoskva.jpg
    - granderevolucao.store/5c92d3b8734b4f498752f735a1ca0987
    - ia601808.us.archive.org
    slug: ethereum-dead-drop-resolution
    tactic: command-and-control
  - name: DLL Sideloading via SentinelOne
    observables:
    - SentinelMemoryScanner.exe
    - SentinelAgentCore.dll
    - LdrpLoaderLock
    - LdrpWorkInProgress
    slug: dll-sideloading-sentinelone
    tactic: defense-evasion
  - name: Malicious Extension Integrity Bypassing
    observables:
    - Secure Preferences
    - App-Bound encrypted hashes
    - HMAC regeneration
    - Kr3mlin4rt1st
    slug: browser-extension-forgery
    tactic: persistence
    techniques:
    - T1176
  summary: KREMLIN is a Brazilian banking malware operation that uses multi-stage
    JavaScript loaders to establish persistence via scheduled tasks and DLL sideloading.
    The malware leverages Ethereum smart contracts as dead-drop resolvers to fetch
    payload URLs, ultimately installing malicious browser extensions that forge Chromium's
    Secure Preferences to steal session tokens.
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


# KREMLIN Loader and Malicious Browser Extension Forgery

This hunt follows the KREMLIN infection chain across two phases. First, it identifies early beachhead markers: the temporary JavaScript loader files and the specific scheduled task used for Node.js persistence. After an agent triages these leads, the hunt pivots to technical payloads, looking for a signed SentinelOne binary sideloading an unsigned DLL. Finally, it uses stack-counting to identify rare processes modifying Chrome or Edge Secure Preferences to install malicious extensions and steal banking sessions.

## scope-browser-hosts
<!-- Scope to hosts with Chromium browsers -->
Focus the hunt on hosts with Chrome or Edge installed as they are the targets for the KREMLIN extension forgery.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with targeted browsers. Silence indicates no inventory,
  meaning the hunt proceeds unscoped.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%')
```

## early-indicators-parallel
<!-- Hunt early beachhead markers -->
parallel:
- → js-loader-files
- → persistence-task
join: → early-triage

## js-loader-files
<!-- Deceptive JavaScript loader creation -->
Detect the temporary scripts created to lure users into execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of scripts with the popup prefix. Silence means no such files were
  logged, but they are often deleted quickly.
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
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) LIKE 'popup_%.js' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-task
<!-- Persistent Node.js updater task -->
Identify the specific scheduled task used by KREMLIN to maintain execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, malicious_task_name=malicious_task_name)
~~~yaml
expected: The presence of the MicrosoftNodeRuntimeUpdater task. This is a high-confidence
  indicator of persistence.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE LOWER(job_name) = LOWER('{{malicious_task_name}}') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-triage
<!-- Triage early indicators -->
```agent target=hunter
cite: required
context:
- js-loader-files
- persistence-task
max_iterations: 3
objective: Determine if hosts show evidence of the KREMLIN loader scripts or the specific
  Node.js persistence task.
success_criteria: A per-host verdict with citations for artifacts.
tools:
- endpoint
```

## follow-on-indicators-parallel
<!-- Hunt follow-on technical payloads -->
parallel:
- → sentinel-sideloading
- → browser-forgery-prevalence
- → c2-dns-resolution
join: → final-triage

## sentinel-sideloading
<!-- SentinelOne DLL sideloading -->
Detect the use of SentinelMemoryScanner.exe to sideload an unsigned or missing-signature malware DLL.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row showing a security tool loading an unsigned DLL with a specific name.
  This confirms the defense evasion stage.
reads:
- device_hostname
- process_name
- module_name
- module_signed
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, module_name, module_signed, time FROM hb_module_activity WHERE LOWER(process_name) LIKE '%sentinelmemoryscanner.exe' AND LOWER(module_name) = 'sentinelagentcore.dll' AND (module_signed = 'False' OR module_signed IS NULL) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## browser-forgery-prevalence
<!-- Rare browser preference modifications -->
Stack-count processes modifying Secure Preferences to find rare forgery events.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, known_browsers=known_browsers)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Any rare process modifying browser preferences is a high-confidence indicator
  of forgery. Silence means no such tampering was caught.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS touches, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\\secure preferences' AND NOT (instr(',' || '{{known_browsers}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## c2-dns-resolution
<!-- C2 and payload domain resolution -->
Corroborate endpoint activity with network resolutions to campaign infrastructure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
expected: DNS resolutions to known C2 domains. Silence is expected if domains have
  rotated.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Synthesize the intrusion story -->
```agent target=hunter
cite: required
context:
- early-triage
- sentinel-sideloading
- browser-forgery-prevalence
- c2-dns-resolution
max_iterations: 5
objective: Combine early-stage verdicts with sideloading, C2 activity, and browser
  tampering results to confirm a KREMLIN intrusion.
success_criteria: A final verdict of malicious for hosts showing multiple stages of
  the attack chain.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-triage verdict identifies multiple stages of the KREMLIN infection on the same host" (confidence: high, judge=hunter)
then: → contain-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-module-telemetry)
else: → close-out

## contain-and-remediate
<!-- Contain and Remediate Infection -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint to prevent banking session theft. Delete the 'MicrosoftNodeRuntimeUpdater' scheduled task and stop the SentinelMemoryScanner.exe process if it is still running.
```
→ analyst-review

## analyst-review
<!-- Analyst review and validation -->
```manual target=analyst
Review the browser extension directories for the author string 'Kr3mlin4rt1st'. Verify the Secure Preferences file for regenerated HMACs or unexpected extension IDs. Confirm whether any banking sessions were successfully exfiltrated in proxy logs.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the infection chain artifacts. Update the C2 domain list if any new resolvers were discovered during the hunt.
```
→ end
