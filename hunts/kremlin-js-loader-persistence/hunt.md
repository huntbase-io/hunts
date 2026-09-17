---
analysis: A simple detection rule for the task name 'MicrosoftNodeRuntimeUpdater'
  is easily bypassed by renaming. This hunt uses a multi-surface approach (prevalence
  of random popup JS files, script-based evasion patterns, and DNS to resolvers) that
  a single rule cannot correlate.
blind_spots:
- id: no-script-visibility
  question: whether the loader's obfuscated stages were visible to the script interpreter
  requires: hb_script_activity support for deobfuscated or expanded script blocks
  risk: If the script activity surface does not capture the final stage execution
    or expanded strings, the sandbox checks (WMI queries) will remain invisible.
  stage: initial-javascript-loader
- id: no-http-path-visibility
  question: whether the specific /api/log_loader path was accessed
  requires: hb_http_activity or proxy logging
  risk: Without HTTP path data, DNS resolutions to Archive.org or attacker domains
    are less actionable and may be lost in background noise.
  stage: ethereum-dead-drop-c2
coverage:
- stage: initial-javascript-loader
  status: covered
  steps:
  - rare-popup-files
  - sandbox-script-behavior
- stage: persistence-via-scheduled-task
  status: covered
  steps:
  - detect-malicious-task
- stage: ethereum-dead-drop-c2
  status: covered
  steps:
  - dns-to-c2
- reason: 'Belongs to another part of the "The extension you never installed: KREMLIN
    forges Chrome''s own integrity checks to steal banking sessions" series.'
  stage: sideloaded-malware-installer
  status: out_of_scope
- reason: 'Belongs to another part of the "The extension you never installed: KREMLIN
    forges Chrome''s own integrity checks to steal banking sessions" series.'
  stage: browser-extension-manipulation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The KREMLIN operation targets Brazilian banking users with 1,500+
    documented infections. Its use of legitimate-looking Node.js tasks and multi-stage
    JS loaders makes it a significant risk for financial session theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using a multi-stage JavaScript loader to establish persistence
  via a spoofed Node.js scheduled task and resolves C2 infrastructure using Ethereum
  smart contracts.
labels:
- hunt
- attack.t1047
- attack.t1053.005
- attack.t1059.001
name: KREMLIN JS Loader and Task Persistence
parameters:
  c2_domains:
    default:
    - connection.upgradeonline.site
    - granderevolucao.store
    - archive.org
    - ia601808.us.archive.org
    description: C2 domains and dead-drop resolvers from the report.
    from:
      kind: article
      observed: '2026-09-14'
      ref: "Elastic Security Labs \u2014 KREMLIN"
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for whole estate.
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
rationale: Focus on Windows endpoints where Chrome or Edge are present. The infection
  starts with manual execution of a JS file, often from Downloads or Temp folders.
references:
- name: "Elastic Security Labs \u2014 Malicious browser extension KREMLIN"
  url: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
related:
- hunt: kremlin-installer-sideloading
  reason: This hunt focuses on the loader and persistence; the next hunt covers the
    installer binary and the SentinelOne sideloading technique.
  relation: follows
scenario:
  stages:
  - name: Initial JavaScript Loader and Sandbox Evasion
    observables:
    - popup_{date}_{random}.js
    - shell.Popup
    - certutil.exe decoding
    - WMI query for process counts
    - Desktop file count < 5
    - Process count < 50
    slug: initial-javascript-loader
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: Persistence via Scheduled Task
    observables:
    - MicrosoftNodeRuntimeUpdater
    - conhost.exe --headless node.exe
    - Node.js V8 Runtime description
    - Embedded CAB archive extraction
    slug: persistence-via-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Ethereum Dead-Drop C2 Configuration
    observables:
    - '0xCD7360A83E5cdbBbbbcEB0e78748babA6740d07b'
    - connection.upgradeonline.site
    - granderevolucao.store
    - archive.org/download/hotelmoskva/hotelmoskva.jpg
    - ia601808.us.archive.org
    - /api/log_loader?hash=
    slug: ethereum-dead-drop-c2
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Side-loaded C++ Malware Installer
    observables:
    - SentinelMemoryScanner.exe
    - SentinelAgentCore.dll
    - PigSyscall
    - LdrLockLiberator technique
    - 0x1337 access violation on VM detection
    - Indirect syscalls via ntdll.dll
    slug: sideloaded-malware-installer
    tactic: defense-evasion
    techniques:
    - T1047
  - name: Browser Extension Installation and Forgery
    observables:
    - Secure Preferences modification
    - Chrome integrity HMAC regeneration
    - App-Bound encrypted hashes modification
    - Malicious extension in Chrome/Edge
    - Kr3mlin4rt1st author name
    slug: browser-extension-manipulation
    tactic: persistence
    techniques:
    - T1176
  summary: KREMLIN (REF9334) is a multi-stage Brazilian banking threat that uses obfuscated
    JavaScript loaders to establish persistence via scheduled tasks and download payloads
    via Ethereum-based dead-drop resolvers. The campaign ultimately installs a malicious
    browser extension by side-loading an installer via a legitimate security binary
    and forging Chrome integrity checks to steal session tokens.
series:
  index: 1
  slug: the-extension-you-never-installed-kremlin-forges-chrome-s-own-integrity-checks-to-steal-banking-
  title: 'The extension you never installed: KREMLIN forges Chrome''s own integrity
    checks to steal banking sessions'
  total: 2
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# KREMLIN JS Loader and Task Persistence

This hunt identifies the early stages of the KREMLIN banking malware infection chain. It focuses on identifying the discovery of temporary 'popup' helper scripts used for user-luring, the identification of sandbox evasion techniques (such as WMI-based process counting) within script blocks, and the detection of persistence established through a suspiciously named scheduled task ('MicrosoftNodeRuntimeUpdater') that executes Node.js in a headless environment. The hunt corroborates these endpoint signals with DNS traffic to reported Ethereum dead-drop resolvers and payload hosting infrastructure on Archive.org.

## scope-to-browsers
<!-- Scope to hosts with Chrome or Edge -->
Identify hosts where the targeted browsers (Chrome/Edge) are installed to focus the hunt for browser-specific malware.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts containing the target browsers. Silence means the browsers
  are not inventoried or not present.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%')
```

## detect-malicious-task
<!-- Identify KREMLIN persistence task -->
Detect the specific scheduled task used by KREMLIN to maintain persistence for its Node.js components.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any scheduled task matching the reported name or utilizing a headless Node.js
  runtime. This is the primary detection candidate.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'microsoftnoderuntimeupdater' OR (LOWER(job_cmd_line) LIKE '%node.exe%' AND LOWER(job_cmd_line) LIKE '%--headless%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-corroboration
<!-- Corroborate independent signals -->
parallel:
- → rare-popup-files
- → dns-to-c2
- → sandbox-script-behavior
join: → triage-agent

## rare-popup-files
<!-- Rare 'popup_*.js' helper scripts -->
Identify the creation of temporary JS files used to show the fake error lure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rarely seen JS files with names following the reported pattern. High prevalence
  would indicate legitimate enterprise software.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(file_name) LIKE 'popup_%.js' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY LOWER(file_name) HAVING hosts <= 3
```

## dns-to-c2
<!-- DNS lookups for Ethereum resolvers -->
Find communication with domains resolving Ethereum-based dead-drop configurations or payload hosting.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains)
~~~yaml
expected: DNS requests to the reported domains. Correlate with the process performing
  the lookup (often node.exe or shell interpreters).
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%archive.org%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname, process_name
```

## sandbox-script-behavior
<!-- WMI sandbox-counting logic -->
Search script execution blocks for the specific WMI counting logic used to detect sandbox environments.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script contents checking for process or file counts. This behavior is highly
  characteristic of the KREMLIN loader's evasion logic.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%winmgmts%' AND (LOWER(script_content) LIKE '%win32_process%' OR LOWER(script_content) LIKE '%desktop%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Triage KREMLIN loader evidence -->
```agent target=hunter
cite: required
context:
- detect-malicious-task
- rare-popup-files
- dns-to-c2
- sandbox-script-behavior
max_iterations: 5
objective: Evaluate whether the combination of the 'MicrosoftNodeRuntimeUpdater' task,
  rare 'popup' JS files, and DNS resolutions to Ethereum-linked domains indicates
  an active KREMLIN infection.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  evidence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host involving the Node runtime scheduled task or the popup helper scripts" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-visibility)
else: → analyst-review

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Remove the 'MicrosoftNodeRuntimeUpdater' scheduled task. Collect the parent JavaScript lure and any 'popup_*.js' files for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Manual analyst verification -->
```manual target=analyst
Inspect the host's Chrome and Edge extension directories for uninstalled or unauthorized folders. Verify the integrity of 'node.exe' in the suspected installation paths.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Record the results of the hunt. If no indicators were found, document the scope and lookback window for future reference.
```
→ end
