---
analysis: Standard rules may alert on 'atob' or 'eval', but they cannot differentiate
  between a legitimate minified library and a multi-stage deobfuscation routine. This
  hunt pivots from npm context to script content and rare extension persistence, distinguishing
  malice through the attack chain.
blind_spots:
- id: no-script-visibility
  question: whether the deobfuscated script is visible in cleartext
  requires: hb_script_activity with high block resolution
  risk: If the script is deobfuscated only at the final execution sink and logging
    does not capture the evaluated string, the hunt will only see the obfuscated wrapper.
  stage: defense-evasion-script-obfuscation
- id: ephemeral-extensions
  question: whether the malicious extension was deleted before detection
  requires: hb_file_activity with real-time auditing
  risk: A script that installs, steals data, and then uninstalls an extension may
    leave no footprint in snapshot inventories, relying entirely on file events.
  stage: persistence-browser-extensions
coverage:
- stage: execution-npm-install-scripts
  status: covered
  steps:
  - npm-install-scripts
- stage: defense-evasion-script-obfuscation
  status: covered
  steps:
  - obfuscated-script-content
- stage: persistence-browser-extensions
  status: covered
  steps:
  - browser-extension-changes
- stage: collection-credential-and-cookie-theft
  status: covered
  steps:
  - credential-collection-utilities
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: initial-access-phishing-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''JavaScript obfuscation: From party trick
    to phishing kit'' series.'
  stage: exfiltration-over-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: JavaScript obfuscation is a primary method for hiding credential
    theft in phishing and malicious packages. A negative result over the estate confirms
    these deobfuscation primitives are not being abused for local collection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using obfuscated JavaScript within npm install scripts
  or malicious browser extensions to collect credentials and cookies from the local
  endpoint while evading static analysis.
labels:
- hunt
- attack.t1566
- attack.t1176
- attack.t1115
- attack.t1041
- collection
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: Obfuscated JavaScript and Local Collection
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-scoping
    type: list[host]
  suspicious_binaries:
    default:
    - clip.exe
    - pbpaste
    - get-clipboard
    description: Binaries or cmdlets associated with clipboard data collection.
    from:
      kind: article
      observed: '2024-05-20'
      ref: talos-js-obfuscation
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with developer-heavy hosts or machines running node.js. Focus on
  user profiles where browser extensions and npm packages are locally installed.
references:
- name: "Talos \u2014 JavaScript obfuscation: From party trick to phishing kit"
  url: https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/
related:
- hunt: initial-access-phishing-delivery
  reason: This hunt focuses on execution and collection, not the delivery vector.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing Kit and Social Engineering Delivery
    observables:
    - phishing kit
    - fake CAPTCHA
    - fake update flows
    - compromised website injections
    slug: initial-access-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Malicious Package Installation
    observables:
    - npm package install scripts
    - npm tokens
    slug: execution-npm-install-scripts
    tactic: execution
    techniques:
    - T1566
  - name: JavaScript Obfuscation and Anti-Analysis
    observables:
    - eval()
    - atob()
    - String.fromCharCode()
    - atob('ZXZhbA==')
    - JSFuck
    - navigator.webdriver
    - control-flow flattening
    - _0x identifiers
    slug: defense-evasion-script-obfuscation
    tactic: defense-evasion
    techniques:
    - T1176
  - name: Browser Extension Abuse
    observables:
    - browser extension abuse
    - malicious software extensions
    slug: persistence-browser-extensions
    tactic: persistence
    techniques:
    - T1176
  - name: Credential and Browser Data Collection
    observables:
    - window.document.cookie
    - clipboard contents
    - clip.exe
    - pbpaste
    slug: collection-credential-and-cookie-theft
    tactic: collection
    techniques:
    - T1115
  - name: Exfiltration via Web Request
    observables:
    - https://example.com
    - fetch
    - ?password=
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Threat actors employ sophisticated JavaScript obfuscation techniques, including
    packing, encoding, and JSFuck, to conceal malicious payloads in phishing kits,
    malware loaders, and npm packages. These scripts often include anti-analysis features
    like browser fingerprinting and control-flow flattening to evade detection while
    exfiltrating credentials and cookies from victim systems.
series:
  index: 1
  slug: javascript-obfuscation-from-party-trick-to-phishing-kit
  title: 'JavaScript obfuscation: From party trick to phishing kit'
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


# Obfuscated JavaScript and Local Collection

This hunt targets the intersection of developer-focused delivery through npm and client-side credential theft. It identifies suspicious npm install hooks and the use of deobfuscation primitives like atob, String.fromCharCode, and eval within script blocks. The hunt then pivots to look for resulting persistence via browser extensions and the execution of collection utilities like clip.exe, providing a full picture of the attack chain from execution to collection.

## scope-npm-hosts
<!-- Scope hosts with npm installed -->
Identify machines with npm packages or node.js installed to narrow the search for malicious install scripts.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely to run developer workloads or handle npm packages.
  Silence implies no npm-managed software is in the inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE package_type = 'npm' OR LOWER(package_name) LIKE '%node%'
```

## detect-early-execution
<!-- Detect execution and obfuscation -->
parallel:
- → npm-install-scripts
- → obfuscated-script-content
join: → triage-early-stage

## npm-install-scripts
<!-- Suspicious npm install scripts -->
Find shells launched from npm during package installation which are commonly used for malware delivery.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes like sh, bash, or cmd.exe running as children of npm or node.
  Presence of arbitrary commands suggests a malicious hook.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%npm%' OR LOWER(parent_process_name) LIKE '%node%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## obfuscated-script-content
<!-- Obfuscated script block detection -->
Identify script blocks using deobfuscation primitives or anti-analysis signals in the actual script text.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script fragments resolving strings at runtime or checking for automated
  browser environments. Minified libraries may trigger false positives.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, script_content, script_type, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%string.fromcharcode%' OR LOWER(script_content) LIKE '%atob%(' OR LOWER(script_content) LIKE '%navigator.webdriver%' OR LOWER(script_content) LIKE '%eval%(') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-stage
<!-- Evaluate execution and obfuscation -->
```agent target=hunter
cite: required
context:
- npm-install-scripts
- obfuscated-script-content
max_iterations: 3
objective: Identify hosts where npm processes and deobfuscation primitives indicate
  a high likelihood of malicious script execution.
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign citing specific
  script fragments or process chains.
tools:
- endpoint
```

## detect-follow-on-activity
<!-- Detect persistence and collection -->
parallel:
- → browser-extension-changes
- → credential-collection-utilities
join: → assess-full-chain

## browser-extension-changes
<!-- Rare browser extension file activity -->
Identify new or modified browser extensions that may have been installed by the obfuscated script.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Extension paths found on only a few hosts. New manifest files in user profile
  directories across multiple platforms.
prevalence:
  by: device_hostname
  key:
  - ext_path
  rare_below: 3
reads:
- file_path
- device_hostname
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT LOWER(file_path) AS ext_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/extensions/%' OR LOWER(file_path) LIKE '%\extensions\%' OR LOWER(file_path) LIKE '%manifest.json%') AND activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## credential-collection-utilities
<!-- Execution of collection utilities -->
Find the use of standard OS utilities for stealing clipboard data or browser credentials.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_binaries=suspicious_binaries)
~~~yaml
expected: The use of clip.exe or pbpaste on hosts where suspicious JS or npm activity
  was previously identified.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{suspicious_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{suspicious_binaries}}' || ',', ',' || LOWER(process_cmd_line) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-full-chain
<!-- Final assessment of attack chain -->
```agent target=hunter
cite: required
context:
- triage-early-stage
- browser-extension-changes
- credential-collection-utilities
max_iterations: 5
objective: Determine if any host shows a complete chain from suspicious execution
  to persistence and collection.
success_criteria: A detailed report identifying the compromised host, the malicious
  package or extension, and the scope of data collected.
tools:
- endpoint
```

## decision-route
<!-- Route based on verdict -->
if~: "the assess-full-chain verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-script-visibility)
else: → hunt-closure

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the suspected malicious binary or script before killing any associated processes.
```
→ manual-review

## manual-review
<!-- Manual analyst review -->
```manual target=analyst
Extract the script content from hb_script_activity. Use a controlled sandbox to recover the final payload. Identify any exfiltration endpoints found in the decoded strings.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure and documentation -->
```manual target=analyst
Record all identified IOCs including script hashes and extension IDs. Update prevalence baselines for extensions if legitimate software was flagged.
```
→ end
