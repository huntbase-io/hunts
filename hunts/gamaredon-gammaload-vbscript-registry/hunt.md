---
analysis: A simple detection rule on specific registry keys is easily bypassed by
  rotation. This hunt uses a prevalence-based approach to find rare keys in the Console
  hive and corroborates them with in-memory script behavior and DNS patterns, which
  a static rule cannot do.
blind_spots:
- id: no-endpoint-telemetry
  question: Can we see modifications to HKCU\Console in real-time?
  requires: Endpoint telemetry reporting HKCU registry modifications.
  risk: Registry-based C2 caching would be missed if the agent only monitors HKLM
    or system-wide keys.
  stage: c2-registry-caching-and-fingerprinting
- id: amsi-script-visibility
  question: Are in-memory VBScript executions using ExecuteGlobal visible?
  requires: hb_script_activity (AMSI-sourced telemetry).
  risk: Without content-level script telemetry, the loader's execution inside legitimate
    script hosts remains invisible.
  stage: in-memory-vbscript-execution
coverage:
- stage: c2-registry-caching-and-fingerprinting
  status: covered
  steps:
  - registry-c2-caching
  - prevalence-registry-value-names
  - dns-to-ddr-domains
- stage: in-memory-vbscript-execution
  status: covered
  steps:
  - vbscript-in-memory-execution
- reason: 'Belongs to another part of the ''FSB Matryoshka: Gamaredon GammaLoad''
    series.'
  stage: persistence-via-ads-and-scheduled-task
  status: out_of_scope
- reason: 'Belongs to another part of the ''FSB Matryoshka: Gamaredon GammaLoad''
    series.'
  stage: obfuscated-powershell-memory-load
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Gamaredon (UAC-0010) is a highly active FSB-operated intrusion set.
    Detecting their intermediate loaders (GammaLoad) is critical for disrupting their
    access before they deploy credential-stealing final payloads (GammaSteel).
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is maintaining stealthy persistence by using VBScript-based
  loaders (GammaLoad) to cache C2 addresses within the unusual HKCU\Console registry
  hive and exfiltrating host fingerprints through crafted User-Agent strings.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1059.001
- attack.t1053.005
- attack.t1555
name: Gamaredon GammaLoad VBScript & Registry Interaction
parameters:
  ddr_domains:
    default:
    - te.legra.ph
    - telegram.me
    - check-host.net
    - trycloudflare.com
    - workers.dev
    - huaweicloud.com
    - selltosell.ru
    description: Legitimate domains used as Dead Drop Resolvers (DDR) by GammaLoad.
    from:
      kind: article
      observed: '2026-01-23'
      ref: blog.sekoia.io
    type: list[domain]
  gammaload_registry_keys:
    default:
    - HistoryURL
    - WindowsResponby
    - CloudURL
    - IpURL
    description: Registry value names used by GammaLoad for C2 caching in HKCU\Console.
    from:
      kind: article
      observed: '2026-01-23'
      ref: blog.sekoia.io
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to Windows hosts using software inventory. It prioritizes
  the HKCU registry hive, which requires active endpoint telemetry (e.g., Sysmon or
  osquery) for full visibility.
references:
- name: "Sekoia.io \u2014 FSB\u2019s Matryoshka: Gamaredon GammaLoad"
  url: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
related:
- hunt: gammaload-persistence-ads-scheduled-task
  reason: This hunt focuses on the initial registry/C2 interaction; persistence via
    ADS and Scheduled Tasks is handled in the next part of the series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: C2 Registry Caching and Host Fingerprinting
    observables:
    - 'Registry keys: HKCU\Console\HistoryURL, HKCU\Console\WindowsResponby, HKCU\Console\CloudURL,
      HKCU\Console\IpURL'
    - 'DDR domains: te.legra.ph, telegram.me, check-host.net'
    - 'User-Agent fingerprint separators: ##, !!, ??, ==, ::, _, @, #, =, %, ?'
    - 'HTTP GET requests with anomalous Content-Length: 2114'
    - 'Fingerprint: %COMPUTERNAME% and system drive serial number'
    slug: c2-registry-caching-and-fingerprinting
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
  - name: In-Memory VBScript Execution
    observables:
    - VBScript ExecuteGlobal() function calls
    - Base64 obfuscated scripts with '&&' markers inserted every 54 characters
    slug: in-memory-vbscript-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via ADS and Scheduled Task
    observables:
    - 'Alternate Data Stream (ADS) file: %TEMP%\:divedz0f'
    - 'Scheduled Task name: \Windows\ApplicationData\DsSvcCleanup'
    - 'Scheduled Task interval: every 11 minutes'
    - Task action executing VBScript from ADS
    slug: persistence-via-ads-and-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Obfuscated PowerShell Memory Load
    observables:
    - 'Process command line: powershell.exe -nol -nop -encodedcommand'
    - 'PowerShell disabling SSL validation: [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}'
    - PowerShell XOR-decryption and IEX execution of downloaded strings
    slug: obfuscated-powershell-memory-load
    tactic: execution
    techniques:
    - T1059.001
  summary: Gamaredon uses a multi-stage infection chain known as GammaLoad to maintain
    persistent access and deploy stealers. The chain leverages VBScript loaders that
    use Dead Drop Resolvers and registry caching for C2 resiliency, ultimately persisting
    via scheduled tasks that execute payloads hidden in Alternate Data Streams (ADS).
series:
  index: 1
  slug: fsb-matryoshka-gamaredon-gammaload
  title: 'FSB Matryoshka: Gamaredon GammaLoad'
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


# Gamaredon GammaLoad VBScript & Registry Interaction

This hunt targets the 'GammaLoad' stage of Gamaredon (FSB-linked) operations, focusing on their unique method of using the Windows Console registry hive (HKCU\Console) to persist C2 configurations. It identifies hosts where these specific registry values are created, uses prevalence to highlight rare registry entries, and corroborates the findings against in-memory VBScript execution patterns and network activity targeting legitimate Dead Drop Resolvers (DDR).

## scope-to-windows-hosts
<!-- Scope to Windows hosts with PowerShell -->
Identify potential targets by finding Windows systems that have PowerShell installed, as the loaders heavily utilize script-based execution.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the Windows fleet. Silence means no systems
  matching the OS/software inventory criteria were found.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%powershell%' OR LOWER(vendor_name) LIKE '%microsoft%'
```

## registry-c2-caching
<!-- C2 URL Caching in Console Registry -->
Find registry modifications where the HKCU\Console hive is used to store URL-like data in GammaLoad-specific keys.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, gammaload_registry_keys=gammaload_registry_keys)
~~~yaml
expected: Value names like 'HistoryURL' or 'CloudURL' appearing under the Console
  key, containing URLs. This is a strong behavioral match for GammaLoad.
reads:
- device_hostname
- actor_user_name
- reg_target
- reg_value_data
- reg_value_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, actor_user_name, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\console\\%' AND (instr(',' || '{{gammaload_registry_keys}}' || ',', ',' || reg_value_name || ',') > 0 OR LOWER(reg_value_data) LIKE 'http%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## prevalence-registry-value-names
<!-- Rare Registry Value Names under Console -->
Stack-count the value names created in the HKCU\Console path across the fleet to highlight unique persistence keys.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of registry value names appearing on only a handful of hosts. Genuine
  terminal settings will appear fleet-wide.
prevalence:
  by: device_hostname
  key:
  - reg_value_name
  rare_below: 3
reads:
- reg_value_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT reg_value_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\console\\%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_value_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## parallel-corroboration
<!-- Corroborate Scripting and Network Signals -->
parallel:
- → vbscript-in-memory-execution
- → dns-to-ddr-domains
join: → triage-agent

## vbscript-in-memory-execution
<!-- In-Memory VBScript with Gamaredon Markers -->
Identify VBScript blocks using ExecuteGlobal() with GammaLoad-specific obfuscation ('&&' every 54 characters).

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing ExecuteGlobal and the '&&' pattern or references
  to Console registry keys.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%executeglobal%' AND (LOWER(script_content) LIKE '%&&%' OR LOWER(script_content) LIKE '%console%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-to-ddr-domains
<!-- DNS Traffic to Dead Drop Resolvers -->
Confirm if the hosts identified in the registry or script steps are communicating with known Gamaredon DDR services.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, ddr_domains=ddr_domains)
~~~yaml
expected: DNS queries for Telegraph, Telegram API, or cloudflare workers occurring
  on the same hosts as registry anomalies.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{ddr_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-agent
<!-- GammaLoad Correlation Agent -->
```agent target=hunter
cite: required
context:
- registry-c2-caching
- prevalence-registry-value-names
- vbscript-in-memory-execution
- dns-to-ddr-domains
max_iterations: 6
objective: Determine if the observed HKCU\Console registry activity, obfuscated VBScript
  execution, and DDR-related DNS queries represent a unified GammaLoad infection pattern.
success_criteria: A per-host verdict (Malicious | Suspicious | Benign) with specific
  citations for the registry keys used and the scripts executed.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and remove the malicious HKCU\Console registry keys identified by the triage agent.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the correlated registry, script, and DNS telemetry. Check for file creations in %TEMP% (specifically ADS) which might indicate the next stage (GammaSteel).
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
No indicators of GammaLoad were found. Document the lookback period and domains examined.
```
→ end
