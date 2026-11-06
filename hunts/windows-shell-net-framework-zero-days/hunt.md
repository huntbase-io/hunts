---
analysis: A single detection rule for these CVEs only confirms a vulnerability is
  present. This hunt pivots to rare registry stack-counts and MOTW alternate data
  stream contents to provide the behavioral evidence an analyst needs to differentiate
  exploitation from legitimate software updates.
blind_spots:
- id: missing-file-stream-telemetry
  owner: Infrastructure
  question: whether a file actually has the MOTW tag
  remediation: Enable Sysmon Event ID 15 logging for sensitive directories.
  requires: hb_file_activity with file_contents (Sysmon Event ID 15)
  risk: Without alternate data stream contents, the MOTW bypass is invisible and the
    triage query will return zero rows.
  stage: initial-access-motw-bypass
- id: vulnerability-scan-lag
  owner: Vulnerability Management
  question: whether the device is truly vulnerable today
  remediation: Trigger an immediate scan for the October 2026 CVEs.
  requires: hb_vulnerability_finding with CVE-2026-96951
  risk: If the vulnerability scanner has not refreshed since the Patch Tuesday release,
    hosts may be missing from the scope despite being vulnerable.
coverage:
- stage: initial-access-motw-bypass
  status: covered
  steps:
  - identify-vulnerable-hosts
  - motw-bypass-evidence
- stage: defense-evasion-net-assembly-hijack
  status: covered
  steps:
  - identify-vulnerable-hosts
  - rare-net-registrations
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Exploited-in-the-wild zero-day vulnerabilities targeting core OS
    security mechanisms (MOTW and Defender) represent a high risk of undetected initial
    access and evasion. A negative result confirms the estate is either patched or
    currently unexploited.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a Windows Shell MOTW bypass to execute malicious
  web downloads without warning, or has achieved stealthy persistence by registering
  a rare .NET assembly that evades Defender signature checks.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1553.005
- attack.t1204.002
- attack.t1574
- attack.t1127.001
- defense evasion
- initial access
name: Windows Shell and .NET Framework Zero-Day Bypasses
parameters:
  cve_ids:
    default:
    - CVE-2026-96951
    - CVE-2026-108398
    description: Target CVE identifiers.
    from:
      kind: article
      observed: '2026-10-13'
      ref: Rapid7 Patch Tuesday October 2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioral indicators.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Hostnames to restrict the behavioral search; leave empty for fleet-wide
      scan.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The scoping step identifies vulnerable devices by their provider UID. Resolve
  these UIDs to hostnames using hb_devices and then paste them into the scope_hosts
  parameter to focus the behavioral analysis.
references:
- name: "Rapid7 \u2014 Patch Tuesday - October 2026"
  url: https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026
related:
- hunt: unusual-process-loading-dotnet
  reason: This hunt specifically targets the October 2026 zero-day registry triggers;
    general .NET hijacking requires deeper process-to-module correlation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Windows Shell MOTW Bypass
    observables:
    - explorer.exe
    - specially crafted malicious file
    - attacker-controlled site visit
    - outlook.com
    slug: initial-access-motw-bypass
    tactic: initial-access
    techniques:
    - T1190
    - T1566
    - T1553.005
    - T1204.002
  - name: .NET Framework Assembly Hijack
    observables:
    - malicious .NET assembly registration
    - assembly loaded by protected process
    - CVE-2026-108398
    slug: defense-evasion-net-assembly-hijack
    tactic: defense-evasion
    techniques:
    - T1574
    - T1127.001
  summary: 'This campaign involves the exploitation of two zero-day vulnerabilities:
    CVE-2026-96951 to bypass Mark-of-the-Web (MOTW) security features via malicious
    files or websites, and CVE-2026-108398 to bypass Windows Defender Application
    Control (WDAC) by registering malicious .NET assemblies for loading by protected
    processes.'
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


# Windows Shell and .NET Framework Zero-Day Bypasses

This hunt targets two zero-day vulnerabilities from the October 2026 Patch Tuesday: CVE-2026-96951 (Windows Shell MOTW bypass) and CVE-2026-108398 (.NET Framework assembly hijacking). The hunt identifies vulnerable hosts and then looks for behavioral indicators of exploitation, specifically monitoring for rare registry modifications within the .NET Framework and CLSID paths, and hunting for files in user-writable directories that contain Zone.Identifier tags indicating an untrusted internet origin. An agent triage step settles the findings across these independent surfaces.

## identify-vulnerable-hosts
<!-- Identify vulnerable hosts -->
Locate devices reporting the specific zero-day vulnerabilities in their latest vulnerability scan.

```sqlite target=endpoint role=scoping params=(cve_ids=cve_ids)
~~~yaml
expected: A list of device UIDs susceptible to the targeted bypasses. Silence indicates
  either no vulnerabilities were found or the scanner has not yet been updated with
  October 2026 logic.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{cve_ids}}' || ',', ',' || cve_uid || ',') > 0
```

## parallel-corroboration
<!-- Corroborate behavioral evidence -->
parallel:
- → rare-net-registrations
- → motw-bypass-evidence
join: → triage-exploitation

## rare-net-registrations
<!-- Rare .NET assembly registrations -->
Stack-count registry writes to .NET Framework paths to identify rare assembly registrations that may indicate hijacking.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A registry value seen on very few hosts. Legitimate software updates may
  appear, but a rare path or value data is the primary indicator of assembly hijacking.
prevalence:
  by: device_hostname
  key:
  - reg_target
  - reg_value_data
  rare_below: 3
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT LOWER(reg_target) AS target, reg_value_data, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(reg_target) LIKE '%\\software\\microsoft\\.netframework%' OR LOWER(reg_target) LIKE '%\\software\\classes\\clsid%') AND activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING host_count <= 3 ORDER BY host_count ASC
```

## motw-bypass-evidence
<!-- MOTW bypass file indicators -->
Find files downloaded from the internet (ZoneID=3) into user folders that may have bypassed security warnings.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Files with MOTW metadata in user-writable paths. The presence of such files
  on vulnerable hosts suggests a failure of the MOTW security feature.
reads:
- device_hostname
- file_name
- file_path
- file_contents
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%\\temp\\%') AND LOWER(file_contents) LIKE '%zoneid=3%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-exploitation
<!-- Triage exploitation -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-hosts
- rare-net-registrations
- motw-bypass-evidence
max_iterations: 5
objective: Determine whether any host identified as vulnerable also shows evidence
  of MOTW bypass downloads or rare .NET assembly registration.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  registry or file activity rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-stream-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host to prevent further lateral movement and preserve the malicious files for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Examine the registry values and files cited by the agent. Check whether the file_contents confirm a MOTW ZoneID=3 download and whether the registry process is a known legitimate installer or an untrusted binary.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hosts examined and the evidence of absence. If vulnerabilities were present but no behavioral matches were found, recommend scheduling a follow-up hunt in two weeks.
```
→ end
