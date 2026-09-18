---
analysis: A simple rule might catch BluetoothService.exe loading an unsigned log.dll,
  but this hunt pivots across file hashes, DNS lookups, and orchestration API calls
  to distinguish a simple test from a full-blown agentic incident involving automated
  SOC tools.
blind_spots:
- id: no-sysmon-eid7
  owner: Endpoint Engineering
  question: Was log.dll loaded by BluetoothService.exe?
  remediation: Enable Sysmon Event ID 7 for the Windows server fleet.
  requires: hb_module_activity with Sysmon EID 7 coverage
  risk: If module load events are not captured, the primary execution indicator is
    invisible.
  stage: chrysalis-dll-side-loading
- id: http-blind-spot
  owner: Network Security
  question: Did the agent create a Slack channel or Elastic Case?
  remediation: Deploy proxy or endpoint HTTP monitoring for internal-to-SaaS API traffic.
  requires: hb_http_activity with decrypted SSL inspection
  risk: Automated orchestration via API calls may be missed without HTTP-level visibility
    at the proxy or agent.
  stage: agentic-response-orchestration
coverage:
- stage: chrysalis-dll-side-loading
  status: covered
  steps:
  - side-loading-discovery
  - eicar-hash-detection
- stage: agentic-confirmation-phase
  status: covered
  steps:
  - dns-vt-lookups
- stage: agentic-response-orchestration
  status: covered
  steps:
  - agentic-response-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: DLL side-loading is a stealthy execution technique that often bypasses
    standard EDR rules; tracking the subsequent 'agentic' response actions ensures
    we see the full lifecycle of a modern automated intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed the Chrysalis backdoor via DLL side-loading
  (BluetoothService.exe/log.dll) on srv-win-defend-01, potentially triggering automated
  SOC agent responses or external lookups.
labels:
- hunt
- attack.t1574.002
name: Chrysalis DLL Side-Loading and Agentic Response
parameters:
  eicar_sha256:
    default: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    description: SHA256 of the EICAR test file used in the Chrysalis simulation.
    from:
      kind: article
      observed: '2026-08-04'
      ref: elastic-chrysalis-report
    type: hash
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  orchestration_domains:
    default:
    - virustotal.com
    - slack.com
    description: Domains involved in the agentic response phase.
    from:
      kind: article
      observed: '2026-08-04'
      ref: elastic-chrysalis-report
    type: list[domain]
  scope_hosts:
    default:
    - srv-win-defend-01
    description: Target hosts for the hunt; defaults to the srv-win-defend-01 host
      mentioned in research.
    from:
      kind: article
      observed: '2026-08-04'
      ref: elastic-chrysalis-report
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus specifically on Windows servers in the 'srv-win-' range as identified
  in the research scenario. Use the host-scoping step to confirm availability of srv-win-defend-01.
references:
- name: Elastic Security Labs - Benchmarking the Agentic SOC
  url: https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc
related:
- hunt: generic-dll-search-order-hijack
  reason: This hunt is specifically tailored to the Chrysalis campaign observables;
    a broader search for hijacking generic DLL paths is a separate effort.
  relation: alternative
scenario:
  stages:
  - name: Chrysalis DLL Side-Loading
    observables:
    - BluetoothService.exe
    - log.dll
    - srv-win-defend-01
    - EICAR test file hash
    slug: chrysalis-dll-side-loading
    tactic: execution
    techniques:
    - T1574.002
  - name: Agentic Confirmation and Enrichment
    observables:
    - vt.hash.lookup
    - VirusTotal
    - hunt logs
    - EICAR
    slug: agentic-confirmation-phase
    tactic: discovery
  - name: Automated Response Orchestration
    observables:
    - create.case
    - create.channel
    - check.on.call.schedule
    - Slack
    - get.time
    slug: agentic-response-orchestration
    tactic: impact
  summary: The Chrysalis campaign involves a DLL side-loading attack on Windows hosts
    where a malicious library, log.dll, is loaded by the legitimate BluetoothService.exe
    process. The article details an agentic SOC evaluation framework that detects
    this intrusion and automates the confirmation and response phases, including threat
    intelligence enrichment and incident coordination via Slack and case management.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Chrysalis DLL Side-Loading and Agentic Response

This hunt targets the Chrysalis DLL side-loading technique, specifically looking for the 'log.dll' module being loaded by 'BluetoothService.exe'. It further corroborates this activity by searching for the EICAR test hash (used as a stand-in for malicious payloads in this campaign) and monitoring for the secondary 'agentic' actions described in the Elastic research, such as VirusTotal lookups and automated Slack/Case orchestration. It flows from a host scoping step to behavioral module loading, then parallel triage of network and file indicators.

## host-scoping
<!-- Identify Windows Servers in Scope -->
Identify Windows hosts, particularly the srv-win-defend-01 host mentioned in the Chrysalis scenario, within the lookback window.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames matching the expected naming convention for the Chrysalis
  simulation.
reads:
- hostname
- device_uid
- os_version
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname as device_hostname, device_uid, os_version, platform FROM hb_devices WHERE platform = 'windows' AND (LOWER(hostname) = 'srv-win-defend-01' OR LOWER(hostname) LIKE 'srv-win-%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## side-loading-discovery
<!-- Chrysalis DLL Side-Loading Discovery -->
Detect BluetoothService.exe loading the log.dll module, which is the primary execution indicator for the Chrysalis backdoor.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Instances of BluetoothService.exe loading a DLL named log.dll. Legitimate
  services rarely load a generic 'log.dll' from their own directory.
reads:
- device_hostname
- process_name
- module_name
- module_path
- module_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_name, module_path, module_hash_sha256, time FROM hb_module_activity WHERE LOWER(process_name) LIKE '%\\bluetoothservice.exe' AND LOWER(module_name) = 'log.dll' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## corroborate-activity
<!-- Corroborate with Payloads and Agentic Actions -->
parallel:
- → eicar-hash-detection
- → dns-vt-lookups
- → agentic-response-activity
join: → triage-agent

## eicar-hash-detection
<!-- Detection of EICAR Test Payload -->
Check for the presence of the EICAR hash in file activity, which the research uses as a stand-in for the malicious log.dll.

```sqlite target=endpoint role=enrichment params=(eicar_sha256=eicar_sha256, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File touches involving the EICAR hash, specifically by BluetoothService.exe
  or related setup processes.
reads:
- device_hostname
- file_name
- file_path
- file_hash_sha256
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, file_hash_sha256, process_name, time FROM hb_file_activity WHERE file_hash_sha256 = '{{eicar_sha256}}' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## dns-vt-lookups
<!-- External Domain and Tool Lookups -->
Identify DNS lookups to VirusTotal or Slack domains that align with the agentic confirmation phase of the scenario.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, orchestration_domains=orchestration_domains)
~~~yaml
expected: DNS traffic to VirusTotal for hash lookups or Slack for incident coordination.
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
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count FROM hb_dns_activity WHERE (instr(',' || '{{orchestration_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%virustotal%' OR LOWER(query_hostname) LIKE '%slack.com%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname, process_name
```

## agentic-response-activity
<!-- Automated Response Orchestration Activity -->
Identify HTTP traffic related to case creation or Slack channel creation, mimicking the 'agentic response' phase.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to Elastic Case APIs or Slack APIs immediately following the
  detection of the side-loading event.
reads:
- device_hostname
- url_hostname
- url_path
- http_method
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/api/cases%' OR LOWER(url_path) LIKE '%/api/conversations.create%' OR LOWER(url_path) LIKE '%/api/chat.postmessage%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Chrysalis Event Triage -->
```agent target=hunter
cite: required
context:
- side-loading-discovery
- eicar-hash-detection
- dns-vt-lookups
- agentic-response-activity
max_iterations: 4
objective: Analyze the module loading, file hashes, and orchestration activity to
  determine if a Chrysalis side-loading event has occurred and whether an automated
  response was triggered.
success_criteria: A verdict per host indicating if the side-loading event is malicious
  and linked to the Chrysalis simulation.
tools:
- endpoint
- web
```

## judgment
<!-- Route Based on Chrysalis Verdict -->
if~: "the triage verdict is malicious for side-loading of log.dll and corroborates with EICAR or orchestration activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: http-blind-spot)
else: → manual-review

## isolate-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate srv-win-defend-01 (or the affected host) to prevent further C2 or automated response side-effects.
```
→ manual-review

## manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the triage results. Verify if the 'agentic' response was triggered by our own SOC LLM or by an adversary-controlled automation.
```
→ end
