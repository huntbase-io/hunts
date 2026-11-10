---
analysis: A rule for SGTool.exe writing DLLs is noisy due to legitimate updates. This
  hunt correlates specific network resolution anomalies (Alibaba IPs for Tencent domains)
  with rare file creation events that stack-count hashes across the fleet.
blind_spots:
- id: endpoint-telemetry-gap
  question: Whether a host without an agent is resolving Sogou domains to rogue IPs.
  requires: Endpoint agent on every host in scope
  risk: A host without an agent contributes no DNS or file activity rows, leaving
    it invisible to this hunt.
  stage: initial-access-dns-hijack
- id: dns-vector-blindness
  question: How the DNS hijacking is being achieved (e.g., router compromise or ISP
    interception).
  requires: Router or ISP-level DNS logs
  risk: We see the results of the hijack but cannot identify the root cause of the
    network-level manipulation.
  stage: initial-access-dns-hijack
coverage:
- stage: initial-access-dns-hijack
  status: covered
  steps:
  - dns-hijack-detection
- stage: execution-dll-side-loading
  status: covered
  steps:
  - rare-sgtool-file-writes
- reason: "Belongs to another part of the 'SlippyNunchucks hijacks Sogou Input Method\u2019\
    s brand promotion mechanism to distribute malware' series."
  stage: persistence-registry-storage
  status: out_of_scope
- reason: "Belongs to another part of the 'SlippyNunchucks hijacks Sogou Input Method\u2019\
    s brand promotion mechanism to distribute malware' series."
  stage: command-and-control-dmtp
  status: out_of_scope
- reason: "Belongs to another part of the 'SlippyNunchucks hijacks Sogou Input Method\u2019\
    s brand promotion mechanism to distribute malware' series."
  stage: exfiltration-c2-channel
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SlippyNunchucks is an active China-aligned actor targeting organizations
    via AitM vectors. Detecting this DNS hijack is critical to stopping DarkVigil
    delivery before exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked DNS resolution for Sogou Input Method update
  domains to deliver a malicious configuration, causing the legitimate SGTool.exe
  process to download and side-load the DarkVigil implant.
labels:
- hunt
- attack.t1574.001
- attack.t1036.005
- attack.t1105
- attack.t1557
- attack.t1659
- attack.t1190
- command and control
- execution
- exfiltration
- initial access
- persistence
name: SlippyNunchucks Sogou Update Hijack
parameters:
  attacker_ips:
    default:
    - 47.239.250.102
    - 47.237.122.175
    - 47.86.15.162
    - 47.236.254.159
    description: Known attacker-controlled staging and hijacking IPs.
    from:
      kind: article
      observed: '2026-11-04'
      ref: eset-research
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt; leave empty for fleet-wide.
    type: list[host]
  sogou_domains:
    default:
    - config.pinyin.sogou.com
    - sogou-cdn.com
    - dev.soft-pn
    description: Sogou update and configuration domains targeted for hijacking.
    from:
      kind: article
      observed: '2026-11-04'
      ref: eset-research
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts running Sogou Pinyin, prioritizing South and East Asia
  regions. Use software inventory to narrow to versions before 16.10.
references:
- name: "ESET Research \u2014 SlippyNunchucks hijacks Sogou Input Method\u2019s brand\
    \ promotion mechanism"
  url: https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
related:
- hunt: darkvigil-registry-persistence
  reason: This hunt targets the delivery; the follow-on identifies how the implant
    stores plugins in the registry.
  relation: follows
scenario:
  stages:
  - name: DNS Hijacking and Configuration Injection
    observables:
    - config.pinyin.sogou.com
    - 47.236.254.159
    - 47.237.122.175
    - 47.239.250.102
    - CVE-2026-120422
    slug: initial-access-dns-hijack
    tactic: initial-access
    techniques:
    - T1557
    - T1659
    - T1190
  - name: Payload Delivery and DLL Side-Loading
    observables:
    - SGTool.exe
    - libcef.dll
    - Microsoft.VisualStudio.QualityTools.UnitTestFramework.dll
    - sogou-cdn.com
    - Adobe binary renamed as Sogou component
    slug: execution-dll-side-loading
    tactic: execution
    techniques:
    - T1574.001
    - T1036.005
    - T1105
  - name: Modular Plugin Storage
    observables:
    - Compressed binaries stored in registry keys
    slug: persistence-registry-storage
    tactic: persistence
    techniques:
    - T1112
  - name: DarkVigil DMTP Communication
    observables:
    - blog.wangmen
    - update.msspr
    - img.fusfu
    - 47.86.15.162
    - Duplex Message Transport Protocol (DMTP)
    - dev.soft-pn
    slug: command-and-control-dmtp
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1573
    - T1105
  - name: Data Exfiltration via Vigil Panel
    observables:
    - Vigil web administration panel
    - DMTP exfiltration traffic
    slug: exfiltration-c2-channel
    tactic: exfiltration
    techniques:
    - T1041
  summary: "SlippyNunchucks hijacks Sogou Input Method\u2019s branded vocabulary promotion\
    \ mechanism via DNS interception of insecure HTTP requests to deliver a malicious\
    \ configuration. This configuration triggers the download of the DarkVigil implant,\
    \ which is executed through DLL side-loading and maintains persistence by storing\
    \ modular plugins within the Windows Registry. Command and control is handled\
    \ via the custom Duplex Message Transport Protocol (DMTP) for tasking and data\
    \ exfiltration."
series:
  index: 1
  slug: slippynunchucks-hijacks-sogou-input-method-s-brand-promotion-mechanism-to-distribute-malware
  title: "SlippyNunchucks hijacks Sogou Input Method\u2019s brand promotion mechanism\
    \ to distribute malware"
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


# SlippyNunchucks Sogou Update Hijack

This hunt targets a sophisticated campaign where the SlippyNunchucks threat actor exploits insecure HTTP communications in Sogou Input Method (CVE-2026-120422). By hijacking DNS requests for Sogou's configuration domains, the attacker serves a malicious configuration that instructs the legitimate application to download payloads into directories used for DLL side-loading. The hunt identifies Sogou installations, detects anomalous DNS resolutions to infrastructure outside of Sogou's typical network (specifically targeting Alibaba-hosted staging areas), and corroborates these with rare file writes by the Sogou component manager SGTool.exe. An agent weighs the timing and prevalence of these indicators to identify compromised endpoints.

## sogou-inventory-scoping
<!-- Identify Sogou Input Method installations -->
Identify hosts that have Sogou software installed to scope subsequent queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with Sogou software. Versions below 16.10 are vulnerable
  to the reported configuration hijacking.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%sogou%' OR LOWER(package_name) LIKE '%pinyin%')
```

## corroborate-hijack
<!-- Corroborate hijack and delivery -->
parallel:
- → dns-hijack-detection
- → rare-sgtool-file-writes
join: → agent-triage

## dns-hijack-detection
<!-- Detect DNS hijack of Sogou domains -->
Identify if Sogou domains are resolving to attacker-controlled infrastructure.

```sqlite target=endpoint role=detection-candidate params=(sogou_domains=sogou_domains, attacker_ips=attacker_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS answers containing the reported attacker IPs for legitimate Sogou domains.
  Silence suggests normal resolution.
reads:
- device_hostname
- query_hostname
- answers
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, query_hostname, answers, time FROM hb_dns_activity WHERE (instr(',' || '{{sogou_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{attacker_ips}}' || ',', ',' || answers || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-sgtool-file-writes
<!-- Identify rare binaries written by SGTool.exe -->
Find rare DLL or EXE files written by the Sogou component manager to distinguish malware delivery from standard updates.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A file written by SGTool.exe that is present on very few hosts. Legitimate
  software updates should be prevalent across the estate.
prevalence:
  by: device_hostname
  key:
  - file_hash_sha256
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- file_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT device_hostname, LOWER(file_path) AS path, file_name, file_hash_sha256, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(process_name) LIKE '%sgtool.exe' AND (LOWER(file_name) LIKE '%.dll' OR LOWER(file_name) LIKE '%.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, file_path, file_name, file_hash_sha256 HAVING host_count <= 3 ORDER BY host_count ASC
```

## agent-triage
<!-- Weigh hijack and delivery evidence -->
```agent target=hunter
cite: required
context:
- dns-hijack-detection
- rare-sgtool-file-writes
max_iterations: 6
objective: Determine if the DNS resolution of Sogou domains to known attacker IPs
  (specifically Alibaba infrastructure) and the subsequent rare file writes by SGTool.exe
  indicate a successful SlippyNunchucks infection.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  DNS answers and the rare file paths.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the agent-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the rare DLL/EXE files identified by the hunt for forensic analysis, then remove the payloads and the SGTool.exe binary.
```
→ analyst-review

## analyst-review
<!-- Analyst review and confirmation -->
```manual target=analyst
Review the DNS answers and geolocate the IPs. Confirm if the written DLL is one of the reported names (libcef.dll, Microsoft.VisualStudio.QualityTools.UnitTestFramework.dll) or if its PE metadata matches the reported Adobe binary renaming.
```
→ close-out

## close-out
<!-- Close-out and documentation -->
```manual target=analyst
Record the results. If infections were found, pivot to the follow-on hunt for registry-based plugin persistence. Ensure all Sogou installations are updated to version 16.10.
```
→ end
