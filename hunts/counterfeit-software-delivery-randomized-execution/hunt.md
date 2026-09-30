---
analysis: 'A detection rule fires on a single domain. This hunt pivots from a network
  lead into a behavioral audit: looking for rare processes extracted by archivers
  into public paths and verifying them against fabricated metadata used by the actor.'
blind_spots:
- id: no-dns-visibility
  question: Did the host resolve the domains via DNS-over-HTTPS (DoH)?
  requires: Endpoint DNS monitoring or proxy decryption
  risk: If the browser uses DoH, the lead query will return zero results, gating the
    hunt even if an infection occurred.
  stage: initial-access-spoofed-sites
- id: metadata-rotation
  question: What if the actor rotates the 'Philips' masquerade brand?
  requires: hb_process_activity metadata
  risk: The metadata audit is high-fidelity for current samples but will miss payloads
    using different fabricated resource strings.
  stage: execution-randomized-payloads
coverage:
- stage: initial-access-spoofed-sites
  status: covered
  steps:
  - dns-campaign-lead
- stage: delivery-dynamic-archive
  status: covered
  steps:
  - rare-archiver-execution
- stage: execution-randomized-payloads
  status: covered
  steps:
  - metadata-masquerade-audit
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: persistence-scheduled-task
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: c2-alibaba-oss-update
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Active malware campaign using server-side payload regeneration makes
    hash-based detection alone ineffective. This hunt provides confidence by correlating
    infrastructure leads with behavioral indicators.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established initial access by tricking a user into downloading
  a polymorphic installer from a spoofed vendor site, which then launches a masqueraded
  payload from a randomized directory.
labels:
- hunt
- attack.t1566.002
- attack.t1204.002
- attack.t1036.005
name: Counterfeit software delivery and randomized execution
parameters:
  archiver_names:
    default:
    - 7zfm.exe
    - 360zip.exe
    - winrar.exe
    description: Common archiver binaries used to extract malicious installers.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[string]
  campaign_hashes:
    default:
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    description: Confirmed SHA256 hashes of late-stage payloads.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[hash]
  impersonated_packages:
    default:
    - razer
    - edge
    - kaspersky
    - sejda
    - youdao
    - diskgenius
    - baidu
    - ocam
    - draw.io
    - steelseries
    - sogou
    - calibre
    - mindmaster
    description: Software names known to be impersonated by the campaign.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  masquerade_companies:
    default:
    - Speech Processing Solutions GmbH
    description: Fabricated company names observed in malicious payload metadata.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[string]
  masquerade_filenames:
    default:
    - PhilipsSpeechDriverConfiguration.exe
    - tu_rt.exe
    description: Original file names from genuine products being masqueraded.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[string]
  scope_hosts:
    default: []
    description: Focus the hunt on specific hosts; leave empty to scan the estate.
    type: list[host]
  spoofed_domains:
    default:
    - pc-razerzone.com.cn
    - kaspersky-lab.hl.cn
    - app-microsoft-edge.com.cn
    - calibre-ebook.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    description: Spoofed vendor and delivery domains from the research.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts running software the campaign is known to impersonate
  (e.g., Razer, Kaspersky, Microsoft Edge) as identified in the scoping step, then
  use the DNS lead to broaden the search.
references:
- name: "MSRC \u2014 Counterfeit installers to system compromise: Tracking a deceptive\
    \ software download campaign"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-task-persistence
  reason: Persistence through scheduled tasks is a downstream stage that requires
    baselining of the Schedule service.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - app-microsoft-edge.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    slug: initial-access-spoofed-sites
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Dynamically generated installer archive
    observables:
    - app_setup.6653004.zip
    - zinst.zip
    - zintall.zip
    - intsoft.zip
    - innstll.zip
    - /712down
    - /73inst
    slug: delivery-dynamic-archive
    tactic: execution
    techniques:
    - T1204.002
  - name: Randomized stage-one payload execution
    observables:
    - a_instapp83353001.exe
    - C:\Users\Public\
    - C:\ProgramData\
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - 'TODO: <Product name>'
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    slug: execution-randomized-payloads
    tactic: execution
    techniques:
    - T1204.002
    - T1036.005
  - name: Implant persistence via Scheduled Task
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Repurposed update client C2
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - tu_rt.exe
    - _ir_tu2_temp_
    - Indigo Rose TrueUpdate Client
    slug: c2-alibaba-oss-update
    tactic: command-and-control
    techniques:
    - T1071
    - T1105
  summary: This campaign uses high-fidelity vendor look-alike domains to distribute
    dynamically generated installer archives to Chinese-speaking users. Once executed,
    the malicious installers drop randomized payloads that establish persistence via
    Scheduled Tasks and repurpose legitimate update utilities to retrieve further
    stages from Alibaba Cloud infrastructure.
series:
  index: 1
  slug: counterfeit-installers-to-system-compromise-tracking-a-deceptive-software-download-campaign
  title: 'Counterfeit installers to system compromise: Tracking a deceptive software
    download campaign'
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


# Counterfeit software delivery and randomized execution

This hunt identifies the early stages of the Silver Fox (Yinhu) campaign by gating expensive behavioral queries behind a cheap DNS lead. It first identifies hosts running software the campaign frequently impersonates (Kaspersky, Razer, Microsoft Edge) to provide context. The hunt then scans for resolutions of known look-alike domains. If confirmed, it fans out to detect the execution of rare binaries spawned from archiver tools and audits for fabricated file metadata used to masquerade malicious payloads. An agent correlates the delivery traffic with randomized execution patterns to route high-confidence findings to containment.

## identify-impersonated-software
<!-- Scope: Identify potential targets -->
Find hosts with software matching the campaign's lure list to provide asset context.

```sqlite target=endpoint role=scoping params=(impersonated_packages=impersonated_packages)
~~~yaml
expected: A list of hosts running software titles like Razer or Kaspersky. Silence
  means the specific software is not installed, but does not preclude infection via
  other lures.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{impersonated_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{impersonated_packages}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## dns-campaign-lead
<!-- Lead: Look-alike domain resolutions -->
Identify hosts that successfully resolved domains known to host spoofed download pages or deliver payloads.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, spoofed_domains=spoofed_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving campaign domains. Silence proves the domains listed are
  not currently active in the estate.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{spoofed_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## gate-agent
<!-- Gate: Evaluate the lead -->
```agent target=hunter
cite: required
context:
- dns-campaign-lead
max_iterations: 3
objective: Confirm if any host successfully resolved the suspicious look-alike domains
  within the lookback window.
success_criteria: A verdict per host citing the specific domain resolution.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Open fan-out -->
if~: "the gate-agent verdict confirms at least one host resolved a campaign domain" (confidence: high, judge=hunter)
then: → behavioral-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-visibility)
else: → close-out

## behavioral-fan-out
<!-- Behavioral Fan-out -->
parallel:
- → rare-archiver-execution
- → metadata-masquerade-audit
join: → triage-agent

## rare-archiver-execution
<!-- Behavior: Rare processes from archivers -->
Detect binaries launched by archiver tools from randomized folders in Public or ProgramData, then stack-count to find anomalies.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, archiver_names=archiver_names, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare binaries spawned from archivers into world-writable paths.
  Fleet-wide software will exceed the host threshold and be filtered.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, LOWER(process_path) AS path, parent_process_name, COUNT(*) AS run_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{archiver_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND (LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\programdata\\%') AND time >= datetime('now', '-{{lookback_days}} days')) GROUP BY device_hostname, process_name, path, parent_process_name HAVING COUNT(DISTINCT device_hostname) <= 3
```

## metadata-masquerade-audit
<!-- Behavior: Metadata masquerade audit -->
Audit process events for metadata fabricated by the attacker to bypass verification, including 'Philips' or 'Speech Processing' resources.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, masquerade_companies=masquerade_companies, masquerade_filenames=masquerade_filenames, campaign_hashes=campaign_hashes, lookback_days=lookback_days)
~~~yaml
expected: Process events with campaign-consistent masquerade attributes. This confirms
  the presence of payloads even if filenames are randomized.
reads:
- device_hostname
- process_name
- process_path
- process_file_company
- process_original_file_name
- process_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_file_company, process_original_file_name, process_hash_sha256, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{masquerade_companies}}' || ',', ',' || process_file_company || ',') > 0 OR instr(',' || '{{masquerade_filenames}}' || ',', ',' || process_original_file_name || ',') > 0 OR instr(',' || '{{campaign_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days'))
```

## triage-agent
<!-- Triage: Weigh the evidence -->
```agent target=hunter
cite: required
context:
- identify-impersonated-software
- gate-agent
- rare-archiver-execution
- metadata-masquerade-audit
max_iterations: 6
objective: Determine if any host showing look-alike domain traffic also executed a
  rare binary extracted from an archiver or carrying fabricated metadata.
success_criteria: A per-host verdict citing rows for every claim.
tools:
- endpoint
```

## route-decision
<!-- Route findings -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the binary identified in the randomized path for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the DNS resolutions and archiver lineage. Verify if any software identified in the scoping step was the intended lure.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no campaign-consistent DNS resolutions or archiver-spawned processes were observed.
```
→ end
