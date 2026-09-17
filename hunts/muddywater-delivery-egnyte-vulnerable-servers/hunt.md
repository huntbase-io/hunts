---
analysis: A rule fires on 'Egnyte' or 'rare EXE', but this hunt combines inventory
  state (scoping), delivery behavior (HTTP), and prevalence (rare files) into a single
  triage context that can distinguish between a standard Egnyte user and a targeted
  phishing victim.
blind_spots:
- id: no-http-telemetry
  question: whether the host accessed the Egnyte links
  requires: hb_http_activity with full URL or domain
  risk: Endpoints behind encrypted proxies or missing proxy telemetry will not show
    Egnyte activity, leaving rare file creation as the only signal.
  stage: initial-access-delivery
- id: zip-content-visibility
  question: what is inside the ZIP archive before it is extracted
  requires: sandboxing or file-content extraction
  risk: Adversaries can nest files deep inside archives to bypass surface-level file
    monitoring; we only see the .exe once it touches the disk as a standalone file.
  stage: initial-access-delivery
coverage:
- stage: initial-access-delivery
  status: covered
  steps:
  - identify-exposed-products
  - egnyte-delivery-traffic
  - rare-zip-exe-creation
- reason: Belongs to the second hunt in this series.
  stage: muddyrot-execution-and-setup
  status: out_of_scope
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: persistence-scheduled-task
  status: out_of_scope
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: command-and-control-raw-tcp
  status: out_of_scope
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: interactive-shell-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MuddyWater targets strategic sectors globally. Identifying the delivery
    vector early prevents the 'MuddyRot' implant from achieving persistence and allows
    for proactive patching of exposed server products.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are targeting the organization via phishing PDFs linking to
  Egnyte storage or by exploiting vulnerabilities in internet-exposed Exchange and
  SharePoint servers to deliver the MuddyRot implant.
labels:
- hunt
- attack.t1566.002
- attack.t1190
- attack.t1059
name: MuddyWater delivery via Egnyte and vulnerable servers
parameters:
  egnyte_domains:
    default:
    - egnyte.com
    - egnyte.net
    description: Domains used by the Egnyte storage service for payload delivery.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  muddyrot_hashes:
    default:
    - 94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472
    - b8703744744555ad841f922995cef5dbca11da22565195d05529f5f9095fbfca
    - 73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e
    - 960d4c9e79e751be6cad470e4f8e1d3a2b11f76f47597df8619ae41c96ba5809
    description: Known MuddyRot implant hashes from the article.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: list[hash]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus first on hosts running Exchange and SharePoint to address the exploitation
  vector. Then widen to user workstations to identify phishing victims who may have
  clicked Egnyte links.
references:
- name: "Sekoia \u2014 MuddyWater replaces Atera with custom MuddyRot implant"
  url: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
related:
- hunt: muddyrot-execution-and-setup
  reason: This hunt detects arrival; the execution hunt detects activation and initial
    setup.
  relation: follows
scenario:
  stages:
  - name: Initial Access via Phishing or Exploitation
    observables:
    - PDF decoys related to online courses or webinars
    - Links to Egnyte storage service
    - Malicious ZIP archives containing MuddyRot
    - Exploitation of Exchange or SharePoint servers
    slug: initial-access-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: MuddyRot Implant Execution
    observables:
    - Process documentsmanagerreporter.exe
    - Mutex named DocumentUpdater
    - Dynamic loading of Kernel32.dll, Advapi32.dll, Ole32.dll, and Ws2_32.dll
    - In-memory string deobfuscation
    slug: muddyrot-execution-and-setup
    tactic: execution
    techniques:
    - T1059
  - name: Persistence via Scheduled Task
    observables:
    - Path c:\programdata\softwarememory\documentsmanagerreporter.exe
    - Scheduled task named DocumentsManagerReporter
    - COM object CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DDBD3E73E6154572DD
    - Daily execution schedule
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: C2 Communication over Port 443
    observables:
    - IP 91.235.234.202
    - IP 146.19.143.14
    - TCP port 443
    - Obfuscated C2 traffic (byte subtraction by 3)
    slug: command-and-control-raw-tcp
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
  - name: Reverse Shell and File Triage
    observables:
    - cmd.exe spawned via anonymous pipes
    - Buffer file named 'exit' in working directory
    - Hostname and username fingerprinting in format 'hostname/username'
    slug: interactive-shell-and-exfiltration
    tactic: execution
    techniques:
    - T1059.003
  summary: MuddyWater is distributing a new C-based implant named MuddyRot via spear
    phishing PDF lures and Egnyte downloads, replacing their previous use of legitimate
    RMM tools like Atera. The implant establishes persistence via scheduled tasks
    using COM objects and provides reverse shell and file management capabilities
    over raw TCP port 443.
series:
  index: 1
  slug: muddywater-replaces-atera-with-custom-muddyrot-implant
  title: MuddyWater replaces Atera with custom MuddyRot implant
  total: 3
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


# MuddyWater delivery via Egnyte and vulnerable servers

This hunt focuses on the initial delivery phase of MuddyWater's MuddyRot campaign. It begins by identifying high-value targets—servers running Exchange or SharePoint—that the research identifies as primary exploitation vectors. It then monitors for web activity to Egnyte domains, which the actor uses to host malicious ZIP archives, and correlates this with the creation of rare archive or executable files in user-writable paths. An agent weighs the findings from these independent surfaces to distinguish targeted attacks from normal user activity.

## identify-exposed-products
<!-- Identify potentially targeted server products -->
Scope the hunt to hosts running Exchange or SharePoint, which are named in the research as primary exploitation targets for this actor.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts running sensitive web-facing software. Silence means no
  such software is inventoried on the enrolled estate.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%exchange%' OR LOWER(package_name) LIKE '%sharepoint%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-delivery
<!-- Corroborate delivery via web and file activity -->
parallel:
- → egnyte-delivery-traffic
- → rare-zip-exe-creation
join: → triage-delivery

## egnyte-delivery-traffic
<!-- HTTP requests to Egnyte domains -->
Identify hosts interacting with the cloud storage service used by MuddyWater for payload delivery.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Endpoints requesting files from Egnyte. Presence is common in some orgs,
  requiring correlation with rare file landing.
reads:
- device_hostname
- url_full
- user_agent
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_full, user_agent, src_endpoint_ip, time FROM hb_http_activity WHERE (LOWER(url_hostname) LIKE '%egnyte.com' OR LOWER(url_hostname) LIKE '%egnyte.net') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-zip-exe-creation
<!-- Rare ZIP or EXE creation in writable paths -->
Find potentially malicious files dropped from a web browser or archive extraction, stack-counting to isolate campaign artifacts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A file that appeared on very few hosts. Presence of a hash from the known
  list confirms the campaign.
prevalence:
  by: device_hostname
  key:
  - file_hash_sha256
  rare_below: 3
reads:
- file_name
- file_path
- file_hash_sha256
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT file_name, file_path, file_hash_sha256, device_hostname, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%.zip' OR LOWER(file_path) LIKE '%.exe') AND (LOWER(file_path) LIKE '%\downloads\%' OR LOWER(file_path) LIKE '%\temp\%' OR LOWER(file_path) LIKE '%\public\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, file_path, file_hash_sha256, device_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-delivery
<!-- Correlate delivery and exposure evidence -->
```agent target=hunter
cite: required
context:
- identify-exposed-products
- egnyte-delivery-traffic
- rare-zip-exe-creation
max_iterations: 3
objective: 'Determine if a host was targeted or compromised via phishing or exploitation,
  checking the rare-zip-exe-creation findings against the list of known hashes: {{muddyrot_hashes}}.'
success_criteria: A per-host verdict (malicious | suspicious | benign) with citations
  for the HTTP traffic or file hashes.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on delivery verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and preserve the downloaded ZIP/EXE for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the HTTP logs for the Egnyte connection and the subsequent file creation. Verify if any process executed from the suspicious path. If vulnerable servers were identified, review web logs for exploitation attempts.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
If servers running Exchange/SharePoint were found but no delivery was detected, prioritize patching. If delivery was detected but blocked by existing rules, document the success.
```
→ end
