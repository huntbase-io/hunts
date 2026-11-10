---
analysis: A simple rule may fire on the task name, but this hunt correlates the initial
  staging behavior, the rare temporary executables, and the network callbacks into
  a two-phase assessment that confirms the infection chain.
blind_spots:
- id: no-dns-attribution
  question: Which specific host resolved the campaign tracking domain?
  requires: hb_dns_activity with host-to-IP attribution
  risk: If DNS logs only capture the resolver's traffic without the client's internal
    IP, the infected host cannot be identified directly from network telemetry.
  stage: c2-offer-callback
- id: http-query-truncation
  question: Was the 'd=inno' parameter present in the tracking callback?
  requires: hb_http_activity with url_query retention
  risk: The campaign relies on HTTP query parameters for attribution; if proxy logs
    truncate the URL after the path, the offer-execution signal is lost.
  stage: c2-offer-callback
coverage:
- stage: initial-access-deceptive-lures
  status: covered
  steps:
  - scope-hosts-with-lures
- stage: execution-inno-runner-staging
  status: covered
  steps:
  - inno-staging-activity
  - rare-temporary-runners
- stage: c2-offer-callback
  status: covered
  steps:
  - tracking-callbacks
- stage: persistence-monetization-payloads
  status: covered
  steps:
  - monetization-persistence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Silent proxyware and compute-resource theft expose an organization
    to unauthorized network traffic and resource degradation; identifying and clearing
    these persistent tasks is necessary to stop the ongoing monetization of business
    assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has delivered monetization payloads using a trojanized Inno
  Setup installer that stages numbered executables in temporary paths, contacts offer-tracking
  infrastructure, and establishes persistence via SYSTEM-level scheduled tasks.
labels:
- hunt
- attack.t1036
- attack.t1053.005
- attack.t1059.001
- attack.t1071.001
- attack.t1105
- attack.t1195.002
- attack.t1204.002
- attack.t1496
- attack.t1562.001
- attack.t1564.003
- command and control
- execution
- initial access
- persistence
name: Trojanized Inno Installer Staging and Callbacks
parameters:
  c2_domains:
    default:
    - offerloader.da
    - orbittrack.cfd
    - prairielink.cfd
    - willowbox.xyz
    - stonestation.cfd
    - foldlodge.xyz
    - friendsanchor.xyz
    - fallport.cfd
    - wishcourt.cfd
    - cratebase.cfd
    description: Offer-tracking and callback domains identified in the report.
    from:
      kind: article
      observed: '2026-11-03'
      ref: msrc-blog-20261103
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on user workstations where software inventory shows activators or
  cracked tools. If these are not present, expand to the whole estate filtering for
  Inno-specific temp paths.
references:
- name: "Microsoft Security Blog \u2014 Fake-download campaign uses trojanized installers\
    \ to deliver monetization payloads"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/
related:
- hunt: proxyware-resource-theft
  reason: This hunt focuses on the Inno Setup delivery mechanism; a broader hunt would
    look for any proxyware installation regardless of the original lure.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Deceptive download lures
    observables:
    - Echo Client.exe
    - FabFilter Total Bundle.exe
    - Navicat Premium crack.exe
    - auto-clicker.exe
    - clownfishvoicechanger.exe
    slug: initial-access-deceptive-lures
    tactic: initial-access
    techniques:
    - T1195.002
    - T1204.002
  - name: Inno Setup runner staging
    observables:
    - '%TEMP%\is-*.tmp\'
    - eld0.exe
    - eld1.exe
    - eld5.exe
    - set_*.exe
    - /SL5=
    - /SPAWNWND=
    - /FIRSTWND=
    slug: execution-inno-runner-staging
    tactic: execution
    techniques:
    - T1059.001
    - T1036
  - name: Offer execution callback
    observables:
    - d=inno
    - r=offer_execution
    - r=offer_execution_fail
    - orbittrack.cfd
    - prairielink.cfd
    - willowbox.xyz
    - stonestation.cfd
    - foldlodge.xyz
    - friendsanchor.xyz
    - fallport.cfd
    - wishcourt.cfd
    - cratebase.cfd
    - beliefdesk.xyz
    - companyharbor.xyz
    - signalpane.cfd
    - inkact.xyz
    - wishgrove.cfd
    slug: c2-offer-callback
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1105
  - name: Monetization payload installation
    observables:
    - C:\Program Files\WorldProxyPool\sdk-agent.exe
    - WorldProxyPoolAgent
    - WorldProxyPoolWatchdog
    - WorldProxyPoolUpdater
    - CharityEngine
    - Berkeley Open Infrastructure for Network Computing
    - Advanced Windows Manager
    - Windows Manager
    slug: persistence-monetization-payloads
    tactic: persistence
    techniques:
    - T1053.005
    - T1496
    - T1564.003
    - T1562.001
  summary: A campaign using trojanized Inno Setup installers delivered via fake software
    downloads to install various monetization payloads such as proxyware, distributed
    computing agents, and adware. The campaign utilizes a structured HTTP callback
    system to track offer installation status and secures persistence through SYSTEM-level
    scheduled tasks.
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


# Trojanized Inno Installer Staging and Callbacks

This hunt identifies the multi-stage execution and persistence model used by a fake-download campaign. The campaign lures users with cracked software and activators to run Inno Setup-style wrappers. These wrappers stage numbered payloads in the user's temp directory and contact rotating infrastructure to report offer outcomes. Finally, the campaign installs monetization components like proxyware or compute-resource miners, often persistent through SYSTEM-level scheduled tasks. The hunt follows these stages in two phases: first identifying the temporary staging activity and then corroborating it with the network callbacks and persistence mechanisms.

## scope-hosts-with-lures
<!-- Scope to hosts with software lures -->
Identify hosts running software packages commonly used as lures for this campaign, such as cracked tools, activators, or game-related executors.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts containing suspicious software. Silence means no such software
  is indexed, but the hunt should still proceed unscoped if the analyst chooses.
reads:
- asset_scope
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%crack%' OR LOWER(package_name) LIKE '%activator%' OR LOWER(package_name) LIKE '%unlocker%' OR LOWER(package_name) LIKE '%roblox%') AND asset_scope = 'endpoint'
```

## early-stage-fan-out
<!-- Early staging search -->
parallel:
- → inno-staging-activity
- → rare-temporary-runners
join: → triage-early-staging

## inno-staging-activity
<!-- Inno runner execution patterns -->
Identify processes executing from the Inno temporary directory or using characteristic wrapper arguments like /SL5.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process rows showing the Inno runner staging environment. The parent may
  be the original lure filename.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, process_path, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\temp\is-%.tmp\%' OR LOWER(process_cmd_line) LIKE '%/sl5=%' OR LOWER(process_cmd_line) LIKE '%/spawnwnd=%' OR LOWER(process_cmd_line) LIKE '%/firstwnd=%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-temporary-runners
<!-- Prevalence of temporary runner names -->
Stack-count processes running from the Inno temp path so rare numbered stages like eld0.exe stand out from legitimate updaters.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary name seen on very few hosts (e.g., eld1.exe); common installer
  names are ignored.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT LOWER(process_name) AS p_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\temp\is-%.tmp\%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY 1 HAVING host_count <= 5 ORDER BY host_count ASC
```

## triage-early-staging
<!-- Triage early staging activity -->
```agent target=hunter
cite: required
context:
- inno-staging-activity
- rare-temporary-runners
max_iterations: 3
objective: Identify hosts showing Inno Setup runner activity based on temp paths and
  rare numbered process names.
success_criteria: A verdict of suspicious if rare processes execute from the Inno
  temp path with /SL5 arguments.
tools:
- endpoint
```

## follow-on-fan-out
<!-- Search for follow-on activity -->
parallel:
- → tracking-callbacks
- → monetization-persistence
join: → final-monetization-triage

## tracking-callbacks
<!-- DNS callbacks to tracking domains -->
Match the report's offer-tracking domains to DNS activity on the host.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any row links a host to a known campaign tracking domain. Silence is common
  as domains rotate.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## monetization-persistence
<!-- Monetization task persistence -->
Find scheduled tasks associated with WorldProxyPool, CharityEngine, or BOINC installed by the campaign.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts with monetization tasks. WorldProxyPoolAgent is the high-confidence
  indicator.
reads:
- device_hostname
- job_cmd_line
- job_name
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%worldproxypool%' OR LOWER(job_name) LIKE '%charityengine%' OR LOWER(job_name) LIKE '%boinc%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## final-monetization-triage
<!-- Confirm monetization payload installation -->
```agent target=hunter
cite: required
context:
- triage-early-staging
- tracking-callbacks
- monetization-persistence
max_iterations: 3
objective: Confirm whether the host has been compromised by the fake-download campaign
  by linking the Inno staging activity to follow-on callbacks and monetization tasks.
success_criteria: A verdict of malicious for hosts showing both staging activity and
  either persistent tasks or DNS callbacks.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on monetization verdict -->
if~: "the final-monetization-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: no-dns-attribution)
else: → close-out-report

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host to prevent proxyware traffic and compute monetization. Collect temporary files and task XML for forensic capture.
```
→ remediation-review

## remediation-review
<!-- Remediation and analyst review -->
```manual target=analyst
Review the rows cited by the agents. Confirm the removal of the WorldProxyPool or CharityEngine tasks and their associated binaries from Program Files. Scan for other PUA components that may have been bundled.
```
→ close-out-report

## close-out-report
<!-- Close-out report -->
```manual target=analyst
Summarize the number of hosts identified and the specific monetization branches found. Note any blind spots in DNS or HTTP telemetry encountered during the hunt.
```
→ end
