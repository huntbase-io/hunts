---
analysis: "A detection rule for the naming pattern exists, but it is prone to false\
  \ positives from legitimate installers. This hunt provides the necessary context\u2014\
  DNS interaction with malicious domains and fleet-wide rarity\u2014to distinguish\
  \ the campaign from normal software updates."
blind_spots:
- id: limited-endpoint-visibility
  owner: Endpoint Security Team
  question: whether randomized payloads executed on unmanaged assets
  remediation: Validate agent coverage against the asset management database.
  requires: endpoint agent presence on all workstations
  risk: A host without an agent resolving a lure domain will show DNS activity but
    no process or file events, leading to an incomplete triage.
  stage: execution-randomized-stage-one
- id: ssl-inspection-gap
  owner: Network Engineering
  question: which specific zip archive was retrieved during the session
  remediation: Enable SSL/TLS interception for egress traffic to cloud hosting providers.
  requires: hb_http_activity with full URL path visibility
  risk: Without URL paths, we see the visit to 'gehie246.com' but cannot confirm if
    a download occurred, relying solely on DNS as the lead.
  stage: initial-access-spoofed-downloads
coverage:
- stage: initial-access-spoofed-downloads
  status: covered
  steps:
  - dns-resolutions-to-lures
- stage: execution-wrapper-installer
  status: covered
  steps:
  - wrapper-installer-naming
- stage: execution-randomized-stage-one
  status: covered
  steps:
  - rare-execution-in-public-paths
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: defense-evasion-masquerading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: persistence-scheduled-task
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: c2-alibaba-oss
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This campaign leverages server-side payload regeneration, which invalidates
    static hash-based detections. This hunt provides the behavioral correlation between
    infrastructure interaction and rare execution patterns necessary to find these
    changing payloads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has directed users to spoofed vendor domains to download archive-wrapped
  installers, which execute randomized stage-one payloads from user-writable paths
  like C:\Users\Public.
labels:
- hunt
- attack.t1071
- attack.t1204.002
- attack.t1059
- attack.t1562.001
name: Counterfeit Installer Delivery and Randomized Execution
parameters:
  delivery_hosts:
    default:
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    description: Intermediate infrastructure used for payload delivery.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-silver-fox
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-lookback
    type: number
  lure_domains:
    default:
    - pc-razerzone.com.cn
    - app-microsoft-edge.com.cn
    - kaspersky-lab.hl.cn
    - sejda.hl.cn
    - translate-youdao.hl.cn
    - zh-diskgenius.com.cn
    - baidu-pan.com.cn
    - ocam-pc.com.cn
    - cn-drawio.com.cn
    - steelseries-cn.com.cn
    - gw-sogou.com.cn
    - calibre-ebook.com.cn
    - mindmoster.com.cn
    description: Vendor impersonation domains used in the campaign.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-silver-fox
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt, typically derived from the scoping
      step.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-defined
    type: list[host]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially focus on hosts that already have legitimate instances
  of software commonly used in the lures (Razer, Kaspersky, etc.) to prioritize users
  who might realistically seek out an update for those products.
references:
- name: "MSRC Blog \u2014 Counterfeit installers to system compromise: Tracking a\
    \ deceptive software download campaign"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-masquerade-and-persistence
  reason: This hunt identifies the initial entry and stage-one execution; subsequent
    persistence through scheduled tasks is covered by the sibling hunt.
  relation: follows
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - app-microsoft-edge.com.cn
    - kaspersky-lab.hl.cn
    - sejda.hl.cn
    - translate-youdao.hl.cn
    - zh-diskgenius.com.cn
    - baidu-pan.com.cn
    - ocam-pc.com.cn
    - cn-drawio.com.cn
    - steelseries-cn.com.cn
    - gw-sogou.com.cn
    - calibre-ebook.com.cn
    - mindmoster.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    slug: initial-access-spoofed-downloads
    tactic: initial-access
    techniques:
    - T1071
  - name: Wrapper installer execution
    observables:
    - a_instapp83353001.exe
    - z_instapp83351010.exe
    - ainstaller-86533003.exe
    - ainst8663586104.exe
    - app_setup.6653004.zip
    slug: execution-wrapper-installer
    tactic: execution
    techniques:
    - T1204.002
  - name: Randomized stage-one payload
    observables:
    - C:\Users\Public\sE94yD\aLcUaw.exe
    - C:\Users\Public\nvdPX5\2b3L5i.exe
    - C:\Users\Public\yZ6A88\9bEELI.exe
    - C:\Users\Public\Y93eny\Ge86Zr.exe
    - C:\Users\Public\Mmzm0e\Lrrhwp.exe
    - C:\Users\Public\YJMvsB\BcQVw7.exe
    - 'sha256: 676a2a7b94ca54e19597793a388053c892850931f6e076735e5d122283083e9d'
    slug: execution-randomized-stage-one
    tactic: execution
    techniques:
    - T1059
  - name: Binary masquerading
    observables:
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - tu_rt.exe
    - Indigo Rose TrueUpdate Client
    - 'TODO: <Product name>'
    - D:\hellothere\svchost.exe
    - XPSPLOG.dll
    slug: defense-evasion-masquerading
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1036.005
  - name: Persistence via Task Scheduler
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\zsMmvukD\beuv4Mie.exe
    - C:\ProgramData\uwMUCYBN\SaYC4Mga.exe
    - Temp\_ir_tu2_temp_
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: C2 via Alibaba Cloud OSS
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - port 443
    slug: c2-alibaba-oss
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  summary: Attackers impersonate legitimate software brands via look-alike domains
    to distribute server-side regenerated installer archives. These installers drop
    stage-one payloads in randomized paths and establish persistence through scheduled
    tasks, masquerading as legitimate drivers and update utilities to facilitate C2
    communications.
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


# Counterfeit Installer Delivery and Randomized Execution

This hunt targets the initial stages of a Silver Fox (Yinhu) style campaign. It begins by identifying hosts that have installed versions of software frequently impersonated by the actor (Razer, Kaspersky, Calibre) to establish a baseline of potential targets. It then searches for DNS resolutions to known lure domains and delivery infrastructure. The core of the hunt identifies the execution of installers with generated naming patterns and the launch of rare binaries from world-writable directories like Public and ProgramData. An agent triage step correlates these signals to identify successful compromises where a domain visit led to a suspicious execution.

## scope-potential-targets
<!-- Scope potential software targets -->
Identify hosts that have legitimate versions of the software impersonated by the lures, as these users are the most likely targets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running software that matches the campaign's lure
  brands.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%razer%' OR LOWER(package_name) LIKE '%kaspersky%' OR LOWER(package_name) LIKE '%sejda%' OR LOWER(package_name) LIKE '%calibre%' OR LOWER(package_name) LIKE '%edge%')
```

## dns-resolutions-to-lures
<!-- DNS resolutions to lure and delivery domains -->
Find hosts within the scoped group that resolved known lure or delivery domains.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, lure_domains=lure_domains, delivery_hosts=delivery_hosts, scope_hosts=scope_hosts)
~~~yaml
expected: Any resolution is a strong indicator of interest or redirect to the campaign
  infrastructure.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as resolution_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{delivery_hosts}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## parallel-behavior-check
<!-- Corroborate execution patterns -->
parallel:
- → wrapper-installer-naming
- → rare-execution-in-public-paths
join: → triage-correlations

## wrapper-installer-naming
<!-- Wrapper installer naming patterns -->
Detect the campaign-specific installer naming convention used for stage-one payloads.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of binaries with these specific naming patterns, often launched
  from a zip extractor.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE 'a_instapp%' OR LOWER(process_name) LIKE 'z_instapp%' OR LOWER(process_name) LIKE 'ainstaller-%' OR LOWER(process_name) LIKE 'ainst8663%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-execution-in-public-paths
<!-- Rare binary execution in Public paths -->
Identify randomized payloads running from Public or ProgramData subdirectories that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries appearing on only one or two hosts in these writable paths are
  highly suspicious.
prevalence:
  by: device_hostname
  key:
  - process_path
  - process_hash_sha256
  rare_below: 3
reads:
- device_hostname
- process_path
- process_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_path, process_hash_sha256, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE 'c:\users\public\%' OR LOWER(process_path) LIKE 'c:\programdata\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path, process_hash_sha256 HAVING host_count <= 2 ORDER BY host_count ASC
```

## triage-correlations
<!-- Weigh correlation of delivery and execution -->
```agent target=hunter
cite: required
context:
- dns-resolutions-to-lures
- wrapper-installer-naming
- rare-execution-in-public-paths
max_iterations: 3
objective: Determine if any host resolving a lure domain subsequently executed a binary
  from a public directory that matches the campaign's naming or prevalence pattern.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows from DNS and process activity.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-correlations verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-endpoint-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate any processes identified as stage-one payloads by the agent.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the DNS resolution times against the process start times. Collect the suspicious binary from the host for static analysis if possible.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the scoping list and resolution counts. If no matches were found, mark as evidence of absence for this campaign's current infrastructure.
```
→ end
