---
analysis: A standard detection rule fires on a known domain or a specific task name.
  This hunt pivots across inventory (victim profile), network (origin lure), and execution
  behavior (archive tool -> rare randomized binary) to confirm a successful social
  engineering compromise where single-surface rules would be too noisy.
blind_spots:
- id: no-process-visibility
  owner: Endpoint Engineering
  question: Did the unzipped binary actually execute on hosts without an agent?
  remediation: Deploy endpoint agents to all China-based branch offices.
  requires: hb_process_activity from an endpoint agent
  risk: A host without an agent might resolve the domain and download the file but
    leave the execution invisible.
  stage: execution-wrapped-installer-delivery
- id: server-side-regeneration
  owner: Network Security
  question: What are the hashes of the unique archives being downloaded?
  remediation: Enable SSL decryption for the identified delivery domains.
  requires: Network payload inspection
  risk: Because hashes change per download, we cannot use static file hashes to detect
    the archive itself before it is unzipped.
  stage: execution-wrapped-installer-delivery
coverage:
- stage: initial-access-spoofed-software-sites
  status: covered
  steps:
  - dns-to-spoofed-domains
- stage: execution-wrapped-installer-delivery
  status: covered
  steps:
  - archive-tree-execution
  - rare-unzipped-binaries
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: defense-evasion-masquerading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: persistence-scheduled-task-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: c2-cloud-storage-communication
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Silver Fox uses high-fidelity social engineering that specifically
    targets organizations with operations in China. Because payloads are regenerated
    server-side to evade static detection, a behavioral hunt connecting lures to execution
    is the only way to identify new victims.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has tricked a user into downloading a server-side regenerated
  malware archive from a spoofed vendor site, which executes a randomized stage-one
  payload via a common archive tool.
labels:
- hunt
- attack.t1071
- attack.t1562.001
- attack.t1053.005
- attack.t1090.003
name: Counterfeit Installer Delivery and Execution
parameters:
  delivery_hosts:
    default:
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    - www.gehie246.com
    description: Direct delivery hosts serving the malicious archives.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-2026-09-01
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  spoofed_domains:
    default:
    - pc-razerzone.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - app-microsoft-edge.com.cn
    - sejda.hl.cn
    - translate-youdao.hl.cn
    - zh-diskgenius.com.cn
    - baidu-pan.com.cn
    - ocam-pc.com.cn
    - cn-drawio.com.cn
    - steelseries-cn.com.cn
    - gw-sogou.com.cn
    - mindmoster.com.cn
    description: Look-alike brand domains identified in the research.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-2026-09-01
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts with Razer, Kaspersky, or browser software first, as they
  are the intended victims for the specific lures used by Silver Fox. Focus on the
  last 14 days of DNS and process telemetry.
references:
- name: "MSRC \u2014 Counterfeit installers to system compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-persistence-scheduled-tasks
  reason: This hunt focuses on the delivery and initial execution; persistence through
    scheduled tasks requires hb_scheduled_job and is handled separately.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - app-microsoft-edge.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    slug: initial-access-spoofed-software-sites
    tactic: initial-access
    techniques:
    - T1071
  - name: Dynamic installer execution
    observables:
    - app_setup.6653004.zip
    - a_instapp83353001.exe
    - z_instapp83351010.exe
    - C:\Users\Public\sE94yD\aLcUaw.exe
    - msedge.exe
    - 7zFM.exe
    - 360zip.exe
    - WinRAR.exe
    slug: execution-wrapped-installer-delivery
    tactic: execution
    techniques:
    - T1071
  - name: Payload masquerading and randomization
    observables:
    - C:\Program Files (x86)\
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - D:\hellothere\svchost.exe
    - XPSPLOG.dll
    slug: defense-evasion-masquerading
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Scheduled task persistence
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\zsMmvukD\beuv4Mie.exe
    - Indigo Rose TrueUpdate Client
    - ProductVersion 3.8.0.0
    - tu_rt.exe
    - _ir_tu2_temp_
    slug: persistence-scheduled-task-execution
    tactic: persistence
    techniques:
    - T1053.005
  - name: Command and control via Cloud Storage
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - Port 443
    slug: c2-cloud-storage-communication
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  summary: The Silver Fox campaign uses a large-scale network of spoofed software
    download sites to trick users into downloading dynamically generated malicious
    archives. Once executed, a wrapper installer drops masqueraded payloads into randomized
    system directories, establishes persistence via Windows Task Scheduler, and communicates
    with Alibaba Cloud OSS for further payload delivery.
series:
  index: 1
  slug: counterfeit-installers-to-system-compromise-tracking-a-deceptive-software-download-campaign
  title: 'Counterfeit installers to system compromise: Tracking a deceptive software
    download campaign'
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
tlp: clear
type: investigation
---


# Counterfeit Installer Delivery and Execution

This hunt focuses on the initial access and execution stages of the Silver Fox (Yinhu) campaign. It identifies users searching for legitimate software (Razer, Edge, Kaspersky) on look-alike domains and correlates this with the unique execution behavior where archive tools (7-Zip, WinRAR) spawn rare, randomized binaries in world-writable paths. By combining software inventory context, DNS lure patterns, and process-tree anomalies, we find the entry point before persistence is fully established.

## scoping-targeted-software
<!-- Scope to hosts with targeted software -->
Identify hosts that have software from the impersonated vendors installed, as they are the primary targets for this social engineering campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that use the impersonated software. This identifies the
  'profile' of likely victims who would visit the spoofed sites.
reads:
- device_hostname
- vendor_name
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, vendor_name, package_name, package_version FROM hb_software_inventory WHERE LOWER(vendor_name) LIKE '%razer%' OR LOWER(vendor_name) LIKE '%kaspersky%' OR LOWER(vendor_name) LIKE '%steelseries%' OR LOWER(vendor_name) LIKE '%calibre%' OR LOWER(vendor_name) LIKE '%edge%' OR LOWER(vendor_name) LIKE '%sejda%'
```

## corroborate-evidence
<!-- Corroborate DNS and Execution -->
parallel:
- → rare-unzipped-binaries
- → dns-to-spoofed-domains
- → archive-tree-execution
join: → triage-delivery-chain

## rare-unzipped-binaries
<!-- Rare binaries in suspicious paths -->
Identify binaries executing from randomized paths that are rare across the fleet, regardless of their parent.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries in public directories. Legitimate software rarely runs from
  C:\Users\Public or C:\ProgramData subfolders.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
- process_name
- process_file_description
- process_file_company
- activity_id
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_path) AS suspicious_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, process_name, process_file_description, process_file_company FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\programdata\%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 4, 5, 6 HAVING host_count <= 3
```

## dns-to-spoofed-domains
<!-- DNS to spoofed and delivery domains -->
Match the report's brand-spoofing and delivery domains exactly on the DNS surface.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, spoofed_domains=spoofed_domains, delivery_hosts=delivery_hosts)
~~~yaml
expected: Hosts resolving the malicious domains. Silence suggests the domains have
  rotated, which is why the behavioral prevalence step is included.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{spoofed_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{delivery_hosts}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LOWER(query_hostname) LIKE '%.com.cn' AND (LOWER(query_hostname) LIKE '%razer%' OR LOWER(query_hostname) LIKE '%kaspersky%'))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## archive-tree-execution
<!-- Archive tool spawning suspicious child -->
Detect the core execution behavior: an archive tool launches a child process from a world-writable path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A process launched from a public path where the parent is a ZIP or RAR utility.
  This represents the 'unzip-and-run' social engineering step.
reads:
- device_hostname
- process_name
- process_path
- parent_process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_path, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%7zfm.exe' OR LOWER(parent_process_name) LIKE '%360zip.exe' OR LOWER(parent_process_name) LIKE '%winrar.exe') AND (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\programdata\%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-delivery-chain
<!-- Triage delivery and execution -->
```agent target=hunter
cite: required
context:
- scoping-targeted-software
- rare-unzipped-binaries
- dns-to-spoofed-domains
- archive-tree-execution
max_iterations: 4
objective: 'Determine if a host''s behavior follows the chain: targeted software context
  -> DNS resolution to spoofed domains -> execution of a rare binary from an archive
  tool.'
success_criteria: A verdict of malicious | suspicious | benign citing specific rows
  from the parallel steps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host showing both the DNS lookup and the archive tool tree" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the rare binary from the path identified in the triage.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the rare binary's metadata. Look for masquerading indicators like 'TODO: <Product name>' or unexpected Company Names like 'Speech Processing Solutions GmbH' for a driver installer. Confirm the DNS lure led to the execution.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
No confirmed malicious activity. Note if any domains resolved but didn't lead to execution, as these may be future targets.
```
→ end
