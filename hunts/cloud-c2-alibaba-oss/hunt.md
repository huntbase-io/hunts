---
analysis: A single detection rule would likely false-positive on legitimate cloud
  storage usage. This hunt uses stack-counting (prevalence) to isolate rare binaries
  and correlates them with suspicious on-disk locations and known malicious URI patterns
  to verify the threat.
blind_spots:
- id: blind-spot-network-encryption
  question: What is the full request URI when encrypted via HTTPS?
  requires: TLS decryption / SSL Inspection
  risk: Without inspection, an analyst cannot distinguish between legitimate use of
    a cloud provider and the specific malicious buckets used in this campaign unless
    the domain itself is exclusive to the attacker.
  stage: c2-cloud-storage-communication
- id: blind-spot-ephemeral-ips
  question: Which domain did this IP address belong to at the time of connection?
  requires: hb_dns_activity (historical logs)
  risk: Alibaba OSS IPs are shared across many tenants; if DNS logs are missing or
    aged out, a direct IP connection to an Alibaba node cannot be reliably attributed
    to the campaign.
  stage: c2-cloud-storage-communication
coverage:
- stage: c2-cloud-storage-communication
  status: covered
  steps:
  - dns-resolutions-to-campaign-infra
  - network-connections-from-suspicious-paths
  - rare-processes-talking-to-oss
  - http-request-triage
- reason: Belongs to the delivery/initial-access hunt in this series.
  stage: initial-access-spoofed-software-sites
  status: out_of_scope
- reason: Covered by the execution/evasion focused hunt in this series.
  stage: defense-evasion-masquerading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: execution-wrapped-installer-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: persistence-scheduled-task-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This campaign leverages legitimate cloud services (Alibaba OSS) to
    blend C2 traffic with normal business activity. Identifying this requires cross-surface
    correlation between network destinations and suspicious process paths that simple
    IP blocklists cannot provide.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Alibaba Cloud Object Storage Service (OSS) for command
  and control or payload staging, initiated by binaries residing in randomized or
  user-writable paths.
labels:
- hunt
- attack.t1071
- attack.t1090.003
name: Cloud-based C2 via Alibaba OSS
parameters:
  c2_domains:
    default:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    - pc-razerzone.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - app-microsoft-edge.com.cn
    - sejda.hl.cn
    - translate-youdao.hl.cn
    description: Identified C2 and delivery domains from the report.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: number
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
rationale: The hunt should prioritize endpoints reporting from the China region or
  users with Chinese-language OS locales, as identified in the report. If no hits
  are found on the specific domains, broaden the scope to all rare processes connecting
  to '.aliyuncs.com' on port 443.
references:
- name: "MSRC Blog \u2014 Counterfeit installers to system compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-installer-masquerade
  reason: This hunt covers the C2 and staging phase; the initial delivery and installer
    masquerade behavior is handled by a sibling hunt focusing on file activity.
  relation: out-of-scope-alternative
- hunt: persistent-masqueraded-payloads
  relation: follows
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
  index: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Cloud-based C2 via Alibaba OSS

This hunt isolates command-and-control behavior targeting legitimate cloud providers, specifically Alibaba OSS, as seen in the Silver Fox campaign. It identifies hosts resolving delivery domains, correlates those resolutions with network connections initiated from suspicious directories (Users\Public, ProgramData), and uses stack-counting to find rare binaries communicating with cloud storage. By weighing network telemetry against process metadata and URL paths, an agent identifies whether legitimate update mechanisms (like TrueUpdate) are being abused for malicious staging.

## dns-resolutions-to-campaign-infra
<!-- DNS resolutions to campaign infrastructure -->
Identify hosts that have resolved known delivery or OSS C2 domains.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: A hit shows a host attempting to contact the campaign infrastructure. Silence
  indicates no resolution of these specific domains in the window.
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
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.aliyuncs.com') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name ORDER BY lookup_count DESC
```

## parallel-corroboration
<!-- Corroborate behavior and prevalence -->
parallel:
- → network-connections-from-suspicious-paths
- → rare-processes-talking-to-oss
- → http-request-triage
join: → agent-triage

## network-connections-from-suspicious-paths
<!-- Network connections from suspicious paths -->
Identify connections to Alibaba OSS or C2 domains initiated by binaries in user-writable or randomized directories.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Any connection from these paths to Alibaba OSS is highly suspicious, especially
  if the binary name is randomized.
reads:
- device_hostname
- process_path
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_path, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\programdata\%' OR LOWER(process_path) LIKE '%\appdata\%') AND (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR LOWER(dst_endpoint_hostname) LIKE '%.aliyuncs.com') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-processes-talking-to-oss
<!-- Rare processes talking to OSS -->
Baseline common cloud storage usage to find outlier binaries that may be campaign payloads.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare binary (e.g., seen on 1 host) communicating with Alibaba OSS stands
  out from common cloud usage.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS conn_count, MIN(time) AS first_seen FROM hb_network_connection WHERE LOWER(dst_endpoint_hostname) LIKE '%.aliyuncs.com' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count <= 3 ORDER BY host_count ASC
```

## http-request-triage
<!-- HTTP request triage for staging URLs -->
Capture the full URL path and user agent to confirm staging behavior (e.g., /712down, /7qinst).

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Presence of randomized URI paths or known delivery paths like /712down on
  these domains.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_hostname) LIKE '%.aliyuncs.com') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage C2 and staging activity -->
```agent target=hunter
cite: required
context:
- dns-resolutions-to-campaign-infra
- network-connections-from-suspicious-paths
- rare-processes-talking-to-oss
- http-request-triage
max_iterations: 4
objective: Determine if any host is compromised by checking if a suspicious binary
  in a randomized path is communicating with Alibaba OSS or campaign delivery domains.
  Pay close attention to URI paths and user-agent strings in the HTTP data.
success_criteria: A verdict for each host with a citation to specific network connections
  or process paths.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route based on agent verdict -->
if~: "The agent verdict is 'malicious' or 'suspicious' for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: blind-spot-network-encryption)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the binary identified in the process_path for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Forensic review of staging activity -->
```manual target=analyst
Review the identified binaries and URI paths. Check if the process metadata (description, company) matches the masquerade profile (Philips/TrueUpdate) mentioned in the report.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document whether any campaign activity was found. If no activity was found, report a clean estate regarding the Silver Fox C2 staging phase.
```
→ end
