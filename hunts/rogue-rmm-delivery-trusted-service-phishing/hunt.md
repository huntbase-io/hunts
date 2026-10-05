---
analysis: Detecting RMM tools is trivial with a single rule, but distinguishing a
  legitimate IT install from a phishing-driven rogue install requires correlating
  time-aligned web traffic to lure domains with the arrival of rare binaries on the
  same endpoint. This hunt provides the cross-surface context necessary to avoid drowning
  in the noise of approved RMM activity.
blind_spots:
- id: proxy-encryption-blind-spot
  question: whether the specific 'View Document' button was clicked within an encrypted
    Adobe session
  requires: TLS inspection on web proxies
  risk: Attackers can hide lure-specific URL paths within encrypted traffic to trusted
    domains.
  stage: phishing-delivery-and-lure
- id: renamed-installer-blind-spot
  question: whether an RMM installer was renamed to a generic name like 'update.exe'
    to avoid keyword detection
  requires: file hashing and reputation services
  risk: A renamed binary will bypass the keyword-based file activity query.
  stage: c2-redirect-and-payload-download
coverage:
- stage: phishing-delivery-and-lure
  status: covered
  steps:
  - lure-web-traffic
  - rare-payload-drops
- stage: c2-redirect-and-payload-download
  status: covered
  steps:
  - rare-payload-drops
- reason: 'Belongs to another part of the ''Rogue RMM Abuse: How Attackers Exploit
    Remote Access Tools'' series.'
  stage: rogue-rmm-installation-and-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Rogue RMM Abuse: How Attackers Exploit
    Remote Access Tools'' series.'
  stage: defense-evasion-activity
  status: out_of_scope
- reason: 'Belongs to another part of the ''Rogue RMM Abuse: How Attackers Exploit
    Remote Access Tools'' series.'
  stage: redundant-rmm-stacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Attackers use legitimate RMM tools to bypass malware signatures;
    identifying the phishing-driven delivery phase prevents persistent access before
    the attacker can stack redundant clients.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised a host by delivering a rogue RMM installer
  (ScreenConnect or ITarian) via phishing lures hosted on legitimate cloud services
  like Adobe or TransferXL, bypassing traditional email security filters.
labels:
- hunt
- attack.t1566
- attack.t1203
- attack.t1190
name: Rogue RMM Delivery via Trusted Service Phishing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: default-retention
    type: number
  lure_domains:
    default:
    - indesign.adobe.com
    - transferxl.com
    description: Known lure-hosting domains from the report.
    from:
      kind: article
      observed: '2026-09-23'
      ref: huntress-rmm-abuse
    type: list[domain]
  rmm_keywords:
    default:
    - screenconnect
    - itarian
    - connectwise
    - itarian client
    - screenconnect client
    description: Exact software names or keywords to identify RMM clients.
    from:
      kind: article
      observed: '2026-09-23'
      ref: huntress-rmm-abuse
    type: list[string]
  scope_hosts:
    default: []
    description: Limit analysis to these hosts; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rogue-rmm-abuse-phishing-persistent-access
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the initial run on workstations and servers with no legitimate RMM
  presence; expand to the whole estate if suspicious downloads are found on a single
  host.
references:
- name: "Huntress \u2014 Rogue RMM Abuse: How Attackers Exploit Remote Access Tools"
  url: https://www.huntress.com/blog/rogue-rmm-abuse-phishing-persistent-access
related:
- hunt: rogue-rmm-persistence-stacking
  reason: This hunt focuses on the delivery phase; a sibling hunt is required to detect
    the persistent services and redundant client stacking on already-infected hosts.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing Delivery and Lure
    observables:
    - TransferXL email
    - Adobe InDesign lure page
    - View Document button
    - ZIP files
    - Nested PDF lures
    slug: phishing-delivery-and-lure
    tactic: initial-access
    techniques:
    - T1566
  - name: C2 Redirect and Payload Download
    observables:
    - Attacker-controlled C2 infrastructure
    - Rogue RMM installer download
    - ScreenConnect client installer
    - ITarian client installer
    slug: c2-redirect-and-payload-download
    tactic: execution
    techniques:
    - T1203
  - name: Rogue RMM Installation and Persistence
    observables:
    - ITarian client installation
    - ScreenConnect client installation
    - SYSTEM-level privileges
    - Persistent remote access service
    slug: rogue-rmm-installation-and-persistence
    tactic: persistence
    techniques:
    - T1219
  - name: Defense Evasion Activity
    observables:
    - HideUL_x64.exe
    slug: defense-evasion-activity
    tactic: defense-evasion
    techniques:
    - T1562
  - name: Redundant RMM Stacking
    observables:
    - Multiple rogue RMM clients
    - ITarian and ScreenConnect coexistence
    - Redundant ScreenConnect instances
    slug: redundant-rmm-stacking
    tactic: persistence
    techniques:
    - T1219
  summary: Threat actors are using phishing emails with lures hosted on legitimate
    services like TransferXL and Adobe InDesign to trick victims into installing rogue
    RMM tools like ITarian and ScreenConnect. These tools provide persistent, hands-on
    control and are often deployed in redundant pairs alongside defense evasion binaries
    like HideUL_x64.exe to maintain long-term access.
series:
  index: 1
  slug: rogue-rmm-abuse-how-attackers-exploit-remote-access-tools
  title: 'Rogue RMM Abuse: How Attackers Exploit Remote Access Tools'
  total: 2
severity: medium
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Rogue RMM Delivery via Trusted Service Phishing

This hunt identifies the early stages of RMM abuse where attackers use legitimate document-sharing platforms to deliver installers. It correlates web-based lure visits on Adobe and TransferXL with the subsequent arrival of RMM-related binaries on the same endpoints. By identifying these transitions, the hunt distinguishes unauthorized rogue RMM deployments from legitimate IT operations. An agent weighs the timing and rarity of these events to confirm an intrusion.

## scoping-rmm-software
<!-- Inventory of existing RMM software -->
Identify hosts that already have the RMM tools mentioned in the report to provide baseline context for the analyst.

```sqlite target=endpoint role=scoping params=(rmm_keywords=rmm_keywords, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts with matching software; widespread presence usually indicates
  approved IT tools, while isolated instances warrant closer inspection.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(vendor_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-evidence
<!-- Correlate delivery evidence -->
parallel:
- → lure-web-traffic
- → rare-payload-drops
join: → triage-delivery-chain

## lure-web-traffic
<!-- Lure web traffic -->
Find connections to the trusted domains hosting the malicious lures.

```sqlite target=web role=detection-candidate params=(lure_domains=lure_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts visiting Adobe or TransferXL domains; zero results suggest the initial
  phishing link was not clicked.
reads:
- device_hostname
- url_hostname
- url_full
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, url_hostname, url_full, time FROM hb_http_activity WHERE instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-payload-drops
<!-- Rare RMM payload drops -->
Identify RMM installers arriving on disk that are rare across the fleet, suggesting unauthorized installation.

```sqlite target=endpoint role=baseline params=(rmm_keywords=rmm_keywords, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare RMM-themed binaries; common IT updaters appearing on dozens of hosts
  are ignored.
prevalence:
  by: device_hostname
  key:
  - file_name
  - file_path
  rare_below: 4
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, file_name, file_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_file_activity WHERE (LOWER(file_name) LIKE '%.exe' OR LOWER(file_name) LIKE '%.msi' OR LOWER(file_name) LIKE '%.zip' OR LOWER(file_name) LIKE '%.pdf') AND (instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR LOWER(file_name) LIKE '%itarian%' OR LOWER(file_name) LIKE '%screenconnect%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, file_path HAVING host_count <= 3
```

## triage-delivery-chain
<!-- Triage RMM delivery chain -->
```agent target=hunter
cite: required
context:
- scoping-rmm-software
- lure-web-traffic
- rare-payload-drops
max_iterations: 4
objective: Determine if any host exhibits the phishing-to-RMM-delivery pattern described
  in the article, specifically visiting a lure domain followed by a rare RMM binary
  drop.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows and time alignment.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: proxy-encryption-blind-spot)
else: → remediation-and-tuning

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any active sessions for the user identified in the HTTP logs.
```
→ forensic-investigation

## forensic-investigation
<!-- Forensic investigation -->
```manual target=analyst
Search for secondary RMM installations (ScreenConnect, ITarian) and defense evasion binaries like HideUL_x64.exe on the host. Verify if the ZIP/PDF lure resulted in execution via hb_process_activity.
```
→ remediation-and-tuning

## remediation-and-tuning
<!-- Remediation and tuning -->
```manual target=analyst
Record the findings in the incident report. Update the authorized RMM software inventory to include any newly discovered legitimate tools found during the baseline step.
```
→ end
