---
analysis: A single detection rule would miss the 'one-pass' nature of this threat.
  This hunt pivots between unauthorized credential access, rare process behavior stack-counting,
  and network exfiltration patterns, providing context that an analyst must weigh
  to confirm the intrusion.
blind_spots:
- id: no-file-telemetry
  owner: Endpoint Security Team
  question: Did any process read the browser SQLite databases?
  remediation: Enable 'Audit File System' for application data paths under user profiles
    via GPO.
  requires: hb_file_activity with read-access auditing
  risk: Without read auditing, unauthorized access to credentials leaves no trace
    in the lead query.
  stage: browser-intel-harvesting
- id: encrypted-network-exfiltration
  owner: Network Operations
  question: Was the data transmitted to Telegram or the C2 encrypted or plain text?
  remediation: Deploy SSL inspection for traffic to known cloud services like Telegram
    and correlate with process telemetry.
  requires: HTTPS inspection or endpoint socket attribution
  risk: The use of RC4 encryption on top of HTTPS makes it impossible to determine
    the volume or content of stolen data from network telemetry alone.
  stage: network-c2-and-exfiltration
coverage:
- stage: browser-intel-harvesting
  status: covered
  steps:
  - suspicious-credential-access
  - rare-process-file-behavior
- stage: network-c2-and-exfiltration
  status: covered
  steps:
  - exfiltration-network-traffic
- stage: post-intrusion-cleanup
  status: covered
  steps:
  - rare-process-file-behavior
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: spearphishing-delivery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: exploit-winrar-traversal
  status: out_of_scope
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: dropper-execution-vba-ps
  status: out_of_scope
- reason: 'Belongs to another part of the ''Gorbag: Orcs at the border harvesting
    intelligence from Ukraine'' series.'
  stage: startup-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Gorbag acts as an initial access broker for Russia-aligned APTs,
    harvesting intelligence for strategic battle damage assessment. Detecting their
    tools in the collection phase prevents the follow-on intrusions that these stolen
    credentials enable.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A Russia-aligned actor is stealing browser credentials and VPN configurations,
  exfiltrating them via Telegram or direct IP, and then deleting the evidence from
  disk.
labels:
- hunt
- attack.t1555.003
- attack.t1539
- attack.t1217
- attack.t1005
- attack.t1071.001
- attack.t1567
- attack.t1048.001
- attack.t1070.004
- attack.t1560
- command and control
- credential access
- defense evasion
- execution
- initial access
- persistence
name: 'Gorbag: Browser Data Harvesting and Exfiltration'
parameters:
  gorbag_domains:
    default:
    - psw.agent.ma
    - agent.eji
    - runner.fb
    description: C2 domains identified in the report.
    from:
      kind: article
      observed: '2026-11-03'
      ref: eset-research
    type: list[domain]
  gorbag_ips:
    default:
    - 89.44.9.186
    - 142.111.194.73
    description: C2 and exfiltration IPs identified in the report.
    from:
      kind: article
      observed: '2026-11-03'
      ref: eset-research
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to hunt across the
      entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on Ukrainian justice, law enforcement, and defense sector
  entities. Prioritize systems where WinRAR is installed or systems belonging to administrative
  staff who process fines or tax documents.
references:
- name: 'Gorbag: Orcs at the border harvesting intelligence from Ukraine'
  url: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/
related:
- hunt: winrar-exploit-startup-persistence
  reason: This hunt focuses on the collection and exfiltration phase; the WinRAR exploit
    and startup folder persistence are covered in a companion hunt.
  relation: out-of-scope-alternative
- hunt: gorbag-rapid-harvester-deployment
  relation: follows
scenario:
  stages:
  - name: Spearphishing with Malicious Lures
    observables:
    - "\u0434\u043E\u0434\u0430\u0442\u043E\u043A \u043F\u043E\u0434\u0430\u0442\u043A\
      \u043E\u0432\u0430.xlsm"
    - "\u041F\u043E\u0432\u0456\u0434\u043E\u043C\u043B\u0435\u043D\u043D\u044F 4726-49.rar"
    - Email subjects regarding administrative fines or taxes
    slug: spearphishing-delivery
    tactic: initial-access
    techniques:
    - T1566.001
    - T1199
  - name: WinRAR Path Traversal Exploitation
    observables:
    - CVE-2025-8088
    - Extraction of alternate data streams outside directory
    - LNK file written to Startup folder
    slug: exploit-winrar-traversal
    tactic: execution
    techniques:
    - T1203
  - name: Macro or PowerShell Dropper Execution
    observables:
    - VBA decoding base64 from Excel cells
    - Payload dropped into %ProgramData%
    - PowerShell loader in %ProgramData%
    slug: dropper-execution-vba-ps
    tactic: execution
    techniques:
    - T1059.001
    - T1027.009
  - name: Persistence via Startup Folder
    observables:
    - LNK file in %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
    slug: startup-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Rapid Browser and VPN Data Theft
    observables:
    - BeautyStealer access to browser profile databases
    - Collection of VPN configurations
    - Staging of documents for exfiltration
    slug: browser-intel-harvesting
    tactic: credential-access
    techniques:
    - T1555.003
    - T1539
    - T1217
    - T1005
  - name: C2 and Telegram Exfiltration
    observables:
    - HTTPS connection to 89.44.9.186 (Prime ReverseShell)
    - Exfiltration to 142.111.194.73
    - Data exfiltration via Telegram API
    - RC4 encrypted payloads
    slug: network-c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1567
    - T1048.001
  - name: Self-Deletion Cleanup
    observables:
    - Malware binary removal from %ProgramData% after single pass execution
    slug: post-intrusion-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: Gorbag is a Russia-aligned threat actor targeting Ukrainian law enforcement
    and defense sectors since 2025. They utilize spearphishing with macro-enabled
    spreadsheets or WinRAR exploits (CVE-2025-8088) to deploy BeautyStealer for rapid
    credential and file harvesting and Prime ReverseShell for command and control
    before performing self-deletion.
series:
  index: 2
  slug: gorbag-orcs-at-the-border-harvesting-intelligence-from-ukraine
  title: 'Gorbag: Orcs at the border harvesting intelligence from Ukraine'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Gorbag: Browser Data Harvesting and Exfiltration

This hunt identifies the one-pass data harvesting pattern of BeautyStealer and Prime ReverseShell, as observed in attacks against Ukrainian administrations and defense sectors. It begins by identifying unauthorized access to browser credential databases and VPN configurations. The hunt then corroborates this behavior using two parallel queries: one that identifies rare archiving and cleanup activity across the fleet, and another that matches network traffic against known exfiltration infrastructure and the Telegram API. Finally, an agent weighs the combined evidence to identify hosts where intelligence harvesting has occurred.

## suspicious-credential-access
<!-- Suspicious browser and VPN data access -->
Identify non-browser processes reading sensitive credential databases or VPN configurations as a lead for data theft.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row names a process that has no business reading browser or VPN secrets.
  Silence suggests no such unauthorized access occurred via this vector.
reads:
- device_hostname
- process_name
- file_path
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, process_name, file_path, time FROM hb_file_activity WHERE activity_id = 2 AND (LOWER(file_path) LIKE '%\google\chrome\user data%\login data' OR LOWER(file_path) LIKE '%\microsoft\edge\user data%\login data' OR LOWER(file_path) LIKE '%\google\chrome\user data%\cookies' OR LOWER(file_path) LIKE '%.ovpn' OR LOWER(file_path) LIKE '%.pcf' OR LOWER(file_path) LIKE '%\etc\openvpn%') AND (LOWER(process_name) NOT LIKE '%\chrome.exe' AND LOWER(process_name) NOT LIKE '%\msedge.exe' AND LOWER(process_name) NOT LIKE '%\vpn.exe' AND LOWER(process_name) NOT LIKE '%\browser.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborative-activity
<!-- Corroborate with behavior and network -->
parallel:
- → rare-process-file-behavior
- → exfiltration-network-traffic
join: → agent-triage

## rare-process-file-behavior
<!-- Rare archiving and cleanup activity -->
Find rare processes creating archives or performing cleanup in ProgramData, characteristic of BeautyStealer.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process creating archives or deleting files in common malware staging
  paths. Frequent processes are likely legitimate software.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT LOWER(process_name) AS process, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS event_count, MIN(time) AS first_seen FROM hb_file_activity WHERE ((activity_id = 1 AND (LOWER(file_path) LIKE '%.rar' OR LOWER(file_path) LIKE '%.zip' OR LOWER(file_path) LIKE '%.7z')) OR (activity_id = 4 AND LOWER(file_path) LIKE 'c:\programdata\%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## exfiltration-network-traffic
<!-- Connections to exfiltration infrastructure -->
Match network traffic against known Gorbag infrastructure or the Telegram API used for exfiltration.

```sqlite target=network role=triage params=(lookback_days=lookback_days, gorbag_ips=gorbag_ips, gorbag_domains=gorbag_domains)
~~~yaml
expected: Traffic to specific IPs or the Telegram API linked to a suspicious process
  confirms exfiltration.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-04'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_hostname, time FROM hb_network_connection WHERE (instr(',' || '{{gorbag_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR instr(',' || '{{gorbag_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR LOWER(dst_endpoint_hostname) = 'api.telegram.org') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage harvesting behavior -->
```agent target=hunter
cite: required
context:
- suspicious-credential-access
- rare-process-file-behavior
- exfiltration-network-traffic
max_iterations: 5
objective: Determine if the observed behavior on a host constitutes a Gorbag data-stealing
  intrusion by linking unauthorized credential access to exfiltration traffic.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  rows that link the harvesting process to its exfiltration destination.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for at least one host, indicating data harvesting and exfiltration has occurred." (confidence: high, judge=hunter)
then: → remediate-and-isolate
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: no-file-telemetry)
else: → hunt-closeout

## remediate-and-isolate
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to prevent further exfiltration. Revoke all active sessions and initiate password resets for any user whose browser profile or VPN configuration was accessed.
```
→ forensic-investigation

## forensic-investigation
<!-- Forensic validation -->
```manual target=analyst
Review the file activity rows to identify the specific documents and credential stores accessed. Examine the exfiltration destination to confirm if data was successfully sent. Search for signs of lateral movement or secondary payloads that may have been deployed before BeautyStealer removed itself.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout -->
```manual target=analyst
Record the final status of all hosts examined. If suspicious-credential-access returned high-fidelity results, promote it to a standing detection rule.
```
→ end
