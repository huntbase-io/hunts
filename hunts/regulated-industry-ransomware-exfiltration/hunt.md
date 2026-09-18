---
analysis: This hunt correlates proxy connections with the parent process context of
  a mail client and the downstream high-velocity file activity burst (100+ files).
  This provides the multi-surface context needed to confirm an active campaign that
  single-surface rules miss.
blind_spots:
- id: limited-endpoint-visibility
  owner: Infrastructure Team
  question: whether the initial execution occurred on unmanaged or shadow-IT devices
  remediation: Audit device inventory and ensure 100% agent coverage on all high-value
    assets.
  requires: Endpoint agents on all hosts in scope
  risk: A host without an agent provides no telemetry, meaning an intrusion could
    progress entirely in a blind spot.
  stage: initial-access-phishing
- id: encrypted-c2-content
  owner: Network Security
  question: what the actual content of the multi-hop proxy traffic was
  remediation: Implement TLS inspection for outbound traffic to known VPS and ORB
    networks.
  requires: SSL/TLS decryption at the proxy
  risk: While the presence of the proxy is visible via port and suffix, the specifics
    of data being exfiltrated remain hidden without traffic decryption.
  stage: c2-multi-hop-proxy
coverage:
- stage: initial-access-phishing
  status: covered
  steps:
  - phishing-execution-chains
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - outbound-proxy-activity
  - rare-proxy-dns-lookups
- stage: impact-data-encryption
  status: covered
  steps:
  - ransomware-impact-signals
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Regulated industries face significant legal and ethical consequences
    for data loss. Hunting across the entire attack lifecycle is necessary as single-surface
    rules are frequently bypassed by evolving tactics.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access to a healthcare or financial host
  via a phishing campaign and is using multi-hop proxies to exfiltrate data or deploy
  ransomware.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1486
name: Regulated Industry Ransomware and Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: number
  phishing_child_names:
    default:
    - cmd.exe
    - powershell.exe
    - wscript.exe
    - cscript.exe
    - certutil.exe
    - mshta.exe
    description: Suspicious child processes spawned from entry points.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[string]
  phishing_parent_names:
    default:
    - outlook.exe
    - chrome.exe
    - msedge.exe
    - excel.exe
    - winword.exe
    - acrobat.exe
    description: Process names for common entry points like mail clients and browsers.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[string]
  proxy_domain_suffixes:
    default:
    - .onion
    - .hiddenservice.net
    - .onion.it
    - .onion.to
    - .onion.cab
    description: Common suffixes for multi-hop or onion routing services.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: list[domain]
  proxy_ports:
    default:
    - '1080'
    - '9001'
    - '9050'
    - '9150'
    - '8080'
    description: Common ports used by multi-hop proxies and SOCKS tunnels.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: list[string]
  ransom_extensions:
    default:
    - .locked
    - .crypted
    - .crypt
    - .enc
    - .honey
    description: Known extensions appended during ransomware encryption.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt (e.g., servers in medical/finance
      VLANs).
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/cyberattack-readiness
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers and workstations within regulated VLANs (Finance, Medical).
  Use the scope_hosts parameter if specific server naming conventions are available.
references:
- name: "Huntress \u2014 Cyberattack Readiness"
  url: https://www.huntress.com/blog/cyberattack-readiness
related:
- hunt: cloud-credential-theft-regulated
  reason: This hunt focuses on host-level ransomware, whereas phishing may lead directly
    to cloud credential theft.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing for Initial Access
    observables:
    - Phishing links clicked in email clients
    - Automated phishing messages
    - AI-enhanced deepfake social engineering
    - Unusual attachments downloaded from webmail
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Command and Control via Multi-hop Proxy
    observables:
    - Connections to Tor onion services
    - Multi-hop proxy chain traffic
    - High-frequency outbound traffic to VPS or ORB networks
    - DNS lookups for known proxy or onion domains
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Data Encrypted for Impact
    observables:
    - Rapid modification of file extensions to known ransomware suffixes
    - Creation of ransom note files such as README.txt or DECRYPT.txt
    - High volume of file rename and write activity in user directories
    - Process activity involving cryptographic APIs or ransomware executables
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors targeting the healthcare and finance sectors utilize phishing
    to obtain initial access before establishing command-and-control through multi-hop
    proxies. The campaign concludes with the deployment of ransomware that encrypts
    sensitive data to cause operational disruption and financial loss.
severity: medium
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
tlp: clear
type: investigation
---


# Regulated Industry Ransomware and Exfiltration

This hunt targets the primary threat lifecycle identified for regulated sectors like healthcare and finance. It focuses on identifying three critical pivots: the initial execution of shells or administrative tools from productivity applications, the subsequent masking of C2 traffic via multi-hop proxy chains (Tor/ORB networks), and the final impact phase marked by rapid file modification and ransom note creation. By correlating these signals, the hunt identifies intrusions that bypass traditional endpoint-only detection rules.

## scope-regulated-hosts
<!-- Inventory Active Regulated Sector Hosts -->
Identify active hosts in the estate to provide context for the hunt scope and verify enrollment.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts currently reporting telemetry. Absence of a host here means
  it is a blind spot.
reads:
- hostname
- os_name
- platform
- last_seen
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, os_name, platform, last_seen FROM hb_devices WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0)
```

## phishing-execution-chains
<!-- Suspicious Process Spawned from Entry Points -->
Identify potential phishing success by finding shells or admin tools spawned from browsers or mail clients, extracting the filename from the path to ensure matches.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, phishing_parent_names=phishing_parent_names, phishing_child_names=phishing_child_names)
~~~yaml
expected: Execution of system interpreters (PowerShell, CMD) triggered directly by
  productivity software.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{phishing_parent_names}}' || ',', ',' || REPLACE(LOWER(parent_process_name), RTRIM(LOWER(parent_process_name), REPLACE(LOWER(parent_process_name), '\', '')), '') || ',') > 0 OR instr(',' || '{{phishing_parent_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (instr(',' || '{{phishing_child_names}}' || ',', ',' || REPLACE(LOWER(process_name), RTRIM(LOWER(process_name), REPLACE(LOWER(process_name), '\', '')), '') || ',') > 0 OR instr(',' || '{{phishing_child_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## corroborate-lifecycle
<!-- Corroborate Multi-hop C2 and Impact -->
parallel:
- → outbound-proxy-activity
- → rare-proxy-dns-lookups
- → ransomware-impact-signals
join: → triage-lifecycle

## outbound-proxy-activity
<!-- Outbound Multi-hop Proxy Traffic -->
Identify connections to common proxy ports, filtering out legitimate browser noise.

```sqlite target=network role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, proxy_ports=proxy_ports)
~~~yaml
expected: Connections to ports like 9050 or 9150 (Tor) from non-standard processes.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE direction = 'outbound' AND instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND LOWER(process_name) NOT LIKE '%\chrome.exe' AND LOWER(process_name) NOT LIKE '%\msedge.exe' AND LOWER(process_name) NOT LIKE '%\firefox.exe' AND LOWER(process_name) NOT LIKE '%\svchost.exe' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-proxy-dns-lookups
<!-- Rare Proxy and Onion Domain Lookups -->
Identify potential C2 through DNS activity for known onion suffixes or rare external domains.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, proxy_domain_suffixes=proxy_domain_suffixes)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS requests for multi-hop proxy suffixes or rare domains seen on very few
  hosts.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  - process_name
  rare_below: 3
reads:
- query_hostname
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, process_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{proxy_domain_suffixes}}' || ',', ',' || LOWER(SUBSTR(query_hostname, instr(query_hostname, '.'))) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY query_hostname, process_name HAVING host_count <= 2
```

## ransomware-impact-signals
<!-- High-Velocity Ransomware Encryption Bursts -->
Detect the final impact stage by identifying rapid file creation or rename activity exceeding normal OS thresholds.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ransom_extensions=ransom_extensions)
~~~yaml
expected: Rapid bursts of at least 100 file modifications with encrypted suffixes
  or note creation from a single process.
reads:
- device_hostname
- file_name
- file_path
- activity_id
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, COUNT(*) as activity_count, MIN(time) as start_time, MAX(time) as end_time FROM hb_file_activity WHERE activity_id IN (1, 3, 5) AND (instr(LOWER(file_name), 'readme') > 0 OR instr(LOWER(file_name), 'decrypt') > 0 OR (instr(file_name, '.') > 0 AND instr(',' || '{{ransom_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, instr(file_name, '.'))) || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name HAVING activity_count >= 100
```

## triage-lifecycle
<!-- Correlate Attack Chain Signals -->
```agent target=hunter
cite: required
context:
- phishing-execution-chains
- outbound-proxy-activity
- rare-proxy-dns-lookups
- ransomware-impact-signals
max_iterations: 5
objective: Determine if execution from entry points is linked to the observed proxying
  or file impact activity. Citing process names and hostnames is mandatory.
success_criteria: A verdict of 'malicious' for hosts showing the full lifecycle, or
  'suspicious' for isolated behaviors.
tools:
- endpoint
- network
```

## route-by-verdict
<!-- Route on Attack Verdict -->
if~: "the triage verdict is malicious for at least one host exhibiting a complete chain from phishing to impact" (confidence: high, judge=hunter)
then: → isolate-malicious-host
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review (blind_spot: limited-endpoint-visibility)
else: → analyst-remediation-review

## isolate-malicious-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Immediately isolate the identified host from the network to prevent further encryption or exfiltration. Collect volatile memory and current network connections before analyst review.
```
→ analyst-remediation-review

## analyst-remediation-review
<!-- Analyst Review and Remediation -->
```manual target=analyst
Review the cited rows from the triage agent. For confirmed malicious hosts, initiate credential resets and forensic imaging. For suspicious but benign cases, update exclusions.
```
→ close-out-investigation

## close-out-investigation
<!-- Close Out and Record Gaps -->
```manual target=analyst
Document the hunt outcome and escalate coverage gaps to infrastructure teams.
```
→ end
