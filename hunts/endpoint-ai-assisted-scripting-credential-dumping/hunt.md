---
analysis: A standard rule alerts on ntdsutil. This hunt is required to correlate that
  sensitive action with a preceding chain of numbered binaries (socktz_v8), DuckDNS
  traffic, and AI-driven troubleshooting suffixes across three distinct surfaces.
blind_spots:
- id: no-endpoint-coverage
  owner: Infrastructure Team
  question: Are iterative scripts running on unmanaged WordPress/JBoss hosts?
  remediation: Audit and enroll all internet-facing assets into the EDR fleet.
  requires: Endpoint agent on all internet-facing servers
  risk: The attackers targeted vulnerable web servers specifically; without an agent,
    the SockTz execution is invisible.
  stage: ai-assisted-script-execution
- id: short-dns-retention
  owner: Security Engineering
  question: Was the infrastructure established in February visible during this hunt?
  remediation: Increase DNS log retention to cover a 90-day window.
  requires: hb_dns_activity with 90+ days retention
  risk: Attackers establish infrastructure months before the final dump; if logs have
    rotated, only the execution phase is visible.
  stage: c2-and-proxy-tunneling
coverage:
- reason: Requires email logs or web-mail forensic artifacts not available in the
    hb_ surfaces.
  stage: initial-access-phishing-resume
  status: not_visible
- stage: ai-assisted-script-execution
  status: covered
  steps:
  - rare-iterative-script-execution
- stage: credential-access-directory-dumping
  status: covered
  steps:
  - credential-dumping-behavior
- stage: c2-and-proxy-tunneling
  status: covered
  steps:
  - dns-traffic-to-duckdns
  - connections-to-attacker-infra
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: "The use of AI to generate troubleshooting scripts and iterative\
    \ malware versions allows attackers to bypass static signatures. A behavioral\
    \ hunt for these specific trial-and-error patterns\u2014rare iterative naming\
    \ and repetitive VSS attempts\u2014is required to detect this evolving Latin American\
    \ threat."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using AI-generated scripts with iterative naming conventions
  to facilitate credential dumping and proxy tunneling across target organizations
  in Latin America.
labels:
- hunt
- attack.t1566.001
- attack.t1059.003
- attack.t1059.006
- attack.t1003.002
- attack.t1003.003
- attack.t1572
- attack.t1090
- attack.t1568.002
name: Endpoint AI-Assisted Scripting and Credential Dumping
parameters:
  c2_ips:
    default:
    - 62.171.185.97
    - 165.22.184.26
    - 178.128.87.160
    - 167.148.195.53
    description: Attacker-controlled infrastructure IPs.
    from:
      kind: article
      observed: '2026-09-03'
      ref: unit42
    type: list[ip]
  duckdns_domains:
    default:
    - m-doxa-apodo.duckdns.org
    - m-doxa-geo.duckdns.org
    - m-doxa-intel.duckdns.org
    - m-doxa-vacunas.duckdns.org
    description: DuckDNS subdomains used by the CL-CRI-1131 cluster.
    from:
      kind: article
      observed: '2026-09-03'
      ref: unit42
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Hosts to narrow the hunt; leave empty for fleet-wide.
    from:
      kind: manual
      ref: analyst-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus specifically on Windows Domain Controllers and servers running critical
  services like JBoss or WordPress, as targeted in the campaign. The first scoping
  query narrows the estate before behavioral triggers run.
references:
- name: Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America
  url: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
related:
- hunt: generic-vss-abuse-detection
  reason: General shadow copy abuse is covered by broad behavioral rules; this hunt
    focuses on the correlation with AI-characteristic naming and DuckDNS infra.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Job-themed Phishing
    observables:
    - Resume-themed phishing email attachments
    - Compromised WordPress sites hosting installers
    slug: initial-access-phishing-resume
    tactic: initial-access
    techniques:
    - T1566.001
  - name: AI-Generated Iterative Script Execution
    observables:
    - Numbered batch scripts (e.g., iterative collection scripts)
    - Filenames with '_output' suffix
    - exploit_creative.py
    - exploit_careful.py
    - rce_focused.py
    - Permissions checks in batch scripts
    slug: ai-assisted-script-execution
    tactic: execution
    techniques:
    - T1059.003
    - T1059.006
  - name: Credential and Active Directory Dumping
    observables:
    - Shadow copy creation across multiple drives
    - Dumping Security Account Manager (SAM) registry hive
    - NTDS.dit file access and copying
    slug: credential-access-directory-dumping
    tactic: credential-access
    techniques:
    - T1003.002
    - T1003.003
  - name: Proxy Tunneling and C2 Infrastructure
    observables:
    - socktz_v1.exe through socktz_v9.exe
    - m-doxa-apodo.duckdns.org
    - m-doxa-geo.duckdns.org
    - m-doxa-intel.duckdns.org
    - m-doxa-vacunas.duckdns.org
    - 62.171.185.97
    - 167.148.195.53
    - 178.128.87.160
    - NextChat interface on TCP port 3000
    - 'Multi-SAN TLS certificates (SHA256: 4e218e70afdbb116209ec0ebe8fc556e296e69648aa4e0425b83c0e863a8fee5)'
    slug: c2-and-proxy-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1090
    - T1568.002
  summary: Threat actors targeting Latin American government and financial sectors
    are utilizing commercial LLMs to generate iterative batch and Python scripts for
    data collection and exfiltration. The campaigns, tracked as CL-CRI-1131 and CL-CRI-1163,
    rely on custom Go-based SOCKS5 proxies (SockTz) and self-hosted NextChat instances
    for orchestration, often revealing their operations through poor operational security
    and predictable file naming conventions.
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


# Endpoint AI-Assisted Scripting and Credential Dumping

This hunt identifies multi-stage intrusions where attackers leverage AI to generate troubleshooting and execution scripts. It follows the attack chain from early infrastructure setup and DuckDNS resolutions to the characteristic behavioral patterns of iterative script naming (v1-v9) and trial-and-error credential dumping via volume shadow copies. The hunt uses a phased approach to correlate infrastructure leads with rare endpoint execution behaviors.

## scoping-windows-servers
<!-- Scope Windows Servers and Domain Controllers -->
Identify high-value targets such as Domain Controllers where NTDS.dit theft is the primary goal.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the server estate. The analyst uses these
  to populate scope_hosts.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%windows%server%' OR LOWER(package_name) LIKE '%active%directory%')
```

## parallel-early-leads
<!-- Gather Infrastructure Leads -->
parallel:
- → dns-traffic-to-duckdns
- → connections-to-attacker-infra
join: → agent-infra-triage

## dns-traffic-to-duckdns
<!-- DNS Traffic to m-doxa Domains -->
Identify hosts resolving the campaign-specific dynamic DNS naming scheme.

```sqlite target=endpoint role=triage params=(duckdns_domains=duckdns_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct matches for the DuckDNS subdomains used by the attacker.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{duckdns_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE 'm-doxa-%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## connections-to-attacker-infra
<!-- Connections to Staging and AI Infrastructure -->
Find network traffic to reported IPs, focusing on port 3000 which hosts the attacker's NextChat AI interface.

```sqlite target=network role=triage params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Connections to port 3000 or the listed C2 IPs, confirming engagement with
  attacker infrastructure.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 3000) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-infra-triage
<!-- Infrastructure Phase Triage -->
```agent target=hunter
cite: required
context:
- dns-traffic-to-duckdns
- connections-to-attacker-infra
max_iterations: 4
objective: Identify hosts demonstrating early infrastructure matches and determine
  if any resolve the campaign subdomains.
success_criteria: A verdict of malicious | suspicious | benign per host based on DuckDNS
  and NextChat patterns.
tools:
- endpoint
- network
```

## parallel-behavioral-leads
<!-- Search for Behavioral Execution Evidence -->
parallel:
- → rare-iterative-script-execution
- → credential-dumping-behavior
join: → agent-synthesis-triage

## rare-iterative-script-execution
<!-- Rare AI-Characteristic Script Execution -->
Stack-count processes with iterative names (v1-v9) or AI-characteristic suffixes across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries or scripts with campaign-specific naming that are rare across the
  estate.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS script_name, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS run_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%socktz%' OR LOWER(process_name) LIKE '%_output%' OR LOWER(process_name) LIKE '%_creative%' OR LOWER(process_name) LIKE '%_careful%' OR LOWER(process_name) LIKE '%_focused%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_name HAVING host_count <= 3 ORDER BY host_count ASC
```

## credential-dumping-behavior
<!-- Trial-and-Error Credential Dumping -->
Identify repeated attempts to dump the SAM registry hive or NTDS.dit file using shadow copies.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Commands creating volume shadow copies or saving critical registry hives,
  especially on servers scoped earlier.
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%shadow%create%' OR LOWER(process_cmd_line) LIKE '%ntdsutil%' OR (LOWER(process_cmd_line) LIKE '%reg%save%' AND (LOWER(process_cmd_line) LIKE '%sam%' OR LOWER(process_cmd_line) LIKE '%system%'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-synthesis-triage
<!-- Final Attack Chain Synthesis -->
```agent target=hunter
cite: required
context:
- agent-infra-triage
- rare-iterative-script-execution
- credential-dumping-behavior
max_iterations: 6
objective: Determine if the hosts demonstrating early infrastructure leads are also
  the ones running rare iterative scripts and attempting VSS-based credential theft.
success_criteria: A final verdict citing specific process names, command lines, and
  infrastructure connections.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Synthesis Verdict -->
if~: "the agent-synthesis-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-endpoint-coverage)
else: → hunt-close-out

## isolate-infected-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the EDR. Preserve the SockTz binary and any numbered batch scripts for further analysis.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Examine hb_file_activity for resume-themed files (e.g., resume.pdf, cv.zip) around the time of the initial SockTz execution. Review browser logs for connections to port 3000.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt Close-out -->
```manual target=analyst
Summarize the hosts identified. Record whether the DuckDNS naming scheme matched the m-doxa- standard. Update the C2 list if new IPs were discovered during forensic review.
```
→ end
