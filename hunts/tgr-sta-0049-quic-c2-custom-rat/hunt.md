---
analysis: This hunt correlates novel network protocols (QUIC) with post-exploitation
  behaviors across four different telemetry surfaces. A single detection rule cannot
  reliably track the progression from a UDP 443 flow to LSASS memory harvesting and
  lateral SMB scanning while compensating for heuristic camouflage.
blind_spots:
- id: quic-visibility-gap
  owner: Network Operations
  question: Are we seeing the specific malicious hashed endpoints inside the encrypted
    QUIC stream?
  remediation: Update IDS/IPS signatures to support QUIC/HTTP3 parsing or rely on
    endpoint-level network telemetry.
  requires: Deep packet inspection of UDP 443 (QUIC) traffic.
  risk: If network sensors cannot parse HTTP/3 over UDP, specific command identifiers
    remain invisible at the network layer.
  stage: command-and-control-http3-quic
- id: synthetic-noise-drowning
  owner: Detection Engineering
  question: Can the analyst distinguish RAT-generated noise from legitimate OS or
    application automation?
  remediation: Implement stack-counting for high-volume automated file and registry
    events.
  requires: Heuristic baseline of normal automated file and registry activity.
  risk: KUKURAT's camouflage engine is designed to hide malicious activity within
    synthetic volume; a lack of established baseline leads to false negatives.
  stage: defense-evasion-stealth-and-camouflage
coverage:
- stage: defense-evasion-stealth-and-camouflage
  status: covered
  steps:
  - lsass-access-activity
  - camouflage-investigation
- stage: command-and-control-http3-quic
  status: covered
  steps:
  - dns-lookups
  - quic-network-flows
- stage: discovery-and-lateral-movement
  status: covered
  steps:
  - smb-lateral-scanning
- stage: exfiltration-and-collection
  status: covered
  steps:
  - lsass-access-activity
- reason: 'Belongs to another part of the ''QUIC and Covert: Novel HTTP/3-Powered
    RATs Target Southeast Asian Governments'' series.'
  stage: initial-access-exploitation-phishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''QUIC and Covert: Novel HTTP/3-Powered
    RATs Target Southeast Asian Governments'' series.'
  stage: execution-sideloading-rat-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: TGR-STA-0049 is an advanced cyberespionage group targeting strategic
    government entities. Their adoption of HTTP/3 and automated camouflage represents
    a significant evasion leap that standard security policies may bypass.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using HTTP/3 (QUIC) over UDP 443 for command and control
  and loading custom RAT modules to perform data collection, while masking their activity
  with synthetic background noise.
labels:
- hunt
- attack.t1071.001
- attack.t1572
- attack.t1003.001
- attack.t1021.002
- attack.t1047
- attack.t1055
- attack.t1547.001
- attack.t1574.002
- collection
- command and control
- defense evasion
- execution
- initial access
- lateral movement
name: 'TGR-STA-0049: QUIC C2 and Custom RAT Operations'
parameters:
  browser_processes:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    - opera.exe
    description: Standard browser processes to exclude from behavioral QUIC traffic
      search.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: hunt-designer
    type: list[string]
  c2_domains:
    default:
    - ads-edge.com
    - www.maui-cocktailbar.com
    - www.cloudflacecdn.com
    - www.police.gr.com
    - www.investigationj6.com
    - www.sacofficegov.com
    description: Known C2 domains for KUKURAT and PerfectPioneer.
    from:
      kind: article
      observed: '2026-11-16'
      ref: unit42-tgr-sta-0049
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Hostnames of internet-facing servers to constrain the hunt.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: scoping-output
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with high-value internet-facing infrastructure (Exchange and Web
  servers). The lookback period should be at least 14 days to capture the progression
  from initial beaconing to internal scanning.
references:
- name: 'Unit 42: QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian
    Governments'
  url: https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
related:
- hunt: exchange-server-webshell-scoping
  reason: The broader topic of Exchange exploitation is handled by specialized server-hygiene
    hunts.
  relation: out-of-scope-alternative
- hunt: tgr-sta-0049-initial-access-exploitation-phishing
  relation: follows
scenario:
  stages:
  - name: Server Exploitation and Phishing
    observables:
    - ASPXSpy, Godzilla, Bysunue.aspx, or Suo5 web shells on Exchange or web servers
    - Decoy PDF documents targeting government sectors
    - 'Lookalike domains: www.wkuyda.com, www.thailisting.net, www.yangon.it.com'
    slug: initial-access-exploitation-phishing
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
    - T1566
  - name: Execution via Sideloading and RAT Deployment
    observables:
    - DLL side-loading of modified legitimate binaries
    - XOR-encrypted shellcode embedded in payloads
    - PerfectPioneer RAT (Go-based)
    - KUKURAT modular agent
    - Decoy installers
    slug: execution-sideloading-rat-deployment
    tactic: execution
    techniques:
    - T1574.002
    - T1218
    - T1059.001
  - name: Defense Evasion and Heuristic Camouflage
    observables:
    - KUKURAT heuristic camouflage engine generating synthetic baseline noise
    - PerfectPioneer isDangerousCommand validation engine
    - Process injection commands (process_inject)
    - UAC bypass modules
    slug: defense-evasion-stealth-and-camouflage
    tactic: defense-evasion
    techniques:
    - T1055
    - T1572
  - name: HTTP/3 QUIC Command and Control
    observables:
    - HTTP/3 over UDP port 443
    - Hashed C2 URL endpoints (e.g., /c8a4e192)
    - 'C2 Domains: ads-edge.com, www.maui-cocktailbar.com, www.cloudflacecdn.com,
      www.police.gr.com, www.investigationj6.com, www.sacofficegov.com'
    slug: command-and-control-http3-quic
    tactic: command-and-control
    techniques:
    - T1071
    - T1572
  - name: Discovery and Lateral Movement
    observables:
    - MyPsExec.dll module
    - SmbBrute.dll module
    - Async port and host scanning modules (portscan, hostscan)
    - WMI command execution (ComExec.dll)
    slug: discovery-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1018
    - T1021.002
    - T1047
  - name: Exfiltration and Credential Collection
    observables:
    - BofLoader.dll for Beacon Object File execution
    - Keylogger module activity
    - LSASS memory access for credential harvesting
    - File upload/download activity (file_upload, file_download)
    - Screenshot module
    slug: exfiltration-and-collection
    tactic: collection
    techniques:
    - T1003.001
    - T1056.001
    - T1041
  summary: TGR-STA-0049 is a Southeast Asian espionage campaign deploying custom Go-based
    RATs (PerfectPioneer and KUKURAT) via server exploitation and phishing. The campaign
    features early adoption of HTTP/3 (QUIC) for command and control and an automated
    heuristic camouflage engine designed to blend malicious endpoint activity into
    a baseline of synthetic noise.
series:
  index: 2
  slug: quic-and-covert-novel-http-3-powered-rats-target-southeast-asian-governments
  title: 'QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian Governments'
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


# TGR-STA-0049: QUIC C2 and Custom RAT Operations

This hunt targets the cyberespionage tradecraft of TGR-STA-0049, focusing on their adoption of HTTP/3 as a stealthy communication protocol and the deployment of the KUKURAT and PerfectPioneer RAT families. The hunt follows a phased approach: first, it identifies high-value internet-facing servers showing signs of behavioral QUIC C2 traffic or DNS resolutions to the report's indicators. Second, it pivots to investigate post-exploitation behavior including internal SMB scanning and credential harvesting from LSASS memory, reaching a final verdict on the host's compromise state despite the actor's heuristic camouflage.

## scoping-servers
<!-- Scope potential beachhead servers -->
Identify internet-facing web or Exchange servers that were primary targets for initial exploitation.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the exposed server surface area. Silence
  suggests the estate does not run these platforms.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%exchange%' OR LOWER(package_name) LIKE '%iis%' OR LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%nginx%') AND asset_scope = 'endpoint'
```

## early-parallel
<!-- Parallel search for C2 evidence -->
parallel:
- → dns-lookups
- → quic-network-flows
join: → early-agent

## dns-lookups
<!-- DNS resolutions to C2 domains -->
Find DNS queries for the specific domains identified in the research.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: High-fidelity indicator of a host attempting to reach threat actor infrastructure.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## quic-network-flows
<!-- Non-browser QUIC network flows -->
Identify behavioral QUIC (UDP 443) traffic from processes that are not standard web browsers.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days, browser_processes=browser_processes)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous processes communicating over UDP 443, suggesting evasion of standard
  TCP-based deep packet inspection.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
- protocol
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE protocol = 'udp' AND dst_endpoint_port = 443 AND NOT instr(',' || '{{browser_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-agent
<!-- Early-stage triage -->
```agent target=hunter
cite: required
context:
- scoping-servers
- dns-lookups
- quic-network-flows
max_iterations: 3
objective: Determine if any scoped server shows evidence of C2 activity through listed
  domains or behavioral QUIC traffic.
success_criteria: A verdict citing specific DNS queries or network rows.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Parallel search for post-exploitation -->
parallel:
- → smb-lateral-scanning
- → lsass-access-activity
join: → lifecycle-agent

## smb-lateral-scanning
<!-- Internal SMB and port scanning -->
Detect automated internal reconnaissance through high-volume outbound SMB connections.

```sqlite target=network role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A single host reaching out to multiple internal IP addresses via SMB, suggesting
  the use of SmbBrute or hostscan modules.
reads:
- device_hostname
- dst_endpoint_ip
- time
- direction
- dst_endpoint_port
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND dst_endpoint_port IN (445, 139) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING connection_count > 5 ORDER BY connection_count DESC
```

## lsass-access-activity
<!-- Credential harvesting via LSASS -->
Identify process access to LSASS memory from non-standard locations, characteristic of RAT collection modules.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Non-system processes accessing LSASS memory for credential theft. Silence
  on high-value servers is evidence of absence for this specific technique.
reads:
- device_hostname
- actor_process_name
- object_name
- access_mask
- time
- object_type
silence: evidence_of_absence
source: hb_resource_activity
verified: dry-run
verified_at: '2026-11-17'
~~~
SELECT device_hostname, actor_process_name, object_name, access_mask, time FROM hb_resource_activity WHERE object_type = 'Process' AND LOWER(object_name) LIKE '%lsass.exe' AND actor_process_name NOT LIKE 'C:\Windows\System32\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lifecycle-agent
<!-- Full lifecycle triage -->
```agent target=hunter
cite: required
context:
- early-agent
- smb-lateral-scanning
- lsass-access-activity
max_iterations: 5
objective: Decide if the progression of network behavior, internal scanning, and credential
  access confirms an intrusion by TGR-STA-0049.
success_criteria: A detailed verdict citing rows from both network and endpoint activities
  across the lifecycle.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on final verdict -->
if~: "the lifecycle-agent verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → camouflage-investigation
unavailable: → camouflage-investigation (blind_spot: quic-visibility-gap)
else: → camouflage-investigation

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate the TGR-STA-0049 incident response playbook.
```
→ camouflage-investigation

## camouflage-investigation
<!-- Investigate heuristic camouflage -->
```manual target=analyst
Review hb_registry_activity and hb_file_activity for high-volume, automated entries that appear benign but align with the compromise window. These are the likely heuristic camouflage artifacts used by KUKURAT to hide its actual functions.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Summarize the findings, document any new C2 domains or behavioral patterns, and decide if the LSASS memory access pattern should be promoted to a permanent rule.
```
→ end
