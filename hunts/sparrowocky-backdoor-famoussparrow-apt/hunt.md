---
analysis: "This hunt correlates evidence across four surfaces\u2014processes, modules,\
  \ files, and network activity\u2014to detect a phased infection that a single registry\
  \ or network rule would likely miss due to the modularity of the backdoor."
blind_spots:
- id: no-reflective-mapping-telemetry
  owner: Detection Engineering
  question: whether the backdoor was reflectively loaded directly into memory
  remediation: Enable memory-mapping event logging for web server processes.
  requires: hb_process_activity with on_disk = 0 context
  risk: SparroWocky strips PE magic values to evade memory scanners; standard process
    activity may miss the reflective load event.
  stage: execution-trident-side-loading
coverage:
- stage: initial-access-exploit-public-app
  status: covered
  steps:
  - scoping-web-servers
- stage: execution-trident-side-loading
  status: covered
  steps:
  - rare-unsigned-modules
  - suspicious-dat-files
- stage: persistence-service-registry
  status: covered
  steps:
  - persistence-check
- stage: c2-exfiltration-tls
  status: covered
  steps:
  - c2-network-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: FamousSparrow is an active APT targeting governmental assets. SparroWocky
    is their latest implant designed to evade standard detections through DLL side-loading
    and memory-only execution; a negative result provides assurance against this specific
    regional threat.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a beachhead on a web-facing server using
  a trident loader scheme and is communicating with SparroWocky C2 infrastructure.
labels:
- hunt
- attack.t1190
- attack.t1574.002
- attack.t1547.001
- attack.t1041
name: SparroWocky Backdoor and FamousSparrow APT Activity
parameters:
  c2_ips:
    default:
    - 216.238.110.120
    description: Known SparroWocky C2 IP addresses.
    from:
      kind: article
      observed: '2026-09-17'
      ref: eset-sparrowocky
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the hunt.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: analyst-defined
    type: list[host]
  web_server_processes:
    default:
    - w3wp.exe
    - httpd.exe
    - nginx.exe
    - exchange.exe
    - tomcat.exe
    description: Process names for common web servers to scope initial access.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: standard-web-processes
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts running critical web-facing services (IIS, Apache, Exchange)
  particularly in Latin American regional subnets.
references:
- name: "ESET Research \u2014 Beware the SparroWock: The backdoor that bites, the\
    \ commands that catch"
  url: https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/
related:
- hunt: sparrowdoor-persistence-detection
  reason: SparroWocky has replaced SparrowDoor as the group's primary implant.
  relation: supersedes
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - Vulnerable governmental web servers
    - ProxyLogon (historical context)
    slug: initial-access-exploit-public-app
    tactic: initial-access
    techniques:
    - T1190
  - name: Trident Loader DLL Side-loading
    observables:
    - Legitimate executable loading patched DLL
    - Payload file with .dat extension
    - Encrypted file header magic value 0x11328712
    - Malicious code in patched .text section of legitimate DLLs
    - Reflective PE loading with stripped MZ/PE magic values
    slug: execution-trident-side-loading
    tactic: execution
    techniques:
    - T1574.002
  - name: Persistence via Service or Registry
    observables:
    - Service name ProcAuditManager
    - Registry Run keys for persistence
    - Configuration field Persistence method set to 1 (Service) or 2 (Registry)
    slug: persistence-service-registry
    tactic: persistence
    techniques:
    - T1547.001
  - name: Exfiltration over TLS C2 Channel
    observables:
    - C2 IP 216.238.110.120
    - C2 Port 443
    - TLS protocol used for secure channel
    - RC4 encrypted exfiltration data
    - Periodic screenshots
    - TCP proxy activity
    slug: c2-exfiltration-tls
    tactic: exfiltration
    techniques:
    - T1041
  summary: The China-aligned FamousSparrow APT group is targeting Latin American governmental
    organizations using the modular SparroWocky backdoor. The campaign uses a trident
    loader scheme involving DLL side-loading and a custom encrypted payload to establish
    persistence via services or registry keys and communicate with a hardcoded C2
    infrastructure.
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


# SparroWocky Backdoor and FamousSparrow APT Activity

This hunt targets the China-aligned FamousSparrow APT group and its SparroWocky backdoor. The attack chain begins with the exploitation of web-facing applications, followed by the deployment of a trident loader that uses DLL side-loading to reflectively load the backdoor from an encrypted .dat payload. The hunt uses a phased approach: it first scopes the web-facing estate and searches for the loader's side-loaded modules and companion data files, then follows on to hunt for service-based persistence and confirmed C2 traffic. An agent synthesizes the evidence across process, module, file, and network telemetry to reach a verdict.

## scoping-web-servers
<!-- Scope potential beachheads -->
Identify hosts running web server processes, which are the primary initial access targets.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts, web_server_processes=web_server_processes)
~~~yaml
expected: A list of hostnames representing the web-facing attack surface. Silence
  means no web server processes were active.
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE instr(',' || '{{web_server_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early
<!-- Hunt for loader artifacts -->
parallel:
- → rare-unsigned-modules
- → suspicious-dat-files
join: → loader-early-agent

## rare-unsigned-modules
<!-- Rare unsigned module loads -->
Identify potential DLL side-loading by finding rare, unsigned modules loaded from non-system directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unsigned modules appearing on a small number of hosts in application-specific
  paths.
prevalence:
  by: device_hostname
  key:
  - module_path
  rare_below: 3
reads:
- device_hostname
- module_path
- module_signed
- time
- process_name
silence: evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, module_path, process_name, COUNT(*) AS load_count, MIN(time) AS first_seen FROM hb_module_activity WHERE module_signed = 'false' AND LOWER(module_path) NOT LIKE 'c:\windows\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, module_path, process_name HAVING COUNT(DISTINCT device_hostname) <= 3 ORDER BY load_count ASC
```

## suspicious-dat-files
<!-- Suspicious payload file activity -->
Detect the .dat payload files typically associated with the SparroWocky loader.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process activity touching .dat files in non-standard directories. Silence
  proves no such files were touched.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) LIKE '%.dat' AND LOWER(file_path) NOT LIKE 'c:\windows\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## loader-early-agent
<!-- Evaluate loader beachhead -->
```agent target=hunter
cite: required
context:
- scoping-web-servers
- rare-unsigned-modules
- suspicious-dat-files
max_iterations: 3
objective: Identify hosts where rare unsigned modules and suspicious .dat files exist
  on web-facing infrastructure.
success_criteria: A list of suspicious hosts with cited evidence of the trident loader
  scheme.
tools:
- endpoint
- network
```

## parallel-follow-on
<!-- Hunt for follow-on activity -->
parallel:
- → persistence-check
- → c2-network-activity
join: → backdoor-final-agent

## persistence-check
<!-- Identify SparroWocky persistence -->
Search for the specific service name or Run key entries used by SparroWocky.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry writes associated with service creation or run-key persistence.
  Silence means no such activity was recorded.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%procauditmanager%' OR LOWER(reg_target) LIKE '%\currentversion\run%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-activity
<!-- Confirmed C2 network traffic -->
Identify active network connections to the known SparroWocky C2 infrastructure.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_ips=c2_ips)
~~~yaml
expected: Connections to 216.238.110.120. Silence proves no communication with this
  IP occurred.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## backdoor-final-agent
<!-- Final infection assessment -->
```agent target=hunter
cite: required
context:
- loader-early-agent
- persistence-check
- c2-network-activity
max_iterations: 4
objective: Reach a final verdict by correlating early loader artifacts with confirmed
  persistence and C2 traffic.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing all
  relevant rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on verdict -->
if~: "the final assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-reflective-mapping-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via EDR containment. Collect the suspicious .dat and DLL files for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows. Confirm the existence of the 'ProcAuditManager' service. Verify if any other hosts contacted 216.238.110.120.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the compromised hosts and the identified loader artifacts. Propose a standing rule for connections to the C2 IP.
```
→ end
