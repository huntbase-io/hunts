---
analysis: This hunt correlates masqueraded service persistence with anti-analysis
  script behavior and kernel-level impact, providing context that a single detection
  rule on any one indicator would lack.
blind_spots:
- id: no-script-block-logging
  question: Is the anti-analysis script obfuscated or split across multiple blocks?
  requires: Complete PowerShell script block logging (Event ID 4104)
  risk: Fragmented or obfuscated scripts may bypass simple keyword searches for taskmgr
    and service controls.
  stage: anti-analysis-evasion
- id: no-kernel-load-events
  question: Was the WinRing0 driver loaded via a method that avoids standard API calls?
  requires: hb_kernel_extension_activity reporting for all drivers
  risk: Manual mapping of drivers can bypass standard EDR load notification callbacks.
  stage: kernel-driver-execution
coverage:
- stage: persistence-via-service
  status: covered
  steps:
  - fake-edge-service
- stage: anti-analysis-evasion
  status: covered
  steps:
  - anti-analysis-logic
- stage: kernel-driver-execution
  status: covered
  steps:
  - vulnerable-driver-load
- stage: cryptomining-impact
  status: covered
  steps:
  - miner-network-traffic
- reason: Belongs to another part of the 'Threat Actors Exploit Critical AhsayCBS
    Flaws to Drop Webshells and XMRig Cryptominer' series.
  stage: initial-exploitation-rce
  status: out_of_scope
- reason: Belongs to another part of the 'Threat Actors Exploit Critical AhsayCBS
    Flaws to Drop Webshells and XMRig Cryptominer' series.
  stage: webshell-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Threat Actors Exploit Critical AhsayCBS
    Flaws to Drop Webshells and XMRig Cryptominer' series.
  stage: payload-ingress-and-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The exploitation of AhsayCBS provides an unauthenticated RCE pathway
    into sensitive backup infrastructure. A negative result confirms that the server
    has not yet been used for resource hijacking, which can degrade performance and
    signal deeper attacker persistence.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has established persistence on an AhsayCBS server via a fake
  Edge service and is running a cryptominer that evades detection by monitoring for
  Task Manager and using a vulnerable kernel driver.
labels:
- hunt
- attack.t1543.003
- attack.t1036.004
- attack.t1036.005
- attack.t1564
- attack.t1057
- attack.t1124
- attack.t1059.001
- attack.t1496.001
- attack.t1571
- command and control
- defense evasion
- impact
- initial access
- persistence
name: Masqueraded Cryptominer Persistence and Stealthy Operation
parameters:
  c2_domains:
    default:
    - xmr.kryptex.network
    description: Cryptominer pool domains.
    from:
      kind: article
      observed: '2026-10-08'
      ref: huntress-ahsaycbs
    type: list[domain]
  c2_ips:
    default:
    - 51.195.127.124
    description: Cryptominer pool IP addresses from the report.
    from:
      kind: article
      observed: '2026-10-08'
      ref: huntress-ahsaycbs
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of AhsayCBS servers to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ahsaycbs-flaws-exploit
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on AhsayCBS application servers by checking software inventory first.
  If not explicitly tagged, widen scope to all servers with public-facing web services.
references:
- name: "Huntress \u2014 AhsayCBS Flaws Exploit"
  url: https://www.huntress.com/blog/ahsaycbs-flaws-exploit
related:
- hunt: ahsaycbs-initial-exploitation-rce
  reason: Initial RCE and webshell deployment are precursors to the cryptomining persistence
    covered here.
  relation: follows
scenario:
  stages:
  - name: AhsayCBS Unauthenticated RCE
    observables:
    - cbssvcX64.exe
    - cbssvcX86.exe
    - /rps/api/json/UpdateReceivers.do
    - random token bypass in checkSysPwd
    slug: initial-exploitation-rce
    tactic: initial-access
    techniques:
    - T1190
    - T1059.003
  - name: JSP Webshell Deployment
    observables:
    - .jsp files in application directory
    - com/ahsay/obs/api/ApiStructsAction.java
    slug: webshell-persistence
    tactic: persistence
    techniques:
    - T1505.003
  - name: Miner Toolkit Ingress
    observables:
    - curl -sk -o
    - certutil.exe
    - imagefiles-backup.oss-ap-southeast-7.aliyuncs.com
    - C:\Users\ADMINI~1\AppData\Local\Temp\Taskgmr.ps1
    - config.json
    - msedge.exe
    - edge.exe
    slug: payload-ingress-and-staging
    tactic: command-and-control
    techniques:
    - T1105
    - T1071.001
  - name: Masqueraded Service Creation
    observables:
    - MicrosoftEdgeUpdateSvc
    - msedge.exe
    - edge.exe
    - --daemonized
    - modified NSSM utility
    - renamed XMRig miner
    slug: persistence-via-service
    tactic: persistence
    techniques:
    - T1543.003
    - T1036.004
    - T1036.005
  - name: Task Manager Aware Evasion
    observables:
    - Taskgmr.ps1
    - Get-Process taskmgr
    - Get-Date
    - stop MicrosoftEdgeUpdateSvc when taskmgr opens
    slug: anti-analysis-evasion
    tactic: defense-evasion
    techniques:
    - T1564
    - T1057
    - T1124
    - T1059.001
  - name: Vulnerable Kernel Driver Loading
    observables:
    - WinRing0x64.sys
    - OpenLibSys driver
    slug: kernel-driver-execution
    tactic: defense-evasion
    techniques:
    - T1543.003
  - name: XMRig Resource Hijacking
    observables:
    - xmr.kryptex.network
    - 51.195.127.124:8029
    - edge.exe
    slug: cryptomining-impact
    tactic: impact
    techniques:
    - T1496.001
    - T1571
  summary: Threat actors are chaining CVE-2026-105133 and CVE-2026-105134 to achieve
    unauthenticated remote code execution on internet-exposed AhsayCBS backup management
    servers. Once compromised, actors deploy JSP webshells and download a cryptomining
    toolkit that includes XMRig, a modified NSSM utility for persistence, and an anti-analysis
    PowerShell script designed to hide mining activity from the Task Manager.
series:
  index: 2
  slug: threat-actors-exploit-critical-ahsaycbs-flaws-to-drop-webshells-and-xmrig-cryptominer
  title: Threat Actors Exploit Critical AhsayCBS Flaws to Drop Webshells and XMRig
    Cryptominer
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


# Masqueraded Cryptominer Persistence and Stealthy Operation

This hunt targets the post-exploitation lifecycle of AhsayCBS compromises. It identifying vulnerable hosts and then hunts for the creation of a fake Microsoft Edge service used to maintain a renamed XMRig miner. It looks for PowerShell script blocks that monitor for the Task Manager process to pause mining activity, evading user discovery. Finally, it correlates these behaviors with the loading of the WinRing0 vulnerable kernel driver and outbound connections to known mining infrastructure.

## scoping-ahsay-hosts
<!-- Identify AhsayCBS Servers -->
Find hosts running AhsayCBS software to prioritize behavioral checks.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames where Ahsay software is installed. Silence means no
  Ahsay packages were found in the current inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%ahsay%'
```

## early-stage-parallel
<!-- Hunt for Persistence and Evasion Scripts -->
parallel:
- → fake-edge-service
- → anti-analysis-logic
join: → triage-persistence-evasion

## fake-edge-service
<!-- Detect Masqueraded Edge Service -->
Find the MicrosoftEdgeUpdateSvc service created to daemonize the miner.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of a service with a name mimicking Edge, pointing to a binary in
  a temporary directory. This is a high-fidelity indicator of the campaign.
reads:
- device_hostname
- service_name
- service_cmd_line
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, service_name, service_cmd_line, actor_user_name, time FROM hb_service_activity WHERE activity_id = 1 AND (LOWER(service_name) LIKE '%microsoftedgeupdatesvc%' OR LOWER(service_cmd_line) LIKE '%temp%msedge.exe%' OR LOWER(service_cmd_line) LIKE '%--daemonized%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## anti-analysis-logic
<!-- Detect Anti-TaskMgr Script Blocks -->
Identify PowerShell scripts that monitor for Task Manager to hide mining activity.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing logic to stop services when taskmgr is found. Silence
  proves the exact string was not seen, but evasion may be obfuscated.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE activity_id = 1 AND (LOWER(script_content) LIKE '%taskmgr%' AND (LOWER(script_content) LIKE '%stop-service%' OR LOWER(script_content) LIKE '%start-service%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-persistence-evasion
<!-- Analyze Persistence and Evasion Patterns -->
```agent target=hunter
cite: required
context:
- fake-edge-service
- anti-analysis-logic
max_iterations: 3
objective: Determine if the service activity and script content on these hosts represent
  the Taskgmr.ps1 and MicrosoftEdgeUpdateSvc pattern described in the research.
success_criteria: Verdicts citing specific rows from both queries that demonstrate
  correlated activity.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Hunt for Mining Impact and Kernel Loads -->
parallel:
- → vulnerable-driver-load
- → miner-network-traffic
join: → evaluate-complete-intrusion

## vulnerable-driver-load
<!-- Identify WinRing0 Driver Loads -->
Find the vulnerable WinRing0 kernel driver used to optimize mining performance.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Loads of the WinRing0x64.sys driver, especially in user-writable paths.
  Fleet-wide rarity increases confidence.
prevalence:
  by: device_hostname
  key:
  - driver_path
  rare_below: 3
reads:
- device_hostname
- driver_path
- driver_signature_subject
- time
silence: not_evidence_of_absence
source: hb_kernel_extension_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, driver_path, driver_signature_subject, MIN(time) AS first_seen FROM hb_kernel_extension_activity WHERE activity_id = 1 AND LOWER(driver_path) LIKE '%winring0x64.sys%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, driver_path, driver_signature_subject
```

## miner-network-traffic
<!-- Identify Miner Network Connections -->
Corroborate host activity with outbound connections to mining pool infrastructure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_domains=c2_domains, c2_ips=c2_ips)
~~~yaml
expected: Connections to the known pool IP, domain, or the specific non-standard port
  8029 used by the campaign.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 8029) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-complete-intrusion
<!-- Evaluate Full Intrusion Chain -->
```agent target=hunter
cite: required
context:
- vulnerable-driver-load
- miner-network-traffic
- triage-persistence-evasion
max_iterations: 6
objective: Consolidate the findings from all previous steps. Assess if the host has
  persistence, is using the anti-analysis scripts, has loaded the WinRing0 driver,
  and is connecting to mining pools.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the chain of evidence.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the evaluate-complete-intrusion verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-collect
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-script-block-logging)
else: → close-out

## isolate-and-collect
<!-- Isolate Endpoint and Collect Artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect any binaries found in user temp folders, specifically msedge.exe, edge.exe, and Taskgmr.ps1.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Review the collected artifacts and script content. Confirm if msedge.exe is a renamed NSSM utility and analyze Taskgmr.ps1 for anti-analysis loops. Check for secondary backdoors that may have been deployed alongside the miner.
```
→ close-out

## close-out
<!-- Hunt Closure -->
```manual target=analyst
Document the hosts found, the severity of the intrusion, and any blind spots encountered during the hunt.
```
→ end
