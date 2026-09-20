---
analysis: A single rule on ScreenConnect or UltraViewer is too noisy for many environments.
  This hunt uses stack-counting (prevalence) to isolate rare installations and correlates
  them with network plane indicators (port 8041, known C2 IPs) that a static process
  rule would ignore.
blind_spots:
- id: encrypted-dns
  question: whether the attacker used DNS-over-HTTPS to resolve C2 domains
  requires: hb_dns_activity with DoH decryption
  risk: Resolutions to anondns.net would be invisible to standard DNS logs, making
    the DNS query step miss the activity.
  stage: network-c2-and-staged-download
- id: http-path-visibility
  question: whether the Dropbox download of map.txt occurred
  requires: hb_http_activity with full URL path
  risk: Without URL path visibility, we cannot distinguish legitimate Dropbox traffic
    from the attacker retrieving the staging map.
  stage: network-c2-and-staged-download
coverage:
- stage: network-c2-and-staged-download
  status: covered
  steps:
  - lead-network-connections
  - dns-c2-lookup
- stage: secondary-rmm-redundancy
  status: covered
  steps:
  - rare-rmm-processes
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: rogue-screenconnect-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: host-profiling-and-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: persistence-via-run-key
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: powershell-payload-decryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Unauthorized RMM deployment is a major vector for persistent access
    and ransomware preparation. This hunt ensures that even if individual file indicators
    rotate, the behavioral pattern of RMM tools communicating with non-standard IPs
    and ports is captured.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using rogue ScreenConnect instances and secondary RMM tools
  to maintain persistence, identified by non-standard port connections and rare binaries
  running from user-writable directories.
labels:
- hunt
- attack.t1090.003
- attack.t1572
- attack.t1021.001
- attack.t1566
name: RMM Command and Control and Redundancy
parameters:
  c2_domains:
    default:
    - tele-sync.opik.net
    - borertors92.anondns.net
    description: C2 domains linked to the IPs during August.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: list[domain]
  c2_ips:
    default:
    - 45.13.237.190
    - 131.123.40.98
    - 15.204.185.204
    - 146.59.55.107
    - 45.32.192.150
    description: C2 and relay IP addresses observed in the report.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: standard-lookback
    type: number
  rare_below:
    default: '3'
    description: Threshold for stack-counting rare processes across the estate.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: standard-prevalence
    type: number
  rmm_port:
    default: '8041'
    description: The specific port used by the rogue ScreenConnect client for C2 communications.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rogue-screenconnect-installations
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on standard user workstations rather than servers, as the attack
  relies on social engineering and Quick Assist which are user-centric. Prioritize
  hosts where ScreenConnect is not a standard business tool.
references:
- name: "Huntress \u2014 Rogue ScreenConnect Installations Across Unrelated Hosts"
  url: https://www.huntress.com/blog/rogue-screenconnect-installations
related:
- hunt: rmm-vbs-script-execution-patterns
  reason: This hunt focuses on network and process identity; a sibling hunt focuses
    on the internal VBS script content analysis via hb_script_activity.
  relation: out-of-scope-alternative
- hunt: rogue-screenconnect-host-execution-persistence
  relation: follows
scenario:
  stages:
  - name: Initial Access via Social Engineering
    observables:
    - Quick Assist
    - ScreenConnect.ClientSetup.msi
    - Geek Squad refund form
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
    - T1021.001
  - name: Rogue ScreenConnect and Script Execution
    observables:
    - ScreenConnect.WindowsClient.exe
    - ScreenConnect.Client.exe
    - wscript.exe
    - 1.vbs
    - 2.vbs
    - 3.vbs
    - 4.vbs
    slug: rogue-screenconnect-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Host Profiling and EDR Discovery
    observables:
    - 1.vbs
    - value.txt
    - Huntress
    - Cisco AMP
    - CrowdStrike
    - SentinelOne
    - Sophos
    - Malwarebytes
    - Microsoft Defender
    - RAM check > 5GB
    slug: host-profiling-and-discovery
    tactic: discovery
    techniques:
    - T1059.001
  - name: Persistence via Registry Run Key
    observables:
    - WindowsServiceHost
    - WindowsServiceHost.vbs
    - WindowsServiceHost.bat
    - AppData
    slug: persistence-via-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Network C2 and Staged Download
    observables:
    - 45.13.237.190
    - 131.123.40.98
    - 15.204.185.204
    - tele-sync.opik.net
    - borertors92.anondns.net
    - port 8041
    - Dropbox
    - map.txt
    - user.enc
    - acc.enc
    - combo.enc
    slug: network-c2-and-staged-download
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: PowerShell Payload Decryption and Execution
    observables:
    - runner.ps1
    - PyTorchFix.ps1
    - sys_cache.zip
    - out.enc
    - AES-CBC
    slug: powershell-payload-decryption
    tactic: execution
    techniques:
    - T1059.001
  - name: Secondary RMM Deployment
    observables:
    - UltraViewer
    - 146.59.55.107
    - 45.32.192.150
    slug: secondary-rmm-redundancy
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: Attackers leverage social engineering or phishing to deploy rogue ScreenConnect
    instances, which then execute a multi-stage VBScript chain to profile the host
    and bypass security products. The campaign establishes persistence through registry
    Run keys and downloads encrypted payloads from Dropbox, including secondary RMM
    tools like UltraViewer and tunneling utilities, with some samples exhibiting worm-like
    propagation via connected ScreenConnect endpoints.
series:
  index: 2
  slug: rogue-screenconnect-installations-across-unrelated-hosts-suggest-worm-like-activity
  title: Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like
    Activity
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


# RMM Command and Control and Redundancy

This hunt focuses on the network and software footprint of rogue ScreenConnect and UltraViewer deployments. It follows a funnel flow: starting with network leads on observed C2 ports and IPs, then fanning out to identify rare process metadata and dynamic DNS resolutions. By correlating these surfaces, the hunt identifies unauthorized remote management tools that bypass standard application controls and security product enumeration.

## lead-network-connections
<!-- Network connections to C2 IPs and RMM ports -->
Identify hosts communicating with the report's C2 infrastructure or using the ScreenConnect C2 port.

```sqlite target=network role=detection-candidate params=(c2_ips=c2_ips, rmm_port=rmm_port, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating connections to known bad IPs or the specific RMM port. Silence
  suggests these network indicators are absent from the logs.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = {{rmm_port}}) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate leads with DNS and processes -->
parallel:
- → dns-c2-lookup
- → rare-rmm-processes
join: → triage-rmm-behavior

## dns-c2-lookup
<!-- DNS resolutions for C2 domains -->
Check for lookup activity against the reported dynamic DNS domains.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving the malicious domains. Silence means no lookups occurred
  in the monitored window.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-rmm-processes
<!-- Rare RMM binaries in user directories -->
Find RMM software running from suspicious user-writable paths and stack-count them to find outliers.

```sqlite target=endpoint role=baseline params=(rare_below=rare_below, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few hosts running RMM software from temporary or application data folders.
  Large counts across the estate suggest legitimate usage.
prevalence:
  by: device_hostname
  key:
  - process_original_file_name
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_original_file_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_original_file_name, COUNT(DISTINCT device_hostname) AS hosts FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%screenconnect%' OR LOWER(process_name) LIKE '%ultraviewer%' OR LOWER(process_original_file_name) IN ('screenconnect.client.exe', 'ultraviewer_desktop.exe')) AND (LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%\appdata\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING hosts <= {{rare_below}}
```

## triage-rmm-behavior
<!-- Triage RMM activity -->
```agent target=hunter
cite: required
context:
- lead-network-connections
- dns-c2-lookup
- rare-rmm-processes
max_iterations: 4
objective: Identify hosts where ScreenConnect or UltraViewer are making connections
  to known C2 IPs, using port 8041, or resolving dynamic DNS, specifically when the
  processes are running from Temp or AppData paths. Note if any wscript.exe activity
  is visible in the process context.
success_criteria: The agent identifies malicious hosts with high-confidence network
  and process overlap.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage-rmm-behavior verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: encrypted-dns)
else: → analyst-investigation

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR console and revoke active sessions for the impacted user.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst investigation -->
```manual target=analyst
Review the process tree for the identified hosts. Look for ScreenConnect.WindowsClient.exe spawning wscript.exe. Check the user's AppData and Temp directories for 1.vbs through 4.vbs or WindowsServiceHost.vbs.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record which hosts were true positives. If legitimate RMM tools were flagged, provide their paths as exclusions for the lead query. Update detection engineering if unauthorized software was found that was not already covered by a rule.
```
→ end
