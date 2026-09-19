---
analysis: A simple rule for the C2 domain is easily bypassed by domain rotation. This
  hunt pivots to look for the companion FileSystemWatcher script logic and uses fleet-wide
  stacking of Python connections to identify the tunnel behavior itself.
blind_spots:
- id: no-script-block-logging
  owner: Infrastructure Team
  question: What commands were executed via the Invoke-Expression loop?
  remediation: Enable GPO for PowerShell Script Block Logging and forward events to
    the SIEM.
  requires: PowerShell Script Block Logging (Event ID 4104)
  risk: Without script block logging, we see the 'primitive shell' infrastructure
    but cannot see the actual reconnaissance commands executed through it.
  stage: c2-reverse-websocket-tunnel
- id: missing-process-net-link
  owner: Security Engineering
  question: Which specific process is creating the WebSocket traffic to port 443?
  remediation: Deploy Sysmon or ensure EDR network monitoring is configured to capture
    the originating process context.
  requires: hb_network_connection with process_name and pid
  risk: If network telemetry lacks process identity, the tunnel traffic may be lost
    among legitimate browser traffic to Cloudflare or GitHub infrastructure.
  stage: c2-reverse-websocket-tunnel
coverage:
- stage: c2-reverse-websocket-tunnel
  status: covered
  steps:
  - scoping-by-dns
  - detect-python-tunnel-execution
  - rare-python-network-outbound
  - script-filesystem-watcher-loop
  - detect-tunnel-script-presence
- reason: The reconnaissance results are written to local files (watch/output) that
    are not ingested into the central telemetry lake; visibility requires host-level
    forensic collection.
  stage: discovery-ad-and-network-recon
  status: not_visible
- reason: Covered in the first hunt of the series focusing on the social engineering
    and ZIP delivery.
  stage: initial-access-fake-captcha-execution
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: defense-evasion-dll-sideloading
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: steganographic-payload-extraction
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: persistence-registry-and-task
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Reverse tunnels provide attackers with direct network-level ingress
    that bypasses ingress firewall rules and persists past standard user logoffs.
    A negative result over the estate confirms the environment is not currently facilitating
    such a proxy.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a persistent network-level proxy using a
  Python-based reverse WebSocket tunnel and a PowerShell-based file-watching command
  loop to pivot within the environment.
labels:
- hunt
- attack.t1572
- attack.t1090.003
- attack.t1059.001
- attack.t1547.001
- attack.t1115
name: TerminalFix Reconnaissance and Reverse Tunneling
parameters:
  c2_domains:
    default:
    - gitnow.dev
    description: C2 domains identified in research for reverse WebSocket tunneling.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: list[domain]
  interpreter_binaries:
    default:
    - pythonw.exe
    - python.exe
    description: Binaries used to run the Python tunnel implant without visible windows.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search.
    type: list[host]
  tunnel_scripts:
    default:
    - client.py
    - 1.bat
    description: Script filenames associated with the TerminalFix tunnel implant.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The primary indicator is the resolution of gitnow.dev. If this is empty,
  widen the scope to all hosts where pythonw.exe was launched from ProgramData or
  other user-writable directories.
references:
- name: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-initial-access-and-sideloading
  reason: This hunt focuses on the post-exploitation tunnel; the previous hunt covers
    the fake CAPTCHA and DLL sideloading.
  relation: precedes
- hunt: active-directory-reconnaissance-baselining
  reason: The reconnaissance activity itself (ping sweeps, AD harvesting) is a follow-on
    behavior to the tunnel establishment.
  relation: out-of-scope-alternative
- hunt: terminalfix-staging-persistence
  relation: follows
scenario:
  stages:
  - name: Fake CAPTCHA PowerShell Execution
    observables:
    - Fake Cloudflare Turnstile overlay 'Verify you are human'
    - Clipboard manipulation to stage PowerShell command
    - powershell.exe downloading ZIP archive from gitnow.dev
    - Extraction to C:\ProgramData\f47f2a8c21c9df4e
    - Execution of 1.bat
    slug: initial-access-fake-captcha-execution
    tactic: initial-access
    techniques:
    - T1566.002
    - T1115
    - T1059.001
  - name: DLL Sideloading via LockScreenContentServer
    observables:
    - LockScreenContentServer.exe loading malicious dui70.dll
    - dui70.dll with forged future timestamp 2104
    - Masquerading DLL name 'Windows DirectUI Engine'
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
    - T1574.002
  - name: Steganographic Payload Extraction
    observables:
    - PowerShell function Extract-RawFileFromImage
    - POST requests to content domains for PNG images
    - DLL fragments extracted from pixel RGBA channels
    - Reassembly of executables from PNG data
    slug: steganographic-payload-extraction
    tactic: execution
    techniques:
    - T1059.001
    - T1027.003
  - name: Persistent Execution Loop
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM
    - Scheduled task re-executing LockScreenContentServer.exe every 60 minutes
    - Folder hidden via attrib +s +h C:\ProgramData\f47f2a8c21c9df4e
    slug: persistence-registry-and-task
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Active Directory and Network Reconnaissance
    observables:
    - nltest /domain_trusts
    - net group 'domain admins' /domain
    - Ping sweeps of 'dc', 'backup', 'mail', 'gateway' servers
    - Active Directory user description harvesting
    - System information collection (English, Spanish, German)
    slug: discovery-ad-and-network-recon
    tactic: discovery
    techniques:
    - T1018
    - T1087.002
    - T1482
  - name: Reverse WebSocket Tunneling
    observables:
    - pythonw.exe executing client.py
    - Encrypted WebSocket tunnel to gitnow.dev:443
    - FileSystemWatcher asynchronous command loop
    - SOCKS-style TCP proxy access
    slug: c2-reverse-websocket-tunnel
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  summary: The TerminalFix campaign uses social engineering with fake CAPTCHA overlays
    to trick users into executing PowerShell scripts that deploy a multi-stage infection.
    The attack leverages DLL sideloading of a signed binary and steganographic payload
    extraction to establish persistent access and deploy a Python-based reverse tunnel
    for encrypted WebSocket C2.
series:
  index: 2
  slug: terminalfix-campaign-deploys-a-reverse-tunnel-through-multistage-intrusion
  title: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
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


# TerminalFix Reconnaissance and Reverse Tunneling

This hunt targets the TerminalFix post-exploitation capabilities. It focuses on identifying a custom Python reverse tunnel ('client.py') that provides SOCKS-style TCP proxy access through an encrypted WebSocket channel. Simultaneously, it looks for a unique asynchronous command loop implemented via PowerShell's FileSystemWatcher, which allows attackers to execute arbitrary code by monitoring a local text file. By correlating rare Python network connections, specific script block signatures, and the presence of these proxy scripts, this hunt identifies hosts being used as ingress points for internal reconnaissance and lateral movement.

## scoping-by-dns
<!-- Scope by C2 DNS resolutions -->
Identify hosts that have resolved the specific C2 infrastructure domains associated with the reverse tunnel.

```sqlite target=endpoint role=scoping params=(c2_domains=c2_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts that queried the known C2 domain. Silence suggests the domain
  has rotated or the implant is dormant.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, query_hostname, MIN(time) AS first_resolution FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2
```

## detect-python-tunnel-execution
<!-- Python tunnel interpreter execution -->
Identify the execution of Python interpreters that often run the tunnel implant in a hidden state.

```sqlite target=endpoint role=detection-candidate params=(interpreter_binaries=interpreter_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Python or Pythonw execution, especially those with non-standard command
  lines. Silence proves no Python-based implants ran on enrolled hosts during the
  window.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{interpreter_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate via network, script, and file activity -->
parallel:
- → rare-python-network-outbound
- → script-filesystem-watcher-loop
- → detect-tunnel-script-presence
join: → triage-tunnel-evidence

## rare-python-network-outbound
<!-- Rare Python outbound network connections -->
Identify Python processes making unusual outbound connections, which is a hallmark of the reverse tunnel proxying traffic.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound connections from Python to port 443 or other SOCKS-like traffic
  that is rare across the fleet. High-volume connections to standard SaaS endpoints
  can be disregarded.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_hostname
  rare_below: 3
reads:
- process_name
- dst_endpoint_hostname
- dst_endpoint_port
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, dst_endpoint_hostname, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_connection FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%python%' OR LOWER(process_path) LIKE '%python%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING host_count <= 3 ORDER BY host_count ASC
```

## script-filesystem-watcher-loop
<!-- Asynchronous PowerShell command loop -->
Search for the specific PowerShell script pattern that uses FileSystemWatcher to execute commands from a local text file.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks establishing a file-watch loop. Silence is common unless script
  block logging (4104) is enabled.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE LOWER(script_content) LIKE '%io.filesystemwatcher%' AND (LOWER(script_content) LIKE '%invoke-expression%' OR LOWER(script_content) LIKE '%iex %') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-tunnel-script-presence
<!-- TerminalFix tunnel script filenames -->
Detect the presence of the exact filenames used for the tunnel implant and its supporting batch files.

```sqlite target=endpoint role=enrichment params=(tunnel_scripts=tunnel_scripts, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation or access of client.py or 1.bat. This corroborates that the malicious
  ZIP was extracted and the tunnel script is in place.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE instr(',' || '{{tunnel_scripts}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-tunnel-evidence
<!-- Triage tunnel and proxy activity -->
```agent target=hunter
cite: required
context:
- scoping-by-dns
- detect-python-tunnel-execution
- rare-python-network-outbound
- script-filesystem-watcher-loop
- detect-tunnel-script-presence
max_iterations: 5
objective: Determine if the evidence indicates an active reverse tunnel (client.py
  running via pythonw.exe) or the command loop on any host.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  DNS, process, and script rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host showing both the Python interpreter activity and either the script loop or rare C2 connections" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-block-logging)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate any pythonw.exe or powershell.exe processes identified by the triage agent. Revoke all user tokens for the affected account. Collect 'client.py' and any text files in C:\ProgramData\f47f2a8c21c9df4e for analysis.
```
→ analyst-review

## analyst-review
<!-- Manual forensic review -->
```manual target=analyst
Review the cited telemetry. Check for local ping sweep logs or Active Directory discovery artifacts (e.g., ad_users.txt) mentioned in research. If lateral movement is confirmed, pivot to an incident response playbook.
```
→ end
