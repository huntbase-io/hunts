---
analysis: A single rule might catch the DNS lookup, but this hunt correlates the network
  lead with behavioral signals from PowerShell script blocks and Python process activity,
  baseline counts the rarity of the tunnel script, and weighs all three pieces of
  evidence to confirm active C2.
blind_spots:
- id: no-script-logging
  question: whether the file-watch command loop is running on hosts where script logging
    is disabled
  requires: PowerShell Script Block Logging (EID 4104)
  risk: An attacker can maintain a stealthy shell that leaves no process command-line
    artifacts.
  stage: command-and-control-asynchronous-shell
- id: ephemeral-tunnel-processes
  question: whether the Python tunnel was established and torn down between collection
    intervals
  requires: high-frequency hb_process_activity snapshots
  risk: Short-lived proxy connections used for targeted data exfiltration might be
    missed.
  stage: command-and-control-reverse-tunnel
coverage:
- stage: command-and-control-asynchronous-shell
  status: covered
  steps:
  - powershell-async-shell
- stage: command-and-control-reverse-tunnel
  status: covered
  steps:
  - dns-c2-lead
  - python-tunnel-implant
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: execution-powershell-launcher
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: defense-evasion-dll-sideloading
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: defense-evasion-steganography
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: persistence-mechanisms
  status: out_of_scope
- reason: Belongs to another part of the 'TerminalFix campaign deploys a reverse tunnel
    through multistage intrusion' series.
  stage: discovery-domain-reconnaissance
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Reverse tunnels provide persistent, bypass-capable access to the
    internal network. Identifying these implants is critical for preventing lateral
    movement and data exfiltration after an initial social engineering compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established long-term C2 presence using a PowerShell file-watch
  loop for asynchronous command execution and a Python-based reverse tunnel for persistent
  network-level proxying.
labels:
- hunt
- attack.t1059.001
- attack.t1572
- attack.t1090.003
name: TerminalFix Asynchronous Shell and Reverse Tunnel
parameters:
  c2_domains:
    default:
    - gitnow.dev
    description: C2 domains observed in the TerminalFix campaign.
    from:
      kind: article
      observed: '2026-08-28'
      ref: msrc-blog-terminalfix
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
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
rationale: Target systems with recent suspicious software installations or those that
  triggered earlier ClickFix-related alerts. Focus on workstations where Windows Terminal
  or PowerShell is frequently used by non-admins.
references:
- name: 'MSRC Blog: TerminalFix campaign deploys a reverse tunnel through multistage
    intrusion'
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-initial-persistence
  reason: This hunt focuses on the C2 stage; persistence mechanisms via DLL sideloading
    and scheduled tasks are handled in the preceding hunt.
  relation: out-of-scope-alternative
- hunt: terminalfix-clickfix-delivery-reconnaissance
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Fake CAPTCHA
    observables:
    - Cloudflare Turnstile verification overlay
    - Verification command copied to clipboard
    - Instructions to open Windows Terminal or PowerShell
    - Fake Cloudflare-themed terminal output messages
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1204.001
  - name: Malicious PowerShell Launcher
    observables:
    - C:\ProgramData\f47f2a8c21c9df4e
    - 1.bat
    - ZIP archive download with custom User-Agent
    - 'I am not a robot - Cloudflare ID: f47f2a8c21c9df4e'
    slug: execution-powershell-launcher
    tactic: execution
    techniques:
    - T1059.001
    - T1105
  - name: DLL Sideloading via LockScreenContentServer
    observables:
    - LockScreenContentServer.exe
    - dui70.dll (unsigned, forged timestamp 2104)
    - LockScreenContentServer.exe loading dui70.dll from ProgramData
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
  - name: Steganographic Payload Extraction
    observables:
    - p1.png
    - p2.png
    - p3.png
    - gitnow.dev
    - Extract-RawFileFromImage PowerShell function
    - Reassembling DLL fragments from PNG pixel data
    slug: defense-evasion-steganography
    tactic: defense-evasion
    techniques:
    - T1027.003
  - name: Redundant Persistence
    observables:
    - LockScreenContentServer_MuODG5yBM
    - 'Registry Run Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    - Scheduled Task running every 60 minutes
    - attrib +h +s folder hiding on C:\ProgramData subfolders
    slug: persistence-mechanisms
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Extensive Domain Discovery
    observables:
    - nltest /domain_trusts
    - net group "domain admins" /domain
    - get-aduser
    - get-adcomputer
    - Ping sweeps of dc, db, backup, gateway, mail servers
    slug: discovery-domain-reconnaissance
    tactic: discovery
    techniques:
    - T1018
    - T1087.002
    - T1482
  - name: Asynchronous File-Watch Command Loop
    observables:
    - PowerShell file-watch loop monitoring text files
    - Invoke-Expression (IEX) on watched file content
    - Command output written to disk files
    slug: command-and-control-asynchronous-shell
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Reverse WebSocket Tunneling
    observables:
    - pythonw.exe
    - client.py
    - gitnow.dev:443
    - Reverse WebSocket tunnel providing SOCKS proxy access
    slug: command-and-control-reverse-tunnel
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  summary: The TerminalFix campaign employs fake Cloudflare CAPTCHA prompts to trick
    users into executing malicious PowerShell commands that initiate a multi-stage
    infection. The attack leverages DLL sideloading and steganography to deploy a
    persistent Python-based reverse tunnel, enabling attackers to conduct extensive
    Active Directory reconnaissance and maintain encrypted SOCKS-style proxy access
    to the victim's internal network.
series:
  index: 3
  slug: terminalfix-campaign-deploys-a-reverse-tunnel-through-multistage-intrusion
  title: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
  total: 3
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
tlp: clear
type: investigation
---


# TerminalFix Asynchronous Shell and Reverse Tunnel

The TerminalFix campaign establishes persistent control by deploying an asynchronous command shell and a reverse WebSocket tunnel. The command shell monitors a local text file using PowerShell's FileSystemWatcher and executes content via Invoke-Expression, while the reverse tunnel, typically a Python script named client.py running under pythonw.exe, connects to attacker infrastructure to provide proxy access. This hunt identifies the network lead for the C2 domain, then fanned-out searches for both the shell and the tunnel implant to settle on a per-host verdict.

## dns-c2-lead
<!-- DNS lookups for TerminalFix C2 domains -->
Identify hosts attempting to resolve the known C2 infrastructure used for reverse tunneling.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Specific hostnames resolving gitnow.dev. This indicates the reverse tunnel
  is likely active on those hosts.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## c2-parallel-checks
<!-- Parallel evidence gathering -->
parallel:
- → powershell-async-shell
- → python-tunnel-implant
join: → triage-c2-evidence

## powershell-async-shell
<!-- PowerShell file-watch command loop -->
Locate the script blocks responsible for monitoring a file and executing its contents, which forms the attacker's shell.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks showing FileSystemWatcher being initialized on a text file
  followed by Invoke-Expression (IEX).
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%filesystemwatcher%' AND LOWER(script_content) LIKE '%invoke-expression%' AND (LOWER(script_content) LIKE '%set-content%' OR LOWER(script_content) LIKE '%out-file%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## python-tunnel-implant
<!-- Python reverse tunnel processes -->
Find the specific Python runtime instances used to maintain the reverse WebSocket tunnel.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A pythonw.exe process running client.py, often from a hidden or non-standard
  directory like ProgramData.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%pythonw.exe%' AND LOWER(process_cmd_line) LIKE '%client.py%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-c2-evidence
<!-- Triage C2 evidence -->
```agent target=hunter
cite: required
context:
- dns-c2-lead
- powershell-async-shell
- python-tunnel-implant
max_iterations: 6
objective: Determine if any host shows confirmed TerminalFix command-and-control activity
  by combining the DNS, script activity, and process evidence.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  rows from all input steps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for at least one host, indicating an active reverse tunnel or command loop." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-logging)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke any active sessions for users logged into this host. Collect the client.py file and any monitored text files for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the Python process and PowerShell script activity to confirm the C2 nature; search for secondary implants or lateral movement from this host. Examine the text file content being watched for evidence of past commands.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no active command loops or reverse tunnels were found on the scoped hosts. Note any legitimate Python or FileSystemWatcher usage discovered for future tuning.
```
→ end
