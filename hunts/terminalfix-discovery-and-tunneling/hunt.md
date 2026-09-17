---
analysis: "While a rule can catch 'nltest' or a specific domain, this hunt correlates\
  \ the windowless Python process with its parentage, stack-counts the reconnaissance\
  \ commands to find anomalous bursts, and joins these to the established WebSocket\
  \ socket\u2014a holistic approach that a single rule cannot perform without high\
  \ false-positive rates."
blind_spots:
- id: blind-to-non-agent-hosts
  owner: IT Infrastructure
  question: Are there unmanaged hosts in the network serving as the reverse tunnel
    pivot?
  remediation: Validate agent coverage across the entire estate and remediate gaps.
  requires: hb_devices and hb_process_activity
  risk: A host without the endpoint agent could maintain the tunnel and perform reconnaissance
    invisibly to this hunt.
  stage: reverse-tunnel-deployment
- id: websocket-payload-encryption
  owner: Network Security
  question: What specifically is being tunneled through the WebSocket?
  remediation: Deploy TLS inspection on outbound traffic to non-reputable domains.
  requires: TLS Inspection / Proxy Logs
  risk: We can see the tunnel existence (network flow) but cannot see the individual
    commands or exfiltrated data within the encrypted channel.
  stage: reverse-tunnel-deployment
coverage:
- stage: internal-reconnaissance
  status: covered
  steps:
  - recon-activity
- stage: reverse-tunnel-deployment
  status: covered
  steps:
  - scoping-python-runtime
  - dns-to-c2
  - network-tunnel-established
- reason: Handled by the first hunt in the series focusing on social engineering and
    initial PowerShell execution.
  stage: initial-access-clipboard-captcha
  status: out_of_scope
- reason: Handled by the first hunt in the series focusing on LockScreenContentServer
    sideloading.
  stage: payload-delivery-sideloading
  status: out_of_scope
- reason: Handled by the second hunt in the series focusing on file-system activity
    and PNG extraction.
  stage: steganographic-extraction
  status: out_of_scope
- reason: Handled by the second hunt in the series focusing on Registry Run keys and
    Scheduled Tasks.
  stage: persistence-establishment
  status: out_of_scope
- reason: Handled by the second hunt in the series focusing on file-watch loops.
  stage: asynchronous-command-loop
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Reverse tunnels provide persistent network access that bypasses firewalls
    and survives identity-based controls. Detecting this and the internal reconnaissance
    phase is critical to stopping lateral movement before attackers reach high-value
    assets like Domain Controllers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is conducting Active Directory reconnaissance and establishing
  a reverse WebSocket tunnel using a windowless Python interpreter after a multistage
  intrusion.
labels:
- hunt
- attack.t1090.003
- attack.t1059.001
- attack.t1572
- attack.t1041
- attack.t1018
- attack.t1087.002
name: 'TerminalFix: Domain Discovery and Reverse Tunneling'
parameters:
  c2_domains:
    default:
    - gitnow.dev
    description: Reverse tunnel C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-08-29'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-29'
      ref: hunt-standard
    type: number
  recon_tools:
    default:
    - nltest.exe
    - net.exe
    - net1.exe
    - ping.exe
    description: Names of reconnaissance and administration tools used in the campaign.
    from:
      kind: article
      observed: '2026-08-29'
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
    - design-checks
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should be prioritized for domain-joined Windows endpoints. Python
  interpreters running in user-writable paths or with non-standard parents (like LockScreenContentServer.exe)
  are the primary indicators.
references:
- name: TerminalFix campaign deploys a reverse tunnel through multistage intrusion
  url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
related:
- hunt: terminalfix-initial-sideloading-persistence
  reason: Initial access, sideloading, and establishing persistence are covered in
    a previous hunt in this series.
  relation: out-of-scope-alternative
- hunt: terminalfix-steganography-and-payloads
  reason: The steganographic extraction of payloads from PNG files is a specialized
    behavioral hunt handled separately.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Socially engineered clipboard execution
    observables:
    - Fake Cloudflare Turnstile CAPTCHA overlay
    - PowerShell command copied to clipboard and pasted by user
    - 'Terminal output: Starting Cloudflare verification...'
    - 'Terminal output: I am not a robot - Cloudflare ID: f47f2a8c21c9df4e'
    slug: initial-access-clipboard-captcha
    tactic: initial-access
    techniques:
    - T1059.001
    - T1115
  - name: DLL sideloading via LockScreenContentServer
    observables:
    - C:\ProgramData\f47f2a8c21c9df4e
    - 1.bat
    - LockScreenContentServer.exe
    - dui70.dll (unsigned, forged timestamp 2104)
    - 'SHA-256: 18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f'
    slug: payload-delivery-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.001
    - T1574.002
  - name: Steganographic payload retrieval
    observables:
    - POST requests to attacker domains for PNG files
    - 'PowerShell function: Extract-RawFileFromImage'
    - Decoding RGBA pixel data to reconstruct executables and DLLs
    slug: steganographic-extraction
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Redundant persistence configuration
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockScreenContentServer_MuODG5yBM
    - 'Scheduled task: LockScreenContentServer_MuODG5yBM'
    - 'Task frequency: every 60 minutes'
    - 'Hidden folder attributes: attrib +s +h'
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Active Directory and infrastructure discovery
    observables:
    - nltest /domain_trust
    - net group "domain admins" /domain
    - Get-ADUser
    - Get-ADComputer
    - Ping sweeps of dc, sql, db, backup, gateway, and mail servers
    slug: internal-reconnaissance
    tactic: discovery
    techniques:
    - T1059.001
  - name: File-based C2 command loop
    observables:
    - PowerShell file-watch loop on local text file
    - Invoke-Expression (IEX) execution of file contents
    - Command results written to output text file
    slug: asynchronous-command-loop
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Reverse WebSocket SOCKS tunnel
    observables:
    - pythonw.exe
    - client.py
    - gitnow.dev:443
    - Encrypted WebSocket channel for TCP proxy access
    slug: reverse-tunnel-deployment
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
    - T1041
  summary: The TerminalFix campaign utilizes fake Cloudflare CAPTCHA prompts to trick
    users into executing PowerShell scripts that download and sideload a malicious
    DLL. The intrusion leverages steganography within PNG files to deliver a second-stage
    payload, establishes persistent network access via Registry Run keys and scheduled
    tasks, and deploys a Python-based reverse tunnel for internal network proxying
    and reconnaissance.
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


# TerminalFix: Domain Discovery and Reverse Tunneling

This hunt targets the final stages of the TerminalFix campaign, focusing on the deployment of a Python-based reverse tunnel and subsequent internal reconnaissance. The attacker utilizes pythonw.exe to establish an encrypted WebSocket channel to attacker-controlled infrastructure (gitnow.dev), providing SOCKS-style proxy access. Once established, the adversary performs discovery on domain trusts, administrative groups, and pings critical servers such as domain controllers and databases. We look for the presence of the windowless Python interpreter, network connections to known C2 over port 443, and the execution of AD enumeration tools, specifically checking for processes with unusual parentage or those running from memory.

## scoping-python-runtime
<!-- Hidden Python interpreter execution -->
Identify hosts running the pythonw.exe interpreter or the sideloading host (LockScreenContentServer.exe), which are the prerequisites for the reverse tunnel.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts running the windowless Python interpreter or the specific sideloading
  binary. Zero rows mean no such processes were observed.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- on_disk
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, on_disk, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%pythonw.exe%' OR LOWER(process_name) LIKE '%lockscreencontentserver.exe%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-telemetry
<!-- Corroborate Network and Process Evidence -->
parallel:
- → recon-activity
- → dns-to-c2
- → network-tunnel-established
join: → triage-agent

## recon-activity
<!-- Reconnaissance and Infrastructure Discovery -->
Detect domain discovery tools and ping sweeps targeting critical infrastructure roles (dc, sql, db, backup, etc.) as described in the campaign.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, recon_tools=recon_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unusual bursts of reconnaissance commands per host. Baseline counts will
  help distinguish regular admin activity from the automated sweep.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: none
~~~
SELECT device_hostname, process_name, process_cmd_line, COUNT(*) as cmd_count, MIN(time) as first_seen FROM hb_process_activity WHERE (instr(',' || '{{recon_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{recon_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND (process_cmd_line LIKE '%/domain%' OR process_cmd_line LIKE '%domain admins%' OR process_cmd_line LIKE '%dc%' OR process_cmd_line LIKE '%sql%' OR process_cmd_line LIKE '%backup%' OR process_cmd_line LIKE '%gateway%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line
```

## dns-to-c2
<!-- DNS Activity for Tunnel C2 -->
Find DNS resolution of the campaign's C2 domain gitnow.dev, which facilitates the WebSocket tunnel.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Direct match for the campaign's C2 domain. Silence confirms only the absence
  of this specific domain, not the absence of the tunnel technique.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: none
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-tunnel-established
<!-- Reverse WebSocket Tunnel Connections -->
Identify established outbound connections from the Python interpreter to port 443, representing the active reverse tunnel.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A long-lived socket from a windowless Python process to an external IP on
  443. This is a high-fidelity behavioral indicator.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- connection_state
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: none
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, connection_state, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%pythonw.exe%' AND dst_endpoint_port = 443 AND connection_state = 'ESTABLISHED' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Evaluate Campaign Convergence -->
```agent target=hunter
cite: required
context:
- scoping-python-runtime
- recon-activity
- dns-to-c2
- network-tunnel-established
max_iterations: 5
objective: Determine if any host exhibits both the windowless Python reverse tunnel
  and the systematic ping/reconnaissance patterns described in the campaign. Cite
  rows linking the process to the network and command activity.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing evidence
  for every malicious claim.
tools:
- endpoint
- network
```

## routing
<!-- Route Based on Verdict -->
if~: "the triage verdict is malicious for one or more hosts with an active network tunnel" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-verification
unavailable: → analyst-verification (blind_spot: blind-to-non-agent-hosts)
else: → close-out

## isolate-host
<!-- Isolate Compromised Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Kill the suspected pythonw.exe and LockScreenContentServer.exe processes. Collect the content of C:\ProgramData subfolders for forensic analysis.
```
→ analyst-verification

## analyst-verification
<!-- Manual Analyst Review -->
```manual target=analyst
Review the identified reconnaissance tools and target ping patterns. Check hb_auth_signin for unusual logons from the compromised host to internal servers (DCs, SQL) that match the ping sweep targets.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Ensure all compromised hosts are remediated and persistence mechanisms (tasks/registry) are removed. Document any newly discovered C2 domains for blocklist updates.
```
→ end
