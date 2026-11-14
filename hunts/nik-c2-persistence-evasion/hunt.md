---
analysis: While a rule can alert on svchost.exe in a user path, this hunt connects
  initialization (watchdog arguments), fleet rarity (baseline), and persistence (Registry
  Run keys) into a single narrative to distinguish the full NIK C2 lifecycle from
  isolated dropper events.
blind_spots:
- id: no-process-ancestry
  question: whether the implant was launched by a specific web shell or phishing document
  requires: hb_process_activity with parent command line history
  risk: Identifying the implant but missing the initial delivery vector if it was
    exploit-driven.
  stage: execution-and-initial-setup
- id: no-network-listener-scoping
  question: whether the implant's proxy listener is active on specific scoped hosts
  requires: hb_network_listener with device_hostname
  risk: The hb_network_listener surface lacks a hostname column, preventing precise
    multi-host correlation for the lateral movement module.
  stage: lateral-movement-and-pivoting
coverage:
- stage: execution-and-initial-setup
  status: covered
  steps:
  - scope-hosts-with-profile-binaries
  - watchdog-monitoring
- stage: persistence-and-defense-evasion
  status: covered
  steps:
  - rare-profile-binaries
  - persistence-lifecycle
- blind_spot: no-network-listener-scoping
  reason: The hb_network_listener surface lacks device_hostname, making it impossible
    to scope proxy listeners to the hosts identified in this hunt.
  stage: lateral-movement-and-pivoting
  status: not_visible
- reason: Ransomware impact is the final stage; this hunt aims for early detection
    and isolation before encryption occurs.
  stage: ransomware-impact
  status: not_visible
- reason: 'Belongs to another part of the ''NIK C2: The new AI-enabled command-and-control
    framework'' series.'
  stage: credential-access-and-surveillance
  status: out_of_scope
- reason: 'Belongs to another part of the ''NIK C2: The new AI-enabled command-and-control
    framework'' series.'
  stage: c2-and-ai-integration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: NIK C2 collapses the delay between data collection and exploitation
    by using integrated AI models. Detecting its persistent footprint is critical
    to stopping the session before it transitions to screen-lock ransomware impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established persistence for the NIK C2 implant by placing
  masqueraded binaries in user profile paths and creating Registry Run keys to maintain
  an AI-augmented remote access session.
labels:
- hunt
- attack.t1547.001
- attack.t1036.005
- attack.t1021.001
- attack.t1572
- attack.t1055.012
- attack.t1486
- command and control
- credential access
- defense evasion
- execution
- impact
- lateral movement
name: 'NIK C2: Host Persistence and Evasion'
parameters:
  implant_masquerade_names:
    default:
    - svchost.exe
    - simvol.exe
    description: Binary names the implant uses to masquerade as system processes.
    from:
      kind: article
      observed: '2026-10-29'
      ref: talos-nik-c2
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  persistence_path:
    default: \AppData\Roaming\Microsoft\Network
    description: The specific subdirectory used by NIK C2 for persistence; literal
      path found in telemetry.
    from:
      kind: article
      observed: '2026-10-29'
      ref: talos-nik-c2
    type: string
  scope_hosts:
    default: []
    description: Target specific hosts identified in the scoping step; leave empty
      to hunt across the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Begin by examining hosts where binaries run from AppData/Roaming or Users/Public.
  NIK C2 relies on sub-paths like Microsoft\Network and masqueraded names like svchost.exe.
  Use the persistence_path parameter to match sub-folders found in your telemetry.
references:
- name: "Cisco Talos \u2014 NIK C2: The new AI-enabled command-and-control framework"
  url: https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
related:
- hunt: nik-c2-credential-and-ai-surveillance
  reason: This hunt focuses on persistence and evasion; surveillance and AI-driven
    theft commands are handled in a separate network-centric hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Implant Execution and Initialization
    observables:
    - Go-based 64-bit Windows binary
    - watchdog
    - copywatchdog
    - '[NIK] Starting'
    - PID file in temporary application folder
    - Named mutex for single-instance execution
    slug: execution-and-initial-setup
    tactic: execution
    techniques:
    - T1059
  - name: Persistence and Defense Evasion
    observables:
    - '%appdata%/Roaming/Microsoft/Network'
    - svchost.exe
    - simvol.exe
    - Nov 29, 1979 (Zeroed PE TimeDateStamp)
    - Registry Run keys
    - Process hollowing
    - Watchdog process monitoring
    slug: persistence-and-defense-evasion
    tactic: defense-evasion
    techniques:
    - T1547.001
    - T1055.012
    - T1036.005
    - T1070.006
  - name: Credential Access and Surveillance
    observables:
    - netsh wlan show profile
    - Browser SQLite database access (cookies, passwords, autofill)
    - Keylogger buffer dumps
    - Clipboard interception
    - Camera and microphone streaming
    - Discord tokens
    - Crypto wallet databases
    slug: credential-access-and-surveillance
    tactic: credential-access
    techniques:
    - T1003
    - T1056.001
    - T1555
    - T1115
    - T1125
  - name: Lateral Movement and Pivoting
    observables:
    - RDP session interaction
    - SOCKS5/HTTP Proxy listener
    - Reverse proxy tunnel for LAN pivoting
    slug: lateral-movement-and-pivoting
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1572
  - name: C2 Communications and AI Integration
    observables:
    - total-sitevv.lol
    - 87.120.196.120
    - api.openai.com/v1/chat/completions
    - Port 443 WebSockets
    - 250ms HTTP polling interval
    - OPENAI_API_KEY environment variable access
    - gpt-4
    - ai_generate command
    slug: c2-and-ai-integration
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1572
  - name: Screen-Lock Ransomware Impact
    observables:
    - Screen-locking module
    - Ransom demand for Bitcoin or USDT
    slug: ransomware-impact
    tactic: impact
    techniques:
    - T1486
  summary: NIK C2 is a Go-based Windows implant that uses a dual-channel C2 architecture
    over WebSockets and HTTP fallbacks to maintain persistent control. The framework
    notably integrates the OpenAI API directly through the victim host to analyze
    stolen data and orchestrate commands, while also supporting credential theft,
    hidden VNC, and screen-locking ransomware.
series:
  index: 1
  slug: nik-c2-the-new-ai-enabled-command-and-control-framework
  title: 'NIK C2: The new AI-enabled command-and-control framework'
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
tlp: clear
type: investigation
---


# NIK C2: Host Persistence and Evasion

This hunt targets the endpoint footprint of the NIK C2 implant, specifically its use of system process masquerading (svchost.exe, simvol.exe) and its watchdog supervisor routine. The hunt follows a phased flow: first, it identifies hosts with rare binaries in user-writable paths and checks for the implant's specific command-line arguments. Second, it corroborates these findings with Registry-based persistence mechanisms. Finally, an agent synthesizes the evidence to confirm the full malware lifecycle before an analyst takes action to prevent ransomware impact.

## scope-hosts-with-profile-binaries
<!-- Identify hosts with profile-path execution -->
Find hosts where processes are running from user profile paths matching the specific folder named in research.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, persistence_path=persistence_path)
~~~yaml
expected: Rows identify hosts and paths where binaries execute from the targeted Network
  directory. Silence proves these specific paths are clear.
reads:
- device_hostname
- process_cmd_line
- process_path
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, process_path, process_cmd_line, COUNT(*) AS execution_count FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\appdata\roaming\%') AND LOWER(process_path) LIKE '%' || LOWER('{{persistence_path}}') || '%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_path, process_cmd_line
```

## beachhead-analysis
<!-- Analyze beachhead behaviour and prevalence -->
parallel:
- → watchdog-monitoring
- → rare-profile-binaries
join: → triage-beachhead

## watchdog-monitoring
<!-- Detect watchdog supervisor arguments -->
Find the specific Go-based watchdog tokens used by NIK C2 to monitor its masqueraded process.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, implant_masquerade_names=implant_masquerade_names, scope_hosts=scope_hosts)
~~~yaml
expected: A masqueraded process running with supervisor arguments. This is a high-fidelity
  indicator of NIK C2.
reads:
- device_hostname
- process_cmd_line
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%watchdog%' OR LOWER(process_cmd_line) LIKE '%copywatchdog%') AND (instr(',' || '{{implant_masquerade_names}}' || ',', ',' || LOWER(replace(process_path, rtrim(process_path, replace(process_path, '\', '')), '')) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-profile-binaries
<!-- Which profile binaries are rare -->
Stack-count profile binaries across the fleet so the implant stands out from normal updaters.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries seen on only one or two hosts in the entire estate. Genuine system
  binaries should never appear here.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\roaming\%' OR LOWER(process_path) LIKE '%\users\public\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts < 3 ORDER BY hosts, runs
```

## triage-beachhead
<!-- Weigh beachhead evidence -->
```agent target=hunter
cite: required
context:
- scope-hosts-with-profile-binaries
- watchdog-monitoring
- rare-profile-binaries
max_iterations: 6
objective: Identify hosts that show strong evidence of NIK C2 implant initialization
  and masquerading.
success_criteria: A list of hosts and their respective verdicts based on the provided
  telemetry.
tools:
- endpoint
```

## persistence-lifecycle
<!-- Detect Registry Run key persistence -->
Find the registry entries the implant creates to survive reboots, corroborating the earlier beachhead findings.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, implant_masquerade_names=implant_masquerade_names, scope_hosts=scope_hosts)
~~~yaml
expected: Registry writes to Run keys pointing at binaries in user profiles or masqueraded
  system names. This confirms the persistence phase.
reads:
- device_hostname
- process_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, reg_target, reg_value_data, process_name, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\currentversion\run%' AND (LOWER(reg_value_data) LIKE '%\appdata\roaming\%' OR instr(',' || '{{implant_masquerade_names}}' || ',', ',' || LOWER(replace(reg_value_data, rtrim(reg_value_data, replace(reg_value_data, '\', '')), '')) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-lifecycle
<!-- Consolidate NIK C2 lifecycle -->
```agent target=hunter
cite: required
context:
- triage-beachhead
- persistence-lifecycle
max_iterations: 6
objective: Determine if the evidence across multiple stages (initialization and persistence)
  confirms an active NIK C2 infection.
success_criteria: A per-host verdict (malicious | suspicious | benign) citing rows
  from both early and follow-on stages.
tools:
- endpoint
```

## route-infection
<!-- Route based on verdict -->
if~: "the triage-lifecycle verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: no-process-ancestry)
else: → hunt-closure

## isolate-endpoint
<!-- Isolate the compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Collect the binary from the AppData/Roaming/Microsoft/Network path and the PID file from the temp directory for digital forensics.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Analyst forensic review -->
```manual target=analyst
Review the isolated host's network connections to api.openai.com. Analyze the content of the PID file found in the temp directory. Check for browser credential dumping or Discord token access as reported in the NIK C2 framework.
```
→ end

## hunt-closure
<!-- Hunt closure and documentation -->
```manual target=analyst
Summarize the hosts examined and confirm the absence of NIK C2 persistence artifacts in the scoped profiles. Document any false positives related to legitimate updaters in user paths.
```
→ end
