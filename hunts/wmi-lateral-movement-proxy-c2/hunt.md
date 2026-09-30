---
analysis: A single rule on WMI execution or proxy DNS queries often generates high
  noise from administrative tools or browser extensions. This hunt uses a funnel flow
  to combine these signals, utilizing an agent to confirm the relationship between
  the execution lineage and the networking behavior before a decision is reached.
blind_spots:
- id: no-dns-process-correlation
  question: Which process initiated the proxy DNS query?
  requires: process context in hb_dns_activity
  risk: If the DNS source does not attribute queries to a PID, correlating the C2
    traffic to the WMI-spawned shell requires manual alignment of timestamps.
  stage: command-and-control-proxy
- id: dns-over-https-bypass
  question: Are proxy domains being resolved via DoH?
  requires: TLS inspection or endpoint DoH monitoring
  risk: Standard DNS logging cannot see proxy resolutions performed over encrypted
    HTTPS tunnels, leaving a gap in the network-side evidence.
  stage: command-and-control-proxy
coverage:
- stage: lateral-movement-wmi
  status: covered
  steps:
  - identify-windows-hosts
  - wmi-activity-search
- stage: command-and-control-proxy
  status: covered
  steps:
  - proxy-dns-search
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: WMI lateral movement is a core technique for internal propagation,
    and multi-hop proxies are used to bypass perimeter C2 blocks. Coordinating these
    independent signals across process and network surfaces provides a high-confidence
    indicator of an active intruder.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has moved laterally using WMI to execute code on internal
  Windows hosts and is maintaining command-and-control through multi-hop proxies or
  Tor to obfuscate traffic.
labels:
- hunt
- attack.t1047
- attack.t1090.003
name: WMI Lateral Movement and Proxy-based C2
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-01-01'
      ref: default-retention
    type: number
  proxy_indicators:
    default:
    - hiddenservice.net
    - onion.link
    - onion.cab
    - onion.casa
    description: Known domains associated with Tor or multi-hop proxy infrastructure.
    from:
      kind: article
      observed: '2026-07-31'
      ref: elastic-security-labs-agentic-soc
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the behavioral queries; empty checks
      all Windows hosts.
    from:
      kind: manual
      observed: '2025-01-01'
      ref: analyst-input
    type: list[host]
  suspicious_wmi_apps:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - scrcons.exe
    - cscript.exe
    - wscript.exe
    description: Standard shells or script engines often used by attackers via WMI.
    from:
      kind: article
      observed: '2026-07-31'
      ref: elastic-security-labs-agentic-soc
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/agentic-soc-alert-triage-alertzero
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes every Windows host because WMI lateral movement can target
  any system with RPC or WinRM enabled. The behavioral queries focus on the WMI provider
  (wmiprvse.exe), which is the standard host for remote-triggered execution.
references:
- name: 'Alert Zero: AI-driven alert triage and attack investigation for the agentic
    SOC'
  url: https://www.elastic.co/security-labs/blog/agentic-soc-alert-triage-alertzero
related:
- hunt: wmi-event-consumer-persistence
  reason: WMI event consumers represent a related persistence technique that uses
    the same infrastructure as this lateral movement hunt.
  relation: sibling
scenario:
  stages:
  - name: Lateral Movement via WMI
    observables:
    - wmic.exe
    - wmiprvse.exe
    - Process creation with parent wmiprvse.exe
    - Network connections on port 135, 5985, or 5986
    slug: lateral-movement-wmi
    tactic: execution
    techniques:
    - T1047
  - name: Multi-hop Proxy Command and Control
    observables:
    - DNS queries for .onion domains
    - DNS queries for hiddenservice.net
    - Traffic to known Tor entry/exit nodes
    - Chained proxy connection attempts
    slug: command-and-control-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This report details the implementation of AI-driven alert triage and attack
    investigation within a security operations center. It uses a scenario where an
    attacker leverages Windows Management Instrumentation (WMI) for lateral movement
    and multi-hop proxies for command and control to illustrate how automated agents
    can correlate disparate alerts into a single attack narrative.
severity: medium
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


# WMI Lateral Movement and Proxy-based C2

This hunt identifies the dual behavior of internal lateral movement via Windows Management Instrumentation (WMI) and external command-and-control (C2) obfuscation via multi-hop proxies. It begins by scoping the environment for Windows-based systems that could be targets of WMI execution. A fan-out investigation then searches for suspicious child processes of the legitimate WMI provider (wmiprvse.exe) while simultaneously identifying DNS resolutions for known proxy and Tor infrastructure. An agent weighs these signals together to identify the complete attack chain described in the Alert Zero research, specifically looking for process-level relationships between WMI execution and proxy networking.

## identify-windows-hosts
<!-- Identify Windows hosts -->
Identify every Windows system reporting inventory to focus the lateral movement search.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence indicates no Windows systems are reporting
  in the window.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE LOWER(platform) = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-behavior-hunt
<!-- Gather execution and network evidence -->
parallel:
- → wmi-activity-search
- → proxy-dns-search
join: → triage-findings

## wmi-activity-search
<!-- Suspicious WMI child processes -->
Identify instances where the WMI provider process (wmiprvse.exe) spawns shells, scripts, or binaries from non-system paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, suspicious_wmi_apps=suspicious_wmi_apps, scope_hosts=scope_hosts)
~~~yaml
expected: Processes spawned by WMI. Legitimate administrative tools may appear; rarity
  and command context are the primary signals.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- pid
- user_name
- time
- process_path
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, pid, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\\wmiprvse.exe' AND (instr(',' || '{{suspicious_wmi_apps}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_path) NOT LIKE 'c:\\windows\\system32\\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## proxy-dns-search
<!-- Proxy and Tor DNS prevalence -->
Find DNS resolutions for .onion domains or known proxy gateways and stack-count them to isolate rare outliers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, proxy_indicators=proxy_indicators, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS queries to proxy domains. Any hit on a host that also shows suspicious
  WMI activity is the primary indicator of the attack chain.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- pid
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT query_hostname, device_hostname, process_name, pid, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (query_hostname LIKE '%.onion' OR query_hostname LIKE '%.hiddenservice.net' OR instr(',' || '{{proxy_indicators}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname, device_hostname, process_name, pid
```

## triage-findings
<!-- Triage findings -->
```agent target=hunter
cite: required
context:
- wmi-activity-search
- proxy-dns-search
max_iterations: 4
objective: Correlate the process identity (PID or process name) from the DNS findings
  with the WMI child process tree to determine if the same lineage or user context
  is performing both lateral movement and external C2.
success_criteria: A verdict of malicious | suspicious | benign per host, citing matching
  PIDs or process names.
tools:
- endpoint
```

## verdict-decision
<!-- Verdict decision -->
if~: "the triage verdict is malicious for at least one host involving suspicious WMI execution and proxy DNS activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-process-correlation)
else: → close-out-task

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified as malicious and terminate the PIDs associated with the suspicious WMI activity and proxy connections.
```
→ analyst-review

## analyst-review
<!-- Analyst review and network pivot -->
```manual target=analyst
Review the cited rows from the triage step. Pivot to hb_network_connection to identify the source IP address that initiated the RPC (port 135) or WinRM (5985/5986) connection to the target host to find the upstream beachhead.
```
→ close-out-task

## close-out-task
<!-- Close out -->
```manual target=analyst
Document whether the activity represented a true positive intrusion. If the activity was legitimate administrative WMI use, record the specific process command lines to tune the detection candidate.
```
→ end
