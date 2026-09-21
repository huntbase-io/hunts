---
analysis: While individual rules might flag AI domains or high file activity, this
  hunt uses the agent to correlate them by process ID and temporal proximity, significantly
  reducing false positives in environments with legitimate automation.
blind_spots:
- id: limited-file-telemetry
  question: Which specific files were renamed to ransomware extensions?
  requires: hb_file_activity with file extension capture
  risk: The hunt detects the activity volume but cannot identify the specific ransomware
    family without file extensions.
  stage: ransomware-data-encryption
- id: no-auth-context
  question: Which user credentials were used to move laterally to host-314?
  requires: hb_auth_signin
  risk: We see the result of lateral movement but miss the credential theft event
    that enabled it.
  stage: credential-access-and-lateral-movement
coverage:
- stage: credential-access-and-lateral-movement
  status: covered
  steps:
  - scoping-lead
- stage: exfiltration-over-c2
  status: covered
  steps:
  - network-exfil-to-ai
- stage: ransomware-data-encryption
  status: covered
  steps:
  - file-impact-burst
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries often use AI tools to process or exfiltrate stolen data
    before executing ransomware. This hunt identifies that transition point to prevent
    operational impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a beachhead, moved laterally to host-314,
  exfiltrated data via Node.js to an AI service, and initiated ransomware encryption.
labels:
- hunt
- attack.t1003
- attack.t1021
- attack.t1041
- attack.t1486
name: Multi-Stage Intrusion and Ransomware Triage
parameters:
  exfil_domains:
    default:
    - claude.ai
    - anthropic.com
    description: Domains associated with AI tools used for data exfiltration.
    from:
      kind: article
      observed: '2026-05-12'
      ref: elastic-security-mcp-app
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for intrusion signals.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Paste hostnames from the scoping step here to narrow the parallel
      hunt.
    from:
      kind: manual
      observed: '2026-05-12'
      ref: scoping-parameter
    type: list[host]
  suspicious_binaries:
    default:
    - node
    - node.exe
    - mimikatz.exe
    - psexec.exe
    description: Binaries associated with Node.js exfiltration and lateral movement.
    from:
      kind: article
      observed: '2026-05-12'
      ref: elastic-security-mcp-app
    type: list[path]
  target_host:
    default: host-314
    description: The specific host identified in initial alert triage.
    from:
      kind: article
      observed: '2026-05-12'
      ref: elastic-security-mcp-app
    type: host
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/elastic-security-mcp-app
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with host-314. Expand the hunt to any host where the specified lateral
  movement or exfiltration tools are running from rare paths or by non-admin users.
references:
- name: "Elastic Security Labs \u2014 Elastic Security MCP App"
  url: https://www.elastic.co/security-labs/blog/elastic-security-mcp-app
related:
- hunt: node-js-reverse-shell
  reason: The Node.js activity could also indicate a reverse shell rather than exfiltration;
    that requires process-to-network correlation on socket state.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Credential Access and Lateral Movement
    observables:
    - credential theft
    - lateral movement
    - host-314
    - process tree
    slug: credential-access-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1003
    - T1021
  - name: Exfiltration over C2
    observables:
    - data exfiltration
    - node.js
    - claude.ai
    - network events
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Data Encryption
    observables:
    - ransomware
    - file system activity
    - alert triage
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: A multi-stage campaign involving credential theft and lateral movement
    leading to data exfiltration and a final ransomware impact. The intrusion is monitored
    and triaged through an AI-integrated security operations workflow using the Elastic
    Security MCP App.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Multi-Stage Intrusion and Ransomware Triage

This hunt identifies multi-stage activity starting from a known compromised host. It uses process telemetry to scope the intrusion, then fans out to detect data exfiltration to AI services and high-volume file modifications. An agent correlates these signals to confirm if a coordinated attack chain exists, specifically linking the network activity of Node.js to the file system impact of encryption.

## scoping-lead
<!-- Scope host and suspicious tool activity -->
Identify hosts running tools associated with exfiltration or the primary target host.

```sqlite target=endpoint role=scoping params=(target_host=target_host, suspicious_binaries=suspicious_binaries, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and process names. Silence suggests the named host and suspicious
  tools have been inactive.
reads:
- device_hostname
- process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, process_name, user_name, time FROM hb_process_activity WHERE (LOWER(device_hostname) = LOWER('{{target_host}}') OR instr(',' || '{{suspicious_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## fan-out-evidence
<!-- Fan out for exfiltration and impact -->
parallel:
- → network-exfil-to-ai
- → file-impact-burst
join: → agent-triage

## network-exfil-to-ai
<!-- Data exfiltration to AI services -->
Identify processes communicating with AI domains identified in the research.

```sqlite target=network role=detection-candidate params=(scope_hosts=scope_hosts, exfil_domains=exfil_domains, lookback_days=lookback_days)
~~~yaml
expected: Connections from internal processes to AI domains. Silence indicates no
  direct communication to the named domains occurred.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_hostname
```

## file-impact-burst
<!-- Ransomware encryption burst activity -->
Identify processes modifying a high volume of files in a short window.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process performing over 100 updates or renames within one hour. Silence
  confirms no high-speed file impact occurred.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- activity_id
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, STRFTIME('%Y-%m-%d %H', time) AS hour_window, COUNT(*) AS file_ops, MIN(time) AS first_op FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (3, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, hour_window HAVING file_ops > 100
```

## agent-triage
<!-- Correlate exfiltration and impact -->
```agent target=hunter
cite: required
context:
- scoping-lead
- network-exfil-to-ai
- file-impact-burst
max_iterations: 3
objective: Decide whether the process activity on the scoped hosts indicates a coordinated
  intrusion. Determine if the process performing exfiltration to AI domains is also
  the one responsible for the ransomware-like file burst.
success_criteria: A per-host verdict of malicious, suspicious, or benign with cited
  evidence.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route on agent verdict -->
if~: "the agent verdict is malicious for at least one host based on the correlation of exfiltration and ransomware activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: limited-file-telemetry)
else: → analyst-validation

## isolate-host
<!-- Isolate the host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the management console and invalidate all active user sessions associated with the compromised account.
```
→ analyst-validation

## analyst-validation
<!-- Validate intrusion timeline -->
```manual target=analyst
Review the parent process for the suspicious binaries. Confirm which directory paths were targeted by the file burst and assess the sensitivity of data exfiltrated to the AI service.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the exfiltration destination and process names for the permanent blocklist. Evaluate if the file burst threshold needs tuning for different server roles.
```
→ end
