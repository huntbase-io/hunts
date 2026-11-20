---
analysis: This hunt correlates the static state of a vulnerability with live behavioral
  egress telemetry and HTTP pattern matching across multiple surfaces. This provides
  a contextual picture of successful exploitation that a single rule cannot provide.
blind_spots:
- id: incomplete-appliance-telemetry
  question: whether SQL injection payloads were hidden in POST request bodies
  requires: Full HTTP request body logging
  risk: Attackers can bypass detections by placing SQL injection payloads in the POST
    body, which is not captured in hb_http_activity.
  stage: vulnerability-targeting-edge-appliances
- id: missing-endpoint-visibility
  question: whether the reverse shell binary was executed on the underlying appliance
    OS
  requires: hb_process_activity on the appliance OS
  risk: Appliances often do not support standard EDR agents, leaving OS-level execution
    invisible to endpoint surfaces.
  stage: vulnerability-targeting-edge-appliances
coverage:
- stage: vulnerability-targeting-edge-appliances
  status: covered
  steps:
  - identify-vulnerable-fortiweb
  - exploit-attempt-http
  - reverse-shell-egress
  - triage-verdict
- reason: 'Belongs to another part of the ''Break the silence: Kazakhstan-nexus UAT-6275
    targets CIS government organizations'' series.'
  stage: initial-access-lures-and-winrar-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''Break the silence: Kazakhstan-nexus UAT-6275
    targets CIS government organizations'' series.'
  stage: execution-powershell-payload-retrieval
  status: out_of_scope
- reason: 'Belongs to another part of the ''Break the silence: Kazakhstan-nexus UAT-6275
    targets CIS government organizations'' series.'
  stage: persistence-via-tasks-and-startup
  status: out_of_scope
- reason: 'Belongs to another part of the ''Break the silence: Kazakhstan-nexus UAT-6275
    targets CIS government organizations'' series.'
  stage: c2-reverse-shell-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Edge appliances are the primary entry points for UAT-6275. Unauthenticated
    SQL injection on a security appliance like FortiWeb represents a critical risk
    to perimeter security and facilitates further intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary targets internet-facing FortiWeb appliances using CVE-2025-25257
  to achieve initial access via SQL injection, followed by the deployment of a Linux-based
  reverse shell.
labels:
- hunt
- attack.t1190
- command and control
- execution
- initial access
- persistence
name: UAT-6275 FortiWeb Edge Appliance Exposure
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; if empty, all hosts are examined.
    type: list[host]
  target_cve:
    default: CVE-2025-25257
    description: The FortiWeb SQL injection CVE ID mentioned in the research.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on systems reporting CVE-2025-25257. If the scanner is unavailable,
  scope to all hostnames identified as 'Fortinet' or 'FortiWeb' in the software inventory.
references:
- name: "Cisco Talos \u2014 Break the silence: Kazakhstan-nexus UAT-6275 targets CIS\
    \ government organizations"
  url: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
related:
- hunt: uat-6275-windows-persistence-and-payloads
  reason: This hunt focuses on the appliance entry point; subsequent Windows-based
    persistence and PowerShell scripts are handled separately.
  relation: out-of-scope-alternative
- hunt: uat-6275-infection-lifecycle
  relation: follows
scenario:
  stages:
  - name: Malicious Lures and WinRAR Exploitation
    observables:
    - CVE-2025-8088
    - .rar archive
    - .doc (macro-enabled)
    - .lnk (shortcut file)
    slug: initial-access-lures-and-winrar-exploit
    tactic: initial-access
    techniques:
    - T1204.002
    - T1190
  - name: PowerShell and PS2EXE Execution
    observables:
    - powershell.exe
    - raw.githubusercontent.com
    - PS2EXE compiled executables
    - GitHub-hosted scripts
    slug: execution-powershell-payload-retrieval
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task and Startup Persistence
    observables:
    - schtasks.exe
    - PickleShell
    - Windows Startup folder
    - '%AppData%\Microsoft\Windows\Start Menu\Programs\Startup'
    slug: persistence-via-tasks-and-startup
    tactic: persistence
    techniques:
    - T1053.005
    - T1547.001
  - name: Interactive Command and Control
    observables:
    - PickleShell
    - Chvost
    - Laplas
    - custom reverse shells
    slug: c2-reverse-shell-deployment
    tactic: command-and-control
    techniques:
    - T1059
  - name: Internet-Facing Appliance Targeting
    observables:
    - CVE-2025-25257
    - FortiWeb SQL Injection PoC
    - Linux-compatible reverse shell tools
    slug: vulnerability-targeting-edge-appliances
    tactic: initial-access
    techniques:
    - T1190
  summary: UAT-6275 (also known as TAG-193) targets government entities in the CIS
    region using diverse infection vectors including macro-enabled documents, PowerShell
    downloaders, and a WinRAR path traversal exploit (CVE-2025-8088). The campaign
    deploys custom reverse shells such as PickleShell, Chvost, and Laplas, securing
    long-term access through Scheduled Tasks and Windows Startup folder persistence.
series:
  index: 2
  slug: break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations
  title: 'Break the silence: Kazakhstan-nexus UAT-6275 targets CIS government organizations'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# UAT-6275 FortiWeb Edge Appliance Exposure

This hunt examines the organization's external attack surface for vulnerable Fortinet appliances targeted by UAT-6275. The hunt first identifies systems reporting CVE-2025-25257 and maps them to hostnames. An analyst then uses these hostnames to focus behavioral queries on incoming HTTP requests containing SQL injection patterns and anomalous outbound network connections. An agent evaluates these disparate signals to determine if a vulnerable appliance has been successfully compromised.

## identify-vulnerable-fortiweb
<!-- Identify vulnerable FortiWeb appliances -->
Find all systems currently reporting the target CVE and retrieve their hostnames for scoping.

```sqlite target=endpoint role=scoping params=(target_cve=target_cve)
~~~yaml
expected: A list of hostnames reporting the CVE. Silence proves no systems are currently
  flagged with this vulnerability in the scanner.
reads:
- resource_uid
- device_uid
- cve_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT f.resource_uid, d.hostname AS device_hostname, f.cve_uid, f.severity FROM hb_vulnerability_finding f JOIN hb_devices d ON f.device_uid = d.device_uid WHERE f.cve_uid = '{{target_cve}}' AND f.status != 'suppressed'
```

## telemetry-fan-out
<!-- Correlate HTTP and Network activity -->
parallel:
- → exploit-attempt-http
- → reverse-shell-egress
join: → triage-verdict

## exploit-attempt-http
<!-- HTTP SQL injection patterns -->
Identify inbound HTTP requests containing SQL injection markers targeting appliances in scope.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Requests with SQL keywords or non-alphanumeric markers that resulted in
  successful processing or server errors. Silence suggests the WAF or appliance blocked
  the attempts.
reads:
- device_hostname
- url_path
- url_query
- src_endpoint_ip
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, url_path, url_query, src_endpoint_ip, status_code, time FROM hb_http_activity WHERE (LOWER(url_query) LIKE '%select%' OR LOWER(url_query) LIKE '%union%' OR LOWER(url_query) LIKE '%sleep(%' OR url_query LIKE '%''%' OR url_query LIKE '%--%' OR url_query LIKE '%/*%') AND status_code IN (200, 500) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## reverse-shell-egress
<!-- Reverse shell egress from appliances -->
Find outbound network connections from scoped appliances to non-standard ports, signaling potential reverse shell activity.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to rare external IPs or high ports, excluding standard management
  and monitoring ports. Outbound traffic to non-standard ports is the primary indicator
  of a shell.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as conn_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND dst_endpoint_port NOT IN (80, 443, 53, 514, 541) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port
```

## triage-verdict
<!-- Triage appliance compromise -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-fortiweb
- exploit-attempt-http
- reverse-shell-egress
max_iterations: 3
objective: Determine if a vulnerable FortiWeb appliance has been exploited based on
  HTTP SQLi strings and rare outbound network connections.
success_criteria: A verdict of malicious | suspicious | benign for each host in the
  scope.
tools:
- endpoint
- network
- web
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: medium, judge=hunter)
then: → isolate-device
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: incomplete-appliance-telemetry)
else: → forensic-review

## isolate-device
<!-- Isolate appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the FortiWeb appliance at the firewall or through the management console. Revoke any associated cloud service roles.
```
→ forensic-review

## forensic-review
<!-- Forensic review -->
```manual target=analyst
Inspect native appliance logs for specific SQL injection payloads not visible in query strings. Review the file system for reverse shell binaries or modified scripts and verify the integrity of application files.
```
→ remediation-closeout

## remediation-closeout
<!-- Remediation and closeout -->
```manual target=analyst
Apply security patches to FortiWeb appliances to address CVE-2025-25257. Update the vulnerability management status and archive the hunt results.
```
→ end
