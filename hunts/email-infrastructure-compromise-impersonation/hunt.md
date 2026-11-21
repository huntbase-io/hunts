---
analysis: A single rule could detect one of these CVEs, but this hunt correlates vulnerability
  status with authentication anomalies, filesystem persistence, and root-level cron
  execution across multiple surfaces, providing the context necessary to confirm a
  full compromise.
blind_spots:
- id: missing-appliance-access-logs
  owner: Infrastructure Team
  question: whether the specific SaveDraftRequest or MRS payload was delivered
  remediation: Enable and ingest raw appliance access logs into the centralized logging
    platform.
  requires: detailed HTTP access logs from the appliance exported to hb_http_activity
  risk: Proprietary appliances may not export full URL paths or headers by default,
    making it difficult to distinguish exploit traffic from legitimate SOAP requests.
  stage: initial-access-appliance-exploit
- id: ephemeral-script-execution
  owner: Security Engineering
  question: what code the core_watch.sh script executed before it was potentially
    reverted
  remediation: Deploy osquery or a similar auditing agent to all network appliances.
  requires: real-time process auditing on the appliance endpoint
  risk: If auditing is not enabled on the appliance itself, the transient execution
    of a malicious script may leave no trace in the centralized logs.
  stage: execution-via-cron-job
coverage:
- stage: initial-access-appliance-exploit
  status: covered
  steps:
  - scoping-vulnerable-appliances
  - zimbra-auth-anomalies
  - appliance-exploit-request-paths
- stage: persistence-via-script-overwrite
  status: covered
  steps:
  - cisco-seg-script-overwrite
- stage: execution-via-cron-job
  status: covered
  steps:
  - cron-driven-script-execution
- stage: identity-boundary-bypass
  status: covered
  steps:
  - appliance-exploit-request-paths
  - evaluate-early-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromise of email gateways allows for RCE and silent impersonation,
    bypassing traditional identity controls and enabling large-scale spear-phishing
    or data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited vulnerabilities in Zimbra, Cisco Secure Email
  Gateway, or BeyondTrust to achieve remote code execution and persistent access through
  script overwrites and identity boundary bypasses.
labels:
- hunt
- attack.t1190
- attack.t1053.003
- attack.t1021.001
- execution
- initial access
- lateral movement
- persistence
name: Email Infrastructure Compromise and Impersonation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to restrict queries; leave empty to scan the full estate.
    type: list[host]
  target_cves:
    default:
    - CVE-2026-73571
    - CVE-2026-93637
    - CVE-2026-76519
    - CVE-2026-76461
    - CVE-2026-102764
    - CVE-2024-25420
    description: CVE IDs associated with appliance exploits.
    from:
      kind: article
      observed: '2026-11-20'
      ref: Rapid7 Research
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize internet-facing Zimbra servers and Cisco Secure Email Gateways.
  Use the scoping query to populate scope_hosts for behavioural queries.
references:
- name: 'Metasploit Wrap Up: Breaking Zimbra''s Identity Boundaries'
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries
related:
- hunt: appliance-lateral-movement-rdp
  reason: This hunt focuses on the appliance breach itself; movement into the Windows
    estate via RDP is handled in a separate lateral movement hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Public-Facing Appliance
    observables:
    - CVE-2026-76519
    - CVE-2026-76461
    - CVE-2026-102764
    - CVE-2026-93637
    - Zimbra Network Edition GraphQL authentication endpoint
    - BeyondTrust Remote Support MRS
    slug: initial-access-appliance-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Persistence via Script Overwrite
    observables:
    - /data/bin/core_watch.sh
    - TAR files containing PAX archives
    - Metasploit payload overwriting system scripts
    slug: persistence-via-script-overwrite
    tactic: persistence
    techniques:
    - T1053.003
  - name: Execution via Cron Job
    observables:
    - core_watch.sh execution every 5 minutes
    - root privilege execution from cron parent process
    slug: execution-via-cron-job
    tactic: execution
    techniques:
    - T1053.003
  - name: Identity Boundary Bypass
    observables:
    - Zimbra SaveDraftRequest SOAP handler
    - CVE-2026-73571
    - admin.authorizedJIDs system property modification
    - impersonation without delegation grant
    slug: identity-boundary-bypass
    tactic: lateral-movement
    techniques:
    - T1190
  summary: Threat actors exploit unauthenticated vulnerabilities in email infrastructure
    like Cisco Secure Email Gateway and Zimbra to achieve persistence and lateral
    movement. The attack chain includes arbitrary file writes to hijack system scripts
    executed by cron jobs and bypassing identity boundaries via SOAP and GraphQL requests.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Email Infrastructure Compromise and Impersonation

This hunt identifies mail appliances exposed to recent high-severity vulnerabilities, then looks for evidence of multi-stage exploitation. It starts by analyzing authentication bypass attempts on Zimbra and exploit request paths for Cisco SEG and BeyondTrust. The second phase corroborates this early access with evidence of persistence through the modification of system scripts like core_watch.sh and their subsequent execution via cron. An agent evaluates the full compromise chain to identify compromised gateways for isolation and forensic review.

## scoping-vulnerable-appliances
<!-- Identify vulnerable mail infrastructure -->
Find appliance hosts running versions vulnerable to the targeted CVEs to narrow the focus of the hunt.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of resource IDs (hostnames or IPs) currently exposed to the targeted
  vulnerabilities. Silence means no known vulnerable appliances are currently reporting.
reads:
- resource_uid
- cve_uid
- severity
- affected_package_name
- affected_package_version
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT resource_uid AS target, cve_uid, severity, affected_package_name, affected_package_version FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed'
```

## parallel-early-access
<!-- Analyze early stage access indicators -->
parallel:
- → zimbra-auth-anomalies
- → appliance-exploit-request-paths
join: → evaluate-early-access

## zimbra-auth-anomalies
<!-- Zimbra GraphQL auth anomalies -->
Detect rate-limit bypass and credential stuffing on Zimbra Network Edition GraphQL endpoints.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: High volumes of auth attempts on GraphQL from external IPs indicate a rate-limit
  bypass attempt.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- src_endpoint_ip
- request_uri
- event_type
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT device_hostname, src_endpoint_ip, request_uri, COUNT(*) AS attempts FROM hb_auth_signin WHERE (LOWER(request_uri) LIKE '%/graphql%' OR LOWER(event_type) LIKE '%soap%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, request_uri HAVING attempts > 20
```

## appliance-exploit-request-paths
<!-- Exploit request paths -->
Find web requests targeting known vulnerable handlers for Zimbra, Cisco SEG, and BeyondTrust.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Requests to delegated sending handlers or proprietary appliance APIs from
  unauthenticated sources.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- url_query
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, url_query, status_code FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%savedraftrequest%' OR LOWER(url_path) LIKE '%/mrs/%' OR LOWER(url_path) LIKE '%/ecs/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-early-access
<!-- Evaluate early access patterns -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-appliances
- zimbra-auth-anomalies
- appliance-exploit-request-paths
max_iterations: 3
objective: Determine if any host shows evidence of successful exploit payloads or
  credential stuffing via bypassed rate limits.
success_criteria: A verdict of malicious | suspicious | benign per appliance host.
tools:
- endpoint
- identity
- web
```

## parallel-follow-on
<!-- Hunt for follow-on persistence and execution -->
parallel:
- → cisco-seg-script-overwrite
- → cron-driven-script-execution
join: → evaluate-compromise-chain

## cisco-seg-script-overwrite
<!-- Cisco SEG script overwrites -->
Identify the overwriting of core_watch.sh as reported in Cisco SEG CVE-2026-76519 exploitation.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation or modification of the core_watch.sh script, especially if originating
  from a web-server or scanning process.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%/core_watch.sh' AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## cron-driven-script-execution
<!-- Cron-driven script execution -->
Verify if the overwritten script is being executed with root privileges by the system cron daemon.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of core_watch.sh by cron verifies successful persistence and elevation
  to root.
reads:
- device_hostname
- process_path
- parent_process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT device_hostname, process_path, parent_process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%/core_watch.sh' OR LOWER(process_cmd_line) LIKE '%core_watch.sh%') AND (LOWER(parent_process_name) LIKE '%cron%' OR LOWER(parent_process_name) LIKE '%crond%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-compromise-chain
<!-- Evaluate full compromise chain -->
```agent target=hunter
cite: required
context:
- evaluate-early-access
- cisco-seg-script-overwrite
- cron-driven-script-execution
max_iterations: 4
objective: Identify hosts that exhibit both initial access indicators and follow-on
  persistence or execution, confirming a successful breach.
success_criteria: A final verdict of compromised | likely_compromised | benign per
  host.
tools:
- endpoint
- identity
- web
```

## decision-route-remediation
<!-- Route remediation -->
if~: "the evaluate-compromise-chain verdict is compromised or likely_compromised for any host" (confidence: high, judge=hunter)
then: → action-isolate-compromised-host
indeterminate: → task-forensic-mailbox-audit
unavailable: → task-forensic-mailbox-audit (blind_spot: missing-appliance-access-logs)
else: → task-patch-and-harden

## action-isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the appliance from the network. Revoke all active sessions for the appliance service accounts and any administrator credentials used to manage it.
```
→ task-forensic-mailbox-audit

## task-forensic-mailbox-audit
<!-- Forensic mailbox audit -->
```manual target=analyst
Inspect Zimbra audit logs for unauthorized SaveDraftRequest events to identify which accounts were used for impersonation. Review Cisco SEG logs for TAR/PAX file processing errors that may indicate exploitation attempts.
```
→ task-patch-and-harden

## task-patch-and-harden
<!-- Patch and harden infrastructure -->
```manual target=analyst
Apply the latest security patches for Zimbra (10.1.17+), Cisco Secure Email Gateway, and BeyondTrust. Restrict access to GraphQL and SOAP endpoints to known internal administrative IP ranges.
```
→ end
