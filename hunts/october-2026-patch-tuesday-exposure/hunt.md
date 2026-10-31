---
analysis: A standard detection rule might fire on 'shell from web server', but this
  hunt prioritizes confirmed unpatched systems and applies a fleet-wide baseline for
  rare binaries, providing context a single rule cannot provide.
blind_spots:
- id: incomplete-scanner-coverage
  question: Which unmanaged or unscanned hosts are unpatched?
  requires: comprehensive hb_vulnerability_finding data
  risk: Hosts not covered by a vulnerability provider contribute no rows to scoping,
    creating a false sense of security.
  stage: initial-access-public-facing-exploitation
- id: memory-only-exploitation
  question: Is exploitation occurring within the VBS Enclave or kernel space?
  requires: Memory-level kernel tracing
  risk: Exploitation of CVE-2026-102211 or kernel-only CVEs occurs in memory spaces
    that standard process logs cannot observe.
  stage: privilege-escalation-kernel-and-vbs
coverage:
- stage: initial-access-public-facing-exploitation
  status: covered
  steps:
  - vulnerability-scoping
  - shell-execution-from-vulnerable-apps
- stage: execution-client-side-payloads
  status: covered
  steps:
  - vulnerability-scoping
  - shell-execution-from-vulnerable-apps
- blind_spot: memory-only-exploitation
  reason: Kernel and VBS enclave exploitation occurs in memory spaces not visible
    to process-level telemetry.
  stage: privilege-escalation-kernel-and-vbs
  status: not_visible
- reason: Belongs to a separate lateral movement hunt using hb_auth_signin.
  stage: lateral-movement-remote-infrastructure
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The October 2026 Patch Tuesday includes 85 critical RCE vulnerabilities
    and at least one 0-day. Proactive identification of exposed hosts coupled with
    behavioral analysis is required to mitigate the risk of exploitation before patching
    is complete.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are exploiting newly disclosed October 2026 RCE vulnerabilities
  to trigger anomalous shell execution and deploy payloads on unpatched Windows and
  Exchange hosts.
labels:
- hunt
- attack.t1190
- attack.t1203
- attack.t1059.003
- attack.t1068
- execution
- initial access
- lateral movement
- privilege escalation
name: October 2026 Patch Tuesday Exposure Hunt
parameters:
  critical_cves:
    default:
    - CVE-2026-96951
    - CVE-2026-70229
    - CVE-2026-70571
    - CVE-2026-100202
    - CVE-2026-70300
    - CVE-2026-96934
    - CVE-2026-70242
    - CVE-2026-97749
    - CVE-2026-77900
    description: Critical RCE and 0-day CVEs from the October 2026 advisory.
    from:
      kind: article
      observed: '2026-10-13'
      ref: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-october-2026/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to narrow the behavioral search; leave empty to scan the
      full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-october-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Use the first step to identify unpatched systems directly by hostname via
  a join between vulnerability and device inventory. Widen search to the entire estate
  if scanner coverage is suspected to be incomplete.
references:
- name: "Microsoft Patch Tuesday for October 2026 \u2014 Snort rules and prominent\
    \ vulnerabilities"
  url: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-october-2026/
related:
- hunt: lateral-movement-ad-rds-october-2026
  reason: Lateral movement via AD/RDS vulnerabilities requires identity and authentication
    logs (hb_auth_signin) which are handled in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Public-Facing Services
    observables:
    - Microsoft Exchange Server stack-based buffer overflow (CVE-2026-70571)
    - Windows DHCP Server use-after-free (CVE-2026-96934, CVE-2026-88117, CVE-2026-88119,
      CVE-2026-88120)
    - Network Device Enrollment Service (NDES) weak authentication (CVE-2026-69802)
    - Azure App Service missing authentication (CVE-2026-77900)
    slug: initial-access-public-facing-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Client-Side RCE and Command Injection
    observables:
    - Windows Shell command injection 0-day (CVE-2026-96951)
    - Microsoft Excel remote code execution (CVE-2026-100211, CVE-2026-97739)
    - Microsoft Outlook remote code execution (CVE-2026-70242, CVE-2026-97749)
    - Microsoft Word RCE (CVE-2026-70300, CVE-2026-88185)
    - Windows Media Foundation heap buffer overflow (CVE-2026-96952)
    slug: execution-client-side-payloads
    tactic: execution
    techniques:
    - T1203
    - T1059.003
  - name: Kernel and VBS Enclave Escalation
    observables:
    - Windows Kernel heap buffer overflow (CVE-2026-96913)
    - Windows Virtualization-Based Security (VBS) Enclave race condition (CVE-2026-102211)
    - Windows ALPC use-after-free (CVE-2026-83917)
    - Azure SRE Agent SSRF (CVE-2026-69435)
    slug: privilege-escalation-kernel-and-vbs
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Lateral Movement via AD and RDS
    observables:
    - Windows Active Directory Domain Services incorrect authorization (CVE-2026-70229)
    - Windows Remote Desktop Services use-after-free (CVE-2026-70187)
    - AD FS spoofing via improper certificate validation (CVE-2026-96222)
    slug: lateral-movement-remote-infrastructure
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1210
  summary: The October 2026 Microsoft security update addresses 141 vulnerabilities,
    including a Windows Shell command injection 0-day exploited in the wild and critical
    RCEs in Active Directory, Exchange, and Office. The campaign involves potential
    initial access via vulnerable public-facing services or phishing, followed by
    kernel-level privilege escalation and lateral movement through Remote Desktop
    and Active Directory flaws.
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


# October 2026 Patch Tuesday Exposure Hunt

This hunt identifies exposure to the critical remote code execution (RCE) vulnerabilities disclosed in the October 2026 Microsoft Patch Tuesday, including the Windows Shell 0-day (CVE-2026-96951). It follows the exposure flow: first identifying unpatched hosts via vulnerability findings joined with device inventory, then examining rare process activity on those hosts, and finally monitoring for high-confidence behavioral indicators like web servers or productivity applications spawning command shells.

## vulnerability-scoping
<!-- Identify unpatched vulnerable hosts -->
Locate systems where vulnerability scanners have identified missing patches for the critical October 2026 CVEs, joining with device inventory for direct hostname mapping.

```sqlite target=endpoint role=scoping params=(critical_cves=critical_cves)
~~~yaml
expected: Rows identify specific assets by hostname that remain unpatched. Silence
  means no hosts are reporting these specific vulnerabilities.
reads:
- device_uid
- hostname
- cve_uid
- severity
- status
- first_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT d.hostname, v.cve_uid, v.severity, v.status, v.first_seen FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE instr(',' || '{{critical_cves}}' || ',', ',' || v.cve_uid || ',') > 0 AND v.status != 'suppressed' ORDER BY v.severity_id DESC
```

## rare-processes-on-exposed-hosts
<!-- Stack-count rare processes -->
Identify unusual binaries on vulnerable systems to detect first-stage payloads.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A binary or script seen on only 1-3 hosts since the patch disclosure. Silence
  suggests no unique execution occurred on the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 4
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= '2026-10-13' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING host_count <= 3 ORDER BY host_count ASC
```

## shell-execution-from-vulnerable-apps
<!-- Anomalous shell spawning from vulnerable apps -->
Detect successful exploitation of Exchange or Office by monitoring for shells spawned from their respective processes, focused on activity since the patch disclosure.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A shell or script interpreter spawned by a web server or productivity application.
  This indicates remote code execution.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) IN ('c:\windows\system32\inetsrv\w3wp.exe', 'c:\program files\microsoft office\root\office16\excel.exe', 'c:\program files\microsoft office\root\office16\winword.exe', 'c:\program files\microsoft office\root\office16\outlook.exe') AND LOWER(process_name) IN ('c:\windows\system32\cmd.exe', 'c:\windows\system32\windowspowershell\v1.0\powershell.exe', 'c:\windows\system32\mshta.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= '2026-10-13' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Identify high-risk exposed systems -->
```agent target=hunter
cite: required
context:
- vulnerability-scoping
- rare-processes-on-exposed-hosts
- shell-execution-from-vulnerable-apps
max_iterations: 3
objective: Evaluate the results from scoping and behavioral queries. Determine which
  hosts with missing October 2026 patches show anomalous process activity or command
  shell execution consistent with RCE.
success_criteria: A list of hosts classified as 'Exploited', 'Exposed and Anomalous',
  or 'Exposed but Clean'.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage-agent verdict is malicious or suspicious for at least one host" (confidence: medium, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: incomplete-scanner-coverage)
else: → close-out

## remediation-review
<!-- Remediation and Patching Review -->
```manual target=analyst
1. Verify the vulnerability findings on the cited hosts. 2. For hosts showing anomalous shell execution, escalate to Incident Response. 3. Ensure that the October 2026 security updates are applied and validated across the estate.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the number of vulnerable vs clean hosts. Transition the anomalous shell query to a standing detection rule if it was effective.
```
→ end
