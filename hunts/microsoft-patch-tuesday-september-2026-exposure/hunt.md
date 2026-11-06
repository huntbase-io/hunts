---
analysis: A simple detection rule flags a single CVE hit. This hunt pivots between
  vulnerability findings and a host-behavioural baseline, asking whether exposed hosts
  exhibit the specific child-shell patterns and rare process deployments that follow
  successful exploitation of these flaws.
blind_spots:
- id: incomplete-vuln-telemetry
  question: Which unmanaged systems remain vulnerable but are not reporting to hb_vulnerability_finding?
  requires: Complete coverage of vulnerability scanning agents
  risk: Unmanaged systems could serve as a beachhead without being scoped by the initial
    query.
  stage: initial-access-remote-services
- id: short-lived-processes
  question: Did an exploit process run and exit between snapshot intervals?
  requires: Continuous process event logs (Sysmon) rather than snapshots
  risk: Short-lived elevation of privilege payloads might be missed if they complete
    their task before the next process inventory collection.
  stage: privilege-escalation-zero-day
coverage:
- stage: initial-access-remote-services
  status: covered
  steps:
  - vuln-finding-scoping
  - service-child-behaviour
- stage: execution-malicious-media-and-office
  status: covered
  steps:
  - vuln-finding-scoping
  - service-child-behaviour
- stage: privilege-escalation-zero-day
  status: covered
  steps:
  - vuln-finding-scoping
  - rare-process-baseline
- reason: Azure Cosmos DB and Spring Cloud Azure exploitation require cloud control-plane
    telemetry not listed as a source.
  stage: initial-access-cloud-and-database
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The September 2026 Patch Tuesday involves nearly 1,000 vulnerabilities,
    including two zero-day elevation of privilege flaws. Verifying that these have
    not been exploited before the patch cycle completes is critical for ensuring environmental
    integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting September 2026 zero-day or critical remote
  code execution vulnerabilities, such as those in DNS Server or the Windows Update
  Stack, to establish initial access or escalate privileges on unpatched systems.
labels:
- hunt
- attack.t1190
- attack.t1572
- attack.t1068
- attack.t1203
name: Microsoft Patch Tuesday September 2026 Exposure
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on; if empty, examines
      the full estate.
    type: list[host]
  shell_interpreters:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - scrcons.exe
    - wscript.exe
    - cscript.exe
    description: Common shell and script interpreters used in post-exploitation.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: Common post-exploitation tools
    type: list[string]
  target_cves:
    default:
    - CVE-2026-81963
    - CVE-2026-85880
    - CVE-2026-69730
    - CVE-2026-67631
    - CVE-2026-69852
    - CVE-2026-72957
    description: Critical and exploited-in-the-wild CVEs from the September advisory.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-september-2026/
    type: list[string]
  vulnerable_parents:
    default:
    - dns.exe
    - sqlservr.exe
    - winword.exe
    - excel.exe
    - outlook.exe
    - skype.exe
    - wmplayer.exe
    description: Processes associated with the September vulnerabilities that might
      spawn child shells.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: September 2026 Vulnerability List
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-september-2026/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt starts with wide coverage using hb_vulnerability_finding for critical
  CVEs. It prioritizes Domain Controllers (DNS), SQL Servers, and workstations with
  unpatched Office applications. The results populate a list of hosts for more expensive
  behavioural analysis.
references:
- name: "Talos \u2014 Microsoft Patch Tuesday for September 2026"
  url: https://blog.talosintelligence.com/microsoft-patch-tuesday-for-september-2026/
related:
- hunt: azure-cosmos-db-spoofing-bypass
  reason: Exploitation of Azure Cosmos DB (CVE-2026-69857) requires Azure-native activity
    logs, which were not in scope for this endpoint-focused hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Remote Network Services
    observables:
    - DNS Server (port 53)
    - Routing and Remote Access Service (RRAS)
    - Secure Socket Tunneling Protocol (SSTP) (port 443)
    - Windows Kerberos (port 88)
    - DHCP Server (ports 67, 68)
    - Reliable Multicast Transport Driver (RMCAST)
    - CVE-2026-69730
    - CVE-2026-69676
    - CVE-2026-73009
    - CVE-2026-69852
    slug: initial-access-remote-services
    tactic: initial-access
    techniques:
    - T1190
    - T1572
  - name: Client-Side Exploitation via Office and Media
    observables:
    - excel.exe
    - winword.exe
    - outlook.exe
    - skype.exe
    - wmplayer.exe
    - Microsoft Excel (CVE-2026-81948)
    - Microsoft Word (CVE-2026-81952)
    - Microsoft Office Outlook (CVE-2026-78525)
    - Windows Media Player (CVE-2026-70203)
    slug: execution-malicious-media-and-office
    tactic: execution
    techniques:
    - T1203
  - name: Local Privilege Escalation and Zero-Day Exploitation
    observables:
    - Windows Update Stack (CVE-2026-81963)
    - Advanced Local Procedure Call (ALPC) (CVE-2026-85880)
    - Windows Hello (CVE-2026-81354)
    - Secure Kernel Mode (CVE-2026-69501)
    - Windows Virtualization-Based Security (VBS) (CVE-2026-83501)
    slug: privilege-escalation-zero-day
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Cloud Infrastructure and Database Bypass
    observables:
    - Azure Cosmos DB (CVE-2026-69857)
    - Spring Cloud Azure (CVE-2026-69854)
    - Microsoft SQL Server (CVE-2026-67631)
    - Microsoft Dynamics 365 On-Premises (CVE-2026-65772)
    slug: initial-access-cloud-and-database
    tactic: initial-access
    techniques:
    - T1190
  summary: The September 2026 Microsoft Patch Tuesday includes nearly 1,000 vulnerabilities,
    featuring zero-day privilege escalation flaws in the Windows Update Stack and
    ALPC alongside critical remote code execution risks in DNS, Kerberos, and RRAS.
    These vulnerabilities provide multiple paths for attackers to gain initial access
    via remote services or malicious media before escalating to system-level privileges.
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


# Microsoft Patch Tuesday September 2026 Exposure

This hunt identifies exposure and potential exploitation following the September 2026 Microsoft Patch Tuesday. It focuses on the zero-day elevation of privilege in the Windows Update Stack (CVE-2026-81963) and critical remote code execution flaws in infrastructure services like DNS (CVE-2026-69730) and SQL Server (CVE-2026-67631). The hunt scopes the estate using vulnerability telemetry, establishes a process baseline to identify rare binaries on exposed hosts, and hunts for behavioural indicators like shell execution from high-privilege service parents.

## vuln-finding-scoping
<!-- Vulnerability scope for September CVEs -->
Identify which hosts have been flagged with the high-priority CVEs from the September 2026 advisory.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of vulnerable devices. Silence indicates no scanned assets currently
  match the high-priority CVE list.
reads:
- device_uid
- cve_uid
- affected_package_name
- affected_package_version
- severity
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, cve_uid, affected_package_name, affected_package_version, severity FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0
```

## rare-process-baseline
<!-- Rare process baseline on exposed hosts -->
Identify unusual process executions on hosts currently known to be vulnerable, which may indicate payload delivery.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of processes seen on only one or two hosts. Silence suggests a consistent
  software baseline across unpatched systems.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT process_path, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path, process_cmd_line HAVING host_count <= 2 ORDER BY host_count ASC
```

## service-child-behaviour
<!-- Exploitation behaviour from vulnerable services -->
Find behavioural evidence of RCE or EoP where high-privilege service processes or Office apps spawn interpreters.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days, vulnerable_parents=vulnerable_parents, shell_interpreters=shell_interpreters)
~~~yaml
expected: Rows showing a shell spawned from a vulnerable parent process like dns.exe
  or outlook.exe. This is high-confidence evidence of exploitation.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- user_name
- integrity_level
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, user_name, integrity_level, time FROM hb_process_activity WHERE (instr(',' || '{{vulnerable_parents}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR (LOWER(parent_process_name) = 'svchost.exe' AND LOWER(parent_process_cmd_line) LIKE '%rras%')) AND instr(',' || '{{shell_interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exposure-triage
<!-- Triage exposure and behaviour -->
```agent target=hunter
cite: required
context:
- vuln-finding-scoping
- rare-process-baseline
- service-child-behaviour
max_iterations: 3
objective: Determine if any host flagged with critical September 2026 vulnerabilities
  exhibits suspicious process activity, citing rows from the baseline and behaviour
  queries.
success_criteria: A per-host verdict of exposed-benign | exposed-suspicious | potentially-exploited.
tools:
- endpoint
```

## exploitation-decision
<!-- Route on evidence of exploitation -->
if~: "the triage verdict identifies potentially-exploited or exposed-suspicious activity on at least one host" (confidence: high, judge=hunter)
then: → remediation-task
indeterminate: → remediation-task
unavailable: → remediation-task (blind_spot: incomplete-vuln-telemetry)
else: → close-out-task

## remediation-task
<!-- Remediation and vulnerability review -->
```manual target=analyst
Review the agent's findings for the identified hosts. Confirm with the vulnerability management team whether the September 2026 patches have been applied. If the rare process activity or child-shell findings are verified as malicious, escalate to the incident response team and follow the standard isolation playbook. Document any findings that represent authorized administrative tools to tune future runs.
```
→ close-out-task

## close-out-task
<!-- Close out exposure hunt -->
```manual target=analyst
Summarize the total count of vulnerable hosts versus those showing suspicious behaviour. Record any gaps in vulnerability scanning coverage identified during the hunt. Submit a final report to the patch management team to verify the closure of critical exposure windows.
```
→ end
