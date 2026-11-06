---
analysis: A standard detection rule might alert on a shell from a web process, but
  this hunt adds value by scoping to vulnerable software inventory, stack-counting
  rare child processes to find non-standard tool use, and applying an agent read across
  multiple queries to distinguish exploitation from admin maintenance.
blind_spots:
- id: vulnerability-scan-staleness
  question: Which systems have unpatched PHP versions but have not reported inventory
    in the last 24 hours?
  requires: recent hb_software_inventory collection
  risk: A newly deployed or unmanaged server running vulnerable PHP would not appear
    in the scoping query, creating a blind spot for the rest of the hunt.
  stage: vulnerability-exposure
- id: http-payload-visibility
  question: Does the HTTP request contain the php2shell exploit payload?
  requires: hb_http_activity with full request body
  risk: Without the request body, the hunt cannot observe the exploitation attempt
    itself, only the resulting process behavior, which an adversary could attempt
    to obfuscate.
  stage: web-based-exploitation
coverage:
- stage: vulnerability-exposure
  status: covered
  steps:
  - identify-vulnerable-php-instances
- blind_spot: http-payload-visibility
  reason: Exploitation payloads for these CVEs often reside in HTTP bodies or headers
    which hb_http_activity does not reliably capture.
  stage: web-based-exploitation
  status: not_visible
- stage: php-shell-execution
  status: covered
  steps:
  - rare-php-child-processes
  - detect-suspicious-php-children
- stage: ingress-tool-retrieval
  status: covered
  steps:
  - detect-suspicious-php-children
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: PHP is a foundational component for web applications. These unauthenticated
    remote code execution vulnerabilities (CVE-2026-109618, CVE-2026-109619) pose
    a critical risk to any internet-facing host. A negative result across the estate
    provides necessary assurance that these flaws have not been weaponized internally.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting the php2shell vulnerabilities (CVE-2026-109618
  or CVE-2026-109619) to execute unauthenticated code, which manifests as PHP worker
  processes spawning interactive shells or utility tools to retrieve secondary payloads.
labels:
- hunt
- attack.t1190
- attack.t1059.003
- attack.t1059.004
- attack.t1105
- command and control
- execution
- initial access
name: PHP Remote Code Execution and Shell Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Limit analysis to these hostnames; leave empty for the full estate.
    type: list[host]
  suspicious_tools:
    default:
    - sh
    - bash
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - curl
    - wget
    - certutil.exe
    description: Common shells and download tools used in post-exploitation.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt uses hb_software_inventory to identify unpatched PHP versions.
  This is more reliable than vulnerability findings alone, as CISA notes PHP is often
  embedded and not directly observable by all scanners. The behavioral analysis then
  focuses on the hosts running these specific versions.
references:
- name: 'CISA Advisory: Critical Vulnerabilities in PHP Require Immediate Patching'
  url: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
related:
- hunt: web-server-webshell-behavior
  reason: This hunt targets the specific PHP RCE advisory; a sibling hunt addresses
    broader webshell persistence behavior across all web servers.
  relation: sibling
scenario:
  stages:
  - name: Exposure to PHP RCE Vulnerabilities
    observables:
    - CVE-2026-109618
    - CVE-2026-109619
    - PHP 8.2 < 8.2.35
    - PHP 8.3 < 8.3.36
    - PHP 8.4 < 8.4.27
    - PHP 8.5 < 8.5.12
    - PHP 8.1 and earlier
    slug: vulnerability-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthenticated Remote Code Execution
    observables:
    - HTTP requests targeting PHP handlers
    - Exploitation of php2shell
    slug: web-based-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: PHP Worker Process Spawning Shells
    observables:
    - php-fpm spawning /bin/sh
    - php-fpm spawning /bin/bash
    - php.exe spawning cmd.exe
    - php.exe spawning powershell.exe
    - PHP worker processes launching shells
    slug: php-shell-execution
    tactic: execution
    techniques:
    - T1059.003
    - T1059.004
  - name: Tool Download via PHP Process
    observables:
    - php-fpm spawning curl
    - php-fpm spawning wget
    - php.exe spawning certutil.exe
    - PHP worker processes downloading tools
    slug: ingress-tool-retrieval
    tactic: command-and-control
    techniques:
    - T1105
  summary: Attackers exploit unauthenticated remote code execution vulnerabilities
    in PHP, known as 'php2shell' (CVE-2026-109618, CVE-2026-109619), to gain initial
    access to web servers. Following exploitation, the vulnerability is leveraged
    to command PHP worker processes to spawn interactive shells or download additional
    malicious tools.
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


# PHP Remote Code Execution and Shell Activity

This hunt identifies internet-facing systems running vulnerable versions of PHP and monitors for post-exploitation indicators following an unauthenticated remote code execution. It follows the exposure flow, starting with a scope of vulnerable software versions, then baselines the normal behavior of PHP worker processes like php-fpm or php.exe to find rare child processes. Finally, it looks for specific, high-confidence behavior of shells and downloaders being spawned directly from PHP handlers. An agent then weighs the prevalence and behavior together to identify compromised hosts.

## identify-vulnerable-php-instances
<!-- Identify vulnerable PHP instances -->
Inventory systems running PHP versions below the security fix thresholds to establish the vulnerable surface.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running unpatched versions of PHP. Silence indicates
  no known vulnerable PHP installations are present in the inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'php' OR LOWER(package_name) LIKE 'php%') AND (package_version < '8.2.35' OR (package_version >= '8.3' AND package_version < '8.3.36') OR (package_version >= '8.4' AND package_version < '8.4.27') OR (package_version >= '8.5' AND package_version < '8.5.12'))
```

## rare-php-child-processes
<!-- Rare child processes of PHP workers -->
Stack-count children of PHP worker processes across the scoped hosts to find anomalous binaries that differ from standard web server behavior.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous binaries appearing on only a few hosts stand out from fleet-wide
  standard children. Silence suggests the PHP processes are only performing expected
  operations.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- parent_process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT LOWER(process_name) AS child_process, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%php-fpm%' OR LOWER(parent_process_name) LIKE '%php.exe%' OR LOWER(parent_process_name) LIKE '%php-cgi%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY child_process HAVING host_count <= 3 ORDER BY host_count ASC
```

## detect-suspicious-php-children
<!-- Specific shell or downloader activity from PHP -->
Monitor for the high-confidence behavioral indicator of a PHP worker process launching common shells or ingress tools.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, suspicious_tools=suspicious_tools, scope_hosts=scope_hosts)
~~~yaml
expected: A hit shows a PHP process spawning a shell or utility, which is a strong
  indicator of successful remote code execution. Silence is evidence of absence for
  this specific behavioral pattern.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- parent_process_name
- process_original_file_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%php-fpm%' OR LOWER(parent_process_name) LIKE '%php.exe%' OR LOWER(parent_process_name) LIKE '%php-cgi%') AND (instr(',' || '{{suspicious_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{suspicious_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-php-activity
<!-- Analyze PHP exposure and child behavior -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-php-instances
- rare-php-child-processes
- detect-suspicious-php-children
max_iterations: 4
objective: Review the inventory of vulnerable PHP hosts and determine if any match
  the hosts exhibiting rare child processes or specific shell/tool launches. Determine
  if the behavior is malicious exploitation or benign administrator activity.
success_criteria: A verdict for each host citing evidence from process logs and inventory
  state.
tools:
- endpoint
```

## exploitation-decision
<!-- Exploitation decision -->
if~: "the verdict for any host is malicious based on shell or tool activity from a PHP worker" (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: vulnerability-scan-staleness)
else: → close-out

## remediation-review
<!-- Remediation and patching review -->
```manual target=analyst
For hosts identified with malicious shell activity, perform an incident response investigation to determine the extent of the breach and lateral movement. For all other hosts identified in the scoping step, immediately update PHP to the patched versions (8.5.12, 8.4.27, 8.3.36, or 8.2.35) as mandated by CISA.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Confirm that no indicators of active exploitation were found during the lookback period. Provide the list of vulnerable PHP hostnames to the patching team for remediation and close the hunt.
```
→ end
