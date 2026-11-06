---
analysis: This hunt correlates host-specific software inventory with rare URI patterns
  and shell execution. A single detection rule firing on w3wp.exe spawning a shell
  might be too noisy in some environments; this hunt provides the context of unpatched
  versions and anomalous web traffic to confirm the RCE chain.
blind_spots:
- id: missing-iis-logs
  question: whether the exploit attempt reached the server
  requires: hb_http_activity for all web servers
  risk: A host without web activity logging could be exploited without generating
    URI evidence, leaving only process behavior as an indicator.
  stage: exploit-sharepoint-auth-bypass-and-rce
- id: encrypted-payload-visibility
  question: whether the .NET gadget chain was present in the HTTP request body
  requires: HTTPS decryption or server-side request inspection
  risk: The hunt relies on URI path anomalies and status codes; it cannot inspect
    the serialized .NET payload that triggers the code execution.
  stage: exploit-sharepoint-auth-bypass-and-rce
coverage:
- stage: exploit-sharepoint-auth-bypass-and-rce
  status: covered
  steps:
  - identify-sharepoint-hosts
  - rare-http-paths-on-sharepoint
- stage: execution-via-sharepoint-service-account
  status: covered
  steps:
  - iis-worker-shell-execution
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The SharePoint unauthenticated RCE chain is a critical exposure with
    active exploitation recorded in the KEV catalog. A negative result across the
    SharePoint fleet is necessary to confirm that no exploitation has occurred on
    unpatched systems.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting the CVE-2026-55040 and CVE-2026-63520 chain
  to bypass authentication and execute arbitrary commands via the SharePoint worker
  process on unpatched servers.
labels:
- hunt
- attack.t1190
- attack.t1059.003
name: SharePoint Unauthenticated Remote Code Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavior and prevalence.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: List of SharePoint hostnames identified in the scoping step; if empty,
      queries run across all hosts.
    from:
      kind: manual
      observed: '2024-08-24'
      ref: analyst-scoping
    type: list[host]
  shell_binaries:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - wscript.exe
    - cscript.exe
    description: Common shell interpreters often used in RCE follow-on activity.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: adversary-tradecraft
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The software inventory search is the primary scoping mechanism. Analysts
  should prioritize hosts with public exposure detected via hb_exposed_assets.
references:
- name: "Rapid7 \u2014 CVE-2026-63520 Microsoft SharePoint Remote Code Execution"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed/
related:
- hunt: iis-suspicious-child-processes
  reason: This hunt is specific to the SharePoint vulnerability chain; a general IIS
    child process hunt covers a broader range of web server exploits.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: SharePoint Unauthenticated RCE Chain
    observables:
    - HTTP requests targeting Microsoft SharePoint Business Connectivity Services
      (BCS)
    - Exploitation of CVE-2026-55040 (authentication bypass)
    - Exploitation of CVE-2026-63520 (unsafe .NET type instantiation)
    - SharePoint Server versions prior to KB5002893, KB5002894, KB5002896, KB5002905,
      or KB5002906
    slug: exploit-sharepoint-auth-bypass-and-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: Arbitrary OS Command Execution
    observables:
    - Attacker-controlled OS commands executed by the SharePoint service account
    - Unexpected child processes spawned by SharePoint worker processes (e.g., cmd.exe
      or powershell.exe spawned by w3wp.exe)
    - Custom .NET gadget chain instantiation within SharePoint application pool
    slug: execution-via-sharepoint-service-account
    tactic: execution
    techniques:
    - T1059.003
  summary: Attackers can chain an authentication bypass (CVE-2026-55040) with an unsafe
    .NET type instantiation vulnerability in SharePoint's Business Connectivity Services
    (CVE-2026-63520) to achieve unauthenticated remote code execution. This allows
    for arbitrary OS command execution with the privileges of the SharePoint service
    account.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# SharePoint Unauthenticated Remote Code Execution

This hunt identifies SharePoint servers exposed to a critical unauthenticated RCE chain. It uses a multi-surface approach to scope the environment for SharePoint installations, stack-count HTTP requests to identify rare URI patterns targeting Business Connectivity Services, and detect suspicious child processes spawned by the IIS worker process. The hunt focuses on the transition from unauthenticated web access to host-level command execution with service account privileges.

## identify-sharepoint-hosts
<!-- Identify SharePoint servers -->
Scope the environment to find hosts running Microsoft SharePoint software by inspecting the software inventory.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames confirmed to be running SharePoint. The analyst should
  copy these hostnames into the scope_hosts parameter for subsequent steps.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%sharepoint%' OR LOWER(vendor_name) LIKE '%microsoft%sharepoint%')
```

## rare-http-paths-on-sharepoint
<!-- Rare HTTP URI patterns -->
Identify anomalous HTTP requests targeting Business Connectivity Services or other endpoints on the validated SharePoint fleet.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique or rare URI paths targeting SharePoint services. Silence suggests
  no anomalous unauthenticated traffic reached the SharePoint endpoints.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- url_path
- status_code
- time
- device_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT url_path, status_code, MIN(time) AS first_seen, COUNT(DISTINCT device_hostname) AS host_count FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(url_path) LIKE '%_vti_bin%' OR LOWER(url_path) LIKE '%businessdata%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_path, status_code HAVING host_count < 3 ORDER BY host_count ASC
```

## iis-worker-shell-execution
<!-- IIS worker process shell execution -->
Detect shell processes spawned by the IIS worker process on the identified SharePoint fleet, which indicates successful code execution.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, shell_binaries=shell_binaries)
~~~yaml
expected: Shell processes such as cmd.exe or powershell.exe originating from w3wp.exe
  on a SharePoint server. Silence is evidence of absence for this specific behavioral
  indicator.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%w3wp.exe%' AND (instr(',' || '{{shell_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-exposure
<!-- Triage SharePoint exposure -->
```agent target=hunter
cite: required
context:
- rare-http-paths-on-sharepoint
- iis-worker-shell-execution
max_iterations: 4
objective: Check for shell execution on the SharePoint servers that received rare
  HTTP requests. Weight the prevalence of URIs against the behavioral shell activity.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  HTTP and process rows.
tools:
- endpoint
- web
```

## route-results
<!-- Route based on exposure -->
if~: "The triage-exposure verdict is malicious for at least one SharePoint host." (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: missing-iis-logs)
else: → close-out

## remediation-review
<!-- Remediation and patching review -->
```manual target=analyst
Review the SharePoint servers identified as compromised. Apply KB5002893, KB5002894, KB5002896, or KB5002905 depending on the specific SharePoint version. Investigate the OS commands executed by the service account to determine the extent of the intrusion.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the hosts scanned and confirm they are properly patched against CVE-2026-55040 and CVE-2026-63520. Record any false positives from the URI prevalence query to improve future baseline results.
```
→ end
