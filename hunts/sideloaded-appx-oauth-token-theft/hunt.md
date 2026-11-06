---
analysis: Detecting WWAHost network activity alone is too noisy for developer environments.
  This hunt stack-counts the registration commands to find rare packages and correlates
  them with the configuration state to provide high-fidelity results a single rule
  could not achieve.
blind_spots:
- id: missing-wwahost-telemetry
  question: did WWAHost connect to an auth domain without generating a network row?
  requires: endpoint logging of WWAHost.exe network activity
  risk: If network telemetry for signed Microsoft binaries is suppressed, the connection
    to login.microsoftonline.com will be missed.
  stage: wwahost-proxy-execution
- id: historical-registry-enablement
  question: was Developer Mode enabled before the lookback window?
  requires: historical registry state beyond the lookback window
  risk: A host that already has Developer Mode enabled will not show up in the scoping
    query, making the registration command the only indicator.
  stage: enable-developer-mode
coverage:
- stage: enable-developer-mode
  status: covered
  steps:
  - detect-developer-mode-enablement
- stage: appx-package-sideloading
  status: covered
  steps:
  - rare-package-registration
- stage: wwahost-proxy-execution
  status: covered
  steps:
  - wwahost-auth-connections
- reason: Belongs to another part of the "OAuth Token Theft Through Microsoft's Front
    Door | Huntress" series.
  stage: oauth-credential-theft
  status: out_of_scope
- reason: Belongs to another part of the "OAuth Token Theft Through Microsoft's Front
    Door | Huntress" series.
  stage: auth-code-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The sideloading of AppX packages with WinRT access bypasses browser-based
    security and harvests tokens that survive MFA; identifying the prerequisite configuration
    and rare registration events is the only way to stop the theft before exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has enabled Developer Mode and sideloaded a malicious AppX
  package to abuse WWAHost.exe, allowing them to capture MFA-compliant OAuth tokens
  via a legitimate Microsoft login dialog.
labels:
- hunt
- attack.t1566
- attack.t1574.002
- attack.t1218.010
- attack.t1041
name: Sideloaded AppX OAuth Token Theft
parameters:
  auth_domains:
    default:
    - login.microsoftonline.com
    - login.live.com
    - login.windows.net
    description: Microsoft authentication domains targeted by the WebAuthenticationBroker.
    from:
      kind: article
      observed: '2026-09-23'
      ref: huntress-sideloaded-appx
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for configuration changes and execution.
    from:
      kind: article
      observed: '2026-09-23'
      ref: huntress-sideloaded-appx
    type: number
  scope_hosts:
    default: []
    description: Target hosts for the investigation; leave empty to hunt across the
      entire estate.
    from:
      kind: manual
      observed: '2026-09-23'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/stealing-oauth-tokens-through-microsofts-front-door
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on engineering environments, CI/CD runners, and developer workstations
  where Developer Mode is most likely to be enabled.
references:
- name: "Huntress \u2014 Stealing OAuth Tokens Through Microsoft's Front Door"
  url: https://www.huntress.com/blog/stealing-oauth-tokens-through-microsofts-front-door
related:
- hunt: oauth-token-theft-exfiltration
  reason: This hunt focuses on the endpoint setup; a follow-up hunt would examine
    the exfiltration and subsequent use of stolen tokens.
  relation: follows
scenario:
  stages:
  - name: Enable Developer Mode
    observables:
    - reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense
      /t REG_DWORD /d 1 /f
    slug: enable-developer-mode
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: AppX Package Sideloading
    observables:
    - Add-AppxPackage -Register
    - AppxManifest.xml
    - WindowsRuntimeAccess="all"
    slug: appx-package-sideloading
    tactic: initial-access
    techniques:
    - T1566
    - T1574.002
  - name: WWAHost Proxy Execution
    observables:
    - WWAHost.exe
    slug: wwahost-proxy-execution
    tactic: execution
    techniques:
    - T1218.010
  - name: OAuth Credential Theft
    observables:
    - WebAuthenticationBroker.authenticateAsync
    - login.microsoftonline.com
    - d590ed36-52b3-4102-aeff-aad2292ab01c
    - urn:ietf:wg:oauth:2.0:oob
    - AuditLog.Create
    - Directory.Read.All
    - Mail.ReadWrite
    slug: oauth-credential-theft
    tactic: credential-access
    techniques:
    - T1566
  - name: Auth Code Exfiltration
    observables:
    - POST /collect
    slug: auth-code-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: An attacker enables Windows Developer Mode or leverages existing enterprise
    sideloading policies to register a malicious AppX package as a standard user.
    This package uses WWAHost.exe with 'WindowsRuntimeAccess=all' to execute remote
    JavaScript that invokes the WebAuthenticationBroker, stealing legitimate Microsoft
    365 OAuth tokens via a first-party client ID. The resulting tokens bypass MFA
    and provide broad persistent access to the victim's email, files, and Teams environment.
series:
  index: 1
  slug: oauth-token-theft-through-microsoft-s-front-door-huntress
  title: OAuth Token Theft Through Microsoft's Front Door | Huntress
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
tlp: clear
type: investigation
---


# Sideloaded AppX OAuth Token Theft

This hunt identifies the endpoint preparation and execution phase of a Microsoft-signed binary proxy attack. It focuses on the enablement of Developer Mode, the registration of local AppX packages, and the subsequent network activity of the Windows Web App Host (WWAHost.exe) as it interacts with Microsoft identity endpoints. By correlating these three signals, the hunt identifies unauthorized registration of applications that can harvest credentials without triggering typical phishing defenses or domain-based blocks.

## detect-developer-mode-enablement
<!-- Detect Developer Mode enablement -->
Identify hosts where the Developer Mode prerequisite has been enabled to permit sideloading.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows indicate hosts where the sideloading restriction was lifted. Silence
  suggests no recent configuration changes, but does not prove the state is disabled
  if it was set prior to the lookback window.
reads:
- device_hostname
- reg_target
- reg_value_data
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, reg_target, reg_value_data, actor_user_name, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\appmodelunlock\\allowdevelopmentwithoutdevlicense' AND reg_value_data = '1' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## gather-sideload-evidence
<!-- Gather independent evidence -->
parallel:
- → rare-package-registration
- → wwahost-auth-connections
join: → triage-malicious-sideload

## rare-package-registration
<!-- Rare AppX package registration -->
Stack-count package registration commands to isolate local or attacker-deployed packages from enterprise-standard software.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A command line pointing to a local or relative AppxManifest.xml path seen
  on very few hosts. Common enterprise apps will have higher host counts.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%add-appxpackage%' AND LOWER(process_cmd_line) LIKE '%-register%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_cmd_line) HAVING host_count <= 3 ORDER BY host_count ASC
```

## wwahost-auth-connections
<!-- WWAHost connections to Microsoft Auth -->
Identify the proxy execution behavior where WWAHost reaches out to identity services to initiate sign-in.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, auth_domains=auth_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from WWAHost to Microsoft login domains. This confirms the package
  invoked the WebAuthenticationBroker API.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%wwahost.exe' AND instr(',' || '{{auth_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-malicious-sideload
<!-- Triage malicious sideloading -->
```agent target=hunter
cite: required
context:
- detect-developer-mode-enablement
- rare-package-registration
- wwahost-auth-connections
max_iterations: 5
objective: Determine if the registry changes, the registration of a new AppX package,
  and the WWAHost network activity together indicate a malicious OAuth theft attempt.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows from each surface.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host where a rare package registration is followed by WWAHost network traffic" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-wwahost-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate host and revoke tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Revoke all active Microsoft 365 sessions and refresh tokens for users logged into this host during the identified window.
```
→ analyst-review

## analyst-review
<!-- Analyst review and package audit -->
```manual target=analyst
1. Review the cited registration command and network destinations. 2. Collect the AppxManifest.xml and local package files from the target host. 3. Audit for unauthorized service principals created in the tenant during this window.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the findings. If Developer Mode is not required by policy, recommend disabling it via Group Policy by setting AllowDevelopmentWithoutDevLicense to 0.
```
→ end
