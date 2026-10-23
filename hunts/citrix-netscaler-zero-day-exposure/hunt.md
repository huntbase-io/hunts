---
analysis: A standard detection rule would look for a single static URI; this hunt
  uses prevalence counting to find rare management activity across specialized appliances
  and correlates it with anomalous process spawning, which a single-surface rule cannot
  do.
blind_spots:
- id: appliance-http-log-gap
  question: Whether the specific exploit URI reached the management interface
  requires: Citrix NetScaler native HTTP logs integrated into hb_http_activity
  risk: If the appliance is not logging to the central collector, web-based exploitation
    attempts will be missed.
  stage: exploitation-for-remote-code-execution
- id: appliance-process-visibility-gap
  question: Whether post-exploitation shell commands were run locally on the appliance
  requires: Process-level telemetry from the NetScaler OS
  risk: Proprietary appliances often lack standard EDR agents, making in-memory or
    shell-based activity invisible.
  stage: exploitation-for-remote-code-execution
- id: appliance-telemetry-blind-spot
  question: Can the decision agent confirm a clean status?
  requires: Full appliance telemetry (process, network listener, file)
  risk: Incomplete data from appliances makes a negative result less certain, potentially
    masking a successful intrusion.
coverage:
- stage: vulnerability-assessment-and-exposure
  status: covered
  steps:
  - find-vulnerable-appliances
- stage: exploitation-for-remote-code-execution
  status: covered
  steps:
  - rare-management-traffic
  - unexpected-shell-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The identified Citrix zero-days are critical vulnerabilities already
    listed in the CISA KEV catalog. As these appliances sit on the network edge and
    manage access, a successful exploit provides immediate initial access. A negative
    result confirms that patching is safe and not a disruption of an ongoing incident.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting zero-day remote code execution vulnerabilities
  in Citrix NetScaler appliances, characterized by anomalous HTTP requests to management
  interfaces followed by the execution of unauthorized shell commands.
labels:
- hunt
- attack.t1190
- initial access
name: Citrix NetScaler Zero-Day Exposure
parameters:
  citrix_cves:
    default:
    - CVE-2026-88771
    - CVE-2026-88772
    - CVE-2026-88773
    - CVE-2026-88774
    - CVE-2026-88775
    - CVE-2026-88776
    - CVE-2026-88777
    - CVE-2026-88778
    description: CVE identifiers from the CISA advisory.
    from:
      kind: article
      observed: '2026-09-27'
      ref: cisa-advisories
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for behavioural telemetry.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of Citrix appliances identified in the first step; leave
      empty to scan all hosts.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Begin by identifying all appliances via vulnerability findings. If the
  finding surface is empty, fallback to hb_software_inventory for any package containing
  netscaler. The analyst should then use the resulting hostnames to populate the scope_hosts
  parameter for behavioural queries.
references:
- name: 'CISA Alert: Critical Zero-Day Vulnerabilities Exploited in Citrix NetScaler
    ADC, Gateway'
  url: https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway
related:
- hunt: citrix-gateway-brute-force
  reason: This hunt focuses on RCE exploitation; password spray or brute force against
    the gateway requires hb_auth_signin analysis.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Identification of Vulnerable NetScaler Appliances
    observables:
    - Citrix NetScaler ADC
    - Citrix NetScaler Gateway
    - CVE-2026-88771
    - CVE-2026-88772
    - CVE-2026-88773
    - CVE-2026-88774
    - CVE-2026-88775
    - CVE-2026-88776
    - CVE-2026-88777
    - CVE-2026-88778
    slug: vulnerability-assessment-and-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Remote Code Execution via Zero-Day Exploitation
    observables:
    - CVE-2026-88771
    - CVE-2026-88772
    - Web-based exploitation attempts targeting Citrix NetScaler management or gateway
      interfaces
    slug: exploitation-for-remote-code-execution
    tactic: initial-access
    techniques:
    - T1190
  summary: Threat actors are actively exploiting eight zero-day vulnerabilities in
    Citrix NetScaler ADC and Gateway appliances, most notably CVE-2026-88771 and CVE-2026-88772,
    to achieve remote code execution. The campaign is global and affects critical
    internet-facing infrastructure used for load balancing and remote access.
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


# Citrix NetScaler Zero-Day Exposure

The adversary exploits eight critical vulnerabilities in Citrix NetScaler ADC and Gateway (CVE-2026-88771 through CVE-2026-88778) to gain initial access. These flaws allow for unauthenticated remote code execution and are actively being exploited globally. The hunt identifies vulnerable assets, then analyzes web traffic for rare URI patterns that deviate from normal administrative use. Finally, the analyst searches for evidence of post-exploitation activity such as shell spawning or network utility usage on the appliances to confirm the absence of compromise before remediation begins.

## find-vulnerable-appliances
<!-- Identify vulnerable NetScaler appliances -->
Identify every host with an active vulnerability finding for the 2026 Citrix zero-days to define the hunt scope.

```sqlite target=endpoint role=scoping params=(citrix_cves=citrix_cves)
~~~yaml
expected: A list of resource IDs that are vulnerable. Silence indicates no known vulnerable
  Citrix appliances are currently reporting findings.
reads:
- cve_uid
- resource_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT resource_uid, cve_uid, severity FROM hb_vulnerability_finding WHERE instr(',' || '{{citrix_cves}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed'
```

## rare-management-traffic
<!-- Anomalous requests to management interfaces -->
Stack-count HTTP request paths on the scoped appliances to find rare URIs that deviate from normal administrative traffic.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare URI paths targeted at appliance management or VPN login endpoints.
  Silence suggests no unusual traffic was captured within the window.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 20
reads:
- device_hostname
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, url_path, COUNT(*) AS request_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(url_path) LIKE '/mgmt/%' OR LOWER(url_path) LIKE '/logon/%' OR LOWER(url_path) LIKE '/vpn/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path HAVING request_count < 20 ORDER BY request_count ASC
```

## unexpected-shell-activity
<!-- Evidence of shell or utility execution -->
Identify the execution of shells or network utilities on the Citrix hosts, which would indicate successful code execution.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Execution of standard Unix shells or downloaders on a specialized appliance.
  These are rarely used in normal production operations on NetScaler.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/python%' OR LOWER(process_cmd_line) LIKE '%curl %' OR LOWER(process_cmd_line) LIKE '%wget %' OR LOWER(process_cmd_line) LIKE '%nc %') AND time >= datetime('now', '-{{lookback_days}} days')
```

## exposure-assessment
<!-- Assess appliance exposure and compromise -->
```agent target=hunter
cite: required
context:
- find-vulnerable-appliances
- rare-management-traffic
- unexpected-shell-activity
max_iterations: 5
objective: Decide whether any Citrix host shows signs of exploitation by correlating
  rare HTTP requests with subsequent shell activity.
success_criteria: A per-host verdict citing specific rows from HTTP or process activity.
tools:
- endpoint
- web
```

## triage-decision
<!-- Route on assessment -->
if~: "The exposure-assessment verdict is malicious or suspicious for at least one host." (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: appliance-telemetry-blind-spot)
else: → standard-patching

## remediation-review
<!-- Forensic preservation and IR -->
```manual target=analyst
Compromise is suspected. Do not apply updates immediately as they may destroy forensic data. 1. Capture memory and disk images of the affected NetScaler appliance. 2. Verify all local accounts and rotate administrative credentials. 3. Review the NetScaler Console for additional IOCs. 4. Escalate to the IR team for deep packet analysis of captured management traffic.
```
→ end

## standard-patching
<!-- Standard patch deployment -->
```manual target=analyst
No indicators of exploitation were found. Proceed with standard patching of the Citrix appliances following the vendor's security bulletin for CVE-2026-88771 through CVE-2026-88778. Document the hunt results as a baseline for future activity.
```
→ end
