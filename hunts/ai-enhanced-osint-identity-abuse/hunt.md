---
analysis: A single rule might catch a web shell, but this hunt correlates vulnerability
  inventory, external exposure, and anomalous sign-in patterns to identify the full
  lifecycle of an AI-enhanced campaign.
blind_spots:
- id: deepfake-telemetry-gap
  question: whether the phishing attempt used AI-generated deepfake audio calls
  requires: VoIP or voice log analysis
  risk: Social engineering conducted over voice or video cannot be detected via current
    endpoint or cloud telemetry.
  stage: personalized-phishing-and-social-engineering
- id: unmanaged-infra-gap
  question: whether exploitation occurred on shadow-IT or unmanaged servers
  requires: Complete EDR coverage on all web servers
  risk: Exploitation of servers missing an agent will show up in HTTP logs but will
    not show follow-on process activity.
  stage: vulnerability-discovery-and-exploitation
coverage:
- stage: vulnerability-discovery-and-exploitation
  status: covered
  steps:
  - scoping-vulnerable-assets
  - probing-activity
  - exposed-services
- reason: Covered via the outcome of successful phishing (account takeover).
  stage: personalized-phishing-and-social-engineering
  status: covered
  steps:
  - anomalous-signins
- stage: credential-harvesting-and-malware-execution
  status: covered
  steps:
  - shell-execution
  - anomalous-signins
- stage: bec-and-fraudulent-impact
  status: covered
  steps:
  - anomalous-signins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI allows adversaries to scale personalized fraud and vulnerability
    research; confirming these targeted efforts have not transitioned into active
    breaches is a critical hygiene task.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using AI-automated OSINT to identify vulnerable web applications
  and craft high-fidelity phishing lures, leading to server exploitation and account
  takeover for fraud.
labels:
- hunt
- attack.t1190
- attack.t1566
- credential access
- impact
- initial access
name: AI-Enhanced OSINT and Identity Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus the hunt; leave empty for all hosts.
    type: list[host]
  shell_paths:
    default:
    - cmd.exe
    - powershell.exe
    - sh
    - bash
    description: Shell processes to monitor for spawns from web servers.
    type: list[path]
  target_cves:
    default:
    - CVE-2024-21887
    - CVE-2023-46604
    - CVE-2023-22515
    description: Critical CVEs prioritized by automated scanners.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/privacy/ai-powered-osint-why-everyone-viable-target-fraud/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing web servers and employees in high-value roles
  (Finance, HR, C-suite) who are the primary targets of AI-automated OSINT.
references:
- name: "ESET Research \u2014 AI-driven OSINT in the wrong hands"
  url: https://www.welivesecurity.com/en/privacy/ai-powered-osint-why-everyone-viable-target-fraud/
related:
- hunt: social-media-privacy-audit
  reason: This hunt focuses on technical compromise, not the proactive auditing of
    employee social media privacy.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Aided Vulnerability Exploitation
    observables:
    - Automated identification of internet-facing vulnerabilities
    - Exploitation of public-facing software bugs or misconfigurations
    slug: vulnerability-discovery-and-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: AI-Driven Personalized Phishing
    observables:
    - Phishing emails containing personal details (workplace, schools, birthdays,
      recent travel)
    - Malicious links in emails or social media
    - Deepfake video or voice calls impersonating victims
    - Social engineering scripts designed by LLMs
    slug: personalized-phishing-and-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Credential Harvesting and Malware Execution
    observables:
    - Logins to fraudulent credential harvesting pages
    - Installation of malware via malicious email attachments or links
    - Execution of suspicious binary or script payloads
    slug: credential-harvesting-and-malware-execution
    tactic: credential-access
    techniques:
    - T1566
  - name: Business Email Compromise and Fraud
    observables:
    - Anomalous sign-ins using harvested work credentials
    - Business Email Compromise (BEC) targeting colleagues
    - Fraudulent financial requests or sextortion threats
    slug: bec-and-fraudulent-impact
    tactic: impact
    techniques:
    - T1566
  summary: Threat actors are leveraging AI to automate OSINT at scale, creating highly
    personalized phishing and social engineering campaigns by profiling victims' personal
    and professional lives. This AI-driven pipeline facilitates more convincing deepfakes,
    credential harvesting, and Business Email Compromise (BEC) attacks by lowering
    the technical barrier for fraudsters.
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


# AI-Enhanced OSINT and Identity Abuse

This hunt identifies the transition from automated external reconnaissance to active internal breach. It first scopes vulnerable and exposed assets that AI scanners prioritize, then evaluates suspicious HTTP activity. A second phase hunts for the outcome: web shells spawned from server processes and anomalous user sign-ins from rare locations indicating credential theft. An agent correlates these phases to identify successful AI-enhanced social engineering campaigns.

## scoping-vulnerable-assets
<!-- Scope vulnerable internet-facing assets -->
Identify hosts with critical vulnerabilities that AI-assisted reconnaissance would likely discover and exploit.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of vulnerable hosts. Silence indicates no known critical vulnerabilities
  are currently reported.
reads:
- device_uid
- cve_uid
- affected_package_name
- severity
- last_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_uid, cve_uid, affected_package_name, severity, last_seen FROM hb_vulnerability_finding WHERE severity_id >= 4 AND (instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0 OR is_kev = 'true')
```

## early-access-parallel
<!-- Parallel scan for initial access signals -->
parallel:
- → probing-activity
- → exposed-services
join: → early-stage-triage

## probing-activity
<!-- Suspicious HTTP exploitation probing -->
Detect automated POST requests to web applications that suggest vulnerability exploitation attempts.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A high volume of successful POSTs from a single IP to a specific path, suggesting
  automated exploitation.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, src_endpoint_ip, LOWER(url_path) AS path, status_code, COUNT(*) AS req_count FROM hb_http_activity WHERE http_method = 'POST' AND status_code = 200 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, LOWER(url_path) HAVING req_count > 50
```

## exposed-services
<!-- Exposed administrative services -->
Identify internet-exposed RDP, SSH, or SMB ports which AI-driven scanners prioritize for breach attempts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Company IP addresses exposing administrative ports. Rare ports indicate
  potential misconfigurations.
prevalence:
  by: domain_or_ip
  key:
  - port
  rare_below: 2
reads:
- domain_or_ip
- port
- product
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT domain_or_ip, port, product, discovered_at FROM hb_exposed_assets WHERE port IN (22, 445, 3389) AND discovered_at >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early-stage access signals -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-assets
- probing-activity
- exposed-services
max_iterations: 3
objective: Determine which hosts are actively being probed or targeted based on vulnerability
  and exposure data.
success_criteria: A statement identifying specific hosts at risk of initial access.
tools:
- endpoint
- identity
- web
```

## follow-on-parallel
<!-- Hunt for execution and credential abuse -->
parallel:
- → shell-execution
- → anomalous-signins
join: → impact-assessment

## shell-execution
<!-- Web servers spawning shell processes -->
Detect T1190 follow-on activity where an exploited web application executes a shell. The query handles full paths by matching the shell basename.

```sqlite target=endpoint role=detection-candidate params=(shell_paths=shell_paths, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing a web server process as the parent of a shell like cmd.exe
  or bash.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%httpd%' OR LOWER(parent_process_name) LIKE '%nginx%' OR LOWER(parent_process_name) LIKE '%w3wp.exe%') AND (instr(',' || '{{shell_paths}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\powershell.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## anomalous-signins
<!-- Anomalous user sign-ins with geographic context -->
Find users signing in from IPs that are rare for their account, including country data for immediate triage.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Sign-in events from IPs only seen once or twice for a given user, potentially
  in unexpected countries.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, MIN(time) AS first_seen, COUNT(*) AS login_count FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, src_location_country HAVING login_count < 5
```

## impact-assessment
<!-- Final assessment of campaign impact -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- shell-execution
- anomalous-signins
max_iterations: 5
objective: 'Determine if current telemetry indicates a successful intrusion or account
  takeover following AI-based reconnaissance. Note: reconcile the device_uid from
  the scoping step with the device_hostname used in later steps to ensure accurate
  cross-surface correlation.'
success_criteria: A per-host and per-user verdict citing specific process or sign-in
  events.
tools:
- endpoint
- identity
- web
```

## route-on-impact
<!-- Route on verdict -->
if~: "the impact-assessment verdict is malicious for at least one host or user account" (confidence: high, judge=hunter)
then: → contain-threat
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: unmanaged-infra-gap)
else: → close-out-benign

## contain-threat
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host from the network and revoke all active sessions for the identified user in the identity provider.
```
→ analyst-review

## analyst-review
<!-- Review triage and confirm breach -->
```manual target=analyst
Review the shell spawn command lines and the source IPs of anomalous logins. Confirm if the activity aligns with a personalized phishing or exploit campaign.
```
→ final-documentation

## close-out-benign
<!-- Close-out benign findings -->
```manual target=analyst
Record the evidence of absence and document the status of vulnerable/exposed assets for remediation.
```
→ end

## final-documentation
<!-- Final documentation -->
```manual target=analyst
Record patches needed for exploited servers and update the social engineering awareness training for targeted users.
```
→ end
