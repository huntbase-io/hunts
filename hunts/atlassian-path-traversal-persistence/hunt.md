---
analysis: A standard rule might fire on the path traversal sequence; this hunt correlates
  that request with a rare administrative group change on the same host and checks
  software inventory to confirm a successful breach rather than just a failed scan.
blind_spots:
- id: http-log-blindness
  question: whether complex URL encoding or WAF normalization bypassed the string
    matching
  requires: decrypted full-path HTTP logs
  risk: An attacker using double-URL encoding might bypass the detect-traversal-attempts
    query if the log source does not normalize the URL before writing it.
  stage: unauthenticated-path-traversal
- id: identity-log-gaps
  question: whether group changes occurred on hosts not reporting to the identity
    surface
  requires: hb_group_management with complete coverage of Atlassian user databases
  risk: Persistence via a local Atlassian user database that does not emit standard
    OS group management logs would not be visible.
  stage: identity-manipulation-persistence
coverage:
- stage: vulnerability-exposure-assessment
  status: covered
  steps:
  - check-software-vulnerability
- stage: unauthenticated-path-traversal
  status: covered
  steps:
  - detect-traversal-attempts
- stage: identity-manipulation-persistence
  status: covered
  steps:
  - check-admin-group-changes
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: CVE-2026-21589 allows unauthenticated remote access to sensitive
    configuration files like crowd.properties, which often contain plaintext credentials.
    This exposure directly enables persistence through administrative account creation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthenticated attacker is using double-colon path traversal to read
  Atlassian configuration files and then creating administrative accounts for persistence.
labels:
- hunt
- attack.t1190
- attack.t1136
- attack.t1098
- initial access
- persistence
name: Atlassian Path Traversal and Administrative Persistence
parameters:
  admin_groups:
    default:
    - jira-administrators
    - confluence-administrators
    - crowd-administrators
    description: Atlassian administrative groups that attackers may target for persistence.
    from:
      kind: manual
      ref: Atlassian default groups
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the entire
      estate.
    type: list[host]
  traversal_patterns:
    default:
    - crowd.properties
    - urlrewrite.xml
    - WEB-INF
    description: Specific Atlassian configuration files and directories targeted by
      attackers.
    from:
      kind: article
      observed: '2026-10-07'
      ref: Rapid7 ETR CVE-2026-21589
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-21589-critical-unauthenticated-arbitrary-file-access-in-atlassian-products
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing servers identified as running Atlassian Data
  Center products. The hunt automates correlation between HTTP traversal leads and
  identity persistence checks on those specific hosts.
references:
- name: "Rapid7 \u2014 CVE-2026-21589: Critical unauthenticated arbitrary file access\
    \ in Atlassian products"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-21589-critical-unauthenticated-arbitrary-file-access-in-atlassian-products
related:
- hunt: atlassian-rce-credential-reuse
  reason: This hunt focuses on file-read and administrative persistence; a subsequent
    RCE using the stolen credentials would involve process execution and belongs to
    a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Atlassian Vulnerability Exposure
    observables:
    - Bitbucket Data Center versions < 9.4.26
    - Confluence Data Center versions < 9.2.26
    - Jira Software Data Center versions < 9.12.40
    - Crowd Data Center versions < 6.3.7
    - Fisheye/Crucible versions < 4.9.15
    slug: vulnerability-exposure-assessment
    tactic: initial-access
    techniques:
    - T1190
  - name: Path Traversal via Double-Colon Sequences
    observables:
    - '::'
    - ..
    - '%252e%252e'
    - '%253a%253a'
    - WEB-INF/classes/crowd.properties
    - urlrewrite.xml
    - Tomcat RewriteValve
    slug: unauthenticated-path-traversal
    tactic: initial-access
    techniques:
    - T1190
  - name: Account Creation and Privilege Escalation
    observables:
    - jira-administrators
    - Atlassian Crowd user creation
    - application credentials in crowd.properties
    slug: identity-manipulation-persistence
    tactic: persistence
    techniques:
    - T1136
    - T1098
  summary: Unauthenticated remote attackers exploit CVE-2026-21589 in Atlassian Data
    Center products by using double-colon (::) sequences as path separators to read
    sensitive configuration files like crowd.properties. Once credentials are stolen,
    they can be used to create new users and elevate privileges by adding them to
    the jira-administrators group.
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


# Atlassian Path Traversal and Administrative Persistence

This hunt identifies unauthenticated path traversal attempts targeting Atlassian Data Center products and correlates them with subsequent identity manipulation. It follows a gated flow: a lead query identifies high-confidence traversal patterns in HTTP logs, followed by an agent evaluation. If the lead is valid, the hunt fans out to assess the software vulnerability status of those hosts and detect any unauthorized additions to administrative groups.

## detect-traversal-attempts
<!-- Detect Atlassian traversal attempts -->
Identify HTTP requests containing double-colon traversal sequences or attempts to access known Atlassian configuration files.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, traversal_patterns=traversal_patterns, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests showing double-colon sequences (::..) or paths containing
  WEB-INF or crowd.properties. Status code 200 suggests a successful file read.
reads:
- device_hostname
- src_endpoint_ip
- url_full
- status_code
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, status_code, user_agent, time FROM hb_http_activity WHERE (LOWER(url_full) LIKE '%::..%' OR LOWER(url_full) LIKE '%..::%' OR LOWER(url_full) LIKE '%::/..%' OR LOWER(url_full) LIKE '%..%253a%253a%' OR instr(',' || '{{traversal_patterns}}' || ',', ',' || LOWER(url_full) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate traversal lead -->
```agent target=hunter
cite: required
context:
- detect-traversal-attempts
max_iterations: 3
objective: Determine if the HTTP requests in detect-traversal-attempts show malicious
  intent to exploit Atlassian path traversal vulnerabilities.
success_criteria: A clear verdict on whether to proceed with the full investigation.
tools:
- endpoint
- web
```

## gate-decision
<!-- Gate decision -->
if~: "the evaluate-lead verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: http-log-blindness)
else: → close-out

## parallel-investigation
<!-- Parallel investigation -->
parallel:
- → check-software-vulnerability
- → check-admin-group-changes
join: → triage-breach

## check-software-vulnerability
<!-- Check Atlassian software vulnerability -->
Verify if the hosts targeted by traversal attempts are running affected Atlassian products.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of Atlassian software and versions. Comparison with the advisory
  confirms whether the host is vulnerable.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%jira%' OR LOWER(package_name) LIKE '%confluence%' OR LOWER(package_name) LIKE '%bitbucket%' OR LOWER(package_name) LIKE '%crowd%' OR LOWER(package_name) LIKE '%bamboo%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## check-admin-group-changes
<!-- Check rare admin group changes -->
Search for administrative group changes on the target hosts, highlighting rare additions that may indicate persistence.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, admin_groups=admin_groups, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Additions to groups like jira-administrators seen only on a few hosts. High
  frequency on one host with a traversal lead is a strong indicator of compromise.
prevalence:
  by: device_hostname
  key:
  - group_name
  - user_name
  - activity_name
  rare_below: 3
reads:
- device_hostname
- group_name
- user_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_group_management
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, group_name, user_name, activity_name, MIN(time) AS first_seen, COUNT(DISTINCT device_hostname) AS host_count FROM hb_group_management WHERE (LOWER(group_name) LIKE '%admin%' OR LOWER(group_name) LIKE '%atlassian%' OR instr(',' || '{{admin_groups}}' || ',', ',' || LOWER(group_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, group_name, user_name, activity_name HAVING host_count <= 2
```

## triage-breach
<!-- Triage breach verdict -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- check-software-vulnerability
- check-admin-group-changes
max_iterations: 6
objective: Determine if the observed traversal attempts resulted in a successful compromise,
  evidenced by unpatched software and unauthorized administrative changes.
success_criteria: A comprehensive per-host verdict citing evidence from all three
  surfaces.
tools:
- endpoint
- web
```

## route-response
<!-- Route response -->
if~: "the triage-breach verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-breach
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: identity-log-gaps)
else: → analyst-review

## contain-breach
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke all credentials that might have been stored in crowd.properties or urlrewrite.xml and force a password reset for all members of the identified administrative groups.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the traversal leads and the group changes. Confirm if the Atlassian product was internet-facing and if any Crowd IP allowlist was bypassed.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Log the hosts examined and the software versions found. If no malicious activity was identified, confirm that all vulnerable instances have been patched to the versions listed in the advisory.
```
→ end
