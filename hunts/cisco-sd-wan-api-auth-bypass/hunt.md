---
analysis: A simple detection rule may alert on '%6a_security_check', but this hunt
  uses a gated flow to pivot between URL patterns, software inventory context, and
  administrative login anomalies to differentiate true exploitation from scanner noise.
blind_spots:
- id: no-http-visibility
  question: whether an attacker used multiple layers of encoding or a character not
    covered by simple LIKE patterns
  requires: hb_http_activity with URI decoding
  risk: Attackers can use various hex-encoded representations for characters; without
    full URI normalization before logging, the hunt might miss obfuscated requests.
  stage: api-authentication-bypass
- id: appliance-visibility-gap
  question: whether the 'request admin-tech' command was executed locally
  requires: Endpoint agent on the SD-WAN appliance OS
  risk: Most SD-WAN appliances do not support third-party agents; visibility is limited
    to what the management API logs and the network fabric record.
  stage: administrative-session-access
coverage:
- stage: exposure-discovery
  status: covered
  steps:
  - scoping-vulnerable-inventory
- stage: api-authentication-bypass
  status: covered
  steps:
  - lead-encoded-auth-requests
  - prevalence-of-encoded-uris
- stage: administrative-session-access
  status: covered
  steps:
  - reserved-account-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Active exploitation of a CVSS 9.8 vulnerability in SD-WAN management
    infrastructure constitutes a critical risk to network integrity and traffic privacy.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is bypassing authentication on an internet-exposed Cisco Catalyst
  SD-WAN Manager by using URL-encoded characters in the j_security_check path, gaining
  administrative access through reserved system accounts.
labels:
- hunt
- attack.t1190
- attack.t1078.001
- initial access
name: Cisco SD-WAN Manager API Authentication Bypass
parameters:
  auth_endpoint_pattern:
    default: security_check
    description: Path fragment common to the SD-WAN authentication endpoint.
    from:
      kind: article
      observed: '2026-09-30'
      ref: rapid7-cve-2026-76504
    type: string
  lookback_days:
    default: '14'
    description: Days of activity to examine.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: hunt-standard
    type: number
  reserved_user_prefix:
    default: viptela-reserved-
    description: User prefix used by system processes that is hijacked during exploitation.
    from:
      kind: article
      observed: '2026-09-30'
      ref: rapid7-cve-2026-76504
    type: string
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the impact triage; leave empty
      to check the whole estate.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: scoping-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing Cisco SD-WAN Manager instances. Use the results
  of the software inventory step to narrow subsequent triage to confirmed vulnerable
  versions.
references:
- name: "Rapid7 \u2014 Critical Cisco Catalyst SD-WAN Manager API authentication bypass\
    \ exploited in the wild (CVE-2026-76504)"
  url: https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504
related:
- hunt: cisco-sd-wan-vdaemon-bypass
  reason: CVE-2026-20127 and CVE-2026-20182 affect the vdaemon peering service rather
    than the Manager API authentication path.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Internet-Exposed Vulnerable SD-WAN Manager
    observables:
    - Cisco Catalyst SD-WAN Manager
    - Vulnerable software versions 20.9.x, 20.12.x, 20.15.x, 20.18.x
    - Internet-exposed management ports
    slug: exposure-discovery
    tactic: initial-access
    techniques:
    - T1190
  - name: URL-Encoded API Bypass
    observables:
    - HTTP POST /%6a_security_check
    - URL encoded j_security_check path
    - Encoded characters in API authentication URI
    slug: api-authentication-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Admin Access via Reserved Accounts
    observables:
    - Usernames starting with viptela-reserved-
    - Execution of request admin-tech command
    - Privileged administrative access to vManage API
    slug: administrative-session-access
    tactic: initial-access
    techniques:
    - T1078.001
  summary: Remote unauthenticated attackers exploit CVE-2026-76504 in internet-facing
    Cisco Catalyst SD-WAN Manager instances by using URL-encoded paths to bypass API
    authentication rules. Successful exploitation grants administrative privileges,
    typically identified by authentication logs using reserved system usernames and
    the potential execution of diagnostic commands.
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


# Cisco SD-WAN Manager API Authentication Bypass

This hunt follows a gated flow to identify exploitation of CVE-2026-76504. The hunt first searches for anomalous URL-encoded HTTP POST requests targeting the SD-WAN authentication endpoint. If suspicious activity is confirmed, the hunt fans out to verify host vulnerability, check the prevalence of the encoded URI across the fleet, and detect logins from reserved viptela-reserved- accounts. An agent then synthesizes this evidence to identify confirmed compromises.

## lead-encoded-auth-requests
<!-- Encoded API Authentication Requests -->
Identify potential authentication bypass attempts using URL encoding in the security check URI.

```sqlite target=web role=detection-candidate params=(auth_endpoint_pattern=auth_endpoint_pattern, lookback_days=lookback_days)
~~~yaml
expected: A request with an encoded character in the path (e.g., %6a for j). Silence
  proves no such requests were logged during the window.
reads:
- device_hostname
- http_method
- src_endpoint_ip
- time
- url_path
- user_agent
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, src_endpoint_ip, http_method, url_path, user_agent, time FROM hb_http_activity WHERE http_method = 'POST' AND LOWER(url_path) LIKE '%#%%' ESCAPE '#' AND LOWER(url_path) LIKE '%' || LOWER('{{auth_endpoint_pattern}}') || '%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Bypass Lead -->
```agent target=hunter
cite: required
context:
- lead-encoded-auth-requests
max_iterations: 3
objective: Determine if the URL encoded path segments represent attempts to bypass
  the API authentication rules.
success_criteria: A per-host verdict citing the specific HTTP request rows.
tools:
- endpoint
- identity
- web
```

## gate-on-bypass
<!-- Gate: Suspected Bypass Found? -->
if~: "the evaluate-lead verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → verify-impact-parallel
indeterminate: → manual-forensics-review
unavailable: → manual-forensics-review (blind_spot: no-http-visibility)
else: → close-out-report

## verify-impact-parallel
<!-- Verify Impact and Rarity -->
parallel:
- → scoping-vulnerable-inventory
- → prevalence-of-encoded-uris
- → reserved-account-activity
join: → triage-compromise

## scoping-vulnerable-inventory
<!-- Vulnerable Software Inventory -->
Confirm the targeted hosts are running vulnerable Cisco Catalyst SD-WAN Manager versions.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Identification of vulnerable appliances. Absence means either the software
  is patched or not present.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%sd-wan manager%' OR LOWER(package_name) LIKE '%vmanage%') AND (package_version LIKE '20.9%' OR package_version LIKE '20.12%' OR package_version LIKE '20.15%' OR package_version LIKE '20.18%' OR package_version LIKE '26.1%')
```

## prevalence-of-encoded-uris
<!-- Prevalence of Encoded URI Paths -->
Stack-count the encoded URI paths across the fleet to highlight outliers.

```sqlite target=web role=baseline params=(auth_endpoint_pattern=auth_endpoint_pattern, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Encoded paths seen on only a few hosts indicate targeted exploitation attempts.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 2
reads:
- device_hostname
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT url_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE url_path LIKE '%#%%' ESCAPE '#' AND url_path LIKE '%' || LOWER('{{auth_endpoint_pattern}}') || '%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_path
```

## reserved-account-activity
<!-- Reserved Account Sign-ins -->
Search for sign-in activity using reserved accounts on hosts where a bypass attempt was detected.

```sqlite target=identity role=triage params=(reserved_user_prefix=reserved_user_prefix, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A successful sign-in by a reserved user. Silence does not rule out exploitation
  if the attacker used a different account.
reads:
- activity_name
- actor_user_name
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, activity_name, status_id, time FROM hb_auth_signin WHERE (LOWER(actor_user_name) LIKE LOWER('{{reserved_user_prefix}}') || '%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage Compromise Verdict -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- scoping-vulnerable-inventory
- prevalence-of-encoded-uris
- reserved-account-activity
max_iterations: 5
objective: Confirm active exploitation by correlating encoded URI bypasses with vulnerable
  software versions and subsequent reserved account logons.
success_criteria: A verdict of malicious for any host showing both the bypass lead
  and subsequent reserved account usage.
tools:
- endpoint
- identity
- web
```

## route-final-verdict
<!-- Route Final Verdict -->
if~: "the triage-compromise verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-forensics-review
unavailable: → manual-forensics-review (blind_spot: appliance-visibility-gap)
else: → manual-forensics-review

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified SD-WAN Manager host from the network and revoke any active administrative sessions associated with the attacker's source IP.
```
→ manual-forensics-review

## manual-forensics-review
<!-- Manual Forensics and Log Review -->
```manual target=analyst
Log into the affected SD-WAN Manager and review /var/log/nms/containers/service-proxy/serviceproxy-access.log for encoded characters in the j_security_check path. Check /var/log/nms/vmanage-server.log for viptela-reserved- accounts and use the 'request admin-tech' command to generate diagnostic files.
```
→ close-out-report

## close-out-report
<!-- Hunt Close-out and Patching -->
```manual target=analyst
Summarize the hosts examined and any compromises found. Ensure all identified vulnerable SD-WAN Managers are scheduled for upgrade to a fixed release (e.g., 20.15.6.1 or 20.18.4.1).
```
→ end
