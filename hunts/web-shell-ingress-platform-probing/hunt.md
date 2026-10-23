---
analysis: 'A single rule for file creation in MemberFiles is prone to noise if users
  legitimately upload misnamed files. This hunt provides the forensic chain: the boundary
  probe, then the authentication anomaly from the same IP, then the file write. Correlating
  across three surfaces confirms the adversarial intent.'
blind_spots:
- id: missing-iis-logs
  owner: Infrastructure Team
  question: Whether the probes were received by the server
  remediation: Enable IIS W3C logging with URI Stem, URI Query, and Method fields
    for all public-facing application servers.
  requires: hb_http_activity logs from the web server
  risk: If W3C logging is disabled or hb_http_activity is not ingested, the initial
    probing lead will be lost, and the source IP correlation will fail.
  stage: web-application-probing-and-brute-force
- id: no-file-content-visibility
  owner: Security Engineering
  question: What functionality was contained within the uploaded file
  remediation: Implement an EDR with file content analysis or a WAF that logs the
    body of multipart/form-data uploads.
  requires: File content inspection or WAF logs
  risk: Metadata alone cannot distinguish a functional web shell from a benign file
    misnamed by a user without manual forensic inspection.
  stage: webshell-ingress-via-member-upload
coverage:
- stage: web-application-probing-and-brute-force
  status: covered
  steps:
  - identify-targeted-web-servers
  - brute-force-sign-ins
- stage: webshell-ingress-via-member-upload
  status: covered
  steps:
  - web-shell-file-creations
- reason: Belongs to another part of the 'Determined Attacker Uploads Malicious Webshells
    to Parks and Rec Management Platform Servers' series.
  stage: web-worker-shell-execution
  status: out_of_scope
- reason: Belongs to another part of the 'Determined Attacker Uploads Malicious Webshells
    to Parks and Rec Management Platform Servers' series.
  stage: iis-and-web-environment-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'Determined Attacker Uploads Malicious Webshells
    to Parks and Rec Management Platform Servers' series.
  stage: payment-data-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Identifying the ingress of web shells on municipal servers prevents
    the mass harvesting of payment and cardholder data. A negative result confirms
    the integrity of the application boundary for the recreational platform.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited a file upload vulnerability to drop web shells
  in member-facing directories after probing the application boundary and brute-forcing
  credentials.
labels:
- hunt
- attack.t1110
- attack.t1190
- attack.t1505.003
- collection
- discovery
- execution
- initial access
name: Web Shell Ingress and Platform Probing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Target web servers to narrow the search; leave empty to scan the
      entire estate.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: analyst-defined
    type: list[host]
  webshell_indicators:
    default:
    - aa7d-4056-8061-8f32887196b9.aspx
    - 5893-4e83-a45c-188a5e4686fd.aspx
    - 2ae9-4d05-ae6d-ad10ccf25ed9.aspx
    - ed12-4938-9661-f4034526d911.aspx
    - 8362-42b6-8906-4a33eaaa4bb0.aspx
    - 5ef0-4da3-b162-01844bf0109e.aspx
    description: Specific web shell filenames observed in the report.
    from:
      kind: article
      observed: '2026-09-30'
      ref: huntress-parks-rec
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/parks-recreation-platform-webshell-attack
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on Windows servers running IIS that host the Parks and Recreation
  management platform. Narrow the lookback to the last 14 days and prioritize hosts
  exhibiting high-frequency OPTIONS requests or tilde characters in URIs.
references:
- name: "Huntress \u2014 Determined Attacker Uploads Malicious Webshells to Parks\
    \ and Rec Management Platform Servers"
  url: https://www.huntress.com/blog/parks-recreation-platform-webshell-attack
related:
- hunt: web-worker-shell-execution
  reason: This hunt focuses on ingress; the follow-on hunt examines command execution
    by the IIS worker process after the shell is established.
  relation: follows
scenario:
  stages:
  - name: Web Application Probing and Brute Force
    observables:
    - POST /management/login.aspx
    - POST /info/household/login.aspx
    - GET /a*~1* (IIS 8.3 tilde enumeration)
    - WebDAV OPTIONS method
    - Upload.ashx::$DATA
    - FileUpload.ashx::$DATA
    slug: web-application-probing-and-brute-force
    tactic: initial-access
    techniques:
    - T1110
    - T1190
  - name: Webshell Ingress via Member Upload
    observables:
    - 'Path: /documents/MemberFiles/'
    - aa7d-4056-8061-8f32887196b9.aspx
    - 5893-4e83-a45c-188a5e4686fd.aspx
    - 2ae9-4d05-ae6d-ad10ccf25ed9.aspx
    - ed12-4938-9661-f4034526d911.aspx
    - 8362-42b6-8906-4a33eaaa4bb0.aspx
    - 5ef0-4da3-b162-01844bf0109e.aspx
    - 791a-4e96-a5ea-e5c7cfd35fd2.jpg
    slug: webshell-ingress-via-member-upload
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
  - name: Web-Worker Shell Execution
    observables:
    - Parent process w3wp.exe spawning cmd.exe
    - Parent process w3wp.exe spawning powershell.exe
    - cmd.exe /c whoami
    - cmd.exe /c net user
    - cmd.exe /c wmic process where "name='w3wp.exe'" get ProcessId,CommandLine
    - Import-Module WebAdministration; Get-Website
    slug: web-worker-shell-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: IIS and Web Environment Discovery
    observables:
    - appcmd.exe list sites
    - appcmd.exe list vdirs
    - appcmd.exe list app
    - dir /b E:\Content\info\App_Code\*DB*
    - dir /b E:\Content\info\App_Code\*Sql*
    - C:\inetpub\temp\appPools
    - C:\Windows\System32\drivers\etc\hosts
    slug: iis-and-web-environment-discovery
    tactic: discovery
    techniques:
    - T1083
  - name: Payment Data Harvesting
    observables:
    - findstr /i /c:"connectionString" /c:"password" /c:"Data Source" E:\Content\info\web.config
    - findstr /s /i /m /c:"CVV" /c:"CardNumber" /c:"CreditCard" E:\Content\info\*.aspx
    - findstr /s /i /m "AuthorizeNet Fortis CardConnect BluePay PayPal Braintree Stripe"
    - type E:\Content\info\_fortis\Webhooks\*.txt
    - findstr /i "exp_date exp_month exp_year expiration cvv first_six last_four card_number"
    slug: payment-data-harvesting
    tactic: collection
    techniques:
    - T1505.003
  summary: A threat actor, likely based in China, compromised multiple instances of
    a parks and recreation management platform by abusing a legitimate member registration
    and file upload feature to plant ASPX webshells. Once established, the attacker
    performed extensive reconnaissance of the IIS environment and local file system,
    specifically targeting configuration files and Fortis webhook logs to steal payment
    card data and credentials.
series:
  index: 1
  slug: determined-attacker-uploads-malicious-webshells-to-parks-and-rec-management-platform-servers
  title: Determined Attacker Uploads Malicious Webshells to Parks and Rec Management
    Platform Servers
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


# Web Shell Ingress and Platform Probing

The adversary attempts to breach the web application by probing for vulnerabilities and brute-forcing login pages. This hunt identifies these initial stages by correlating external probing activity with illegitimate file creations on the web server. The hunt fans out these signals to check for the creation of ASPX or ASHX files in known user-writable paths, specifically the /documents/MemberFiles/ directory. An agent then evaluates the combined telemetry to link the external probing IP to the resulting file system artifacts, and the analyst confirms the malicious nature of the uploads to differentiate them from legitimate user activity.

## identify-targeted-web-servers
<!-- Identify Targeted Web Servers -->
Find web servers receiving tilde enumeration, WebDAV options requests, or high volumes of login traffic to establish a lead.

```sqlite target=web role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of web servers receiving probing requests. High probe counts or the
  presence of tilde characters indicate active exploitation attempts.
reads:
- device_hostname
- url_path
- http_method
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, url_path, http_method, src_endpoint_ip, COUNT(*) as probe_count, MIN(time) as first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/management/login.aspx%' OR LOWER(url_path) LIKE '%/info/household/login.aspx%' OR url_path LIKE '%~1%' OR url_path LIKE '%::$DATA%' OR http_method = 'OPTIONS') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_path, http_method, src_endpoint_ip ORDER BY probe_count DESC
```

## corroborate-ingress
<!-- Corroborate Ingress Evidence -->
parallel:
- → brute-force-sign-ins
- → web-shell-file-creations
join: → triage-ingress-evidence

## brute-force-sign-ins
<!-- Brute Force Sign-Ins -->
Identify high-volume authentication failures to the web platform login pages on the targeted hosts.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: A single source IP attempting multiple logins. Failure counts above 10 from
  one IP against platform pages are highly suspicious.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_name
- src_endpoint_ip
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, dst_endpoint_name, src_endpoint_ip, actor_user_name, COUNT(*) as failure_count, MIN(time) as first_failure FROM hb_auth_signin WHERE activity_id = 5 AND (LOWER(dst_endpoint_name) LIKE '%/login.aspx%' OR LOWER(dst_endpoint_name) LIKE '%management%' OR LOWER(dst_endpoint_name) LIKE '%household%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_name, src_endpoint_ip, actor_user_name HAVING failure_count > 10 ORDER BY failure_count DESC
```

## web-shell-file-creations
<!-- Web Shell File Creations -->
Detect new ASPX or ASHX files in the member upload directory, matching known indicators or patterns.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, webshell_indicators=webshell_indicators, scope_hosts=scope_hosts)
~~~yaml
expected: ASPX files appearing in the MemberFiles directory. These are unexpected
  as member uploads are typically images or documents.
reads:
- device_hostname
- file_path
- file_name
- process_name
- actor_user_name
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, file_path, file_name, process_name, actor_user_name, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%\\documents\\memberfiles\\%' OR LOWER(file_path) LIKE '%/documents/memberfiles/%') AND (LOWER(file_name) LIKE '%.aspx' OR LOWER(file_name) LIKE '%.ashx' OR instr(',' || '{{webshell_indicators}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-ingress-evidence
<!-- Triage Ingress Evidence -->
```agent target=hunter
cite: required
context:
- identify-targeted-web-servers
- brute-force-sign-ins
- web-shell-file-creations
max_iterations: 6
objective: Determine if any host exhibits a pattern of external probing (tilde enumeration
  or OPTIONS requests) or brute-force authentication followed by the creation of an
  ASPX/ASHX file in the MemberFiles directory. Link these events by source IP and
  timestamp to confirm if the file upload resulted from a successful exploit or session
  takeover.
success_criteria: A verdict of malicious | suspicious | benign per host with cited
  rows.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host where boundary probing is linked to a web shell file creation" (confidence: high, judge=hunter)
then: → contain-and-remediate-server
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: missing-iis-logs)
else: → close-out

## contain-and-remediate-server
<!-- Contain and Remediate Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised web server from the network. Delete the malicious ASPX and ASHX files identified in the MemberFiles directory and any other web root directories. Block the source IP addresses identified in the triage stage at the perimeter firewall.
```
→ forensic-review

## forensic-review
<!-- Forensic Review -->
```manual target=analyst
Inspect the MemberFiles directory for the identified ASPX files. Review the file contents for known web shell functions (eval, request, system). Search the HTTP logs for the Simplified Chinese (zh-CN) User Agent string to identify other potentially compromised hosts in the tenant group.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Document the source IPs, filenames, and affected hosts. Recommend patching the file upload handler to restrict uploads to specific image/document mime types and enforce filename sanitization. Schedule a follow-on hunt for web worker shell execution (w3wp spawning cmd/powershell).
```
→ end
