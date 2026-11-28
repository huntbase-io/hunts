---
analysis: A single detection rule for 'ds' user activity or the maintenance helper
  might fire during normal administrative work. This hunt durably links web-based
  auth bypass signals with sensitive config file access and specific command injection
  patterns, providing the necessary context to distinguish container takeover from
  maintenance.
blind_spots:
- id: container-visibility-gap
  question: Are processes inside the ONLYOFFICE container visible to the host EDR?
  requires: Endpoint agent with full container runtime and namespace visibility
  risk: If the agent cannot see into container namespaces, activity by the 'ds' user
    and shell execution will be invisible, leading to false negatives.
  stage: execution-parameter-injection
- id: no-http-post-bodies
  question: Which specific DocBuilder script (e.g. GetFontBinary) was passed in the
    POST body?
  requires: hb_http_activity with captured POST request bodies
  risk: Without POST bodies, the hunt relies on URL-based tokens and subsequent file-touch
    patterns, which may be harder to correlate in high-traffic environments.
  stage: initial-access-docbuilder
coverage:
- stage: initial-access-docbuilder
  status: covered
  steps:
  - docbuilder-access-baseline
- stage: credential-theft-file-read
  status: covered
  steps:
  - sensitive-file-touches
- stage: execution-parameter-injection
  status: covered
  steps:
  - ds-user-suspicious-processes
- stage: privilege-escalation-root-helper
  status: covered
  steps:
  - root-helper-command-injection
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploiting ONLYOFFICE provides a direct path to sensitive corporate
    documents and root access within the hosting container. A negative result confirms
    that the document infrastructure is not currently undergoing active exploitation
    via these chained vulnerabilities.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker with view-only document access is chaining an authorization
  bypass in the DocBuilder API with a native file read to forge credentials and escalate
  to root via a maintenance script.
labels:
- hunt
- attack.t1190
- attack.t1552.001
- attack.t1203
- attack.t1059.004
- attack.t1548.003
- credential access
- execution
- initial access
- privilege escalation
name: ONLYOFFICE Document Server Container Compromise
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine for exploit indicators.
    from:
      kind: manual
      observed: '2026-11-16'
      ref: default
    type: number
  onlyoffice_packages:
    default:
    - onlyoffice-documentserver
    - onlyoffice-documentserver-ee
    - onlyoffice-documentserver-de
    description: Package names for ONLYOFFICE Document Server products to scope the
      hunt.
    from:
      kind: article
      observed: '2026-11-16'
      ref: rapid7
    type: list[string]
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty to scan the estate.
    from:
      kind: manual
      observed: '2026-11-16'
      ref: default
    type: list[host]
  sensitive_files:
    default:
    - /etc/onlyoffice/documentserver/local.json
    - /etc/passwd
    - /etc/shadow
    - /var/www/onlyoffice/documentserver/server/local.json
    description: Sensitive server files targeted for credential theft and JWT signing
      key access.
    from:
      kind: article
      observed: '2026-11-16'
      ref: rapid7
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ve-from-view-only-access-to-container-root-five-vulnerabilities-in-onlyoffice-docs-fixed
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with Linux servers hosting Docker containers, focusing on those running
  ONLYOFFICE Document Server (often integrated with Zimbra). Use the software inventory
  results to narrow subsequent queries to affected hosts.
references:
- name: "Rapid7 \u2014 From view-only access to container root: five vulnerabilities\
    \ in ONLYOFFICE Docs (FIXED)"
  url: https://www.rapid7.com/blog/post/ve-from-view-only-access-to-container-root-five-vulnerabilities-in-onlyoffice-docs-fixed
related:
- hunt: zimbra-cve-2024-45519-exploitation
  reason: Since ONLYOFFICE is often integrated with Zimbra, a compromised Zimbra instance
    may be the source of the view-only Editor JWTs used in this DocBuilder chain.
  relation: sibling
scenario:
  stages:
  - name: DocBuilder Authorization Bypass
    observables:
    - POST to /docbuilder
    - view-only Editor JWT in url_query token parameter
    - WOPI_ENABLED=true environment
    slug: initial-access-docbuilder
    tactic: initial-access
    techniques:
    - T1190
  - name: Native File Read and Token Forgery
    observables:
    - native.GetFontBinary script usage
    - native.ZipFileAsString script usage
    - /etc/onlyoffice/documentserver/local.json
    - services.CoAuthoring.secret.session.string
    slug: credential-theft-file-read
    tactic: credential-access
    techniques:
    - T1552.001
  - name: DocBuilder Parameter Injection
    observables:
    - builder.SaveFile with duplicate m_sFileTo element
    - path traversal to write outside job directory
    - execution as ds service account
    slug: execution-parameter-injection
    tactic: execution
    techniques:
    - T1203
    - T1059.004
  - name: Root Escalation via Maintenance Helper
    observables:
    - sudo documentserver-flush-cache.sh
    - crafted --hash argument with sed injection
    - sed execution with e flag
    - process execution as root
    slug: privilege-escalation-root-helper
    tactic: privilege-escalation
    techniques:
    - T1548.003
  summary: Attackers chain multiple vulnerabilities in ONLYOFFICE Docs to escalate
    from view-only document access to root command execution within the DocumentServer
    container. The chain involves bypassing JWT authorization for the DocBuilder API,
    reading sensitive configuration files to forge high-privilege tokens, and abusing
    a sudo-permitted maintenance script to elevate privileges.
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


# ONLYOFFICE Document Server Container Compromise

This hunt identifies exploitation of a multi-stage chain in ONLYOFFICE Document Server (vulnerable before v10.0). It starts by scoping the environment for vulnerable versions, then looks for suspicious access to the DocBuilder endpoint and sensitive configuration files like local.json. The hunt then pivots to find evidence of command execution by the 'ds' service account and privilege escalation through the documentserver-flush-cache.sh sudo helper, which allows root execution via sed injection. This phased approach links initial access, credential theft, and terminal compromise into a single investigator read.

## vulnerable-onlyoffice-instances
<!-- Identify vulnerable ONLYOFFICE instances -->
Locate hosts running versions of ONLYOFFICE Document Server prior to the 10.0 fix to prioritize investigation.

```sqlite target=endpoint role=scoping params=(onlyoffice_packages=onlyoffice_packages)
~~~yaml
expected: A list of hosts running vulnerable Document Server versions. Silence suggests
  the estate is patched or ONLYOFFICE is not present.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE instr(',' || '{{onlyoffice_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 AND (CAST(SUBSTR(package_version, 1, INSTR(package_version, '.') - 1) AS INTEGER) < 10 OR package_version LIKE '9.%')
```

## early-stage-activity
<!-- Initial access and credential access activity -->
parallel:
- → docbuilder-access-baseline
- → sensitive-file-touches
join: → triage-early-access

## docbuilder-access-baseline
<!-- DocBuilder endpoint access baseline -->
Identify potential authorization bypass attempts where view-only tokens are used against the /docbuilder endpoint, highlighting rare query patterns.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare URL query parameter containing a token used against the DocBuilder
  endpoint. Common tokens used by automated integrations should be filtered by the
  host count threshold.
prevalence:
  by: device_hostname
  key:
  - url_query
  rare_below: 5
reads:
- url_path
- url_query
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT url_query, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/docbuilder%' OR LOWER(url_path) LIKE '%/docbuilder/%') AND instr(url_query, 'token=') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_query HAVING host_count < 5 ORDER BY host_count ASC
```

## sensitive-file-touches
<!-- Sensitive file touches by DocumentServer -->
Detect the exploitation of GetFontBinary or ZipFileAsString to read configuration files or passwords.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, sensitive_files=sensitive_files, scope_hosts=scope_hosts)
~~~yaml
expected: Access to local.json or system files by ONLYOFFICE processes or the service
  account. This indicates the attacker is exfiltrating signing keys or user data via
  the native file read vulnerability.
reads:
- device_hostname
- file_path
- actor_user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, file_path, actor_user_name, process_name, time FROM hb_file_activity WHERE instr(',' || '{{sensitive_files}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-access
<!-- Triage early access evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-onlyoffice-instances
- docbuilder-access-baseline
- sensitive-file-touches
max_iterations: 3
objective: Identify hosts where rare DocBuilder URL queries are accompanied by unauthorized
  touches on sensitive server configuration files.
success_criteria: A list of suspicious hosts with cited evidence of early-stage exploitation.
tools:
- endpoint
- web
```

## follow-on-activity
<!-- Execution and escalation activity -->
parallel:
- → ds-user-suspicious-processes
- → root-helper-command-injection
join: → triage-full-chain

## ds-user-suspicious-processes
<!-- Suspicious processes under 'ds' account -->
Monitor the DocumentServer service account for unexpected shell usage or command execution following RCE.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Interactive shells or network utilities run by the 'ds' user, which is a
  service account that should only run application binaries. This indicates post-exploitation
  activity.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE user_name = 'ds' AND (LOWER(process_name) IN ('sh', 'bash', 'python', 'python3', 'curl', 'wget', 'nc', 'sed')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## root-helper-command-injection
<!-- Root escalation via maintenance helper -->
Detect the use of the passwordless documentserver-flush-cache.sh sudo helper to execute arbitrary root commands via sed injection.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of the flush-cache script with a crafted --hash parameter. This
  is a high-confidence indicator of a root escalation attempt using the sed e flag
  injection.
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%documentserver-flush-cache.sh%' AND LOWER(process_cmd_line) LIKE '%--hash%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-chain
<!-- Triage full compromise chain -->
```agent target=hunter
cite: required
context:
- triage-early-access
- ds-user-suspicious-processes
- root-helper-command-injection
max_iterations: 5
objective: Determine if any host shows the complete progression from DocBuilder access
  and config file reads (from triage-early-access) to shell execution and root escalation.
success_criteria: A final verdict of compromised | suspicious | benign per host, citing
  sequential evidence across all queried surfaces.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route based on compromise verdict -->
if~: "The final verdict from triage-full-chain is 'compromised' for any host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-confirmation
unavailable: → analyst-confirmation (blind_spot: container-visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate all ONLYOFFICE Docker containers and preserve the container images and local volumes for forensic analysis. Collect the local.json file to check for signing key rotation.
```
→ analyst-confirmation

## analyst-confirmation
<!-- Analyst confirmation -->
```manual target=analyst
Examine the process cmd_line for the 'root-helper-command-injection' step. Specifically look for sed injection patterns like 'e exec' or 'sed e'. Validate if 'ds' user shell activity matches any known administrative maintenance windows.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the hosts examined and record any identified vulnerable Document Server instances for patching. If no compromise was found, archive as a negative result.
```
→ end
