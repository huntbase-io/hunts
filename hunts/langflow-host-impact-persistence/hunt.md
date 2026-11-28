---
analysis: This hunt uses a gated model to pivot from software inventory to deep behavioral
  analysis. A standard detection rule for 'python spawning shells' is often too noisy
  to be useful; this hunt makes it actionable by narrowing the scope to the vulnerable
  application and correlating it with database-level persistence indicators.
blind_spots:
- id: inventory-coverage-gap
  question: Are there Langflow instances running on shadow-IT or unmanaged hosts?
  requires: hb_software_inventory coverage on unmanaged endpoints
  risk: A host without inventory reporting will never open the 'gated' queries, leaving
    it unexamined.
- id: behavioral-telemetry-gap
  question: Can we see Python child processes if Langflow is running in a Docker container?
  requires: hb_process_activity from inside containers
  risk: If the host agent cannot see into the container namespace, the Python-to-shell
    signal is invisible.
  stage: execution-python-rce
- id: datastore-logging-detail
  question: Does the database log the actual 'message' content containing 'tool_code'?
  requires: Full SQL statement auditing in hb_datastore_activity
  risk: If only connections are logged without the SQL query text, the persistence
    mechanism cannot be detected.
  stage: persistence-database-modification
coverage:
- stage: execution-python-rce
  status: covered
  steps:
  - rare-python-shell-spawns
- stage: credential-access-secrets-theft
  status: covered
  steps:
  - langflow-database-tampering
- stage: persistence-database-modification
  status: covered
  steps:
  - langflow-database-tampering
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Langflow, MongoDB,
    and More'' series.'
  stage: initial-access-langflow-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''Metasploit Wrap Up: Langflow, MongoDB,
    and More'' series.'
  stage: lateral-movement-cloud-metadata
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Langflow RCE allows unauthenticated attackers to execute code and
    maintain persistent backdoors in the application database. A negative result confirms
    that confirmed Langflow installs are not actively compromised.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has exploited a code-injection vulnerability in Langflow to
  execute arbitrary Python code, resulting in interactive shell access and persistence
  through unauthorized modifications to the application database.
labels:
- hunt
- attack.t1059.006
- attack.t1552.001
- attack.t1555
- attack.t1505.003
- credential access
- execution
- initial access
- lateral movement
- persistence
name: Langflow Host Impact and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-23'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: The list of hostnames discovered in the scoping step; the behavioral
      queries require this list to avoid a fleet-wide search.
    from:
      kind: manual
      observed: '2026-10-23'
      ref: analyst-defined-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Initially use hb_software_inventory to find any host running 'langflow'.
  The behavioral and datastore queries are expensive and MUST be scoped to these hosts
  to avoid performance issues.
references:
- name: 'Metasploit Wrap Up: Langflow, MongoDB, and More'
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more
related:
- hunt: langflow-unauth-exploit-patterns
  reason: This hunt focuses on host impact; a sibling hunt is needed to look for the
    HTTP exploit patterns (e.g. /api/v1/validate/code) in hb_http_activity.
  relation: out-of-scope-alternative
- hunt: langflow-rce-cloud-metadata-discovery
  relation: follows
scenario:
  stages:
  - name: Exploitation of Langflow Endpoints
    observables:
    - /api/v1/build/
    - /api/v1/validate
    - eval_custom_component_code
    slug: initial-access-langflow-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Python Remote Code Execution
    observables:
    - Python child processes spawning shells
    - langflow process executing arbitrary Python strings
    - Meterpreter python payload execution
    slug: execution-python-rce
    tactic: execution
    techniques:
    - T1059.006
  - name: Credential and Secret Access
    observables:
    - Accessing Langflow database files
    - Reading application secrets from database tables
    - Retrieval of SSO email addresses and phone numbers
    slug: credential-access-secrets-theft
    tactic: credential-access
    techniques:
    - T1552.001
    - T1555
  - name: Cloud Metadata Service Abuse
    observables:
    - HTTP requests to 169.254.169.254
    - Abuse of cloud metadata endpoints for tenant lateral movement
    slug: lateral-movement-cloud-metadata
    tactic: lateral-movement
    techniques:
    - T1552.005
  - name: Persistence via Database Modification
    observables:
    - Modification of tool_code in the Langflow database
    - SQL updates to public flows to re-execute attacker code
    slug: persistence-database-modification
    tactic: persistence
    techniques:
    - T1505.003
  summary: This article describes multiple Metasploit modules targeting vulnerabilities
    in Langflow and OpenCTI, providing unauthenticated remote code execution capabilities.
    In Langflow environments, successful exploitation allows attackers to execute
    arbitrary Python code, access application secrets, pivot to cloud metadata services,
    and maintain persistence by injecting malicious code into the application's database.
series:
  index: 2
  slug: metasploit-wrap-up-langflow-mongodb-and-more
  title: 'Metasploit Wrap Up: Langflow, MongoDB, and More'
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
tlp: clear
type: investigation
---


# Langflow Host Impact and Persistence

This hunt targets the post-exploitation phase of multiple Langflow vulnerabilities (CVE-2026-0768, CVE-2026-0769, CVE-2026-10134). It follows a gated approach designed to minimize performance impact: an initial cheap scoping query identifies hosts running Langflow, and only then are deeper, more expensive queries triggered to find rare Python-to-shell process relationships and suspicious datastore activity. By correlating rare child processes with database-level tampering, the hunt identifies persistence mechanisms that standard detection rules often overlook.

## identify-langflow-installations
<!-- Identify Langflow installations -->
Identify hosts where Langflow is present to narrow the focus of expensive behavioral queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows indicating hosts with Langflow installed. Absence means Langflow is
  not installed via standard package managers.
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
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%langflow%'
```

## evaluate-langflow-exposure
<!-- Evaluate Langflow exposure -->
```agent target=hunter
cite: required
context:
- identify-langflow-installations
max_iterations: 3
objective: Determine if Langflow is installed on any hosts and identify those hosts
  for the next phase.
success_criteria: A verdict of present or absent with a list of hostnames.
tools:
- endpoint
```

## gate-on-presence
<!-- Gate on presence -->
if~: "the evaluate-langflow-exposure verdict is present" (confidence: high, judge=hunter)
then: → impact-investigation-fanout
indeterminate: → close-out
unavailable: → close-out (blind_spot: inventory-coverage-gap)
else: → close-out

## impact-investigation-fanout
<!-- Impact investigation fan-out -->
parallel:
- → rare-python-shell-spawns
- → langflow-database-tampering
join: → triage-impact

## rare-python-shell-spawns
<!-- Rare Python shell spawns -->
Detect Python RCE by identifying rare parent-child pairs where Python launches a shell, restricted to Langflow hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare shell launches from Python on the Langflow hosts. Benign activity like
  developer scripts will typically be frequent across several days or hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  - parent_process_name
  rare_below: 3
reads:
- device_hostname
- parent_process_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, LOWER(process_name) AS proc, LOWER(parent_process_name) AS parent, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%python%' AND LOWER(process_name) IN ('sh', 'bash', 'zsh', 'cmd.exe', 'powershell.exe', 'pwsh') AND instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, proc, parent HAVING hosts <= 3 ORDER BY hosts ASC
```

## langflow-database-tampering
<!-- Langflow database tampering -->
Detect persistence or secret theft by identifying SQL operations targeting Langflow's internal fields, restricted to relevant hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Audit logs showing updates to 'tool_code' or reads from 'secrets' tables
  on Langflow hosts.
reads:
- device_hostname
- activity_name
- message
- time
silence: not_evidence_of_absence
source: hb_datastore_activity
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, activity_name, message, time FROM hb_datastore_activity WHERE (LOWER(message) LIKE '%tool_code%' OR LOWER(message) LIKE '%secrets%' OR LOWER(message) LIKE '%langflow%') AND instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-impact
<!-- Triage impact -->
```agent target=hunter
cite: required
context:
- evaluate-langflow-exposure
- rare-python-shell-spawns
- langflow-database-tampering
max_iterations: 6
objective: Determine if any host with Langflow shows signs of successful RCE (via
  Python shells) or persistence (via tool_code database modification).
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-impact verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: behavioral-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture a memory dump and the application database file for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows. Confirm whether the database modifications to 'tool_code' are legitimate or attacker-controlled persistence from CVE-2026-10134.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the results. If Langflow was found but no suspicious activity was detected, note the versions for patching.
```
→ end
