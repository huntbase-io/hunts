---
analysis: This hunt uses a fleet-wide prevalence baseline to find masqueraded payloads
  launched from temporary paths, then pivots to low-signal hardware tuning events
  (MSR loading) and configuration harvesting that single rules would find too noisy.
blind_spots:
- id: msr-write-parameters
  question: Was the msr module loaded with write access enabled (allow_writes=1)?
  requires: hb_module_activity with module parameters
  risk: Legitimate system utilities might load the msr module; without seeing the
    write parameter, we cannot confirm if it was for mining tuning.
  stage: resource-hijacking-cryptomining
- id: limited-snapshot-visibility
  question: Did the payload execute and terminate between snapshots?
  requires: continuous event stream for hb_process_activity
  risk: Short-lived payloads might be missed if the data source relies on periodic
    process snapshots rather than an execution stream.
  stage: masqueraded-payload-delivery
- id: ssh-key-content
  question: What public key was added to authorized_keys?
  requires: hb_file_activity with content capture
  risk: We can see the file was touched but not what key was added, preventing attribution
    to a known actor without host forensics.
  stage: host-persistence-mechanisms
coverage:
- stage: masqueraded-payload-delivery
  status: covered
  steps:
  - payload-delivery-prevalence
- stage: host-and-miner-discovery
  status: covered
  steps:
  - discovery-and-cleanup
- stage: resource-hijacking-cryptomining
  status: covered
  steps:
  - msr-module-load
- stage: host-persistence-mechanisms
  status: covered
  steps:
  - persistence-activity
- reason: 'Belongs to another part of the ''When AI infrastructure becomes the target:
    Securing gateways and control points'' series.'
  stage: initial-access-ai-gateway-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''When AI infrastructure becomes the target:
    Securing gateways and control points'' series.'
  stage: runtime-credential-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''When AI infrastructure becomes the target:
    Securing gateways and control points'' series.'
  stage: application-layer-data-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI infrastructure components are becoming high-value control points.
    Intruders target them to monetize compute resources and establish persistence
    near high-value credential material.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised an AI gateway or retrieval engine and is now
  deploying masqueraded payloads to monetize the host via cryptomining and establish
  durable SSH or systemd persistence.
labels:
- hunt
- attack.t1105
- attack.t1036.005
- attack.t1082
- attack.t1046
- attack.t1496
- attack.t1098.004
- attack.t1053.003
- attack.t1090.003
name: AI Infrastructure Host Monetization and Persistence
parameters:
  ai_apps:
    default:
    - litellm
    - ragflow
    - kestra
    description: AI infrastructure software names to scope the hunt.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on; leave empty to hunt across
      the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially focus on hosts identified as running LiteLLM,
  RAGFlow, or Kestra using the software inventory step.
references:
- name: 'MSRC - When AI infrastructure becomes the target: Securing gateways and control
    points'
  url: https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/
related:
- hunt: ai-gateway-credential-theft
  reason: Credential harvesting from gateway memory or databases is handled in the
    sibling hunt.
  relation: out-of-scope-alternative
- hunt: ai-gateway-exploitation-credential-theft
  relation: follows
scenario:
  stages:
  - name: Exploitation of Exposed AI Control Points
    observables:
    - CVE-2026-42271
    - CVE-2026-48710
    - CVE-2026-49869
    - CVE-2026-45312
    - CVE-2026-28797
    - CVE-2026-24770
    - CVE-2025-68700
    - Outbound Burp Collaborator callbacks from RAGFlow server
    - POST /mcp-rest/test/connection
    - POST /mcp-rest/test/tools/list
    slug: initial-access-ai-gateway-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Gateway Runtime Secret Harvesting
    observables:
    - Reading /proc/1/environ from gateway PID 1
    - Filtering environment for 'master', 'API key', 'token', 'password', 'DATABASE_URL'
    - Python urllib, curl, or wget used for exfiltration of environment blocks
    slug: runtime-credential-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
  - name: Masqueraded Payload Delivery and Execution
    observables:
    - ELF binaries staged in temporary paths
    - Service-style naming masquerading as benign Linux daemons
    - Shell-stage downloaders with short timeouts and fallbacks
    - python3 -c commands retrieving remote payloads
    slug: masqueraded-payload-delivery
    tactic: execution
    techniques:
    - T1105
    - T1036.005
  - name: Host Discovery and Competitor Cleanup
    observables:
    - Silent passwordless sudo checks
    - Listening port inspection
    - Process sweeps for competing miners or remote shells
    - Modification of crontab to remove other miner entries
    slug: host-and-miner-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1046
  - name: AI Gateway Database Exfiltration
    observables:
    - Access to postgres.database.azure.com
    - Queries against LiteLLM_ProxyModelTable and LiteLLM_VerificationToken
    - Self-contained python3 one-liners installing PostgreSQL support
    - Base64-encoded exfiltration in small chunks
    slug: application-layer-data-exfiltration
    tactic: collection
    techniques:
    - T1041
  - name: Compute Resource Hijacking
    observables:
    - XMRig deployment
    - Loading Linux Model-Specific Register (msr) module with write access
    - RandomX-related CPU tuning
    slug: resource-hijacking-cryptomining
    tactic: impact
    techniques:
    - T1496
  - name: System Persistence and C2
    observables:
    - Modification of SSH authorized_keys under service accounts
    - Hidden-file relay execution
    - Masqueraded systemd service names
    - Periodic out-of-band callbacks (C2 relay)
    slug: host-persistence-mechanisms
    tactic: persistence
    techniques:
    - T1098.004
    - T1053.003
    - T1090.003
  summary: Attackers are targeting exposed AI infrastructure components like LiteLLM
    gateways, RAGFlow document engines, and Kestra orchestrators to harvest LLM provider
    keys and credentials. Once access is gained, they pivot to container host persistence
    and monetize compromised compute resources through cryptomining.
series:
  index: 2
  slug: when-ai-infrastructure-becomes-the-target-securing-gateways-and-control-points
  title: 'When AI infrastructure becomes the target: Securing gateways and control
    points'
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


# AI Infrastructure Host Monetization and Persistence

This hunt focuses on the post-exploitation phase of attacks targeting AI infrastructure like LiteLLM, RAGFlow, and Kestra. It examines the transition from initial gateway command execution to host-level abuse. We first identify hosts running AI software, then hunt for masqueraded binaries in temporary paths using a prevalence baseline to find rare items. We corroborate these with host discovery commands, cryptomining indicators such as MSR module loading, and persistence mechanisms like SSH authorized_keys modifications.

## identify-ai-hosts
<!-- Identify AI infrastructure hosts -->
Scope the hunt to Linux hosts running targeted AI software or retrieval engines, retrieving both UIDs and hostnames for precise filtering.

```sqlite target=endpoint role=scoping params=(ai_apps=ai_apps)
~~~yaml
expected: A list of host UIDs and names currently running AI gateways or retrieval
  engines. This narrows the search for subsequent behavioural telemetry.
reads:
- device_uid
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_uid, device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{ai_apps}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{ai_apps}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## early-stage-parallel
<!-- Early stage delivery and discovery -->
parallel:
- → payload-delivery-prevalence
- → discovery-and-cleanup
join: → agent-early-read

## payload-delivery-prevalence
<!-- Rare binaries in temporary paths -->
Find masqueraded payloads by stack-counting binaries executed from world-writable directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries executing from world-writable paths. Malicious binaries may
  run many times on a single victim but are rare across the fleet.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS executions, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/var/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING executions <= 10 AND hosts <= 3 ORDER BY hosts ASC
```

## discovery-and-cleanup
<!-- Host discovery and cleanup -->
Detect commands used for environment fingerprinting launched directly from AI gateway parent processes.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_apps=ai_apps)
~~~yaml
expected: A sequence of discovery commands or crontab modifications appearing on the
  same hosts that launched rare temporary binaries from the gateway context.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%sudo -l%' OR LOWER(process_cmd_line) LIKE '%crontab -l%' OR LOWER(process_cmd_line) LIKE '%netstat -anp%' OR LOWER(process_cmd_line) LIKE '%rm %crontab%') AND (instr(',' || '{{ai_apps}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-read
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- payload-delivery-prevalence
- discovery-and-cleanup
max_iterations: 3
objective: Determine if the rare binaries in /tmp and the discovery commands suggest
  an attacker is prepping the host for monetization or persistence.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  binary paths and command lines.
tools:
- endpoint
```

## follow-on-parallel
<!-- Follow-on impact and persistence -->
parallel:
- → msr-module-load
- → config-env-harvesting
- → persistence-activity
join: → agent-follow-on-read

## msr-module-load
<!-- MSR module loading -->
Detect the Linux Model-Specific Register module loading, a marker for cryptominer CPU tuning.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The msr module being loaded by an unexpected process, suggesting RandomX/XMRig
  optimization.
reads:
- device_hostname
- module_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, module_name, process_name, time FROM hb_module_activity WHERE LOWER(module_name) = 'msr' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## config-env-harvesting
<!-- Gateway config and environment harvesting -->
Detect attempts to read gateway process environments or configuration files for secret harvesting.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Commands targeting process environments or database connection strings,
  indicating follow-on credential harvesting.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (process_cmd_line LIKE '%/proc/1/environ%' OR process_cmd_line LIKE '%DATABASE_URL%' OR process_cmd_line LIKE '%API_KEY%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-activity
<!-- Persistence via systemd and SSH -->
Identify changes to SSH authorized_keys or systemd service configurations.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unauthorized file modifications to persistent Linux system paths, often
  by masqueraded processes.
reads:
- device_hostname
- file_path
- process_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, LOWER(process_name) AS normalized_process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/authorized_keys' OR LOWER(file_path) LIKE '/etc/systemd/system/%') AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-follow-on-read
<!-- Follow-on triage and correlation -->
```agent target=hunter
cite: required
context:
- agent-early-read
- msr-module-load
- config-env-harvesting
- persistence-activity
max_iterations: 4
objective: Decide if the suspicious early activity on a host is confirmed as a malicious
  compromise by the presence of cryptomining, harvesting, or persistence indicators.
success_criteria: A final verdict citing the linkage between rare binaries, discovery,
  harvesting attempts, MSR loading, and persistence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on compromise -->
if~: "the final triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: limited-snapshot-visibility)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Prevent any further outbound connections to C2 or mining pools.
```
→ forensic-review

## forensic-review
<!-- Forensic review -->
```manual target=analyst
Review the binaries identified in the prevalence step. Collect the modified SSH keys and systemd unit files. Determine if the initial access vulnerability in the AI software was patched.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Log the number of affected hosts and the specific AI workloads involved. Update any detection rules based on the observed masquerading patterns.
```
→ end
