---
analysis: A rule firing on every sshd modification causes excessive false positives
  during legitimate updates. This hunt uses a gated flow to only run expensive fleet-wide
  stack-counts when specific toolkit artifacts are found, then correlates rarity with
  vulnerability context.
blind_spots:
- id: pre-existing-compromise
  question: Was the trojanized crond dropped before the telemetry retention window?
  requires: long-term file creation telemetry
  risk: A host compromised months ago will not show file-activity rows for the initial
    replacement, making the hunt dependent on hash rarity.
  stage: persistence-stager-binary-replacement
- id: unhashed-executables
  question: Does the agent hash every execution of system daemons?
  requires: hb_process_activity with SHA256
  risk: If hashes are not captured for standard system daemons, the stack-counting
    step cannot identify trojanized outliers.
  stage: persistence-stager-binary-replacement
coverage:
- stage: initial-access-exploit
  status: covered
  steps:
  - vulnerable-edge-apps
- stage: credential-harvesting-sshd
  status: covered
  steps:
  - lead-file-discovery
- stage: persistence-stager-binary-replacement
  status: covered
  steps:
  - rare-daemon-hashes
- reason: 'Belongs to another part of the ''DPRK APTs: Ted backdoor and curlRAT target
    South Korean media and automotive sectors'' series.'
  stage: curl-rat-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''DPRK APTs: Ted backdoor and curlRAT target
    South Korean media and automotive sectors'' series.'
  stage: ted-backdoor-interception
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: DPRK APTs use deeply integrated trojanized system binaries that are
    invisible to standard monitoring; a proactive baseline of system daemon hashes
    is required to detect these modifications.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term persistence and credential harvesting
  by replacing legitimate Linux system daemons with trojanized versions that log passwords
  and monitor process health.
labels:
- hunt
- attack.t1056.001
- attack.t1195.002
- attack.t1059.004
- attack.t1190
name: Linux System Daemon Trojanization and Credential Harvesting
parameters:
  daemon_paths:
    default:
    - /usr/sbin/sshd
    - /usr/sbin/crond
    - /usr/sbin/agetty
    - /usr/sbin/atd
    - /usr/sbin/polkitd
    - /usr/sbin/haproxy
    description: System binaries targeted for replacement or backdoor insertion.
    from:
      kind: article
      observed: '2026-09-04'
      ref: rapid7-dprk-ted
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-04'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead query; leave empty to scan the full
      estate.
    from:
      kind: manual
      observed: '2026-09-04'
      ref: analyst-scoping
    type: list[host]
  toolkit_files:
    default:
    - /var/lib/sshd/c8c68e629bba773a10ac80012d10bf19
    - /tmp/jasper-log
    - /var/lib/snapd/g580
    - /var/lib/snapd/g105
    - /usr/lib/libvirtlog.so.0
    description: Hidden log and configuration files associated with the SSH keylogger
      and CurlRAT.
    from:
      kind: article
      observed: '2026-09-04'
      ref: rapid7-dprk-ted
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux servers running HAProxy or edge mail servers (Postfix, Exim).
  Start with a 14-day window for file activity but extend to 90 days for process hash
  baseline if results are inconclusive.
references:
- name: "Rapid7 \u2014 DPRK APTs: Ted backdoor and curlRAT target South Korean media\
    \ and automotive sectors"
  url: https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors
related:
- hunt: curl-rat-c2-behavior
  reason: If a trojanized daemon is found, the next hunt investigates its specific
    network communication patterns.
  relation: follows
scenario:
  stages:
  - name: Exploitation of Edge Applications
    observables:
    - External ports 80, 443, 25
    - Groupware login portal
    - Mail server access
    slug: initial-access-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: Trojanized SSHD Keylogger
    observables:
    - Trojanized /usr/sbin/sshd
    - Encrypted log file /var/lib/sshd/c8c68e629bba773a10ac80012d10bf19
    - Hardcoded master passwords in userauth_passwd()
    slug: credential-harvesting-sshd
    tactic: credential-access
    techniques:
    - T1056.001
    - T1195.002
  - name: Daemon Replacement via Stager
    observables:
    - Stager file /tmp/jasper-log
    - Replacement of /usr/sbin/crond
    - Timestomping crond to match /usr/bin/ssh creation date
    - Trojanized versions of agetty, atd, and polkitd
    - Filtering /root/.bash_history and /var/log/messages
    slug: persistence-stager-binary-replacement
    tactic: persistence
    techniques:
    - T1195.002
    - T1059.004
  - name: CurlRAT Command and Control
    observables:
    - HTTP POST to img.darklights.store
    - HTTP POST to img.monderhouse.space
    - User-token header containing MD5 victim ID
    - Directory /var/lib/snapd/ containing files g580, g105
    - Configuration file /tmp/nimon.unix-docbase.8564479396043450766-db6fb4443bc
    slug: curl-rat-c2
    tactic: c2
    techniques:
    - T1041
    - T1059.004
  - name: HAProxy Traffic Interception
    observables:
    - HAProxy version 2.8.12
    - Custom HAProxy filter plugin 'ted backdoor'
    - File /usr/lib/libvirtlog.so.0
    - Watchdog thread monitoring /var/run/haproxy.pid
    - Cookie stealing and script injection into web traffic
    slug: ted-backdoor-interception
    tactic: collection
    techniques:
    - T1195.002
    - T1056.001
  summary: DPRK-linked actors (likely Kimsuky or APT37) deployed a sophisticated Linux
    toolkit targeting South Korean media and automotive sectors for long-term espionage.
    The campaign features the 'TED backdoor,' a custom HAProxy filter for traffic
    interception and script injection, and 'CurlRAT,' which is embedded in trojanized
    system daemons like crond and sshd to facilitate credential harvesting and remote
    command execution.
series:
  index: 1
  slug: dprk-apts-ted-backdoor-and-curlrat-target-south-korean-media-and-automotive-sectors
  title: 'DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive
    sectors'
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


# Linux System Daemon Trojanization and Credential Harvesting

This hunt targets the endpoint artifacts of the Ted and CurlRAT toolkit used against South Korean automotive and media sectors. It focuses on identifying trojanized system binaries like sshd and crond by first searching for known hidden log and configuration files. If these leads are found, the hunt expands to stack-count binary hashes across the estate to identify outliers and correlates these with high-severity vulnerabilities in edge-facing applications.

## lead-file-discovery
<!-- Lead discovery: Known toolkit artifacts -->
Find hosts where specific encrypted log paths or stager configuration files have been touched.

```sqlite target=endpoint role=scoping params=(toolkit_files=toolkit_files, lookback_days=lookback_days)
~~~yaml
expected: Any row naming a toolkit path on a host. Silence proves these specific IOCs
  are absent but does not rule out the campaign.
reads:
- activity_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, activity_name, time FROM hb_file_activity WHERE (instr(',' || '{{toolkit_files}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-gate-read
<!-- Evaluate lead findings -->
```agent target=hunter
cite: required
context:
- lead-file-discovery
max_iterations: 3
objective: Determine if any host shows activity matching the specific file artifacts
  of the Ted and CurlRAT toolkit.
success_criteria: A verdict citing specific hosts and paths.
tools:
- endpoint
```

## gate-decision
<!-- Gate: Proceed to expansion -->
if~: "the agent-gate-read verdict is malicious because at least one host shows a reported toolkit artifact" (confidence: high, judge=hunter)
then: → parallel-expansion
indeterminate: → close-out-task
unavailable: → close-out-task (blind_spot: pre-existing-compromise)
else: → close-out-task

## parallel-expansion
<!-- Expand investigation -->
parallel:
- → rare-daemon-hashes
- → vulnerable-edge-apps
join: → agent-final-triage

## rare-daemon-hashes
<!-- Stack-count daemon hashes -->
Find system daemons with rare binary hashes that differ from the fleet baseline.

```sqlite target=endpoint role=baseline params=(daemon_paths=daemon_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare SHA256 for a standard path like /usr/sbin/crond on a small number
  of hosts.
prevalence:
  by: device_hostname
  key:
  - process_hash_sha256
  rare_below: 3
reads:
- device_hostname
- process_hash_sha256
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT process_hash_sha256, process_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{daemon_paths}}' || ',', ',' || LOWER(process_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_hash_sha256, process_path HAVING host_count <= 2
```

## vulnerable-edge-apps
<!-- Check for edge vulnerabilities -->
Identify if the suspected hosts run unpatched edge applications that match the reported entry vectors.

```sqlite target=endpoint role=enrichment
~~~yaml
expected: High-severity vulnerabilities on edge servers that validate the initial
  compromise hypothesis.
reads:
- affected_package_name
- affected_package_version
- cve_uid
- device_uid
- severity_id
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, affected_package_name, affected_package_version, severity_id, cve_uid FROM hb_vulnerability_finding WHERE severity_id >= 4 AND (LOWER(affected_package_name) LIKE '%haproxy%' OR LOWER(affected_package_name) LIKE '%sshd%' OR LOWER(affected_package_name) LIKE '%at%' OR LOWER(affected_package_name) LIKE '%cron%' OR LOWER(affected_package_name) LIKE '%polkit%')
```

## agent-final-triage
<!-- Final triage of compromise -->
```agent target=hunter
cite: required
context:
- agent-gate-read
- rare-daemon-hashes
- vulnerable-edge-apps
max_iterations: 6
objective: Determine if the host is compromised by correlating toolkit artifacts,
  rare binary hashes, and edge-facing vulnerabilities.
success_criteria: A final verdict citing rows from both lead and expansion steps.
tools:
- endpoint
```

## route-verdict
<!-- Route verdict -->
if~: "the agent-final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-verification
unavailable: → forensic-verification (blind_spot: unhashed-executables)
else: → close-out-task

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host immediately to stop the trojanized system daemons. Collect the suspect binaries for forensic analysis before reimaging.
```
→ forensic-verification

## forensic-verification
<!-- Forensic verification -->
```manual target=analyst
Inspect the suspect host for timestomping: compare the modification time of /usr/sbin/crond with /usr/bin/ssh. Search for keyword-based line removals in /var/log/secure and .bash_history using strings like 'jasper-log' or 'cron'.
```
→ close-out-task

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Document whether malicious artifacts or rare daemon hashes were confirmed. If a compromise was found, move to the CurlRAT C2 behavior hunt.
```
→ end
