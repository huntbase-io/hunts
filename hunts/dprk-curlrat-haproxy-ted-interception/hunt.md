---
analysis: This is a hunt because it correlates the presence of a specific software
  version with behavioral network patterns and rare file system modifications by the
  proxy process. A single rule misses the context of the load balancer's persistent
  backdoor capabilities.
blind_spots:
- id: no-header-logging
  question: Whether the HTTP request carries the 'User-token' header used by CurlRAT
  remediation: Enable logging for the User-token header on edge proxies.
  requires: hb_http_activity with custom header logging
  risk: Legitimate traffic to the same infrastructure could trigger false positives
    without the unique header verification.
  stage: curl-rat-c2
- id: memory-filter-hooks
  question: Whether the Ted backdoor filter is hooked into the HAProxy memory pool
  remediation: Implement binary integrity monitoring for load balancer executables.
  requires: Kernel-level module monitoring or memory forensics
  risk: A trojanized HAProxy using internal APIs may not leave standard disk-based
    artifacts beyond the initial binary replacement.
  stage: ted-backdoor-interception
coverage:
- stage: curl-rat-c2
  status: covered
  steps:
  - http-c2-traffic
  - outbound-socket-behavior
- stage: ted-backdoor-interception
  status: covered
  steps:
  - scoping-haproxy-version
  - rare-haproxy-files
- reason: 'Belongs to another part of the ''DPRK APTs: Ted backdoor and curlRAT target
    South Korean media and automotive sectors'' series.'
  stage: initial-access-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''DPRK APTs: Ted backdoor and curlRAT target
    South Korean media and automotive sectors'' series.'
  stage: credential-harvesting-sshd
  status: out_of_scope
- reason: 'Belongs to another part of the ''DPRK APTs: Ted backdoor and curlRAT target
    South Korean media and automotive sectors'' series.'
  stage: persistence-stager-binary-replacement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The Ted backdoor enables covert interception of all web traffic and
    session cookies handled by the load balancer. A negative result over the estate
    confirms this specific long-term espionage framework is not currently active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised the edge load balancer by installing a custom
  HAProxy filter and a Curl-based RAT to intercept web traffic and execute remote
  commands.
labels:
- hunt
- attack.t1041
- attack.t1056.001
- attack.t1059.004
- attack.t1195.002
name: DPRK CurlRAT and HAProxy Ted Interception
parameters:
  c2_domains:
    default:
    - img.darklights.store
    - img.monderhouse.space
    description: Domains used by CurlRAT for command and control.
    from:
      kind: article
      observed: '2026-09-04'
      ref: rapid7-dprk-apts-ted-backdoor
    type: list[domain]
  lookback_days:
    default: '14'
    description: The number of days to look back for activity.
    type: number
  scope_hosts:
    default: []
    description: The hostnames identified in the scoping step; leave empty to hunt
      across the entire estate.
    type: list[host]
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
rationale: Start the hunt on edge servers and load balancers. Focus on systems serving
  automotive or media-related groupware portals.
references:
- name: "Rapid7 \u2014 DPRK APTs: Ted backdoor and curlRAT target South Korean media\
    \ and automotive sectors"
  url: https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors
related:
- hunt: sshd-keylogger-integrity
  reason: The SSH keylogger component requires specific integrity checks on sshd binaries
    and its encrypted log file, which is a separate host-integrity hunt.
  relation: out-of-scope-alternative
- hunt: linux-system-daemon-trojanization-credential-harvesting
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# DPRK CurlRAT and HAProxy Ted Interception

This hunt identifies Linux systems running the specific HAProxy version targeted by the Ted backdoor framework and searches for associated command-and-control activity. It focuses on the South Korean media and automotive sector campaign, looking for rare file writes by the haproxy process and HTTP traffic to known malicious domains. The flow uses a funnel approach to scope the environment before corroborating network and host indicators.

## scoping-haproxy-version
<!-- Find HAProxy 2.8.12 Instances -->
Identify Linux hosts running the specific load balancer version used as the base for the Ted backdoor plugin.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running HAProxy 2.8.12. Absence of results reduces the
  probability of this specific toolkit being present.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) = 'haproxy' AND package_version = '2.8.12'
```

## investigation-fanout
<!-- Parallel Investigation of C2 and Artifacts -->
parallel:
- → http-c2-traffic
- → outbound-socket-behavior
- → rare-haproxy-files
join: → agent-triage

## http-c2-traffic
<!-- CurlRAT Domain Traffic -->
Detect communication with hardcoded CurlRAT domains associated with APT37.

```sqlite target=web role=detection-candidate params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to malicious domains from the scoped proxies. Silence only
  proves these specific domains were not used.
reads:
- device_hostname
- url_hostname
- url_path
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, src_endpoint_ip, time FROM hb_http_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## outbound-socket-behavior
<!-- Outbound HAProxy Sockets -->
Identify HAProxy or its children initiating outbound connections to non-internal addresses.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound connections from a load balancer process to the public internet,
  suggesting C2 or exfiltration.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%haproxy%' AND direction = 'outbound' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-haproxy-files
<!-- Rare File Writes by HAProxy -->
Identify rare file modifications by the haproxy process in system directories like /usr/lib or /var/lib.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique files in system libraries or variable directories touched by the
  proxy process on a small number of hosts.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT LOWER(file_path) AS path, device_hostname, process_name, COUNT(*) AS touches, MIN(time) AS first_seen FROM hb_file_activity WHERE LOWER(process_name) LIKE '%haproxy%' AND (LOWER(file_path) LIKE '/usr/lib/%' OR LOWER(file_path) LIKE '/var/lib/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING COUNT(DISTINCT device_hostname) <= 3
```

## agent-triage
<!-- Synthesize Compromise Evidence -->
```agent target=hunter
cite: required
context:
- scoping-haproxy-version
- http-c2-traffic
- outbound-socket-behavior
- rare-haproxy-files
max_iterations: 5
objective: Determine if any host shows evidence of HAProxy version 2.8.12 alongside
  malicious network traffic or unusual file modifications by the proxy process.
success_criteria: A verdict of malicious, suspicious, or benign for each host with
  cited data rows.
tools:
- endpoint
- network
- web
```

## route-findings
<!-- Route on Verdict -->
if~: "the agent-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-forensics
unavailable: → manual-forensics (blind_spot: no-header-logging)
else: → close-out-report

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Preserve the HAProxy process memory and examine system library directories for unauthorized files.
```
→ manual-forensics

## manual-forensics
<!-- Forensic Review -->
```manual target=analyst
Manually inspect the HAProxy configuration and binary symbols for custom filters. Use a 1-byte XOR (0x58) to decrypt any files found in /var/lib/snapd. Search for /var/lib/sshd/c8c68e629bba773a10ac80012d10bf19 to confirm credential harvesting.
```
→ close-out-report

## close-out-report
<!-- Final Reporting -->
```manual target=analyst
Summarize the hosts examined, the software versions identified, and any confirmed indicators. Close the hunt.
```
→ end
