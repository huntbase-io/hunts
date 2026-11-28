---
analysis: Nobody writes a detection for a crontab inside a Redis pod, because nobody
  logs it. Redis keeps no command log either, so a cron file written through CONFIG
  SET leaves only the file itself. Most Redis images ship without a cron daemon, so
  in a container the entry may never fire, and that is a signal too, an attacker
  trying something that does not work. On a VM or node it does fire. This hunt asks
  the hosts directly what is scheduled, what the datastore process has written, and
  what is calling out, instead of waiting for a log line that was never going to be
  collected.
blind_spots:
- id: redis-commands-not-logged
  question: Which client issued CONFIG SET dir, CONFIG SET dbfilename or SAVE to write
    the cron file?
  requires: Redis command auditing (MONITOR capture, ACL LOG, or a proxy that logs
    commands), shipped to a store
  risk: Redis keeps no command audit trail by default. The write shows up only as
    a file created by the redis-server process, with no client address.
  stage: cron-planting
- id: ephemeral-pods-without-agent
  question: Did the same cron entry exist in pods that were rescheduled before the
    hunt ran?
  requires: An endpoint agent or sidecar in data-tier pods, or node-level collection
    that sees container filesystems
  risk: A pod without an agent reports nothing. A pod that was replaced takes its
    crontab with it, and only egress from the node remains.
  stage: callback
- id: pod-environment-not-inventoried
  question: Which secrets and internal service names were in the compromised pod's
    environment?
  requires: Kubernetes pod spec and secret inventory for the cluster
  risk: The operator read environment variables naming about 20 customer tenants.
    Without the pod spec, the blast radius of what was read cannot be stated.
  stage: environment-harvest
coverage:
- stage: datastore-exposure
  status: covered
  steps:
  - datastore-scoping
  - exposed-datastores
- stage: cron-planting
  status: covered
  steps:
  - datastore-file-writes
  - cron-from-writable-paths
  - rare-cron-commands
- stage: callback
  status: covered
  steps:
  - cron-executions-in-syslog
  - reverse-shell-processes
  - recurring-shell-egress
- reason: Reading a pod's environment leaves no trace in host telemetry; see the
    pod-environment-not-inventoried blind spot.
  stage: environment-harvest
  status: not_visible
- reason: Initial access to the cluster belongs to the companion hunt on the exploitation
    loop.
  stage: initial-access
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: universal
  handoff: promote-to-detection
  justification: The researcher behind Operation CAIRN reports a netcat reverse shell
    in a Redis pod's crontab on a multi-tenant SaaS platform. Writing cron through
    Redis is an established technique (RedisRaider, and worms before it), and cron
    in a container or on a datastore host is a gap in most logging pipelines.
  methodology: structured-hypothesis-driven
  trigger: intel-report
hypothesis: An attacker has planted a cron entry in a data-tier container, such as
  a Redis pod, that runs a script from a writable data or temp directory every few
  minutes and opens a reverse shell to an external address.
labels:
- hunt
- attack.t1053.003
- attack.t1059.004
- attack.t1610
- attack.t1552.007
- attack.t1095
name: Data-Tier Container Cron Persistence and Reverse Shells
parameters:
  datastore_processes:
    default:
    - redis-server
    - valkey-server
    - keydb-server
    description: Datastore processes that should never write cron files or shell
      scripts. Matched on the executable's file name.
    from:
      kind: article
      observed: '2026-10-13'
      ref: https://x.com/TheM3gatr0n/status/2110405943964090564
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: Standard hunt window
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to run fleet-wide.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: Analyst-populated from scoping result.
    type: list[host]
  shell_tools:
    default:
    - nc
    - ncat
    - netcat
    - socat
    - sh
    - bash
    - dash
    - curl
    - wget
    description: Shells and tools used for reverse shells. Matched on the executable's
      file name.
    from:
      kind: article
      observed: '2026-10-13'
      ref: The planted script was a netcat reverse shell.
    type: list[string]
provenance:
  authors:
  - name: Huntbase
    org: huntbase.io
rationale: Start with hosts and containers running Redis or a compatible store, especially
  any reachable from the internet, then widen to every Linux host because the technique
  is not specific to Redis.
references:
- name: "@TheM3gatr0n — Operation CAIRN: An Autonomous AI Attack Platform Found\
    \ Running in the Wild"
  url: https://x.com/TheM3gatr0n/status/2110405943964090564
- name: "Datadog Security Labs \u2014 RedisRaider: Weaponizing misconfigured Redis\
    \ to mine cryptocurrency at scale"
  url: https://securitylabs.datadoghq.com/articles/redisraider-weaponizing-misconfigured-redis/
- name: "Unit 42 \u2014 P2PInfect: The Rusty Peer-to-Peer Self-Replicating Worm"
  url: https://unit42.paloaltonetworks.com/peer-to-peer-worm-p2pinfect/
- name: "MITRE ATT&CK — Scheduled Task/Job: Cron (T1053.003)"
  url: https://attack.mitre.org/techniques/T1053/003/
related:
- hunt: autonomous-exploitation-loop-commerce-mail
  reason: The exploitation loop from the same operation, before persistence.
  relation: follows
scenario:
  stages:
  - name: Exposed Datastore
    observables:
    - Redis pod on a multi-tenant SaaS platform on GCP
    slug: datastore-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Initial Access to the Cluster
    observables:
    - Compromise of the SaaS platform by the Cairn operator
    slug: initial-access
    tactic: initial-access
    techniques:
    - T1190
  - name: Cron Planted in the Pod
    observables:
    - '*/5 * * * * /bin/sh /data/pwn.sh in the pod crontab'
    - Script stored in the Redis data directory
    slug: cron-planting
    tactic: persistence
    techniques:
    - T1053.003
  - name: Reverse Shell Callback
    observables:
    - Netcat reverse shell to the operator's C2 every five minutes
    - Reported still running at the time of discovery
    slug: callback
    tactic: command-and-control
    techniques:
    - T1059.004
    - T1095
  - name: Environment Harvest
    observables:
    - Pod environment variables exposing internal service names for about 20 tenants
    slug: environment-harvest
    tactic: credential-access
    techniques:
    - T1552.007
  summary: The researcher who found the Cairn server reports that its operator compromised
    a multi-tenant SaaS platform on GCP and left a crontab entry in a Redis pod to
    run /data/pwn.sh every five minutes, a netcat reverse shell to their C2. The pod's
    environment named internal services for about 20 customer tenants.
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
tlp: clear
type: investigation
---


# Data-Tier Container Cron Persistence and Reverse Shells

The Redis pod in Operation CAIRN had a crontab line meant to open a reverse shell every five minutes. Crontabs inside containers are rarely collected and Redis keeps no command log, so the entry was invisible to anything waiting for an event. Whether it fired depends on whether the pod runs a cron daemon; most Redis images do not, and on a VM or node it would. Either way the file is there to find. This hunt asks the hosts what is scheduled now, what the datastore process has written, and what keeps calling out on a timer.

## datastore-scoping
<!-- Find hosts running Redis or a compatible store -->
List hosts and containers running Redis, Valkey or KeyDB.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hostnames running an in-memory datastore, with versions. These are the first
  places to look.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, asset_scope FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%redis%' OR LOWER(package_name) LIKE '%valkey%' OR LOWER(package_name) LIKE '%keydb%'
```

## exposed-datastores
<!-- Datastore ports reachable from outside -->
Check the external attack surface for Redis-compatible services answering on the internet.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Public addresses answering on 6379 or identified as Redis. Any row is a
  finding on its own.
reads:
- domain_or_ip
- port
- product
- version
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT domain_or_ip, port, product, version, discovered_at FROM hb_exposed_assets WHERE (port IN (6379, 6380, 16379) OR LOWER(product) LIKE '%redis%' OR LOWER(product) LIKE '%valkey%') AND discovered_at >= datetime('now', '-{{lookback_days}} days')
```

## persistence-signals
<!-- Ask the hosts what is scheduled, written and calling out -->
parallel:
- → datastore-file-writes
- → cron-from-writable-paths
- → rare-cron-commands
- → cron-executions-in-syslog
- → reverse-shell-processes
- → recurring-shell-egress
join: → triage-agent

## datastore-file-writes
<!-- The datastore writing cron files or scripts -->
Find files created or modified by the datastore process itself in cron directories, under SSH authorized keys, or ending in .sh. Redis abuse writes these with CONFIG SET dir and SAVE.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, datastore_processes=datastore_processes)
~~~yaml
expected: File writes by redis-server or a compatible process to cron paths, authorized_keys
  or shell scripts. A legitimate datastore writes only its own dump and append files.
reads:
- device_hostname
- process_name
- file_path
- file_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, process_name, file_path, file_name, activity_name, time FROM hb_file_activity WHERE instr(',' || '{{datastore_processes}}' || ',', ',' || LOWER(replace(process_name, rtrim(process_name, replace(process_name, '/', '')), '')) || ',') > 0 AND (LOWER(file_path) LIKE '%cron%' OR LOWER(file_name) LIKE '%.sh' OR LOWER(file_name) = 'authorized_keys') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## cron-from-writable-paths
<!-- Cron entries that run scripts from data or temp directories -->
Read the crontabs on each host and list entries that run something from a data, temp or shared-memory directory, or that pipe a download into a shell. This is the CAIRN entry exactly, and it does not depend on any log having been collected.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Cron entries whose command lives under /data, /tmp, /var/tmp or /dev/shm,
  or that fetch and run code. Short intervals such as */5 make a callback more likely.
reads:
- device_hostname
- job_kind
- job_schedule
- job_cmd_line
- job_user_name
- job_definition_path
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, job_schedule, job_cmd_line, job_user_name, job_definition_path, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_scheduled_job WHERE job_kind = 'cron' AND (LOWER(job_cmd_line) LIKE '%/data/%' OR LOWER(job_cmd_line) LIKE '%/tmp/%' OR LOWER(job_cmd_line) LIKE '%/dev/shm/%' OR LOWER(job_cmd_line) LIKE '%| sh%' OR LOWER(job_cmd_line) LIKE '%|sh%' OR LOWER(job_cmd_line) LIKE '%| bash%' OR LOWER(job_cmd_line) LIKE '%/dev/tcp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, job_schedule, job_cmd_line, job_user_name, job_definition_path ORDER BY first_seen DESC
```

## rare-cron-commands
<!-- Cron commands almost nobody else runs -->
Rank cron commands by how many hosts run them. Fleet-standard jobs appear on many hosts; a planted job appears on one or two. This catches entries the path check misses.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Cron commands present on very few hosts. Read the command and schedule of
  each; most will be legitimate one-offs.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_kind
- job_cmd_line
- job_schedule
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT job_cmd_line, job_schedule, COUNT(DISTINCT device_hostname) AS hosts, GROUP_CONCAT(DISTINCT device_hostname) AS host_list, MIN(time) AS first_seen FROM hb_scheduled_job WHERE job_kind = 'cron' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_cmd_line, job_schedule HAVING hosts < 3 ORDER BY hosts ASC, first_seen DESC LIMIT 300
```

## cron-executions-in-syslog
<!-- Cron running scripts from writable paths, by the hour -->
Where cron logs reach syslog, count how often each command from a writable path ran. A job that fires every five minutes for days is a callback, not maintenance.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: CRON CMD lines for scripts under /data, /tmp or /dev/shm, with run counts
  and the number of distinct hours they ran in.
reads:
- device_hostname
- syslog_tag
- message
- time
silence: not_evidence_of_absence
source: hb_syslog
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, message, COUNT(*) AS runs, COUNT(DISTINCT strftime('%Y-%m-%d %H', time)) AS active_hours, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_syslog WHERE UPPER(syslog_tag) LIKE 'CRON%' AND message LIKE '%CMD (%' AND (message LIKE '%/data/%' OR message LIKE '%/tmp/%' OR message LIKE '%/dev/shm/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, message ORDER BY runs DESC
```

## reverse-shell-processes
<!-- Shell tools started by cron or with reverse-shell arguments -->
Find netcat, socat or a shell started by cron, or started with arguments that wire a socket to a shell.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, shell_tools=shell_tools)
~~~yaml
expected: Shell tools whose parent is cron, or whose command line includes -e, /dev/tcp
  or an interactive shell. Any match on a datastore host should be treated as malicious
  until shown otherwise.
reads:
- device_hostname
- parent_process_name
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, parent_process_name, process_name, process_cmd_line, user_name, COUNT(*) AS executions, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_process_activity WHERE instr(',' || '{{shell_tools}}' || ',', ',' || LOWER(replace(process_name, rtrim(process_name, replace(process_name, '/', '')), '')) || ',') > 0 AND (LOWER(parent_process_name) LIKE '%cron%' OR process_cmd_line LIKE '% -e %' OR process_cmd_line LIKE '%/dev/tcp/%' OR process_cmd_line LIKE '%-i >&%' OR process_cmd_line LIKE '%/data/%.sh%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, parent_process_name, process_name, process_cmd_line, user_name ORDER BY executions DESC
```

## recurring-shell-egress
<!-- Shell tools calling the same public address on a timer -->
Find shell tools that open outbound connections to the same public address in many different hours. A five-minute cron callback shows up as a destination contacted almost every hour.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, shell_tools=shell_tools)
~~~yaml
expected: Process and destination pairs active across many hours. Destinations shared
  with reverse-shell-processes or the exploitation loop hunt are the operator's C2.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connections, COUNT(DISTINCT strftime('%Y-%m-%d %H', time)) AS active_hours, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE instr(',' || '{{shell_tools}}' || ',', ',' || LOWER(replace(process_name, rtrim(process_name, replace(process_name, '/', '')), '')) || ',') > 0 AND LOWER(direction) = 'outbound' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '127.%' AND dst_endpoint_ip NOT LIKE '172.1_.%' AND dst_endpoint_ip NOT LIKE '172.2_.%' AND dst_endpoint_ip NOT LIKE '172.30.%' AND dst_endpoint_ip NOT LIKE '172.31.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port HAVING active_hours >= 6 ORDER BY active_hours DESC
```

## triage-agent
<!-- Weigh persistence evidence per host -->
```agent target=hunter
cite: required
context:
- datastore-scoping
- exposed-datastores
- datastore-file-writes
- cron-from-writable-paths
- rare-cron-commands
- cron-executions-in-syslog
- reverse-shell-processes
- recurring-shell-egress
max_iterations: 10
objective: For each host, decide whether a planted cron job or reverse shell is present.
  A cron entry from a writable path plus a recurring outbound connection from a shell
  tool is malicious; either alone is suspicious.
success_criteria: A per-host verdict of malicious, suspicious or benign citing rows,
  with the cron entry and destination address for each malicious host.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on the per-host verdict -->
if~: "the triage-agent verdict is malicious for any host" (confidence: high, judge=hunter)
then: → contain-and-rotate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: ephemeral-pods-without-agent)
else: → analyst-review

## contain-and-rotate
<!-- Isolate the host and remove the foothold -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected hosts, collect the crontab and the script it runs, then remove the cron entry. Block the callback addresses at egress.
```
→ analyst-review

## analyst-review
<!-- Rotate what the pod could read -->
```manual target=analyst
For each malicious or suspicious host, pull the pod spec and list every secret and service address in its environment. Rotate those credentials, require authentication and protected mode on the datastore, and check whether the same image or Helm release runs elsewhere.
```
→ close-out

## close-out
<!-- Record and promote -->
```manual target=analyst
Record the hosts, cron entries and callback addresses. Promote cron-from-writable-paths and datastore-file-writes to watchers, and note which data-tier pods had no agent so the gap can be closed.
```
→ end
