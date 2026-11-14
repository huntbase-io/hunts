---
analysis: A static rule for the dropper hash misses the resident implant once it has
  deleted its binary. This hunt pivots between file-staging evidence and a fleet-wide
  prevalence check for processes whose images are unmapped (on_disk = 0) while they
  masquerade as system services.
blind_spots:
- id: ephemeral-script-deletion
  question: whether the staging script existed for less than ten seconds between polling
    intervals
  requires: high-frequency file activity logging
  risk: If the script is deleted faster than the sensor reports, the creation event
    may be missed.
  stage: staging-shell-script
- id: passive-bpf-backdoor-socket
  question: whether a process has attached a BPF filter to a raw socket
  requires: hb_kernel_extension_activity or raw eBPF telemetry
  risk: The passive backdoor trigger is invisible to conventional socket monitoring
    because it does not bind to a port; we rely on process masquerading markers instead.
  stage: process-masquerading
coverage:
- stage: averat-dropper-installation
  status: covered
  steps:
  - find-dropper-files
- stage: staging-shell-script
  status: covered
  steps:
  - find-staging-scripts
- stage: process-masquerading
  status: covered
  steps:
  - rare-masqueraded-processes
- stage: forensic-evasion
  status: covered
  steps:
  - detect-environment-evasion
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: passive-bpf-backdoor
  status: out_of_scope
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: network-traffic-blending
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Edge appliances are high-value targets for persistent, silent access.
    A negative result on masqueraded daemons across the appliance estate provides
    a high-confidence signal that this specific resident threat is absent.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has installed persistence on a Linux appliance by using a
  shell script to stage binaries in /sbin, then deleting the files to leave the processes
  running as fileless masqueraded daemons.
labels:
- hunt
- attack.t1059.004
- attack.t1036.004
- attack.t1562.001
- command and control
- defense evasion
- execution
- persistence
name: Resident Watchdog and Masquerading on Linux Edge
parameters:
  dropper_hashes:
    default:
    - 2bedc26d4b29b435c21962beed7db21188a0219a0d28334bba8b4fb1656d7b15
    - a37ea9897221d4495b538de72b74f2aa1d2ff09b7b6dcedd395aee58931adbf3
    - 7e667ba5f9df912e02275d3cfe3809d16f822fe776f4035c84b118ebd925b1b5
    - a6f3b7f932761fb1fd5e74123f2482e36c65dd13e769af2ce08c65da195bfa7a
    - 4435fcd6862921092614dbeaa880e4192352984686ebcd98f0ba13ee8e226ef9
    - 652508a9cf40bee883dc0e5e219dfeba71fe7dac591d01c89f74c21f73b4963f
    description: Known SHA256 hashes for the AVERAT and BPFDoor components.
    from:
      kind: article
      observed: '2026-10-02'
      ref: Rapid7
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-02'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to scan the whole estate.
    from:
      kind: manual
      observed: '2026-10-02'
      ref: scoping
    type: list[host]
  spoofed_names:
    default:
    - /sbin/ntpdate
    - /sbin/udevds
    - /usr/sbin/abrtd
    - /usr/sbin/chronyd
    - /usr/sbin/rsyslogd
    - /usr/sbin/crond
    - /sniper/bin/crond
    - /sniper/bin/earsd
    - /sniper/apache/bin/httpd
    - ora_ppmond
    - dtnpd
    - ofgmd
    - earsd
    - snipe-smtpd
    - '[watchdogd]'
    description: Process names and paths the implants adopt to blend into Linux or
      telecom appliance environments.
    from:
      kind: article
      observed: '2026-10-02'
      ref: Rapid7
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on Linux hosts with non-standard mounts like /addpkg or
  /HDD. Use the scoping step to identify these before pasting them into the scope_hosts
  parameter.
references:
- name: "Rapid7 \u2014 SMTP is the key: BPFDoor and AVERAT hitting the network edge"
  url: https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge
related:
- hunt: passive-bpf-backdoor-network-triggers
  reason: This hunt focuses on host residency; the network trigger and SMTP blending
    are covered in the follow-on network hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AVERAT Dropper Installation
    observables:
    - dropper binary located in add-on package directory /addpkg/sbin/update
    - 'SHA256: 2bedc26d4b29b435c21962beed7db21188a0219a0d28334bba8b4fb1656d7b15'
    - AES-128-ECB key derived from string 'ShareTech'
    slug: averat-dropper-installation
    tactic: execution
    techniques:
    - T1059
  - name: Staging via Shell Script
    observables:
    - shell script written to storage mount /HDD/ms6x2xTo64/updIptable.php
    - watchdog marker file /HDD/ms6x2xTo64/execProcEnd
    - secondary payloads staged in /sbin/ntpdate and /sbin/udevds
    slug: staging-shell-script
    tactic: persistence
    techniques:
    - T1059.004
  - name: Process Identity Masquerading
    observables:
    - 'process names: ntpdate, udevds, abrtd, chronyd, rsyslogd, crond, python, ora_ppmond,
      dtnpd, ofgmd, earsd, httpd, snipe-smtpd'
    - 'PID file: /var/run/spamsniper.pid'
    - processes running with on_disk = false after self-deletion
    slug: process-masquerading
    tactic: defense-evasion
    techniques:
    - T1036.004
  - name: Passive BPF Backdoor
    observables:
    - attachment of BPF filters to PF_PACKET raw sockets
    - 'magic bytes: 0x6693 (UDP), 0x4274 (TCP), 0x7820 (ICMP), 0x5571'
    - 'handshake sequence: 50 01 13 3F 08 5C 73 7B 1A 72 53 78'
    slug: passive-bpf-backdoor
    tactic: command-and-control
    techniques:
    - T1572
  - name: C2 Traffic Blending
    observables:
    - SMTP traffic with source and destination ports equal to 25
    - HTTPS POST requests with mathematical padding to /admin/login.aspx?id=99990
    - 'URL paths: /admin/login.aspx, updiptable.php'
    - 'integrated Tiny Shell command opcodes: S, U, D'
    slug: network-traffic-blending
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1071.003
  - name: Command History Evasion
    observables:
    - 'execution of environment variable overrides: HISTFILE=/dev/null, HISTSIZE=0,
      VIMINIT=''set viminfo='''
    slug: forensic-evasion
    tactic: defense-evasion
    techniques:
    - T1562
  summary: A campaign targeting Linux-based telecom edge appliances in South Korea
    and Taiwan using a multi-stage infection chain involving the AVERAT dropper and
    BPFDoor/Rekoobe implants. The campaign utilizes regionalized process masquerading,
    passive BPF-based triggers, and traffic blending over SMTP and HTTPS to maintain
    persistent, stealthy access to network infrastructure.
series:
  index: 1
  slug: smtp-is-the-key-bpfdoor-and-averat-hitting-the-network-edge
  title: 'SMTP is the key: BPFDoor and AVERAT hitting the network edge'
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


# Resident Watchdog and Masquerading on Linux Edge

This hunt examines the host-level deployment of AVERAT and BPFDoor variants, which use regionalized process masquerading to blend into telecommunications environments. The attack chain involves a dropper writing a shell script to an appliance storage mount, which then stages payloads under common daemon names like ntpdate or udevds and deletes the source files ten seconds later while the processes continue running.

We pivot from initial file activity in appliance-specific paths to a behavioral check for processes running without an on-disk image, stack-counting these across the fleet to identify rare, malicious residency. The hunt further searches for environment variable manipulation used to suppress command history and vim logs, providing multiple points of correlation for resident implants.

## scope-appliance-mounts
<!-- Scope hosts with appliance mount paths -->
Identify the fleet's Linux appliances by looking for activity in non-standard mount paths used by regional edge vendors.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence means no hosts in the estate use these vendor-specific
  directory conventions.
reads:
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT DISTINCT device_hostname FROM hb_file_activity WHERE (LOWER(file_path) LIKE '/addpkg/%' OR LOWER(file_path) LIKE '/hdd/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early-stage
<!-- Parallel search for dropper and staging -->
parallel:
- → find-dropper-files
- → find-staging-scripts
join: → agent-early-assessment

## find-dropper-files
<!-- Search for AVERAT dropper files -->
Find the initial dropper binary using known hashes or the specific add-on package path.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, dropper_hashes=dropper_hashes)
~~~yaml
expected: A file match on one or more hosts. Silence proves the reported hashes and
  path were not written in the window.
reads:
- device_hostname
- file_path
- file_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT device_hostname, file_path, file_hash_sha256, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{dropper_hashes}}' || ',', ',' || file_hash_sha256 || ',') > 0 OR LOWER(file_path) LIKE '%/addpkg/sbin/update') AND time >= datetime('now', '-{{lookback_days}} days')
```

## find-staging-scripts
<!-- Search for shell-script staging -->
Detect the creation of the shell script or watchdog markers used to deploy secondary payloads.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A script file creation event. Silence means the specific staging paths were
  not used.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%updiptable.php' OR LOWER(file_path) LIKE '%execprocend') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-assessment
<!-- Evaluate initial infection signals -->
```agent target=hunter
cite: required
context:
- find-dropper-files
- find-staging-scripts
max_iterations: 3
objective: Determine if any host shows evidence of the AVERAT dropper or the staging
  script execution as described in the Rapid7 research.
success_criteria: A list of potentially infected hosts with the specific staging markers
  found.
tools:
- endpoint
```

## parallel-residency-stage
<!-- Parallel search for residency and evasion -->
parallel:
- → rare-masqueraded-processes
- → detect-environment-evasion
join: → agent-residency-assessment

## rare-masqueraded-processes
<!-- Baseline rare processes with no on-disk image -->
Stack-count processes that match the disguise names or run with no binary on disk.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, spoofed_names=spoofed_names)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare processes (seen on < 3 hosts) that match the masquerading profile or
  run fileless. Silence on on_disk=0 is a strong negative result.
prevalence:
  by: device_hostname
  key:
  - process_name
  - on_disk
  rare_below: 3
reads:
- process_name
- on_disk
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT process_name, on_disk, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (on_disk = 0 OR instr(',' || '{{spoofed_names}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, on_disk HAVING host_count <= 3
```

## detect-environment-evasion
<!-- Detect command history suppression -->
Identify shells attempting to suppress history, a common anti-forensic measure for these implants.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines containing history-evading variables. Silence proves this
  measure was not used.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%histfile=/dev/null%' OR LOWER(process_cmd_line) LIKE '%histsize=0%' OR LOWER(process_cmd_line) LIKE '%viminit=%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-residency-assessment
<!-- Final verdict on resident implants -->
```agent target=hunter
cite: required
context:
- agent-early-assessment
- rare-masqueraded-processes
- detect-environment-evasion
max_iterations: 6
objective: Assess if any host from the early assessment also shows fileless masquerading
  or forensic evasion.
success_criteria: A comprehensive list of malicious hosts citing the full chain of
  evidence.
tools:
- endpoint
```

## decision-route
<!-- Route on resident compromise -->
if~: "the agent-residency-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → action-isolate-host
indeterminate: → task-forensic-collection
unavailable: → task-forensic-collection (blind_spot: ephemeral-script-deletion)
else: → task-hunt-review

## action-isolate-host
<!-- Isolate compromised appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot, as the malware lives in memory and the binary is deleted; capture process memory to preserve the payload.
```
→ task-forensic-collection

## task-forensic-collection
<!-- Perform memory and shell forensics -->
```manual target=analyst
Collect process memory for the masqueraded daemons identified. Check for the presence of the BPFDoor magic bytes in the memory space of the processes.
```
→ task-hunt-review

## task-hunt-review
<!-- Review and close hunt -->
```manual target=analyst
Finalize the incident summary and document any appliance directories found that were not in the original report.
```
→ end
