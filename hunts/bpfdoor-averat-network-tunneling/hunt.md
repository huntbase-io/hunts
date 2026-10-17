---
analysis: A simple rule might find port 25 traffic, but this hunt correlates regionalized
  disguise (SMTP symmetry) with eBPF-level raw socket attachments and specific HTTP
  protocol tunneling offsets, providing context a single rule cannot reach.
blind_spots:
- id: bpf-hostname-missing
  owner: Telemetry Team
  question: which specific host recorded a raw socket attachment
  remediation: Update the osctrl bpf_socket_events mapping to include the reporting
    device hostname.
  requires: a hostname column in the bpf_socket_events table
  risk: Identifying the target host requires manual correlation between process IDs
    and timestamps across different sources.
  stage: passive-bpf-backdoor
- id: ssl-encryption-blindness
  owner: Network Engineering
  question: whether the HTTPS triggers contain the specific 9999 padding
  remediation: Enable SSL termination and full URL query logging at the edge proxy
    layer.
  requires: decrypted HTTP query parameters from the edge proxy
  risk: If the edge proxy does not offload SSL and log query strings, the trigger
    signal remains invisible to this hunt.
  stage: network-traffic-blending
coverage:
- stage: passive-bpf-backdoor
  status: covered
  steps:
  - bpf-raw-sockets
- stage: network-traffic-blending
  status: covered
  steps:
  - smtp-symmetry-prevalence
  - http-trigger-detection
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: averat-dropper-installation
  status: out_of_scope
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: staging-shell-script
  status: out_of_scope
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: process-masquerading
  status: out_of_scope
- reason: 'Belongs to another part of the ''SMTP is the key: BPFDoor and AVERAT hitting
    the network edge'' series.'
  stage: forensic-evasion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Passive BPF backdoors do not maintain open listening ports and are
    invisible to conventional vulnerability scans; identifying the hidden trigger
    mechanisms is the only way to detect them.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed a passive BPF-based backdoor that remains dormant
  until triggered by specially crafted SMTP or HTTPS traffic, allowing for protocol
  tunneling without maintaining an open listening port.
labels:
- hunt
- attack.t1572
- attack.t1071.001
- attack.t1071.003
- attack.t1041
- command and control
- defense evasion
- execution
- persistence
- osctrl
name: BPFDoor and AVERAT Passive Network Tunneling
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: retention-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-defined
    type: list[host]
  trigger_paths:
    default:
    - /admin/login.aspx
    - /updiptable.php
    description: Known URL paths used for HTTPS tunneling triggers.
    from:
      kind: article
      observed: '2026-10-02'
      ref: rapid7-bpfdoor-2026
    type: list[path]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux-based edge appliances, firewalls, and mail relay systems.
  Prioritize systems running South Korean (SpamSniper) or Taiwanese (ShareTech) vendor
  platforms.
references:
- name: "Rapid7 \u2014 SMTP is the key: BPFDoor and AVERAT hitting the network edge"
  url: https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge
related:
- hunt: linux-process-spoofing-watchdog
  reason: This hunt focuses on the network trigger; a sibling hunt handles the behavioral
    process spoofing of ntpdate and udevds.
  relation: out-of-scope-alternative
- hunt: resident-watchdog-masquerading-linux-edge
  relation: follows
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  osctrl:
    category: siem
    huntbase:
      product: osctrl
    name: osctrl
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# BPFDoor and AVERAT Passive Network Tunneling

This hunt targets the network-level persistence and command-and-control mechanisms used by BPFDoor and AVERAT. These implants do not open traditional ports; instead, they use Berkeley Packet Filters (BPF) to sniff for magic sequences in existing traffic streams like SMTP and HTTPS. The hunt looks for symmetric SMTP traffic (port 25 to port 25) characteristic of BPF Rekoobe, unusual raw AF_PACKET socket attachments, and mathematically padded HTTPS requests designed to land triggers at specific TCP offsets. An agent weighs these independent signals to identify systems acting as stealthy network-edge backdoors.

## smtp-symmetry-prevalence
<!-- Symmetric SMTP traffic prevalence -->
Identify rare network connections where both the source and destination ports are 25, which indicates BPF Rekoobe blending with MTA relay traffic.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts showing symmetric port 25 traffic. While normal
  for mail servers, it is rare for general workstations or specific edge appliances
  not acting as relays.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  - dst_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- dst_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT src_endpoint_ip, dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS event_count FROM hb_network_connection WHERE (src_endpoint_port = 25 AND dst_endpoint_port = 25) AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_ip HAVING host_count <= 5 ORDER BY host_count ASC
```

## corroborate-signals
<!-- Corroborate with BPF and HTTP triggers -->
parallel:
- → bpf-raw-sockets
- → http-trigger-detection
join: → triage-signals

## bpf-raw-sockets
<!-- Raw PF_PACKET socket creation -->
Detect the creation of AF_PACKET sockets used by BPF-based backdoors to sniff network traffic without binding to a port.

```sqlite target=osctrl role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Processes opening AF_PACKET (family 17) sockets. This is rare for standard
  applications and indicates the presence of a sniffer or BPF implant.
reads:
- path
- pid
- family
- local_address
- remote_address
- time
silence: not_evidence_of_absence
source: bpf_socket_events
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT path, pid, local_address, remote_address, time FROM bpf_socket_events WHERE family = 17 AND time >= (strftime('%s', 'now') - ({{lookback_days}} * 86400))
```

## http-trigger-detection
<!-- HTTPS triggers with mathematical padding -->
Search for HTTP POST requests to trigger paths that include specific query padding designed to place payloads at predictable TCP offsets.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, trigger_paths=trigger_paths, scope_hosts=scope_hosts)
~~~yaml
expected: POST requests to admin or script paths containing '9999' in the query string.
  This aligns with the trigger mechanism of the Rapid7 BPFDoor controller.
reads:
- device_hostname
- url_path
- url_query
- user_agent
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-03'
~~~
SELECT device_hostname, url_path, url_query, user_agent, src_endpoint_ip, time FROM hb_http_activity WHERE (instr(',' || '{{trigger_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR url_query LIKE '%9999%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-signals
<!-- Triage passive implant signals -->
```agent target=hunter
cite: required
context:
- smtp-symmetry-prevalence
- bpf-raw-sockets
- http-trigger-detection
max_iterations: 4
objective: Analyze the results from the SMTP, BPF socket, and HTTP trigger queries.
  Determine if a system is likely infected with a passive backdoor based on concurrent
  activity across these three surfaces.
success_criteria: A verdict of malicious, suspicious, or benign for each host, citing
  specific PIDs and source IPs.
tools:
- network
- osctrl
- web
```

## route-verdict
<!-- Route based on agent verdict -->
if~: "the triage verdict identifies malicious passive backdoor activity on at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-verification
unavailable: → forensic-verification (blind_spot: bpf-hostname-missing)
else: → hunt-closure

## isolate-endpoint
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Do not reboot or terminate processes, as the BPF filters may only reside in memory. Capture a memory dump for forensic analysis.
```
→ forensic-verification

## forensic-verification
<!-- Forensic verification -->
```manual target=analyst
Manually correlate the PIDs found in bpf_socket_events with the hb_process_activity surface to identify the process name and command line. Check if the process image is deleted (on_disk = 0). Review web logs for the source IP of the padded HTTP triggers.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure -->
```manual target=analyst
Summarize the findings. If symmetric SMTP was confirmed, suggest a detection rule for persistent tcp/25-to-25 connections on non-mail-relay systems.
```
→ end
