---
analysis: A single rule for IP discovery or nvidia-smi queries is prone to noise;
  this hunt correlates these behaviors with kernel-level file indicators and library
  hook backups that an automated rule cannot easily link across multiple surfaces.
blind_spots:
- id: kernel-module-hiding
  question: Can we see the miner process and socket if the rootkit is loaded?
  requires: unhooked kernel-level auditing
  risk: The acpi_thermal_mgr.ko rootkit hooks ftrace to hide itself; if successfully
    loaded, process and network telemetry from the host will be suppressed or falsified.
  stage: defense-evasion-stealth-mechanisms
- id: obfuscated-tor-traffic
  question: Are obfs4 or WebTunnel bridges detectable?
  requires: hb_network_connection with TLS fingerprinting
  risk: SANSAR's use of Lyrebird allows it to tunnel Tor traffic within standard HTTPS
    sessions, bypassing simple protocol-based filters.
  stage: c2-tor-and-ethereum
coverage:
- stage: defense-evasion-stealth-mechanisms
  status: covered
  steps:
  - rootkit-file-indicators
  - gpu-telemetry-query
- stage: c2-tor-and-ethereum
  status: covered
  steps:
  - ip-discovery-behavior
- reason: 'Belongs to another part of the ''0% GPU utilization: How SANSAR hides Linux
    cryptomining'' series.'
  stage: initial-access-ray-job-agent
  status: out_of_scope
- reason: 'Belongs to another part of the ''0% GPU utilization: How SANSAR hides Linux
    cryptomining'' series.'
  stage: execution-reverse-shell
  status: out_of_scope
- reason: 'Belongs to another part of the ''0% GPU utilization: How SANSAR hides Linux
    cryptomining'' series.'
  stage: persistence-toolkit-deployment
  status: out_of_scope
- reason: 'Belongs to another part of the ''0% GPU utilization: How SANSAR hides Linux
    cryptomining'' series.'
  stage: impact-cryptomining
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The SANSAR toolkit falsifies GPU use and uses kernel-level hiding
    to maintain persistent cryptomining; a negative result over the GPU estate is
    required to ensure resource integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed a Linux rootkit and modified library wrappers
  to hide cryptomining while using Tor and external IP discovery services for orchestration.
labels:
- hunt
- attack.t1059
- attack.t1090.003
- attack.t1496
- command and control
- defense evasion
- execution
- impact
- initial access
- persistence
name: SANSAR Stealth and Evasive C2 Channels
parameters:
  ip_check_domains:
    default:
    - api.ipify.org
    - ifconfig.me
    - icanhazip.com
    - checkip.amazonaws.com
    description: External IP discovery services used by SANSAR for C2 bootstrapping.
    from:
      kind: article
      observed: '2026-11-12'
      ref: elastic-security-labs-sansar
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-12'
      ref: analyst-standard
    type: number
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts if the lead query is too broad.
    from:
      kind: manual
      observed: '2026-11-12'
      ref: analyst-defined-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on Linux nodes with NVIDIA GPUs. Use the lead query result
  to populate scope_hosts for higher fidelity behavioral correlation.
references:
- name: "Elastic Security Labs \u2014 0% GPU utilization: How SANSAR hides Linux cryptomining"
  url: https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
related:
- hunt: sansar-persistence-and-impact
  reason: This hunt focuses on stealth and C2 channels; mining impact and systemd
    persistence are handled in a separate hunt.
  relation: out-of-scope-alternative
- hunt: ray-framework-exploitation-sansar-staging
  relation: follows
scenario:
  stages:
  - name: Ray Job Agent Exploitation
    observables:
    - Unauthenticated access to Ray Job API
    - External probes in Ray logs
    - Job submission to Ray head node
    slug: initial-access-ray-job-agent
    tactic: initial-access
    techniques:
    - T1059
  - name: Python Reverse Shell Execution
    observables:
    - nvidia-smi --query-gpu=name
    - Python reverse-shell job submission
    - Connection to external listener via Python
    slug: execution-reverse-shell
    tactic: execution
    techniques:
    - T1059
  - name: Persistence and Toolkit Deployment
    observables:
    - Staging under /opt/vadi_/
    - Modification of authorized_keys for SSH access
    - netns backdoor registered as a systemd service
    - acpi_thermal_mgr kernel module built via DKMS
    - initramfs loader modification
    slug: persistence-toolkit-deployment
    tactic: persistence
    techniques:
    - T1059
  - name: Stealth and Telemetry Falsification
    observables:
    - acpi_thermal_mgr.ko loading
    - Replacement of libnvidia-ml.so.1 with modified wrapper
    - Presence of libnvidia-ml.so.1.backup
    - SANSAR anti-debugging TracerPid check in /proc/self/status
    slug: defense-evasion-stealth-mechanisms
    tactic: defense-evasion
    techniques:
    - T1059
  - name: Evasive Command and Control
    observables:
    - efxisnqldelyr5ra25oqfrsut54b34g26e7zrsiuupsoekjof2gho2id.onion:9051
    - api.ipify.org
    - ifconfig.me
    - icanhazip.com
    - checkip.amazonaws.com
    - Lyrebird transport helper usage (obfs4, WebTunnel)
    - Ethereum smart contract calls for netns C2 resolution
    slug: c2-tor-and-ethereum
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Cryptomining Resource Hijacking
    observables:
    - kurt (XMRig 6.25.0) process activity
    - tilki (SRBMiner-MULTI 3.6.9) process activity
    - Deployment of GPU mining contexts
    slug: impact-cryptomining
    tactic: impact
    techniques:
    - T1496
  summary: Threat actor REF3364 targets Linux GPU hosts by exploiting unauthenticated
    Ray job agents to gain root access and persistent shell control. The campaign
    deploys the SANSAR toolkit, which employs a kernel rootkit to hide its presence
    and modified NVIDIA libraries to falsify GPU utilization while managing cryptomining
    and backdoors via Tor and Ethereum-based infrastructure.
series:
  index: 2
  slug: 0-gpu-utilization-how-sansar-hides-linux-cryptomining
  title: '0% GPU utilization: How SANSAR hides Linux cryptomining'
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


# SANSAR Stealth and Evasive C2 Channels

This hunt identifies the stealth mechanisms and evasive Command and Control channels of the SANSAR toolkit. It targets the installation of the acpi_thermal_mgr kernel module and the libnvidia-ml library hook used to falsify GPU telemetry. The flow correlates these stealth indicators with behavioral patterns such as specific GPU inventory queries and the use of external IP discovery services that precede Tor-based C2 communication.

## rootkit-file-indicators
<!-- Detect rootkit and library hook indicators -->
Identify hosts with the SANSAR kernel module or the modified NVML library backup file.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicating the presence of the toolkit files. Silence suggests these
  specific names were not used or are hidden by a functional rootkit.
reads:
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, file_path, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%acpi_thermal_mgr.ko%' OR LOWER(file_path) LIKE '%libnvidia-ml.so.1.backup%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-checks
<!-- Correlate behavior across surfaces -->
parallel:
- → ip-discovery-behavior
- → gpu-telemetry-query
join: → triage-agent

## ip-discovery-behavior
<!-- DNS lookups to IP discovery services -->
Identify the sequence of IP discovery attempts SANSAR uses to bootstrap its Tor connection.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, ip_check_domains=ip_check_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS queries to multiple services from the list on a single host.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as count FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{ip_check_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## gpu-telemetry-query
<!-- Unusual GPU inventory commands -->
Identify the specific nvidia-smi telemetry query used by the SANSAR orchestrator to select miners.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A specific csv-formatted query command that matches SANSAR's internal logic.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, process_cmd_line, COUNT(*) as count, MIN(time) as first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(process_cmd_line) LIKE '%--query-gpu=name%' AND LOWER(process_cmd_line) LIKE '%--format=csv,noheader%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_cmd_line
```

## triage-agent
<!-- Analyze SANSAR presence -->
```agent target=hunter
cite: required
context:
- rootkit-file-indicators
- ip-discovery-behavior
- gpu-telemetry-query
max_iterations: 3
objective: Evaluate whether the file indicators (acpi_thermal_mgr or library backups)
  intersect with IP discovery DNS lookups and specific GPU inventory queries to confirm
  SANSAR toolkit deployment.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing evidence
  from at least two surfaces.
tools:
- endpoint
```

## verdict-decision
<!-- Route on triage results -->
if~: "The triage-agent verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-investigation
unavailable: → forensic-investigation (blind_spot: kernel-module-hiding)
else: → completion-task

## isolate-host
<!-- Isolate Linux host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host at the network layer. Preserve current process memory to capture the rootkit in its unhidden state. Do not reboot, as this triggers the initramfs persistence module.
```
→ forensic-investigation

## forensic-investigation
<!-- Forensic review and sample collection -->
```manual target=analyst
Manually inspect /opt/vadi_ for the sansar and netns binaries. Extract the acpi_thermal_mgr.ko module from the boot image or RAM. Review network logs for Ethereum smart contract interactions linked to the netns backdoor.
```
→ completion-task

## completion-task
<!-- Close out hunt -->
```manual target=analyst
Record whether the nvidia-smi queries were legitimate administrative activity. Document any observed rootkit samples to improve kernel-module load detections.
```
→ end
