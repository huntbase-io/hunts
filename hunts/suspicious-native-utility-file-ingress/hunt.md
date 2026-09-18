---
analysis: A standard detection rule triggers on any curl execution. This hunt adds
  prevalence (stack-counting IPs), multiple surfaces (DNS, network, process), and
  agent-driven weighing of parent process context to reduce noise and identify the
  few truly suspicious events that matter.
blind_spots:
- id: missing-process-ancestry
  question: Was the download initiated by a manual shell session or a background daemon?
  requires: Auditbeat add_session_metadata or eBPF-based session tracking
  risk: Without session metadata, distinguishing between an admin running curl and
    a cronjob running curl depends entirely on parent process name, which can be spoofed
    or ambiguous.
  stage: ingress-tool-transfer-via-native-utilities
- id: obfuscated-urls
  question: Is the download URL obfuscated or reconstructed at runtime in a script?
  requires: hb_script_activity text analysis
  risk: If the URL is not literal in the command line (e.g., curl $URL), the process-level
    regex will miss it.
  stage: ingress-tool-transfer-via-native-utilities
coverage:
- stage: ingress-tool-transfer-via-native-utilities
  status: covered
  steps:
  - native-utility-executions
  - rare-destination-ips
  - external-dns-lookups
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ingress Tool Transfer is a foundational stage of post-compromise
    activity. In cloud environments, the noise of legitimate automation makes a hunt-based
    approach (targeting the 'long tail' of rare destinations) more effective than
    static rules.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using standard utilities like curl or wget to download
  malicious payloads from infrastructure outside the known-good cloud ecosystem, evading
  detection by blending with legitimate automation.
labels:
- hunt
- attack.t1105
name: Suspicious Native Utility File Ingress
parameters:
  known_good_domains:
    default:
    - acs-mirror.azureedge.net
    - packages.aks.azure.com
    - mcr.microsoft.com
    - artifacts.elastic.co
    - api.github.com
    description: Known package repositories and official service domains to baseline
      out.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: list[domain]
  known_good_ips:
    default:
    - 169.254.169.254
    - 168.63.129.16
    description: Cloud metadata and platform IPs (AWS/Azure/GCP) to ignore.
    from:
      kind: article
      observed: '2026-07-23'
      ref: elastic-security-labs
    type: list[ip]
  lookback_days:
    default: '14'
    description: The number of days to look back for process and network activity.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard-baseline
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to target; leave empty for the entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Target cloud workloads (Linux) and administrative endpoints (macOS). Initial
  runs should use a 14-day lookback to establish a baseline of common download behavior.
references:
- name: "Elastic Security Labs \u2014 ES|QL COMPLETION curl and wget detection triage"
  url: https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage
related:
- hunt: suspicious-python-urllib-ingress
  reason: Adversaries may use Python's built-in urllib or requests modules to bypass
    monitoring of curl/wget binaries.
  relation: sibling
scenario:
  stages:
  - name: Ingress Tool Transfer via Native Utilities
    observables:
    - curl
    - wget
    - 169.254.169.254
    - 168.63.129.16
    - acs-mirror.azureedge.net
    - packages.aks.azure.com
    - packages.microsoft.com
    - login.microsoftonline.com
    - management.azure.com
    - storage.googleapis.com
    - api.github.com
    - artifacts.elastic.co
    - download.elastic.co
    - process.parent.executable
    - process.args
    slug: ingress-tool-transfer-via-native-utilities
    tactic: command-and-control
    techniques:
    - T1105
  summary: Adversaries leverage native Linux utilities like curl and wget to download
    malicious tools or scripts onto compromised cloud hosts. To distinguish this from
    legitimate automation, defenders must filter high-volume activity directed at
    known-good cloud metadata services and package repositories.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
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


# Suspicious Native Utility File Ingress

This hunt identifies the use of built-in file transfer utilities for tool staging in cloud environments. It focuses on the 'long tail' of rare destination IPs and domains that bypass standard automation filters. By corroborating process execution with network connections and DNS lookups, it identifies suspicious downloads that a simple name-based rule would miss.

## scope-linux-and-macos
<!-- Scope to Linux and macOS Hosts -->
Identify active Linux and macOS systems where native utilities are the primary file transfer methods.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts currently active in the estate. Silence means no matching
  hosts were found within the lookback period.
reads:
- hostname
- os_name
- platform
- device_uid
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, os_name, platform, device_uid FROM hb_devices WHERE (LOWER(platform) IN ('linux', 'darwin', 'ubuntu')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## native-utility-executions
<!-- Ingress Utility Executions -->
Capture command-line executions of curl and wget containing URLs.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Raw command lines for ingress utilities. This will contain high volume;
  later steps filter out known-good infrastructure.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%') AND (LOWER(process_cmd_line) LIKE '%http://%' OR LOWER(process_cmd_line) LIKE '%https://%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroboration-parallel
<!-- Parallel Destination Triage -->
parallel:
- → rare-destination-ips
- → external-dns-lookups
join: → triage-utility-activity

## rare-destination-ips
<!-- Rare Destination IP Stack Counting -->
Identify destination IPs contacted by ingress utilities that appear on fewer than 5 hosts.

```sqlite target=network role=baseline params=(known_good_ips=known_good_ips, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IPs that are not standard cloud infrastructure. Rare IPs often indicate
  one-off manual downloads by an adversary.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 5
reads:
- dst_endpoint_ip
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%') AND NOT (instr(',' || '{{known_good_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING host_count < 5
```

## external-dns-lookups
<!-- External DNS Lookups -->
Correlate resolved hostnames against known-good mirrors to isolate suspicious domains.

```sqlite target=endpoint role=enrichment params=(known_good_domains=known_good_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Domains that are not part of the standard allow-list, such as Pastebin,
  transfer.sh, or unknown C2 domains.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (LOWER(process_name) LIKE '%curl%' OR LOWER(process_name) LIKE '%wget%') AND NOT (instr(',' || '{{known_good_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-utility-activity
<!-- Triage Utility Activity -->
```agent target=hunter
cite: required
context:
- native-utility-executions
- rare-destination-ips
- external-dns-lookups
max_iterations: 5
objective: 'Determine if the utility executions on a given host are part of standard
  cloud automation or suspicious behavior. Look for: 1) Downloads to user-writable
  paths (/tmp, /dev/shm), 2) Parent processes that are interactive shells (bash, zsh,
  sshd), and 3) Destinations that are rare or have no association with known vendors.'
success_criteria: A verdict of 'malicious', 'suspicious', or 'benign' per host with
  specific row citations.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious or suspicious for any host" (confidence: high, judge=hunter)
then: → analyst-task
indeterminate: → analyst-task
unavailable: → analyst-task (blind_spot: missing-process-ancestry)
else: → close-out

## analyst-task
<!-- Investigate Suspicious Ingress -->
```manual target=analyst
1) Review the cited curl/wget command lines and parent processes. 2) Check if the downloaded file was executed shortly after (pivot to hb_process_activity by host and time). 3) If the destination is a legitimate internal mirror, add it to 'known_good_ips' or 'known_good_domains'.
```
→ end

## close-out
<!-- Close and Tune -->
```manual target=analyst
The hunt found no evidence of suspicious tool ingress. Note any high-volume legitimate destinations that were encountered for future tuning of the 'known_good' lists.
```
→ end
