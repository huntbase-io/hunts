---
analysis: A simple detection rule would only find the file name netcapa.exe; this
  hunt correlates that metadata with persistent service activity, unique configuration
  file names, and masqueraded network behavior to confirm a targeted Webworm intrusion.
blind_spots:
- id: encrypted-tls
  question: whether the custom CGI paths are visible in HTTPS sessions
  remediation: Enable TLS inspection for outbound traffic to unknown IP spaces.
  requires: TLS inspection on hb_http_activity
  risk: If the SoftEther bridge uses HTTPS and traffic is not decrypted at the sensor,
    the URL paths will be invisible.
  stage: custom-c2-communication
coverage:
- stage: modified-binary-execution
  status: covered
  steps:
  - inventory-scoping
  - vpn-bridge-persistence
- stage: defense-evasion-config
  status: covered
  steps:
  - rare-process-metadata
  - encrypted-config-lookup
- stage: custom-c2-communication
  status: covered
  steps:
  - masqueraded-c2-traffic
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The use of a rebranded open-source VPN bridge allows an attacker
    to maintain a high-bandwidth, long-term persistence channel that bypasses standard
    malware signatures. Identifying these tunnels is critical for preventing persistent
    data exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established a persistent, covert tunnel by deploying a
  customized SoftEther VPN bridge that masquerades as legitimate network monitor software
  using modified PE metadata and encrypted configuration files.
labels:
- hunt
- attack.t1036.005
- attack.t1027.005
- attack.t1027.013
- attack.t1133
- attack.t1071
- attack.t1090.001
- attack.t1140
- attack.t1587.001
- attack.t1599
- attack.t1686.003
- command and control
- defense evasion
- persistence
name: Rebranded SoftEther VPN Tunneling
parameters:
  c2_paths:
    default:
    - /update/alive.cgi
    - /update/picture.cgi
    description: Masqueraded HTTP endpoints used by the custom VPN protocol.
    from:
      kind: article
      observed: '2026-11-19'
      ref: https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge
    type: list[path]
  fake_vendor:
    default: Network Systems Solutions Inc
    description: The fake company name used in the tool PE metadata.
    from:
      kind: article
      observed: '2026-11-19'
      ref: https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty for the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by examining systems with Network Systems Solutions Inc in their
  software inventory. Focus on external-facing servers where a VPN bridge would logically
  be deployed to provide ingress.
references:
- name: "Rapid7 \u2014 Spying on Governments with Zero Lines of Malware"
  url: https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge
scenario:
  stages:
  - name: Modified VPN Bridge Execution
    observables:
    - netcapa.exe
    - SEVPNBRIDGE
    - Network Monitor Software
    - Network Systems Solutions Inc.
    - vpnbridge.pdb
    - 4, 44, 0, 9807
    slug: modified-binary-execution
    tactic: persistence
    techniques:
    - T1036.005
    - T1133
    - T1587.001
  - name: Internal Rebranding and Encrypted Config
    observables:
    - setting.conf
    - RCEN
    - NtMonitor VPN
    - SoftEther Project
    - hamcore.se2
    slug: defense-evasion-config
    tactic: defense-evasion
    techniques:
    - T1027.005
    - T1027.013
    - T1140
  - name: Custom C2 Tunneling
    observables:
    - /update/alive.cgi
    - /update/picture.cgi
    - AS 20473
    - image/jpeg
    - 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
    slug: custom-c2-communication
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.001
    - T1599
  summary: Webworm (China-aligned APT) has modified the open-source SoftEther VPN
    Bridge into a custom variant known as 'NtMonitor' to maintain stealthy persistence.
    The actor rebrands the binary metadata, encrypts the configuration files, and
    alters the network handshake and HTTP endpoints to evade standard VPN detection
    signatures.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Rebranded SoftEther VPN Tunneling

This hunt targets the NtMonitor variant of SoftEther VPN attributed to the Webworm APT. The actor rebrands the open-source tool as Network Monitor Software and uses masqueraded HTTP endpoints like /update/alive.cgi for C2. The hunt starts by identifying potential target hosts via software inventory, then fans out to find persistence through services, rare process metadata matching the actor's rebranding, the presence of the unique setting.conf encrypted configuration file, and custom HTTP URI paths. An agent triages these results to distinguish between legitimate network tools and the Webworm toolkit.

## inventory-scoping
<!-- Software Inventory Scoping -->
Identify hosts running software with the actor's fake vendor name or the specific version of SoftEther used in the build.

```sqlite target=endpoint role=scoping params=(fake_vendor=fake_vendor)
~~~yaml
expected: Hosts with software attributed to the fake vendor or the exact version identified
  in the research. None proves this specific package is not registered in the inventory.
reads:
- device_hostname
- vendor_name
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, vendor_name, package_name, package_version FROM hb_software_inventory WHERE (LOWER(vendor_name) LIKE '%' || LOWER('{{fake_vendor}}') || '%' OR package_version = '4.44.0.9807')
```

## investigate-webworm
<!-- Investigate Webworm Indicators -->
parallel:
- → vpn-bridge-persistence
- → rare-process-metadata
- → masqueraded-c2-traffic
- → encrypted-config-lookup
join: → triage-findings

## vpn-bridge-persistence
<!-- VPN Bridge Service Persistence -->
Find the persistent service installed by the actor, which often retains the original SoftEther service name.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows naming the SEVPNBRIDGE service or the netcapa.exe binary in the command
  line.
reads:
- device_hostname
- service_name
- service_cmd_line
- time
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, service_name, service_cmd_line, time FROM hb_service_activity WHERE (LOWER(service_name) = 'sevpnbridge' OR LOWER(service_cmd_line) LIKE '%netcapa.exe%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-process-metadata
<!-- Rare Processes with Actor Metadata -->
Stack-count processes using the netcapa.exe OriginalFileName to find rare deployments that deviate from fleet baseline.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process binary seen on very few hosts. Stock network tools would appear
  across many servers, whereas the intruder's build is likely rare.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_original_file_name) = 'netcapa.exe' OR LOWER(process_path) LIKE '%netcapa.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY path HAVING hosts <= 3
```

## masqueraded-c2-traffic
<!-- Masqueraded HTTP C2 Traffic -->
Identify outbound HTTP traffic to the specific CGI endpoints used by the custom SoftEther protocol.

```sqlite target=web role=enrichment params=(c2_paths=c2_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Connections to /update/alive.cgi or /update/picture.cgi. Silence may mean
  traffic is encrypted and requires the blind spot note.
reads:
- device_hostname
- url_path
- url_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, url_path, url_hostname, src_endpoint_ip, time FROM hb_http_activity WHERE instr(',' || '{{c2_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## encrypted-config-lookup
<!-- Encrypted Config File Presence -->
Find the presence of the setting.conf file which contains the actor's custom encrypted configuration.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The creation or access of setting.conf, particularly in a directory containing
  netcapa.exe.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-20'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'setting.conf' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-findings
<!-- Triage VPN Findings -->
```agent target=hunter
cite: required
context:
- vpn-bridge-persistence
- rare-process-metadata
- masqueraded-c2-traffic
- encrypted-config-lookup
max_iterations: 3
objective: Determine if the evidence matches the NtMonitor variant of SoftEther VPN
  used by Webworm, specifically focusing on the combination of netcapa.exe, SEVPNBRIDGE,
  and the custom HTTP paths.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-beachhead
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: encrypted-tls)
else: → close-out

## isolate-beachhead
<!-- Isolate Beachhead -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the netcapa.exe binary and setting.conf for forensic analysis and potential decryption of the bridge target IP.
```
→ manual-review

## manual-review
<!-- Manual Forensic Review -->
```manual target=analyst
Inspect the collected binary for the pdb path vpnbridge.pdb and check setting.conf for the RCEN magic bytes. Use the Rapid7 python script to attempt decryption of the cascade target IP.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the findings. If confirmed, promote the netcapa.exe OriginalFileName check to a permanent detection rule.
```
→ end
