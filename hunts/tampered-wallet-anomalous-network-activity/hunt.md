---
analysis: A simple network rule might flag the malicious IP, but would likely miss
  the domain masking or produce false positives on legitimate Exodus users. This hunt
  pivots between the fictional installer metadata, the user-profile install path,
  and the network telemetry to confirm the modular RAT context.
blind_spots:
- id: limited-netflow-retention
  question: whether beaconing occurred before the lookback period
  requires: hb_network_connection long-term retention
  risk: Infections older than the lookback window may not show active network signals,
    relying solely on the presence of the installer/process.
  stage: c2-legitimate-domain-masking
- id: dns-over-https
  question: whether the wallet uses encrypted DNS to hide the masking lookups
  requires: TLS decryption or endpoint-based DNS capture
  risk: Standard DNS activity logs (hb_dns_activity) will miss queries if the binary
    uses its own DoH resolver.
  stage: c2-legitimate-domain-masking
coverage:
- stage: c2-legitimate-domain-masking
  status: covered
  steps:
  - dns-to-masking-domains
  - outbound-to-malicious-ip
  - tampered-process-execution
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: initial-access-script-dropper
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: execution-silent-msi-install
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: persistence-hidden-wallet-install
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Crypto Wallet That Never Opened: Tampered
    Exodus Installer Hides a Modular RAT'' series.'
  stage: evasion-process-reparenting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The use of legitimate infrastructure to mask C2 traffic is a high-confidence
    technique used by this modular RAT to bypass traditional domain-reputation filters;
    identifying the anomalous process origin is critical to distinguishing it from
    legitimate wallet usage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A tampered cryptocurrency wallet is masking its command-and-control activity
  by communicating with legitimate infrastructure while originating from a non-standard
  installation path.
labels:
- hunt
- attack.t1071.001
- attack.t1036.005
- attack.t1547.001
name: Tampered Wallet Anomalous Network Activity
parameters:
  c2_domains:
    default:
    - fiat.a.exodus.io
    - assets-gateway-clarity-api.a.exodus.io
    - us05.org
    - pdf.js
    description: Legitimate and infrastructure domains named in the report.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress-exodus-rat
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_ips:
    default:
    - 35.212.159.20
    description: IP addresses associated with the installer delivery.
    from:
      kind: article
      observed: '2026-09-01'
      ref: huntress-exodus-rat
    type: list[ip]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with endpoints reporting 'Apple Inc' as a software vendor for products
  other than standard Apple software. Focus on workstations where users may handle
  cryptocurrency.
references:
- name: 'The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular
    RAT'
  url: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat
related:
- hunt: initial-access-script-dropper
  reason: The initial delivery via double-extension .pdf.js scripts is handled in
    the execution-focused hunt.
  relation: out-of-scope-alternative
- hunt: tampered-wallet-endpoint-deployment-persistence
  relation: follows
scenario:
  stages:
  - name: JavaScript Dropper Delivery
    observables:
    - .pdf.js
    - Update_GS_7G0N-254V38L2350.zip
    - Update_GS_7G0N-254V38L2350.js
    - search-ms:displayname=Search Results
    - \\us05.org@8080\update
    - us05.org
    - 35.212.159.20
    slug: initial-access-script-dropper
    tactic: initial-access
    techniques:
    - T1566.001
    - T1036.007
  - name: Silent MSI Installation
    observables:
    - msiexec /i "%TEMP%\jn0101.msi" /quiet /norestart
    - msiexec /i "%TEMP%\jg0384.msi" /quiet /norestart
    - jn0101.msi
    - jg0384.msi
    slug: execution-silent-msi-install
    tactic: execution
    techniques:
    - T1218.007
  - name: Persistent Invisible Installation
    observables:
    - '%APPDATA%\ExdBackupTool\'
    - Exodus.exe
    - app.asar
    - INetHealth
    - conhost.exe --headless powershell -e
    slug: persistence-hidden-wallet-install
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: UI Suppression and Reparenting
    observables:
    - explorer.exe parent of Exodus.exe
    - BrowserWindow.prototype.show = function () {};
    - app.setPath('userData', ...)
    - conhost.exe --headless
    slug: evasion-process-reparenting
    tactic: defense-evasion
    techniques:
    - T1134.004
    - T1562.001
  - name: Wallet Domain C2
    observables:
    - fiat.a.exodus.io
    - assets-gateway-clarity-api.a.exodus.io
    - 35.212.159.20
    slug: c2-legitimate-domain-masking
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: A campaign using tampered Exodus wallet installers to deliver a modular
    RAT. Victims are lured via JavaScript droppers with double extensions or ZIP archives
    that silently install a real but modified wallet which suppresses its UI to remain
    invisible while mimics legitimate network traffic to steal credentials.
series:
  index: 2
  slug: the-crypto-wallet-that-never-opened-tampered-exodus-installer-hides-a-modular-rat
  title: 'The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular
    RAT'
  total: 2
severity: high
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


# Tampered Wallet Anomalous Network Activity

This hunt identifies compromised systems by searching for a modular RAT masquerading as a legitimate Exodus wallet. The malware is characterized by a tampered installer that uses a fake 'Apple Inc' manufacturer label and installs into the user's AppData directory rather than Program Files. Once active, the RAT communicates with legitimate Exodus domains to mask its traffic, but also beacons to known malicious infrastructure. We pivot from suspicious software inventory markers to process execution and network corroboration.

## identify-tampered-install-inventory
<!-- Identify tampered software inventory markers -->
Locate hosts with software inventory matching the tampered MSI markers: fictional version 43.4.30 and Apple Inc manufacturer.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts with a 'Background Service' package from 'Apple Inc' at version 43.4.30.
  Silence suggests this specific installer variant is not present in the inventory.
reads:
- device_hostname
- install_path
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (LOWER(vendor_name) = 'apple inc' OR package_version = '43.4.30' OR LOWER(package_name) = 'background service')
```

## tampered-process-execution
<!-- Exodus execution from non-standard paths -->
Detect the tampered wallet running from the specific AppData subfolder identified in the research.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes named Exodus.exe running from the ExdBackupTool directory. This
  is the primary indicator of the persistent modular RAT.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_path
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE LOWER(process_path) LIKE '%\exdbackuptool\exodus.exe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-activity-parallel
<!-- Correlate Network Activity -->
parallel:
- → dns-to-masking-domains
- → outbound-to-malicious-ip
join: → triage-network-activity

## dns-to-masking-domains
<!-- DNS queries to masking and infra domains -->
Stack-count DNS queries to identify hosts resolving Exodus domains, specifically narrowing to the rare binary context.

```sqlite target=endpoint role=baseline params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A high volume of queries to legitimate domains from a process other than
  a standard browser or the official Exodus path.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  - process_name
  rare_below: 5
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
SELECT device_hostname, query_hostname, process_name, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## outbound-to-malicious-ip
<!-- Direct connections to known malicious infrastructure -->
Identify any direct IP-based network activity to the hard-coded C2/delivery IP.

```sqlite target=network role=enrichment params=(malicious_ips=malicious_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Network connections to 35.212.159.20. While the RAT tries to mask via domains,
  early delivery or fallback may hit the IP directly.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_hostname, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{malicious_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-network-activity
<!-- Evaluate evidence for RAT masking -->
```agent target=hunter
cite: required
context:
- identify-tampered-install-inventory
- tampered-process-execution
- dns-to-masking-domains
- outbound-to-malicious-ip
max_iterations: 4
objective: Determine if the Exodus.exe process running from ExdBackupTool is beaconing
  to malicious IPs or performing anomalous DNS requests to legitimate domains in a
  manner that suggests C2 masking.
success_criteria: A verdict citing specific process paths and matched network events
  for every suspicious host.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-netflow-retention)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR agent to prevent data exfiltration. Collect the %APPDATA%\ExdBackupTool\ folder content for forensic analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Verify the triage findings. Check browser history for searches related to 'JavaScript spam' or 'malicious MSI'. Examine the app.asar file in the install directory for the exodus_patch.js modification.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the hunt results. If legitimate Exodus wallets were found in user profiles, verify their origin with the asset owners.
```
→ end
