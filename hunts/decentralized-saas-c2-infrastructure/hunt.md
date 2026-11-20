---
analysis: Static detection rules for specific gateways are easily bypassed by rotating
  infrastructure. This hunt uses prevalence and behavioral process correlation across
  multiple surfaces to find the infrastructure-agnostic pattern of decentralized resolution.
blind_spots:
- id: no-dns-process-correlation
  question: Which process initiated the blockchain gateway resolution?
  requires: endpoint telemetry linking DNS queries to specific processes
  risk: An analyst cannot distinguish between a browser visit and background malware
    resolution, increasing false positives.
  stage: blockchain-and-saas-c2
- id: encrypted-c2-payloads
  question: What configuration was retrieved from the Ethereum or Arweave blob?
  requires: TLS inspection or memory forensics
  risk: The hunt sees the gateway but not the contents of the configuration rotation.
  stage: blockchain-and-saas-c2
coverage:
- stage: blockchain-and-saas-c2
  status: covered
  steps:
  - dns-lookups-to-infra
  - rare-infrastructure-lookups
  - suspicious-outbound-connections
- reason: Belongs to the initial access hunt in this series.
  stage: initial-access-trojanized-msi
  status: out_of_scope
- reason: Requires hb_scheduled_job and hb_file_activity over the SYSVOL directory.
  stage: impact-gpo-ransomware
  status: not_visible
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: etherrat-execution-node-js
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: persistence-registry-run-key
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: internal-reconnaissance-and-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: secondary-payload-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: credential-access-lsass-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: lateral-movement-rmm-and-netexec
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: data-exfiltration-rclone
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Blockchain gateways and SaaS platforms for C2 resolution make traditional
    domain blacklisting ineffective. Identifying rare lookups to these services detects
    resilient malware before ransomware deployment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses decentralized blockchain gateways or SaaS platforms to
  resolve C2 configuration and tunnel traffic, bypassing static network perimeter
  filters.
labels:
- hunt
- attack.t1102.001
- attack.t1572
name: Decentralized and SaaS C2 Infrastructure
parameters:
  c2_infrastructure_domains:
    default:
    - 1rpc.io
    - goldsky.arweave.net
    - arweave.net
    - g8way.io
    - supabase.co
    - supabase.com
    - trycloudflare.com
    - ably.com
    - clickhouse.com
    description: Known blockchain gateways and SaaS platforms used for C2 resolution.
    from:
      kind: article
      observed: '2026-05-11'
      ref: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  malware_process_names:
    default:
    - node.exe
    - greenshot.exe
    - synctrayzor.exe
    - docfx.exe
    - cake.exe
    description: Legitimate process names abused or trojanized in this intrusion.
    from:
      kind: article
      observed: '2026-05-11'
      ref: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to investigate; leave empty to scan the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins with endpoints and servers that lack a business requirement
  for blockchain or decentralized storage access. Focus on high-value targets like
  domain controllers and database servers first.
references:
- name: "The DFIR Report \u2014 Flash Alert: EtherRat and TukTuk C2 End in The Gentleman\
    \ Ransomware"
  url: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
related:
- hunt: initial-access-trojanized-msi
  reason: This hunt focuses on network aftermath; the malicious MSI installation is
    a separate execution stage.
  relation: out-of-scope-alternative
- hunt: secondary-payload-sideloading
  reason: Sideloading detection requires file and module activity telemetry not used
    in this network hunt.
  relation: out-of-scope-alternative
- hunt: etherrat-tuktuk-infection-discovery
  relation: follows
scenario:
  stages:
  - name: Trojanized MSI installer
    observables:
    - msiexec.exe /V
    - MVnVmUYj.cmd
    - RAMMap utility masquerade
    slug: initial-access-trojanized-msi
    tactic: initial-access
    techniques:
    - T1204.002
  - name: EtherRAT execution via Node.js
    observables:
    - curl -sLo "C:\Users\REDACTED\AppData\Local\Temp\9gY0LJMyXW.zip" "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"
    - node-v18.20.5-win-x64.zip
    - node.exe
    - A7Pnj975bl.cfg
    slug: etherrat-execution-node-js
    tactic: execution
    techniques:
    - T1059.003
    - T1105
  - name: Persistence via Registry Run key
    observables:
    - reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver /d
      "conhost --headless "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\gksVMg\node.exe"
      "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\A7Pnj975bl.cfg"" /f
    - AppResolver
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Internal reconnaissance and discovery
    observables:
    - powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command "[System.Globalization.CultureInfo]::InstalledUICulture.Name"
    - powershell -Command "try { (Get-CimInstance -Namespace root/SecurityCenter2
      -ClassName AntivirusProduct -EA Stop).displayName -join ', ' } catch { 'none'
      }"
    - net group "Domain Admins" /domain
    - nltest /domain_trusts /all_trusts
    - netscan.exe
    slug: internal-reconnaissance-and-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1518.001
    - T1087.002
    - T1018
  - name: TukTuk deployment via DLL sideloading
    observables:
    - Greenshot.exe
    - SyncTrayzor.exe
    - docfx.exe
    - Cake.exe
    slug: secondary-payload-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Blockchain and SaaS C2
    observables:
    - 1rpc.io
    - goldsky.arweave.net
    - trycloudflare.com
    - supabase.co
    - 1rpc.io
    - goldsky.arweave.net
    slug: blockchain-and-saas-c2
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1572
  - name: Credential Access via LSASS dumping
    observables:
    - 'rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24'
    - Kerberoasting
    - NTDS dumping
    slug: credential-access-lsass-dumping
    tactic: credential-access
    techniques:
    - T1003.001
    - T1558.003
  - name: Lateral movement via RMM and NetExec
    observables:
    - GoToResolveProcessChecker.exe
    - nxc smb REDACTED_IP -u REDACTED_USER -p REDACTED_PASSWORD --ntds
    - nxc
    - winrm
    slug: lateral-movement-rmm-and-netexec
    tactic: lateral-movement
    techniques:
    - T1219
    - T1021.001
    - T1021.002
  - name: Data exfiltration via Rclone
    observables:
    - rclone
    - Wasabi cloud storage
    slug: data-exfiltration-rclone
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Ransomware deployment via GPO
    observables:
    - The Gentlemen ransomware
    - Microsoft Defender disabled
    - GPO execution via SYSVOL/NETLOGON
    - vssadmin.exe delete shadows
    slug: impact-gpo-ransomware
    tactic: impact
    techniques:
    - T1486
    - T1489
    - T1053.005
    - T1484.001
  summary: A threat actor used a trojanized MSI installer to deploy EtherRAT, leveraging
    Ethereum blockchain and TryCloudflare for resilient C2 before deploying the TukTuk
    framework via DLL sideloading. The intrusion progressed through extensive AD discovery
    and lateral movement using NetExec and GoTo Resolve, concluding with data exfiltration
    via Rclone and domain-wide deployment of The Gentleman ransomware via GPO and
    scheduled tasks.
series:
  index: 2
  slug: flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware
  title: 'Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware'
  total: 3
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


# Decentralized and SaaS C2 Infrastructure

This hunt targets the network infrastructure pattern used by EtherRAT and TukTuk. These malware families use Ethereum and Arweave blockchain gateways to resolve dynamic C2 addresses and use SaaS platforms like Supabase or TryCloudflare for persistent command channels. The hunt identifies rare lookups to these services and correlates them with suspicious processes or non-standard binaries executing on the host.

## dns-lookups-to-infra
<!-- DNS lookups to decentralized infrastructure -->
Find hosts resolving blockchain gateways or SaaS C2 platforms mentioned in the report to build a candidate list.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, c2_infrastructure_domains=c2_infrastructure_domains, scope_hosts=scope_hosts)
~~~yaml
expected: The query returns a list of hosts and processes communicating with decentralized
  infrastructure. Silence means no direct resolution of these domains occurred.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_infrastructure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.trycloudflare.com') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## correlate-network-and-prevalence
<!-- Analyze network connections and domain prevalence -->
parallel:
- → rare-infrastructure-lookups
- → suspicious-outbound-connections
join: → triage-network-evidence

## rare-infrastructure-lookups
<!-- Rare infrastructure domain lookups -->
Stack-count domain lookups to blockchain and SaaS gateways to isolate unusual resolution behavior in the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, c2_infrastructure_domains=c2_infrastructure_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The query returns domains appearing on five or fewer hosts. These are high-priority
  candidates for decentralized C2 resolution.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT LOWER(query_hostname) AS domain, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_infrastructure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.trycloudflare.com') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY domain HAVING host_count <= 5 ORDER BY host_count ASC
```

## suspicious-outbound-connections
<!-- Suspicious outbound network connections -->
Identify established network connections from the trojanized binaries or processes running from suspicious user-writable paths.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, malware_process_names=malware_process_names, scope_hosts=scope_hosts)
~~~yaml
expected: The query shows trojanized binaries or user-path executables making outbound
  connections. Rare destination ports or IPs increase suspicion.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{malware_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_path) LIKE '%\\appdata\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-network-evidence
<!-- Triage network evidence -->
```agent target=hunter
cite: required
context:
- dns-lookups-to-infra
- rare-infrastructure-lookups
- suspicious-outbound-connections
max_iterations: 6
objective: Determine if network connections to blockchain/SaaS domains represent legitimate
  use or decentralized C2 activity for EtherRAT and TukTuk.
success_criteria: A verdict of malicious, suspicious, or benign for each host, citing
  rare domains or suspicious process paths.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-process-correlation)
else: → close-out

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve its memory for further analysis of the C2 configuration blob.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the DNS and network connection rows. Check for parent-child relationships between node.exe and suspicious payloads. Search for Drive-Id patterns if Arweave gateways were contacted.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Summarize findings. If new C2 domains were discovered in command lines or telemetry, update the parameter list for future runs.
```
→ end
