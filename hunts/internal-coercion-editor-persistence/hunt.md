---
analysis: This is a hunt because it uses fleet-wide prevalence to distinguish authorized
  network services from rogue protocol spoofers and correlates them with specific
  editor plugin persistence that standard EDR rules often miss.
blind_spots:
- id: no-endpoint-telemetry
  question: Are there rogue services running on non-enrolled hosts?
  requires: Endpoint agent coverage
  risk: A rogue DHCPv6 server on an unmanaged device can still poison the network,
    but this hunt only detects the server-side behavior if the attacker uses an enrolled
    host.
  stage: ipv6-dns-takeover-coercion
- id: no-kerberos-relay-visibility
  question: Was a Kerberos relay attack actually performed?
  requires: Domain Controller authentication logs
  risk: The hunt detects the coercion setup (the rogue DNS) but cannot confirm if
    a relay successfuly occurred without AD-specific authentication telemetry.
  stage: ipv6-dns-takeover-coercion
coverage:
- stage: ipv6-dns-takeover-coercion
  status: covered
  steps:
  - scope-vulnerable-hosts
  - rare-network-activity
- stage: rdp-anomalous-interaction
  status: covered
  steps:
  - rare-network-activity
- stage: kate-plugin-persistence
  status: covered
  steps:
  - kate-persistence
- reason: "Belongs to another part of the 'Metasploit Wrap Up: Belgian Waffles, Chocolates,\
    \ and\u2026Modules-Frites?' series."
  stage: gitlab-unauthenticated-file-read
  status: out_of_scope
- reason: "Belongs to another part of the 'Metasploit Wrap Up: Belgian Waffles, Chocolates,\
    \ and\u2026Modules-Frites?' series."
  stage: langflow-authenticated-rce
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Internal network coercion via DHCPv6/IPv6 is a critical credential-access
    vector that is often overlooked in traditional network monitoring. Detecting the
    rare rogue services and the prerequisite vulnerability provides a proactive defense
    against Kerberos relay attacks.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using rogue DHCPv6 services to perform DNS takeover for
  Kerberos relaying, or has established persistence via unauthorized Kate editor plugins
  on compromised hosts.
labels:
- hunt
- attack.t1190
- attack.t1021.001
name: Internal Coercion and Editor Persistence
parameters:
  cve_id:
    default: CVE-2026-20929
    description: The Windows HTTP.sys vulnerability used for coercion.
    from:
      kind: article
      observed: '2026-09-25'
      ref: rapid7-metasploit-wrapup-2026-09
    type: string
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      ref: Standard lookback window
    type: number
  scope_hosts:
    default: []
    description: List of hostnames from the scoping step to focus behavioral analysis;
      leave empty to hunt across the entire estate.
    from:
      kind: manual
      ref: Analyst scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-belgian-waffles-chocolates-and-modules-frites
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on systems vulnerable to CVE-2026-20929 as they are the
  primary targets for the network coercion module. Behavioral queries are then filtered
  to these hosts to detect active exploitation.
references:
- name: "Metasploit Wrap Up: Belgian Waffles, Chocolates, and\u2026Modules-Frites?"
  url: https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-belgian-waffles-chocolates-and-modules-frites
related:
- hunt: gitlab-file-read-cve-2026-85706
  reason: GitLab exploitation is a perimeter access vector handled by its own hunt.
  relation: out-of-scope-alternative
- hunt: exploitation-web-facing-gitlab-langflow
  relation: follows
scenario:
  stages:
  - name: GitLab Unauthenticated Arbitrary File Read
    observables:
    - CVE-2026-85706
    - HTTP requests to GitLab repository commits APIs
    - HTTP requests to GitLab repository files APIs
    - 'Module: gather/gitlab_file_read_cve_2026_85706'
    - Affected GitLab versions 18.7 up to 19.3.2
    slug: gitlab-unauthenticated-file-read
    tactic: initial-access
    techniques:
    - T1190
  - name: Langflow AI Authenticated RCE
    observables:
    - CVE-2026-18729
    - Authenticated HTTP requests to Langflow custom components
    - Arbitrary Python code execution via Langflow process
    - 'Module: multi/http/langflow_auth_rce_cve_2026_18729'
    - Langflow versions 1.11.1 and below
    slug: langflow-authenticated-rce
    tactic: execution
    techniques:
    - T1190
  - name: IPv6 DNS Takeover Coercion
    observables:
    - CVE-2026-20929
    - Rogue DHCPv6 server activity on UDP port 547
    - Rogue IPv6 Router Advertisements (RA)
    - Kerberos authentication relay attempts
    - 'Module: spoof/dhcp/dhcpv6_dns_takeover'
    - 'Module: spoof/ipv6/ipv6_ra_dns_takeover'
    slug: ipv6-dns-takeover-coercion
    tactic: credential-access
    techniques:
    - T1190
  - name: Anomalous RDP Interaction
    observables:
    - Unexpected size RDP packets and responses
    - Anomalous Remote Interactive logons
    - RDP connections to internal assets on port 3389
    slug: rdp-anomalous-interaction
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Kate Plugin Persistence
    observables:
    - Writes to Kate editor plugin directories
    - New plugin configuration files for Kate editor
    - 'Module: multi/persistence/kate_plugin'
    slug: kate-plugin-persistence
    tactic: persistence
    techniques:
    - T1190
  summary: Recent Metasploit updates introduced exploitation modules for unauthenticated
    file read in GitLab (CVE-2026-85706) and authenticated RCE in Langflow AI (CVE-2026-18729).
    The release also features native IPv6 DNS takeover modules for Kerberos relay
    attacks and a new persistence mechanism targeting the Kate text editor.
series:
  index: 2
  slug: metasploit-wrap-up-belgian-waffles-chocolates-and-modules-frites
  title: "Metasploit Wrap Up: Belgian Waffles, Chocolates, and\u2026Modules-Frites?"
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
tlp: clear
type: investigation
---


# Internal Coercion and Editor Persistence

This hunt identifies internal network protocol abuse and application-specific persistence following the Metasploit September 2026 update. It first scopes systems vulnerable to the HTTP.sys coercion vector (CVE-2026-20929) and then searches in parallel for rare network activity on DHCPv6 (UDP 547) or RDP (3389) ports, and unauthorized file activity in Kate editor plugin directories. An agent weighs these behavioral signals to distinguish rogue services and persistence mechanisms from legitimate administrative activity.

## scope-vulnerable-hosts
<!-- Identify vulnerable hosts -->
Locate systems susceptible to HTTP.sys privilege elevation which allows the network coercion described in the research.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: A list of host identifiers currently vulnerable to the coercion vector.
  Silence indicates the estate is patched against this specific exploit.
reads:
- device_uid
- resource_uid
- severity
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_uid, resource_uid, severity, collected_at FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status != 'suppressed'
```

## behavioral-fan-out
<!-- Analyze behavior in parallel -->
parallel:
- → rare-network-activity
- → kate-persistence
join: → triage-findings

## rare-network-activity
<!-- Rare network activity on sensitive ports -->
Find processes listening on or initiating connections on DHCPv6 (547) and RDP (3389) ports.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous processes using DHCPv6 or RDP on systems that do not usually provide
  these services. Silence in a complete log indicates the absence of this specific
  network coercion.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_port
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_port
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, dst_endpoint_port, COUNT(*) AS connections, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE (dst_endpoint_port = 547 OR dst_endpoint_port = 3389) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_port
```

## kate-persistence
<!-- Kate editor plugin persistence -->
Detect rare file creations in Kate editor plugin directories used for multi-platform persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Creation of new plugin files by unexpected processes. Benign results include
  legitimate plugin installations by the user.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, file_path, file_name, process_name, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%/kate/plugins/%' OR LOWER(file_path) LIKE '%\\kate\\plugins\\%') AND activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-findings
<!-- Triage behavioral evidence -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-hosts
- rare-network-activity
- kate-persistence
max_iterations: 5
objective: Determine if any host vulnerable to CVE-2026-20929 shows evidence of rogue
  DHCPv6/RDP activity or unauthorized Kate plugin persistence. Identify if the same
  process is responsible for the network listener and any file writes.
success_criteria: A verdict of malicious, suspicious, or benign for each host, citing
  relevant rows from the behavioral queries.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for any host exhibiting rogue DHCPv6 listeners or unauthorized editor plugins" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-endpoint-telemetry)
else: → remediate-vulnerability

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Terminate the process identified as a rogue DHCPv6 or RDP listener.
```
→ manual-review

## manual-review
<!-- Analyst forensic review -->
```manual target=analyst
Inspect the file contents in the Kate plugin directory. Verify if the process listening on port 547 or 3389 matches an authorized network management tool.
```
→ remediate-vulnerability

## remediate-vulnerability
<!-- Remediate HTTP.sys vulnerability -->
```manual target=analyst
Apply the latest Windows updates to all hosts identified in the scoping step to mitigate CVE-2026-20929.
```
→ end
