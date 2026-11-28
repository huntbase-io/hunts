---
analysis: A static detection rule alerts on the presence of a CVE; this hunt correlates
  vulnerability status with active network listening states and anomalous inbound
  connection patterns across multiple surfaces to find exposure that a single alert
  misses.
blind_spots:
- id: missing-network-logs
  question: whether an external attacker connected to the LDAP service
  requires: hb_network_connection logs for inbound traffic
  risk: Without inbound connection logs, we cannot distinguish between a vulnerable
    but idle instance and one being actively probed or exploited.
  stage: exploit-vcenter-auth-bypass
- id: ldaps-encryption
  question: whether the content of an LDAP request on port 636 was malicious
  requires: LDAPS decryption or vmdir application audit logs
  risk: Encrypted LDAP (LDAPS) traffic prevents inspection of the request body, meaning
    we rely on connection prevalence rather than payload analysis.
  stage: exploit-vcenter-auth-bypass
coverage:
- stage: exploit-vcenter-auth-bypass
  status: covered
  steps:
  - identify-vulnerable-findings
  - vcenter-inventory-scoping
  - inbound-ldap-prevalence
  - vmdir-anomaly-check
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: VMware vCenter is a critical asset; an unauthenticated authentication
    bypass allows full control over the virtualization environment, making a negative
    result over the estate highly valuable.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthenticated attacker is attempting to exploit a critical authentication
  bypass in the VMware Directory Service (vmdir) by sending malicious LDAP or RPC
  traffic to exposed vCenter instances.
labels:
- hunt
- attack.t1190
- initial access
name: VMware vCenter Directory Service Authentication Bypass Exposure
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for network and process activity.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of vCenter servers to focus the hunt; leave empty to scan
      the estate.
    type: list[host]
  target_cves:
    default:
    - CVE-2026-123903
    - CVE-2026-123890
    description: CVE identifiers for the vCenter Directory Service authentication
      bypass.
    from:
      kind: article
      observed: '2026-11-24'
      ref: VMSA-2026-0011
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-cve-2026-123903-critical-vmware-directory-service-authentication-bypass-affects-vcenter
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers identified as vCenter in software inventory or those within
  virtualization management subnets. Include any devices with vulnerability findings
  for the targeted CVEs.
references:
- name: "Rapid7 \u2014 CVE-2026-123903: Critical VMware Directory Service Authentication\
    \ Bypass affects vCenter"
  url: https://www.rapid7.com/blog/post/etr-cve-2026-123903-critical-vmware-directory-service-authentication-bypass-affects-vcenter
related:
- hunt: vcenter-post-exploitation-behavior
  reason: This hunt focuses on initial exposure; a follow-on hunt would look for broader
    lateral movement or persistence across the virtualization fabric.
  relation: follows
scenario:
  stages:
  - name: vCenter Directory Service Auth Bypass
    observables:
    - CVE-2026-123903
    - CVE-2026-123890
    - VMware Directory Service (vmdir)
    - LDAP traffic on TCP/389 or TCP/636
    - RPC traffic to vCenter
    - vCenter versions 5.x, 7.0, 8.0, 9.0.x, 9.1.x
    slug: exploit-vcenter-auth-bypass
    tactic: initial-access
    techniques:
    - T1190
  summary: Attackers exploit a critical authentication bypass in the VMware Directory
    Service (vmdir) component of vCenter by sending crafted LDAP or RPC requests.
    Successful exploitation allows an unauthenticated attacker with network access
    to gain administrative control over the vCenter environment, potentially compromising
    all managed virtual infrastructure.
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


# VMware vCenter Directory Service Authentication Bypass Exposure

This hunt identifies VMware vCenter instances exposed to the critical authentication bypass vulnerabilities CVE-2026-123903 (LDAP) and CVE-2026-123890 (RPC). The hunt scopes the estate using vulnerability findings and software inventory, baselines inbound LDAP/RPC traffic to identify anomalous source IPs, and examines vCenter directory service process behavior for signs of post-exploitation activity. An agent weighs the exposure against the observed traffic patterns to prioritize remediation of the virtualization fabric.

## identify-vulnerable-findings
<!-- Identify vulnerability findings -->
Filter the estate for hosts already flagged by scanning products with the targeted vCenter CVEs.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: Rows identify specific devices and resources (vCenter instances) known to
  be vulnerable. Silence means no findings are recorded for these CVEs.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- status
- last_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, status, last_seen FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0
```

## vcenter-inventory-scoping
<!-- Enumerate vCenter software versions -->
Locate vCenter installations that may be vulnerable based on their reported version, providing a list of hostnames for subsequent steps.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames and vCenter versions. Any version below the fixed releases
  (e.g., 9.1.2, 9.0.2.0300, 8.0 U3m) is vulnerable.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%vcenter%'
```

## inbound-ldap-prevalence
<!-- Analyze inbound LDAP traffic prevalence -->
Detect anomalous inbound connections to vCenter LDAP ports (389/636) by stack-counting source IPs per host.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare source IPs connecting to LDAP ports on a vCenter instance. Administrative
  workstations and known load balancers should be the only frequent sources.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-26'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_port, COUNT(*) as connection_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE (dst_endpoint_port = 389 OR dst_endpoint_port = 636) AND direction = 'inbound' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_port ORDER BY connection_count ASC
```

## vmdir-anomaly-check
<!-- Check vmdir process behavior -->
Identify any unusual child processes or commands associated with the VMware Directory Service, which may follow a successful bypass.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The vmdir process should have minimal child activity. Any shell launch or
  unusual binary run by vmdir is highly suspicious.
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
verified_at: '2026-11-26'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%vmdir%' OR LOWER(parent_process_name) LIKE '%vmdir%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-vcenter-exposure
<!-- Triage vCenter exposure and traffic -->
```agent target=hunter
cite: required
context:
- identify-vulnerable-findings
- vcenter-inventory-scoping
- inbound-ldap-prevalence
- vmdir-anomaly-check
max_iterations: 4
objective: Determine if any vulnerable vCenter instances are exposed to potentially
  unauthenticated and unauthorized traffic that might exploit CVE-2026-123903.
success_criteria: A per-host verdict of exposed-at-risk, compromised, or benign, citing
  specific rows from network and process logs.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on exposure risk -->
if~: "the triage verdict identifies at least one vulnerable vCenter instance or suspicious inbound traffic from unknown source IPs" (confidence: medium, judge=hunter)
then: → remediation-task
indeterminate: → remediation-task
unavailable: → remediation-task (blind_spot: missing-network-logs)
else: → close-out

## remediation-task
<!-- Remediate vulnerable vCenter instances -->
```manual target=analyst
Apply VMware patches urgently for all instances identified as vulnerable (fixed in 9.1.2, 9.0.2.0300, 8.0 U3m, or 5.2.5). Review the ownership of anomalous source IPs identified in the network prevalence step. Restrict LDAP (389/636) and RPC traffic to trusted administrative network segments.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document all vulnerable instances discovered and confirm patch application. Update the asset management system to reflect current software versions and ensure the hunt is scheduled for periodic review.
```
→ end
