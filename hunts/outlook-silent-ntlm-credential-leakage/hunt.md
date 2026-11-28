---
analysis: A static rule for Outlook connections to port 445 provides only a partial
  picture. This hunt correlates vulnerability status from the inventory plane with
  network prevalence baselining to distinguish legitimate Office 365 traffic from
  targeted credential beaconing.
blind_spots:
- id: limited-network-telemetry
  question: whether Outlook attempted a leak from a host where EDR or network logging
    is disabled
  requires: hb_network_connection from all scoped hosts
  risk: A successful hash theft via port 445 may occur without a corresponding log
    entry on unmonitored systems.
  stage: forced-ntlm-authentication-leak
- id: webdav-fallback-visibility
  question: whether Outlook utilized WebDAV over port 80 or 443 to leak hashes
  requires: Deep Packet Inspection or Proxy logs
  risk: While port 445 is the primary target, the vulnerability may attempt WebDAV
    fallback; this traffic is difficult to distinguish from legitimate web browsing
    without specialized inspection.
  stage: forced-ntlm-authentication-leak
coverage:
- stage: outlook-vulnerability-exploitation
  status: covered
  steps:
  - find-vulnerable-outlook-assets
- stage: forced-ntlm-authentication-leak
  status: covered
  steps:
  - stack-outlook-external-ips
  - detect-suspicious-outlook-egress
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: CVE-2026-124194 is an actively exploited-in-the-wild vulnerability
    that enables silent credential theft. NTLM hash leakage allows for offline cracking
    and relay attacks, representing a high risk to the identity security of the enterprise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is exploiting CVE-2026-124194 by forcing Outlook to initiate
  outbound SMB connections to an external listener, silently leaking the user's NTLM
  v2 hash upon opening a crafted file.
labels:
- hunt
- attack.t1190
- attack.t1203
- attack.t1204.002
- attack.t1187
- credential access
- initial access
name: Outlook Silent NTLM Credential Leakage
parameters:
  cve_id:
    default: CVE-2026-124194
    description: The specific CVE identifier for the Outlook spoofing vulnerability.
    from:
      kind: article
      observed: '2026-11-10'
      ref: rapid7-patch-tuesday-nov-2026
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-10'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search; leave empty to hunt
      across the whole estate.
    from:
      kind: manual
      observed: '2026-11-10'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/em-patch-tuesday-november-2026
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize hosts running Windows with classic Outlook.
  If hb_vulnerability_finding is unavailable, use hb_software_inventory to identify
  hosts with Outlook versions older than the November 2026 patch cycle.
references:
- name: "Rapid7 \u2014 Patch Tuesday - November 2026"
  url: https://www.rapid7.com/blog/post/em-patch-tuesday-november-2026
related:
- hunt: ntlm-relay-attempt-detection
  reason: This hunt focuses on the outbound leakage originating from Outlook; detecting
    the internal use of those stolen hashes is a separate forensic problem handled
    by authentication monitoring.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Opening of Malicious File in Outlook
    observables:
    - outlook.exe
    - specially crafted malicious file
    - CVE-2026-124194
    slug: outlook-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1203
    - T1204.002
  - name: Forced NTLM Authentication Leak
    observables:
    - NTLM v2 hash
    - outbound SMB connection on port 445
    - outbound HTTP/WebDAV connection
    - attacker-controlled location
    slug: forced-ntlm-authentication-leak
    tactic: credential-access
    techniques:
    - T1187
  summary: Attackers exploit CVE-2026-124194, a spoofing vulnerability in Microsoft
    Outlook, by sending a specially crafted malicious file. When a user opens the
    file, Outlook silently initiates an outbound connection to an external attacker-controlled
    server, resulting in the leakage of the user's NTLMv2 hash for credential theft
    or relay.
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


# Outlook Silent NTLM Credential Leakage

This hunt identifies Windows assets vulnerable to the silent spoofing vulnerability CVE-2026-124194 and monitors for the primary indicator of exploitation: Outlook initiating outbound connections on port 445 (SMB) to non-private IP addresses. The flow first identifies vulnerable hosts using scanner findings, baselines legitimate Outlook network activity to identify rare external destinations, and then focuses specifically on high-risk SMB egress that suggests forced authentication for hash theft.

## find-vulnerable-outlook-assets
<!-- Identify vulnerable Outlook hosts -->
Locate assets where vulnerability scanners have confirmed the presence of CVE-2026-124194 to focus analysis on at-risk endpoints.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: A list of unique IDs and versions for exposed assets. Silence suggests the
  patch is applied or the scanner has not yet detected the vulnerability.
reads:
- resource_uid
- device_uid
- affected_package_version
- severity
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT resource_uid, device_uid, affected_package_version, severity, collected_at FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status != 'suppressed'
```

## stack-outlook-external-ips
<!-- Baseline Outlook external destinations -->
Stack-count outbound destinations from Outlook to external IPs to identify rare endpoints that might be attacker-controlled listeners.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of external IPs contacted by Outlook on very few hosts. Legitimate
  Microsoft services should show high host counts.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%outlook.exe' OR LOWER(process_path) LIKE '%outlook.exe') AND direction = 'outbound' AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '127.%' OR dst_endpoint_ip LIKE '169.254.%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY dst_endpoint_ip HAVING host_count <= 3 ORDER BY host_count ASC
```

## detect-suspicious-outlook-egress
<!-- Detect forced SMB authentication -->
Focus on the specific behavioral signature of hash theft: Outlook connecting to an external IP on port 445 (SMB).

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any row showing Outlook connecting to an external SMB listener is highly
  suspicious and indicative of forced NTLM authentication.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%outlook.exe' OR LOWER(process_path) LIKE '%outlook.exe') AND dst_endpoint_port = 445 AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '127.%' OR dst_endpoint_ip LIKE '169.254.%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-leakage-verdict
<!-- Evaluate exposure and behavioral evidence -->
```agent target=hunter
cite: required
context:
- find-vulnerable-outlook-assets
- stack-outlook-external-ips
- detect-suspicious-outlook-egress
max_iterations: 5
objective: Determine which hosts are vulnerable to CVE-2026-124194 and exhibit the
  forced authentication signature of outbound port 445 connections to rare external
  destinations.
success_criteria: A per-host verdict of 'vulnerable-and-exploited', 'vulnerable-only',
  or 'benign' based on the presence of the vulnerability and outbound SMB telemetry.
tools:
- endpoint
- network
```

## route-on-triage
<!-- Route on triage results -->
if~: "the triage-leakage-verdict confirms exploitation behavior (rare outbound SMB) on at least one host" (confidence: high, judge=hunter)
then: → remediation-review
indeterminate: → remediation-review
unavailable: → remediation-review (blind_spot: limited-network-telemetry)
else: → close-out

## remediation-review
<!-- Remediation and perimeter verification -->
```manual target=analyst
Review the external IP destinations identified in the triage verdict. If they are unaffiliated with corporate services, prioritize the November 2026 Outlook updates on those hosts. Ensure that the network perimeter is explicitly blocking outbound port 445 (SMB) and 137-139 (NetBIOS) to external destinations.
```
→ end

## close-out
<!-- Exposure audit close-out -->
```manual target=analyst
Record the number of vulnerable assets identified. If no suspicious SMB activity was found, recommend that patching for CVE-2026-124194 be prioritized in the standard maintenance window to reduce the exposure window.
```
→ end
