---
analysis: "A simple detection rule flags the vulnerability finding; this hunt corroborates\
  \ that finding with internet exposure data and live process activity\u2014specifically\
  \ looking for high-frequency terminations and restarts\u2014to provide a risk-based\
  \ remediation plan that a single scanner cannot produce."
blind_spots:
- id: incomplete-inventory
  question: Which Orthanc servers are installed on hosts without an inventory agent?
  requires: hb_software_inventory
  risk: Legacy medical equipment or unmanaged IoMT devices may run vulnerable Orthanc
    versions without being visible in software inventory.
  stage: vulnerable-service-inventory
- id: non-standard-ports
  question: Is Orthanc exposed on a port not defined in the orthanc_ports list?
  requires: hb_exposed_assets with full port scanning
  risk: An attacker may find Orthanc on non-standard ports that are missed by filtered
    external scans.
  stage: vulnerable-service-inventory
coverage:
- stage: vulnerable-service-inventory
  status: covered
  steps:
  - orthanc-software-scope
  - orthanc-cve-findings
  - orthanc-exposure-check
  - orthanc-active-activity
- reason: Belongs to another part of the 'Orthanc DICOM Server' series.
  stage: authenticated-access
  status: out_of_scope
- reason: Belongs to another part of the 'Orthanc DICOM Server' series.
  stage: malicious-image-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Orthanc DICOM Server' series.
  stage: process-crash-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Orthanc DICOM servers are critical medical infrastructure; exploitation
    of CVE-2026-87020 can lead to availability failure in healthcare environments.
    Ensuring unpatched systems are identified and isolated is a critical safety control.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Unpatched Orthanc DICOM servers (CVE-2026-87020) are exposed or active,
  detectable by combining vulnerability records with unexplained process crashes and
  high-frequency restarts following external network traffic.
labels:
- hunt
- attack.t1190
name: Vulnerable Orthanc DICOM Server Inventory
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for active process activity.
    type: number
  orthanc_ports:
    default:
    - '104'
    - '11112'
    - '8042'
    - '4242'
    description: Common DICOM and Orthanc web ports.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on clinical network segments and healthcare public health sectors
  where DICOM servers are common. Prioritize systems reporting version <1.13.0.
references:
- name: 'CISA Advisory: Orthanc DICOM Server'
  url: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02
related:
- hunt: orthanc-process-crash-telemetry
  reason: Exploitation results in a process crash; monitoring for Orthanc service
    terminations is the high-fidelity detection signal.
  relation: follows
scenario:
  stages:
  - name: Vulnerable Orthanc Inventory
    observables:
    - Orthanc DICOM Server version <1.13.0
    - DICOM service on port 104
    - DICOM service on port 11112
    - Orthanc web interface
    slug: vulnerable-service-inventory
    tactic: initial-access
    techniques:
    - T1190
  - name: Authenticated External Access
    observables:
    - Authentication to Orthanc DICOM Server
    - Remote access via VPN
    - Login from unusual source IPs
    slug: authenticated-access
    tactic: initial-access
    techniques:
    - T1133
    - T1566
  - name: Malicious Image Delivery
    observables:
    - Attacker-supplied PNG image
    - Attacker-supplied JPEG image
    - HTTP POST requests to image decoding endpoints
    - Orthanc API calls involving image processing
    slug: malicious-image-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Service Denial of Service
    observables:
    - Crash of the Orthanc process
    - Heap out-of-bounds write
    - Service unavailability
    slug: process-crash-impact
    tactic: impact
    techniques:
    - T1190
  summary: Authenticated remote attackers can exploit an integer overflow vulnerability
    (CVE-2026-87020) in Orthanc DICOM Server versions prior to 1.13.0. By providing
    a malicious PNG or JPEG image, an attacker can trigger a heap out-of-bounds write,
    resulting in a process crash and a denial-of-service condition.
series:
  index: 1
  slug: orthanc-dicom-server
  title: Orthanc DICOM Server
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
tlp: clear
type: investigation
---


# Vulnerable Orthanc DICOM Server Inventory

This hunt identifies vulnerable Orthanc DICOM Server installations (<1.13.0) across the healthcare estate. It uses software inventory and vulnerability scanning data to identify the potential footprint of CVE-2026-87020, then corroborates with internet-exposure records and live process activity—specifically looking for the process termination and restart patterns indicative of the heap-overflow crash—to prioritize the most critical assets for remediation.

## orthanc-software-scope
<!-- Orthanc software inventory -->
Identify all hosts with the Orthanc package installed to narrow the scope of the hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running Orthanc. Silence indicates Orthanc is not recorded
  in the package manager inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-11'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%orthanc%'
```

## orthanc-cve-findings
<!-- Vulnerability findings for CVE-2026-87020 -->
Search specifically for CVE-2026-87020 findings to confirm where unpatched servers exist.

```sqlite target=endpoint role=detection-candidate
~~~yaml
expected: Direct scanner confirmation of the vulnerable version. Silence suggests
  the scanner has not detected the CVE or does not have coverage.
reads:
- cve_uid
- affected_package_name
- affected_package_version
- severity
- status
- resource_uid
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-11'
~~~
SELECT cve_uid, affected_package_name, affected_package_version, severity, status, resource_uid FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2026-87020' AND status != 'suppressed'
```

## corroborate-risk
<!-- Corroborate exposure and activity -->
parallel:
- → orthanc-exposure-check
- → orthanc-active-activity
- → orthanc-version-prevalence
join: → triage-risk

## orthanc-exposure-check
<!-- Internet-exposed Orthanc assets -->
Check for external exposure using Shodan or certificate logs.

```sqlite target=endpoint role=enrichment params=(orthanc_ports=orthanc_ports)
~~~yaml
expected: Publicly reachable IP addresses or domains identified as Orthanc DICOM servers.
reads:
- domain_or_ip
- port
- product
- version
- provider
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-11'
~~~
SELECT domain_or_ip, port, product, version, provider FROM hb_exposed_assets WHERE LOWER(product) LIKE '%orthanc%' OR port IN ({{orthanc_ports}})
```

## orthanc-active-activity
<!-- Active Orthanc process activity and stability -->
Verify which hosts are running Orthanc and identify stability issues (crashes/restarts) potentially linked to exploitation.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: A breakdown of launches (1) and terminations (2) per host. High counts of
  terminations followed by launches on a single host indicate the instability caused
  by CVE-2026-87020.
reads:
- device_hostname
- activity_id
- activity_name
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-11'
~~~
SELECT device_hostname, activity_id, activity_name, COUNT(*) as event_count, MIN(time) as earliest_seen, MAX(time) as latest_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%orthanc%' OR LOWER(process_path) LIKE '%orthanc%') AND activity_id IN (1, 2) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, activity_id, activity_name
```

## orthanc-version-prevalence
<!-- Orthanc version prevalence -->
Determine if specific versions are rare across the fleet, which may indicate shadow IT.

```sqlite target=endpoint role=baseline
~~~yaml
baseline:
  compare: first_seen
  window: 14d
expected: A distribution of versions; rare older versions represent high-priority
  patching targets.
prevalence:
  by: device_hostname
  key:
  - package_version
  rare_below: 3
reads:
- package_version
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-11'
~~~
SELECT package_version, COUNT(DISTINCT device_hostname) AS host_count FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%orthanc%' GROUP BY package_version ORDER BY host_count ASC
```

## triage-risk
<!-- Triage inventory risk -->
```agent target=hunter
cite: required
context:
- orthanc-software-scope
- orthanc-cve-findings
- orthanc-exposure-check
- orthanc-active-activity
- orthanc-version-prevalence
max_iterations: 5
objective: Identify hosts running vulnerable Orthanc versions (<1.13.0) and categorize
  them by risk level. Look specifically for 'Critical' risk where vulnerable versions
  are internet-exposed OR show high-frequency terminations/restarts indicative of
  exploitation attempts.
success_criteria: A verdict per host citing specific version strings and corroborating
  activity rows.
tools:
- endpoint
```

## route-risk
<!-- Route on risk -->
if~: "At least one host is classified as 'Critical' risk due to internet exposure or behavioral evidence of crashes/restarts." (confidence: high, judge=hunter)
then: → isolate-critical-hosts
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-inventory)
else: → patching-task

## isolate-critical-hosts
<!-- Isolate critical hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the vulnerable Orthanc host from the internet and clinical VLANs pending emergency update and impact analysis.
```
→ analyst-review

## patching-task
<!-- Routine patching task -->
```manual target=analyst
Update Orthanc DICOM Server to version 1.13.0 or higher on all identified internal systems.
```
→ end

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the isolation status and verify that high-risk Orthanc servers have been remediated. Assess for evidence of data exfiltration if crashes were correlated with high inbound traffic.
```
→ end
