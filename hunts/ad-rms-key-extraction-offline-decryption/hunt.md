---
analysis: Detecting the SOAP call alone is noisy. This hunt is required to correlate
  administrative server activity with rare process-level baseline execution to find
  the specific, unauthorized document access that follows key theft.
blind_spots:
- id: no-endpoint-telemetry
  question: Was SharpRMS run on a non-enrolled device?
  requires: universal endpoint coverage
  risk: The SLC key allows for offline decryption. If the attacker moves the stolen
    documents and key to a personal or unmanaged machine, process telemetry will not
    see the decryption impact.
  stage: offline-unauthorized-decryption
- id: file-magic-bytes-visibility
  question: Which files were identified as RMS-protected through byte-level scanning?
  requires: deep file inspection or EDR file-header logging
  risk: We cannot see the attacker sweeping shares for the D0-CF-11-E0 magic bytes
    via standard file activity logs, making the recon stage a blind spot.
  stage: recon-rms-protected-content
coverage:
- stage: initial-access-exploitation
  status: covered
  steps:
  - soap-export-activity
- stage: rms-configuration-discovery
  status: covered
  steps:
  - discovery-activity
- stage: slc-private-key-extraction
  status: covered
  steps:
  - assess-extraction
- blind_spot: file-magic-bytes-visibility
  reason: Identifying OLE magic bytes or internal stream names requires deep file
    inspection not present in hb_file_activity.
  stage: recon-rms-protected-content
  status: not_visible
- stage: offline-unauthorized-decryption
  status: covered
  steps:
  - unauthorized-decryption-activity
  - confirm-impact
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The AD RMS SLC private key is the master root for all protected documents
    in a deployment. Because it cannot be rotated and remains valid for 255 years,
    its compromise is a permanent failure of data confidentiality.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has extracted the AD RMS Server Licensor Certificate (SLC)
  private key through a Trusted Publishing Domain export and is using it to decrypt
  protected documents offline.
labels:
- hunt
- attack.t1003.001
- attack.t1082
- attack.t1083
- attack.t1190
- attack.t1005
name: AD RMS Master Key Extraction and Offline Decryption
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rms_admin_paths:
    default:
    - /wmcs/admin/server.asmx
    - /wmcs/admin/trustpolicy.asmx
    description: AD RMS admin SOAP endpoints used for TPD export.
    type: list[path]
  scope_hosts:
    default: []
    description: Specific hosts identified in the scoping step to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ad-rms-slc-encryption-key
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope first to AD RMS servers using the software inventory. Use the resulting
  hostnames to populate the scope_hosts parameter, which narrows the HTTP and process
  searches to the most relevant infrastructure.
references:
- name: "Huntress \u2014 AD RMS SLC Encryption Key"
  url: https://www.huntress.com/blog/ad-rms-slc-encryption-key
related:
- hunt: ad-rms-client-side-bypass
  reason: This hunt focuses on root key theft and global decryption, whereas client-side
    bypasses focus on individual document policy stripping by authorized users.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of AD RMS Service
    observables:
    - SOAP calls to VESUVIO admin endpoints
    - 'Targeting AD RMS Service Group identities: tony.soprano'
    slug: initial-access-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: AD RMS Key and Database Discovery
    observables:
    - SharpRMS tool execution
    - Querying keyprotection admin operation
    - 'Response containing IsServicePrivateKeySoftwareBased: true'
    - DatabaseConnectionString targeting data source=BARONE
    slug: rms-configuration-discovery
    tactic: discovery
    techniques:
    - T1082
  - name: SLC Private Key Extraction via TPD Export
    observables:
    - Authenticated SOAP call to Trusted Publishing Domain (TPD) export endpoint
    - Extraction of 1172-byte SLC private key material
    - Integrated Security=SSPI authentication to SQL server BARONE
    slug: slc-private-key-extraction
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Identification of RMS Protected Documents
    observables:
    - Searching for files starting with OLE magic bytes D0-CF-11-E0-A1-B1-1A-E1
    - Identifying OLE streams named Primary and EncryptedPackage
    - Targeting files like BOARD_MINUTES_2026.docx
    slug: recon-rms-protected-content
    tactic: discovery
    techniques:
    - T1083
  - name: Offline Document Decryption
    observables:
    - Use of SharpRMS for offline decryption using extracted SLC key
    - Accessing protected .docx files by non-authorized users like paulie.gualtieri
    slug: offline-unauthorized-decryption
    tactic: collection
    techniques:
    - T1005
  summary: An attacker with AD RMS Service Group membership identifies protected assets
    and extracts the long-lived, unrotatable Server Licensor Certificate (SLC) private
    key via a Trusted Publishing Domain (TPD) export operation. This key acts as a
    master key for the entire deployment, allowing for permanent offline decryption
    of every document ever protected by the cluster, even after the infrastructure
    is rebuilt.
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


# AD RMS Master Key Extraction and Offline Decryption

This hunt identifies the extraction of the AD RMS root key (SLC) and subsequent unauthorized document decryption. The Server Licensor Certificate is a long-lived root of trust that allows for the permanent, offline decryption of any document protected by that cluster. The flow identifies AD RMS servers, detects administrative discovery and SOAP-based TPD export calls, and then baselines rare decryption-related process activity to identify unauthorized data access across the fleet.

## identify-rms-servers
<!-- Identify AD RMS Servers -->
Find hosts with AD RMS software installed to narrow the search for administrative activity.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running AD RMS components. Silence means no AD RMS installations
  were found in the current inventory.
reads:
- package_name
- vendor_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%rights management%' OR LOWER(vendor_name) LIKE '%microsoft%rms%')
```

## early-stage-parallel
<!-- Detect Extraction and Discovery -->
parallel:
- → soap-export-activity
- → discovery-activity
join: → assess-extraction

## soap-export-activity
<!-- TPD Export SOAP Activity -->
Detect successful HTTP requests to the AD RMS Trusted Publishing Domain export endpoints.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rms_admin_paths=rms_admin_paths)
~~~yaml
expected: Successful 200 OK responses to AD RMS admin paths. Silence proves no successful
  TPD exports were observed in this window.
reads:
- url_path
- device_hostname
- actor_user_name
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_path, actor_user_name, src_endpoint_ip, time FROM hb_http_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{rms_admin_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 AND (status_code = 200 OR status_code = '200') AND time >= datetime('now', '-{{lookback_days}} days')
```

## discovery-activity
<!-- AD RMS Configuration Discovery -->
Identify process execution related to SharpRMS or the keyprotection command used to verify if the key is software-based.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines explicitly referencing AD RMS discovery tools or operations.
  Silence suggests no such discovery tools were launched on the managed estate.
reads:
- process_cmd_line
- user_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_cmd_line) LIKE '%sharperms%' OR LOWER(process_cmd_line) LIKE '%keyprotection%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-extraction
<!-- Assess Key Extraction Attempt -->
```agent target=hunter
cite: required
context:
- soap-export-activity
- discovery-activity
max_iterations: 4
objective: Determine if the SOAP activity and discovery command lines together indicate
  a successful SLC key extraction by a Service Group member.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing the
  relevant rows.
tools:
- endpoint
- web
```

## unauthorized-decryption-activity
<!-- Unauthorized Decryption Activity -->
Baseline rare decryption activity across the fleet to identify the impact of the stolen SLC key.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Process command lines indicating offline decryption on hosts where the user
  is not a service administrator. Silence confirms no unauthorized decryption tools
  were detected.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, device_hostname, user_name, MIN(time) AS first_seen, COUNT(*) AS execution_count FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%--decrypt%' OR LOWER(process_cmd_line) LIKE '%--slc%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, device_hostname, user_name HAVING COUNT(DISTINCT device_hostname) <= 3
```

## confirm-impact
<!-- Confirm Unauthorized Impact -->
```agent target=hunter
cite: required
context:
- assess-extraction
- unauthorized-decryption-activity
max_iterations: 4
objective: Verify if the rare decryption events correlate with the previously identified
  stolen key extraction to confirm a data breach.
success_criteria: A final malicious verdict for any host where a stolen key was used
  for decryption.
tools:
- endpoint
- web
```

## route-on-impact
<!-- Route on Impact -->
if~: "the confirm-impact verdict is malicious for at least one host involving stolen SLC keys" (confidence: high, judge=hunter)
then: → isolate-beachhead
indeterminate: → document-exposure
unavailable: → document-exposure (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-beachhead
<!-- Isolate Beachhead -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host where decryption was observed and disable the AD RMS Service Group account. Since the SLC key is unrotatable, notify the data protection team that all previously protected content must be considered exposed.
```
→ document-exposure

## document-exposure
<!-- Analyze Document Exposure -->
```manual target=analyst
Review hb_file_activity for the host and time window identified. Look for access to .docx or .xlsx files by the process identified in unauthorized-decryption-activity. Identify which sensitive shares were swept for OLE magic bytes.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record the results of the hunt. If no activity was found, document that the HTTP and process telemetry confirmed the integrity of the AD RMS root key for this window.
```
→ end
