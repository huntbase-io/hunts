---
analysis: A simple alert for S3 'GetObject' would produce thousands of false positives.
  This hunt uses a 'funnel' flow to baseline high-volume data access and correlates
  it with endpoint ransomware behavior, providing the context necessary to identify
  a data extortion campaign.
blind_spots:
- id: missing-s3-data-logs
  question: Which specific objects within an S3 bucket were retrieved?
  requires: AWS CloudTrail Data Events
  risk: Without data events, we only see management activity (ListBucket) rather than
    the retrieval of individual records.
  stage: collection-and-bulk-data-exfiltration
- id: github-app-visibility
  question: Was a repository cloned using a stolen OAuth token?
  requires: GitHub Enterprise audit logs for individual git-clone commands
  risk: Standard logs may show file interactions but not the specific git-cloning
    action by an OAuth app.
  stage: collection-and-bulk-data-exfiltration
coverage:
- stage: collection-and-bulk-data-exfiltration
  status: covered
  steps:
  - bulk-s3-access-lead
  - github-repo-exfiltration
- stage: impact-extortion-and-data-leakage
  status: covered
  steps:
  - endpoint-file-encryption
- reason: Belongs to another part of the "Gotta Breach 'Em All! The Journey Of ShinyHunters"
    series.
  stage: initial-access-phishing-and-harvesting
  status: out_of_scope
- reason: Belongs to another part of the "Gotta Breach 'Em All! The Journey Of ShinyHunters"
    series.
  stage: token-theft-and-misconfiguration-access
  status: out_of_scope
- reason: Belongs to another part of the "Gotta Breach 'Em All! The Journey Of ShinyHunters"
    series.
  stage: credential-abuse-and-account-takeover
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ShinyHunters has historically stolen hundreds of millions of records
    from cloud-first companies. A negative result confirms that large-scale S3 and
    repository data theft is not actively occurring in the monitored environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised credentials or OAuth tokens to exfiltrate
  bulk S3 data and GitHub repositories before deploying ransomware for extortion.
labels:
- hunt
- attack.t1041
- attack.t1486
- attack.t1555
- attack.t1190
- collection
- credential access
- impact
- initial access
- aws
- github
name: ShinyHunters Cloud Exfiltration and Ransomware
parameters:
  high_volume_threshold:
    default: '100'
    description: Minimum count of S3 GetObject calls to consider as bulk access.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: Baseline heuristic
    type: number
  lookback_days:
    default: '14'
    description: Days of cloud and endpoint history to examine.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: Standard hunt window
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the endpoint investigation.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: Analyst scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/gotta-breach-em-all-the-journey-of-shinyhunters
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on AWS accounts containing high-value user databases or PII. Review
  the last 14 days of CloudTrail Data Events if available, as management events may
  not show object-level reads.
references:
- name: "Sekoia \u2014 Gotta Breach 'Em All! The Journey Of ShinyHunters"
  url: https://www.sekoia.com/blog/gotta-breach-em-all-the-journey-of-shinyhunters
related:
- hunt: cloud-misconfiguration-access
  reason: This hunt focuses on the exfiltration behavior rather than the specific
    misconfiguration (like public S3 buckets) that allowed it.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and credential harvesting
    observables:
    - Fake login pages targeting corporate users
    - Credential harvesting phishing emails
    - 'Use of domains: secure.com, chronicle.com, promo.com'
    slug: initial-access-phishing-and-harvesting
    tactic: initial-access
    techniques:
    - T1566
  - name: OAuth token theft and cloud misconfigurations
    observables:
    - Exposed GitHub OAuth tokens
    - Compromised Slack tokens
    - Unsecured AWS S3 buckets
    - Supply-chain compromise of third-party vendors (Waydev)
    slug: token-theft-and-misconfiguration-access
    tactic: initial-access
    techniques:
    - T1555
    - T1190
  - name: Cloud and SaaS account takeover
    observables:
    - Access to cloud infrastructure lacking MFA
    - Use of infostealer-harvested credentials
    - Abuse of valid GitHub and Slack credentials
    slug: credential-abuse-and-account-takeover
    tactic: credential-access
    techniques:
    - T1555
  - name: Bulk cloud data collection and exfiltration
    observables:
    - Cloning of private GitHub repositories
    - Bulk S3 bucket object retrieval
    - Theft of user databases (Tokopedia, Wattpad, Nitro PDF)
    - Database dumps (SQL, JSON records)
    slug: collection-and-bulk-data-exfiltration
    tactic: collection
    techniques:
    - T1041
  - name: Data encryption and public extortion
    observables:
    - Ransomware encryption (reported by Beazley)
    - Extortion demands for non-disclosure
    - Public data dumps on RaidForums and darkweb markets
    slug: impact-extortion-and-data-leakage
    tactic: impact
    techniques:
    - T1486
  summary: ShinyHunters is a persistent, financially motivated threat brand that evolved
    from traditional phishing to advanced OAuth token theft and SaaS supply-chain
    compromises. They pivot from harvested credentials and misconfigured cloud buckets
    to exfiltrate bulk datasets from providers like AWS, GitHub, and Slack for extortion
    or public sale on cybercrime forums.
series:
  index: 2
  slug: gotta-breach-em-all-the-journey-of-shinyhunters
  title: Gotta Breach 'Em All! The Journey Of ShinyHunters
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# ShinyHunters Cloud Exfiltration and Ransomware

ShinyHunters specializes in cloud-native data theft, often targeting AWS S3 buckets and GitHub repositories for bulk collection. This hunt identifies unusual access patterns in cloud API logs, correlates them with repository cloning activity, and monitors endpoints for the high-volume file renames typical of extortion-driven ransomware. By analyzing the flow from cloud collection to endpoint impact, we can distinguish legitimate data management from a multi-stage extortion campaign.

## bulk-s3-access-lead
<!-- Bulk S3 data retrieval -->
Identify cloud identities performing an unusually high volume of S3 GetObject calls, suggesting bulk exfiltration.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, high_volume_threshold=high_volume_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Multiple rows for a single user name accessing thousands of objects in a
  specific bucket. Rare source IPs for these operations increase suspicion.
prevalence:
  by: resource_name
  key:
  - actor_user_name
  rare_below: 2
reads:
- actor_user_name
- api_operation
- api_service_name
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, resource_name, COUNT(*) AS call_count, MIN(time) AS first_seen, MAX(time) AS last_seen, src_endpoint_ip FROM hb_cloud_api_activity WHERE api_service_name = 's3.amazonaws.com' AND api_operation = 'GetObject' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, resource_name, src_endpoint_ip HAVING call_count > {{high_volume_threshold}} ORDER BY call_count DESC
```

## parallel-investigation
<!-- Examine repository and endpoint activity -->
parallel:
- → github-repo-exfiltration
- → endpoint-file-encryption
join: → triage-shinyhunters-activity

## github-repo-exfiltration
<!-- GitHub repository bulk access -->
Detect bulk reading or cloning of private repositories, a known ShinyHunters tactic.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A single user name interacting with numerous repo-blobs in a short window.
  Legitimate CI/CD tools may show high volume, but individual users should not.
reads:
- actor_user_name
- file_path
- file_type
- provider
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, file_path, COUNT(*) AS event_count, MIN(time) AS first_seen FROM hb_file_activity WHERE provider = 'github' AND file_type = 'repo-blob' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, file_path HAVING event_count > 20 ORDER BY event_count DESC
```

## endpoint-file-encryption
<!-- High-volume file rename events -->
Identify processes that rename files at high frequency, which aligns with recent ShinyHunters extortion tactics.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A host showing hundreds or thousands of file renames within a few minutes.
  Normal user activity rarely generates such a high volume of rename events.
reads:
- activity_id
- device_hostname
- process_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, COUNT(*) AS rename_count, MIN(time) AS start_time, MAX(time) AS end_time, src_endpoint_ip FROM hb_file_activity WHERE activity_id = 5 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING rename_count > 500 ORDER BY rename_count DESC
```

## triage-shinyhunters-activity
<!-- Triage extortion indicators -->
```agent target=hunter
cite: required
context:
- bulk-s3-access-lead
- github-repo-exfiltration
- endpoint-file-encryption
max_iterations: 4
objective: Determine if the bulk S3 access, GitHub interactions, and endpoint file
  renames constitute a malicious extortion attempt; perform cross-surface correlation
  on src_endpoint_ip to link cloud exfiltration leads with endpoint activity.
success_criteria: A per-host and per-user verdict of malicious, suspicious, or benign,
  citing specific volumes and timestamps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on extortion verdict -->
if~: "the triage verdict is malicious for at least one cloud identity or host" (confidence: high, judge=hunter)
then: → revoke-and-isolate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-s3-data-logs)
else: → close-out

## revoke-and-isolate
<!-- Revoke credentials and isolate hosts -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke the access keys or OAuth tokens for the suspicious cloud identity; isolate the affected host from the network to prevent further encryption.
```
→ analyst-review

## analyst-review
<!-- Comprehensive incident review -->
```manual target=analyst
Audit the CloudTrail data events to list every specific S3 object accessed by the actor; review GitHub repository logs for cloning activity; confirm the integrity of backups for encrypted hosts.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Note the absence of bulk exfiltration and ransomware indicators; update parameters if any noise was identified.
```
→ end
