---
analysis: A simple rule for .npmrc modifications is too noisy in developer environments.
  This hunt uses stack-counting (prevalence) and cross-surface correlation (Process
  + DNS) to distinguish legitimate configuration work from security-bypass-then-install
  patterns.
blind_spots:
- id: missing-file-monitoring
  owner: Endpoint Engineering
  question: Was the file modified to reduce the cooldown timer (e.g., set to 0) without
    deleting the line entirely?
  remediation: Implement the CEL-based .npmrc snapshot integration described in the
    reference article.
  requires: endpoint-based file content snapshots (e.g. CEL integration)
  risk: Standard file activity only shows that a file was modified (activity_id 3),
    not the resulting content. A developer could 'impair' the guardrail by setting
    the age to 0, which we would see as a generic modification.
  stage: npm-guardrail-impairment
- id: transitive-dependencies
  owner: AppSec
  question: Was the malicious package a sub-dependency of a benign-looking 'npm install'
    command?
  remediation: Ingest SBOM or package-lock files periodically to scan for transitive
    dependency risks.
  requires: detailed package lock or bill of materials (SBOM) data
  risk: Adversaries often hide in transitive dependencies. A top-level 'npm install'
    might look safe while pulling in a 'poisoned' sub-dependency that was published
    10 minutes ago.
  stage: malicious-dependency-ingress
coverage:
- stage: npm-cooldown-enforcement
  status: covered
  steps:
  - identify-npm-footprint
- stage: npm-guardrail-impairment
  status: covered
  steps:
  - rare-npmrc-modifications
  - detect-config-deletion
- stage: malicious-dependency-ingress
  status: covered
  steps:
  - detect-npm-install
  - detect-registry-dns
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: npm supply chain attacks rely on the speed of installation after
    compromise. The 'min-release-age' setting is a primary defense against this vector.
    Detecting its removal is critical for identifying systems that have been intentionally
    or accidentally exposed to day-zero package risks.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder or an insider has removed the 'min-release-age' security setting
  from an npm configuration to allow the installation of a recently published malicious
  package that would otherwise be blocked.
labels:
- hunt
- attack.t1195.001
name: npm Supply Chain Guardrail Impairment
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  registry_domains:
    default:
    - registry.npmjs.org
    description: Official npm registry domain.
    from:
      kind: article
      observed: '2026-08-07'
      ref: elastic-security-labs
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on (from scoping step).
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
    from: https://www.elastic.co/security-labs/blog/npm-cooldown-removal-detection-elastic-agent
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints with active npm development, identifiable by the presence
  of npm in software inventory or home directories like /Users/*/.npmrc.
references:
- name: 'The security signal log tailing can''t see: tracking npm cooldown removals
    with Elastic Agent'
  url: https://www.elastic.co/security-labs/blog/npm-cooldown-removal-detection-elastic-agent
related:
- hunt: npm-registry-typosquatting
  reason: Typosquatting is another supply chain vector that bypasses the same trust
    model; cooldowns protect against one, name-confusion the other.
  relation: sibling
scenario:
  stages:
  - name: npm Cooldown Configuration Enforcement
    observables:
    - min-release-age=7
    - ~/.npmrc
    - /opt/homebrew/etc/npmrc
    - /usr/local/etc/npmrc
    - /etc/npmrc
    - /usr/lib/node_modules/npm/.npmrc
    - npm config set min-release-age
    slug: npm-cooldown-enforcement
    tactic: initial-access
    techniques:
    - T1195.001
  - name: npm Cooldown Guardrail Removal
    observables:
    - npm config delete min-release-age
    - cooldown.absent = true
    - removal of min-release-age from .npmrc
    - deletion of .npmrc
    slug: npm-guardrail-impairment
    tactic: initial-access
    techniques:
    - T1195.001
  - name: Malicious Dependency Installation
    observables:
    - npm install
    - registry.npmjs.org
    - node.js
    slug: malicious-dependency-ingress
    tactic: initial-access
    techniques:
    - T1195.001
  summary: This campaign focuses on the exploitation of developer workstations by
    removing npm 'min-release-age' security guardrails, which are designed to prevent
    the installation of freshly published (and potentially compromised) packages.
    By monitoring for the absence or deletion of this configuration in .npmrc files,
    defenders can detect windows of vulnerability that allow for software supply chain
    compromises.
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
tlp: clear
type: investigation
---


# npm Supply Chain Guardrail Impairment

This hunt targets the removal of 'cooldown' security settings in npm. Adversaries often compromise packages and publish them immediately; a 'min-release-age' setting (available in npm 11.10+) provides a defensive window. Because config file changes are often 'quiet' in logs, we use a multi-surface approach: identifying systems with npm, stack-counting rare .npmrc modifications, detecting explicit command-line deletions of the setting, and correlating with immediate registry installations.

## identify-npm-footprint
<!-- Identify hosts with npm installed -->
Focus the hunt on systems with npm installed, particularly developer workstations and build servers.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Empty results indicate no npm inventory was found,
  potentially meaning missing coverage in software inventory.
reads:
- device_hostname
- package_name
- package_type
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) = 'npm' OR package_type = 'npm'
```

## rare-npmrc-modifications
<!-- Rare .npmrc modifications across the fleet -->
Identify hosts where .npmrc was modified or deleted, stack-counting to isolate rare actions from standard fleet updates.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: File modification or deletion events for .npmrc. Rare occurrences stand
  out against hosts that might have frequent config changes via automated scripts.
prevalence:
  by: device_hostname
  key:
  - file_path
  - activity_name
  rare_below: 3
reads:
- device_hostname
- file_path
- activity_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, activity_name, COUNT(*) as activity_count, MIN(time) as first_seen FROM hb_file_activity WHERE (LOWER(file_name) = '.npmrc' OR LOWER(file_name) = 'npmrc') AND activity_id IN (3, 4) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, file_path, activity_name HAVING activity_count <= 5 ORDER BY activity_count ASC
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → detect-config-deletion
- → detect-npm-install
- → detect-registry-dns
join: → triage-agent

## detect-config-deletion
<!-- npm command-line config impairment -->
Catch explicit use of the npm CLI to remove the security guardrail.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row showing the config deletion command. This is a direct indicator of
  guardrail removal.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%config delete%' AND LOWER(process_cmd_line) LIKE '%min-release-age%' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## detect-npm-install
<!-- Post-impairment npm installations -->
Identify package installations occurring on the same hosts where config changes were detected.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process events for package installations. Correlation in time with config
  deletion is critical.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%npm%' OR LOWER(process_cmd_line) LIKE 'npm %') AND (LOWER(process_cmd_line) LIKE '% install %' OR LOWER(process_cmd_line) LIKE '% i %') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## detect-registry-dns
<!-- DNS traffic to npm registry -->
Corroborate that the npm client reached out to the registry to download package metadata or binaries.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, registry_domains=registry_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS queries for registry.npmjs.org. Proves the host communicated with the
  registry around the time of the install.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{registry_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Correlate guardrail bypass -->
```agent target=hunter
cite: required
context:
- rare-npmrc-modifications
- detect-config-deletion
- detect-npm-install
- detect-registry-dns
max_iterations: 4
objective: Determine if 'min-release-age' was removed immediately before an 'npm install'
  on the same host.
success_criteria: A verdict of malicious | suspicious | benign citing specific rows
  from at least two surfaces.
tools:
- endpoint
```

## route-findings
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host where guardrail removal and installation are correlated" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-investigation
unavailable: → manual-investigation (blind_spot: missing-file-monitoring)
else: → hygiene-record

## isolate-endpoint
<!-- Isolate host for supply-chain review -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, preserve the .npmrc file, and interview the user regarding the config change.
```
→ manual-investigation

## manual-investigation
<!-- Review package version logs -->
```manual target=analyst
Examine the local npm logs and the project's package-lock.json to identify the installed version. Check the version's release date on npmjs.org.
```
→ end

## hygiene-record
<!-- Record hygiene note -->
```manual target=analyst
Log the hosts that are missing the min-release-age setting and send a report to the endpoint management team for policy re-enforcement.
```
→ end
