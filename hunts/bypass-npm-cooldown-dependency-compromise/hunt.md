---
analysis: A standard rule detects the file modification but lacks the context of fleet-wide
  package rarity and the timing correlation with specific npm command lines that an
  analyst must weigh.
blind_spots:
- id: standard-file-logs-content-blindness
  question: Was the specific min-release-age line removed or was the file changed
    for another reason?
  remediation: Deploy the CEL snapshot integration described in the article to capture
    file content state changes.
  requires: CEL-based snapshot integration
  risk: Standard file logs show that a modification occurred but not the specific
    line removed, leading to potential false positives from legitimate registry credential
    updates.
  stage: npm-cooldown-config-removal
- id: nvm-version-complexity
  question: Which exact npm binary version executed the install command?
  requires: hb_process_activity environmental variables
  risk: If a host carries multiple npm versions via nvm, an older version may ignore
    the config setting even if the setting exists, leading to a successful install
    of a fresh package despite policy.
  stage: compromised-package-installation
coverage:
- stage: npm-cooldown-config-removal
  status: covered
  steps:
  - npmrc-modifications
- stage: compromised-package-installation
  status: covered
  steps:
  - rare-npm-install-activity
  - verify-package-age
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Dependency compromise via npm is a high-impact initial access vector.
    Bypassing security cooldowns is a clear signal of deliberate policy evasion to
    facilitate rapid installation of unvetted code.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder or developer removes the npm cooldown setting to bypass a
  mandatory waiting period for new packages, enabling the installation of a compromised
  dependency.
labels:
- hunt
- attack.t1195.001
- attack.t1562.001
name: Bypass of npm Cooldown and Dependency Compromise
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  npmrc_paths:
    default:
    - /opt/homebrew/etc/npmrc
    - /usr/local/etc/npmrc
    - /etc/npmrc
    - /usr/lib/node_modules/npm/.npmrc
    description: Well-known machine-global npmrc locations.
    from:
      kind: article
      observed: '2026-08-07'
      ref: elastic-security-labs-npm-cooldown
    type: list[path]
  scope_hosts:
    default: []
    description: Hosts with npm installations identified in the first step.
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
rationale: Start with engineering and DevOps hosts where npm usage is frequent. Use
  hb_software_inventory to narrow down the estate to confirmed npm users.
references:
- name: "Elastic Security Labs \u2014 The security signal log tailing can't see: tracking\
    \ npm cooldown removals"
  url: https://www.elastic.co/security-labs/blog/npm-cooldown-removal-detection-elastic-agent
related:
- hunt: npm-post-install-execution
  reason: Installation of a compromised package often leads to immediate script execution;
    this hunt focuses on the bypass itself.
  relation: follows
scenario:
  stages:
  - name: Removal of npm Cooldown Configuration
    observables:
    - Removal of 'min-release-age' string from config files
    - Modification of ~/.npmrc
    - Modification of /opt/homebrew/etc/npmrc
    - Modification of /usr/local/etc/npmrc
    - Modification of /etc/npmrc
    - Modification of /usr/lib/node_modules/npm/.npmrc
    - 'Command: npm config delete min-release-age'
    slug: npm-cooldown-config-removal
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Installation of Compromised Dependency
    observables:
    - 'Process: npm install'
    - 'Domain: registry.npmjs.org'
    - Network connection to npm registry on port 443
    - Recently published npm package versions
    slug: compromised-package-installation
    tactic: initial-access
    techniques:
    - T1195.001
  summary: An adversary or user removes the 'min-release-age' configuration from npm
    configuration files to bypass security cooldown periods. This enables the installation
    of freshly compromised software dependencies before they are detected and removed
    by registry maintainers.
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
tlp: clear
type: investigation
---


# Bypass of npm Cooldown and Dependency Compromise

This hunt looks for signs that npm security controls have been deliberately weakened. It identifies workstations where the min-release-age setting has been removed from configuration files and correlates this with subsequent npm install activity. This pattern suggests an attempt to bypass organizational security policy to install recently published packages that may not have been fully vetted.

## identify-npm-hosts
<!-- Identify hosts with npm -->
Find the development workstations that carry npm and could be impacted by configuration changes.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts and versions. Silence suggests npm is not inventoried or
  not present.
reads:
- device_hostname
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) = 'npm'
```

## analyze-activity
<!-- Analyze file tampering and rare installs -->
parallel:
- → npmrc-modifications
- → rare-npm-install-activity
join: → triage-behavior

## npmrc-modifications
<!-- Modifications to npmrc files -->
Detect when a user or process modifies or deletes npm configuration files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, npmrc_paths=npmrc_paths)
~~~yaml
expected: Rows indicating that an npmrc file was updated or deleted. Silence means
  no modifications occurred on the tracked paths.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%/.npmrc' OR instr(',' || '{{npmrc_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0) AND activity_id IN (3, 4) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-npm-install-activity
<!-- Rare npm install activity -->
Stack-count npm install commands to find unique or rare packages being introduced to the estate.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare installation commands. Silence implies only common, fleet-wide
  packages were installed.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 4
reads:
- device_hostname
- user_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS total_runs, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%npm install%' OR LOWER(process_cmd_line) LIKE '%npm i %') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-behavior
<!-- Triage bypass behavior -->
```agent target=hunter
cite: required
context:
- identify-npm-hosts
- npmrc-modifications
- rare-npm-install-activity
max_iterations: 4
objective: Identify hosts where an npmrc modification preceded an npm install within
  a 2-hour window. Evaluate if the install command contains specific version or package
  strings that appear unique to that host.
success_criteria: A verdict of malicious or suspicious for any host exhibiting both
  behaviors within the temporal window.
tools:
- endpoint
```

## route-on-risk
<!-- Route on risk -->
if~: "the triage verdict is malicious for at least one host involving a rare install within 2 hours of a config change" (confidence: high, judge=hunter)
then: → isolate-workstation
indeterminate: → verify-package-age
unavailable: → verify-package-age (blind_spot: standard-file-logs-content-blindness)
else: → verify-package-age

## isolate-workstation
<!-- Isolate workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and preserve the npmrc files and node_modules directory for analysis.
```
→ verify-package-age

## verify-package-age
<!-- Verify package publication date -->
```manual target=analyst
Look up the package versions identified in the install commands on npmjs.org. If the publication date was less than 7 days prior to the install on a host that modified its npmrc, escalate to Incident Response.
```
→ policy-remediation

## policy-remediation
<!-- Remediate policy configuration -->
```manual target=analyst
Re-apply the min-release-age configuration. Ensure the npm version on the host is 11.10 or higher. Investigate why the daily management script failed to re-apply the setting or was bypassed.
```
→ end
