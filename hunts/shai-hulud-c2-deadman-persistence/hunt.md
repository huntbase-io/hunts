---
analysis: This is a hunt because it requires correlating a hardcoded lock file, a
  specific LaunchAgent/systemd naming convention, and a high-frequency polling pattern
  to GitHub that individually might be ignored as noise or benign developer activity,
  but together indicate a specific framework.
blind_spots:
- id: limited-endpoint-visibility
  question: Does the monitor script actually contain the destructive rm -rf command?
  requires: Deep file content inspection or EDR script-block logging
  risk: An analyst might treat the monitor as a standard persistence mechanism without
    realizing that revoking the token triggers a wipe.
  stage: persistence-deadman-switch
- id: github-content-blindness
  question: Is the stolen token being used to create Dune-themed repositories or search
    for commits?
  requires: GitHub Enterprise Audit Logs / Git repository monitoring
  risk: The hunt only sees the client-side network connections; the actual malicious
    use of tokens in the cloud remains invisible without SaaS-native logs.
  stage: c2-exfiltration-hybrid-channels
coverage:
- stage: persistence-deadman-switch
  status: covered
  steps:
  - monitor-service-persistence
  - lock-file-presence
- stage: c2-exfiltration-hybrid-channels
  status: covered
  steps:
  - c2-network-activity
  - high-frequency-api-polling
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: execution-bootstrap-loaders
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-secrets-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: credential-access-memory-scraping
  status: out_of_scope
- reason: Belongs to another part of the 'Shai-Hulud open source framework static
    analysis' series.
  stage: lateral-movement-repo-poisoning
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: 'The Shai-Hulud framework''s deadman switch presents a unique destructive
    risk: standard remediation (revoking a token) triggers a data wipe. A negative
    result across developer workstations confirms safety against this specific retaliatory
    mechanism.'
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence via a GitHub token monitor (deadman
  switch) and is exfiltrating data to a spoofed domain or using GitHub repositories
  as dead-drops.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1133
- attack.t1547.011
- attack.t1547.015
name: 'Shai-Hulud: C2 and Deadman Persistence'
parameters:
  lock_file_path:
    default: /tmp/tmp.ts018051808.lock
    description: PID-based lock file used by the Shai-Hulud daemon.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud static analysis
    type: path
  lookback_days:
    default: '14'
    description: Days of telemetry to examine.
    type: number
  shai_hulud_c2:
    default:
    - git-tanstack.com
    description: Primary C2 domains identified in the research.
    from:
      kind: article
      observed: '2026-05-12'
      ref: Shai-Hulud static analysis
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets endpoints with development environments (npm, Bun, Node.js).
  Narrowing to these hosts first prevents excessive noise from general users who are
  unlikely to be the primary targets of this supply-chain focused framework.
references:
- name: Shai-Hulud open source framework static analysis
  url: https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/
related:
- hunt: shai-hulud-secrets-harvesting
  reason: The harvesting of secrets and memory scraping belongs to a separate behavioral
    hunt on hb_process_activity and hb_file_activity.
  relation: out-of-scope-alternative
- hunt: shai-hulud-identity-secret-harvesting
  relation: follows
scenario:
  stages:
  - name: Supply chain poisoning and tag hijacking
    observables:
    - Hijacked Trivy and Checkmarx KICS tags
    - Poisoned LiteLLM PyPI package
    - Poisoned TanStack and UiPath npm packages
    - Spoofed commit dates 2099-01-01
    - Author TeamPCP_OSS <TeamPCP>
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: Staged loader execution
    observables:
    - BASH_LOADER.sh
    - PYTHON_LOADER.py
    - config.mjs
    - router_init.js
    - setup.mjs
    - opensearch_init.js
    - Download of Bun runtime
    - __DAEMONIZED=1 environment variable
    slug: execution-bootstrap-loaders
    tactic: execution
  - name: Local and cloud secrets harvesting
    observables:
    - Reading ~/.aws/credentials
    - Reading ~/.azure/accessTokens.json
    - Reading ~/.config/gcloud/credentials.db
    - Reading ~/.ssh/id_*
    - Reading ~/.kube/config
    - Reading /var/run/secrets/kubernetes.io/serviceaccount/token
    - Execution of 'gh auth token'
    - Capturing process.env
    - Regex matching for ghp_, gho_, npm_, ghs_
    slug: credential-access-secrets-harvesting
    tactic: credential-access
  - name: CI/CD runner memory extraction
    observables:
    - Searching for Runner.Worker PID via /proc/*/cmdline
    - Reading /proc/[pid]/maps and /proc/[pid]/mem
    - Python stdin execution with sudo
    - Extraction of JSON structures with 'isSecret':true
    slug: credential-access-memory-scraping
    tactic: credential-access
  - name: Persistence and deadman switch installation
    observables:
    - ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
    - ~/.config/systemd/user/gh-token-monitor.service
    - loginctl enable-linger
    - /tmp/tmp.ts018051808.lock
    - Polling https://api.github.com/user every 60 seconds
    - Execution of 'rm -rf ~/' upon token revocation
    slug: persistence-deadman-switch
    tactic: persistence
    techniques:
    - T1133
  - name: Encrypted exfiltration and C2
    observables:
    - HTTPS POST to git-tanstack[.]com
    - GitHub commit search for 'thebeautifulmarchoftime'
    - Dune-themed GitHub repository creation (e.g., sardaukar-mentat-01)
    - 'GitHub repo description ''Shai-Hulud: Here We Go Again'''
    - Committing encrypted JSON to results/ directory
    - Double-base64-encoded tokens in commit messages
    slug: c2-exfiltration-hybrid-channels
    tactic: exfiltration
    techniques:
    - T1041
    - T1090.003
  - name: Developer tool hook poisoning
    observables:
    - 'Creation of .vscode/tasks.json with runOn: folderOpen'
    - Creation of .claude/settings.json with SessionStart hook
    - Commits attributed to claude@users.noreply.github.com
    - 'Commit message ''chore: update dependencies'''
    slug: lateral-movement-repo-poisoning
    tactic: lateral-movement
    techniques:
    - T1195
  summary: TeamPCP utilizes the Shai-Hulud framework to conduct supply chain attacks
    against developers and CI/CD pipelines, poisoning npm/PyPI packages and GitHub
    repositories with malicious hooks. The framework harvests extensive credentials
    from files, environment variables, and process memory before exfiltrating data
    via encrypted HTTPS channels or GitHub dead-drop repositories.
series:
  index: 2
  slug: shai-hulud-open-source-framework-static-analysis
  title: Shai-Hulud open source framework static analysis
  total: 3
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


# Shai-Hulud: C2 and Deadman Persistence

This hunt focuses on the network and persistence behavior of the Shai-Hulud framework. It specifically looks for the 'deadman switch' monitoring service installed on macOS (LaunchAgents) and Linux (systemd), which polls the GitHub API to detect token revocation. Additionally, it examines network traffic patterns indicative of hybrid exfiltration channels, including the known spoofed domain git-tanstack.com and high-frequency polling to GitHub's user API.

## scope-developer-workstations
<!-- Scope to potential targets -->
Identify hosts that have development environments (Bun or Node.js) capable of running the framework.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of developer-aligned hosts. Silence means no hosts meet the environment
  criteria, narrowing the impact but not the existence of the threat.
reads:
- asset_scope
- device_hostname
- package_name
- package_purl
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) IN ('bun', 'nodejs', 'node') OR LOWER(package_purl) LIKE '%pkg:npm/%') AND asset_scope = 'endpoint'
```

## parallel-evidence-gathering
<!-- Gather persistence and network evidence -->
parallel:
- → monitor-service-persistence
- → c2-network-activity
- → lock-file-presence
- → high-frequency-api-polling
join: → triage-shai-hulud

## monitor-service-persistence
<!-- GitHub token monitor persistence -->
Find the specific LaunchAgent or systemd service used for the deadman switch.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows naming the specific persistence paths found in the report. This is
  a high-fidelity indicator of the deadman switch.
reads:
- device_hostname
- job_cmd_line
- job_definition_path
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE (LOWER(job_definition_path) LIKE '%com.user.gh-token-monitor.plist' OR LOWER(job_definition_path) LIKE '%gh-token-monitor.service') AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-network-activity
<!-- C2 exfiltration traffic -->
Identify network or DNS activity to the report's primary C2 domain.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, shai_hulud_c2=shai_hulud_c2)
~~~yaml
expected: DNS lookups for git-tanstack.com. Absence doesn't clear a host, as they
  may be using GitHub-based fallback channels.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookup_count FROM hb_dns_activity WHERE instr(',' || '{{shai_hulud_c2}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## lock-file-presence
<!-- Shai-Hulud lock file -->
Corroborate framework execution via the specific hardcoded lock file path.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, lock_file_path=lock_file_path)
~~~yaml
expected: Creation or update of the lock file in /tmp. Extremely high fidelity for
  the Shai-Hulud daemon.
reads:
- activity_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_path) = LOWER('{{lock_file_path}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## high-frequency-api-polling
<!-- High-frequency GitHub API polling -->
Identify the 60-second polling behavior of the deadman switch daemon.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A process (likely bun, node, or bash) with a high number of connections
  to GitHub. Stack-counting identifies outliers.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, COUNT(*) AS connection_count, MIN(time) AS first_conn, MAX(time) AS last_conn FROM hb_network_connection WHERE (LOWER(dst_endpoint_hostname) = 'api.github.com' OR dst_endpoint_port = 443) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING connection_count > 60 ORDER BY connection_count DESC
```

## triage-shai-hulud
<!-- Triage framework presence -->
```agent target=hunter
cite: required
context:
- monitor-service-persistence
- c2-network-activity
- lock-file-presence
- high-frequency-api-polling
max_iterations: 4
objective: Determine if any host shows combined evidence of the Shai-Hulud deadman
  switch and C2 communications.
success_criteria: A verdict per host citing the presence of persistence files or the
  /tmp lock file alongside network activity.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent finds malicious persistence or confirmed C2 traffic to the known spoofed domains" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-endpoint-visibility)
else: → close-out

## isolate-infected-host
<!-- Isolate host and preserve evidence -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network to prevent the deadman switch from polling and potentially triggering the destruction handler. Do not revoke tokens until the host is isolated.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual forensic review -->
```manual target=analyst
Review the contents of the detected LaunchAgent or systemd service. Check for the presence of the destructive 'rm -rf ~/' handler in the monitor scripts. Check GitHub audit logs for unusual repository creations matching Dune-themed names.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
If the DNS and persistence queries are empty, the framework is likely not present in this configuration. Document the results and monitor for new C2 domains.
```
→ end
