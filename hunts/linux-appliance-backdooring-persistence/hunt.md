---
analysis: A standard detection rule for 'sudo tee' would likely produce too many false
  positives from legitimate system updates. This hunt adds the context of rare cron
  jobs and targets specific sensitive directories across multiple telemetry surfaces
  (process, file, and schedule), which is required to identify the stealthy BRICKSTORM
  persistence.
blind_spots:
- id: limited-appliance-telemetry
  question: What were the contents of the files written by the 'tee' command?
  requires: EDR agent with full file-read capability
  risk: We can see 'tee' writing to a path, but without content or file hashing, we
    cannot confirm the payload is malicious until it executes.
- id: ephemeral-persistence
  question: Was a cron file created and immediately deleted after execution?
  requires: hb_file_activity with high-fidelity delete events
  risk: VerdantBamboo is known to remove persistence files after triggering them.
    If deletion is not captured, we miss the short window of presence.
  stage: persistence-cron-modification
coverage:
- stage: privilege-escalation-sudo-tee-abuse
  status: covered
  steps:
  - sudo-tee-privesc
- stage: persistence-cron-modification
  status: covered
  steps:
  - rare-cron-jobs
  - cron-file-writes
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: initial-access-valid-credentials-vpn
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: command-and-control-brickstorm-doh
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: lateral-movement-m365-proxying
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: impact-synology-nas-compromise
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Threat actors targeting appliances often use them as long-term beachheads
    because they lack standard security visibility. Identifying persistence on these
    devices is critical to fully eradicating the presence of state-sponsored actors.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained unprivileged access to a Linux appliance and is
  leveraging sudo misconfigurations to write persistence into cron directories.
labels:
- hunt
- attack.t1059.004
- attack.t1505.003
- attack.t1543
- attack.t1078
name: Linux Appliance Backdooring and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  persistence_scripts:
    default:
    - /home/egnyteservice/ssync.sh
    - /usr/local/bin/egnyte/egnyte_host_monitor_client
    description: Known persistence script paths from the article.
    from:
      kind: article
      observed: '2026-06-04'
      ref: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    type: list[path]
  rarity_threshold:
    default: '2'
    description: Max number of hosts a scheduled job can appear on to be considered
      rare.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize Linux/BSD systems identified as appliances (Synology,
  pfSense, Egnyte). If a device is found with the default 'egnyteservice' account,
  it should be prioritized for examination of its sudoers configuration.
references:
- name: "Volexity \u2014 VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall"
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: lateral-movement-via-proxied-m365-sessions
  reason: Once an appliance is backdoored, the attacker uses it to proxy into M365;
    that is handled in the next hunt of this series.
  relation: follows
- hunt: verdantbamboo-identity-misuse-proxy-access
  relation: follows
scenario:
  stages:
  - name: Initial Access via Compromised VPN Credentials
    observables:
    - egnyteservice account
    - SSH connections from internal VPN IP range
    - Source IP assigned by web-based SSL VPN
    slug: initial-access-valid-credentials-vpn
    tactic: initial-access
    techniques:
    - T1078
    - T1133
  - name: Local Privilege Escalation via Sudo Tee
    observables:
    - sudo tee
    - /usr/local/bin/egnyte/rsync_data_migration.sh
    - /usr/bin/config_network
    - inadvertent sudo configuration for egnyteservice
    slug: privilege-escalation-sudo-tee-abuse
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Persistence via Cron Jobs
    observables:
    - /etc/cron.d/ssync
    - /home/egnyteservice/ssync.sh
    - /etc/crontab modification
    - egnyte_host_monitor_client
    - executed at 14:20 on the 15th day of every month
    slug: persistence-cron-modification
    tactic: persistence
    techniques:
    - T1505.003
  - name: C2 via DNS over HTTPS
    observables:
    - TLS connections to 8.8.8.8
    - Cloudflare-fronted domains
    - BRICKSTORM malware in /usr/sbin/
    - No standard DNS traffic for C2 domains
    slug: command-and-control-brickstorm-doh
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: M365 Access via Appliance Proxy
    observables:
    - M365 sign-ins originating from Storage Sync appliance IP
    - Bypass of Conditional Access policies
    slug: lateral-movement-m365-proxying
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Deployment of PLENET on NAS
    observables:
    - Synology NAS web interface admin login
    - SSH enabled on Synology NAS
    - PLENET backdoor deployment
    slug: impact-synology-nas-compromise
    tactic: persistence
    techniques:
    - T1078
    - T1133
  summary: VerdantBamboo compromised an organization's Egnyte Storage Sync and Synology
    NAS appliances using credentials stolen from a breached Managed Service Provider.
    The actor deployed the BRICKSTORM backdoor and AGENTPSD python shell, using the
    appliances as proxies to access Microsoft 365 environments and evade conditional
    access policies.
series:
  index: 2
  slug: verdantbamboo-just-another-brickstorm-in-the-firewall
  title: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
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
tlp: clear
type: investigation
---


# Linux Appliance Backdooring and Persistence

VerdantBamboo (UNC5221) targets Linux-based network appliances like Egnyte Storage Sync and pfSense firewalls that lack EDR coverage. This hunt looks for the specific privilege escalation method used (sudo tee abuse) to write to protected directories and the resulting persistence via non-standard or rare cron jobs and scripts. By pivoting from process execution to scheduled jobs and file modifications, we identify implants that are often manually removed after execution to evade simple disk-scanning rules.

## scope-linux-appliances
<!-- Identify Linux and FreeBSD appliances -->
Scope the hunt to the appliance platforms (Linux/BSD) targeted by VerdantBamboo.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of appliance hosts. This narrows the fleet to targets where EDR might
  be sparse.
reads:
- hostname
- platform
- os_name
- ip_address
- last_seen
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT hostname, platform, os_name, ip_address, last_seen FROM hb_devices WHERE LOWER(platform) IN ('linux', 'freebsd', 'ubuntu', 'debian') AND time >= datetime('now', '-{{lookback_days}} days')
```

## sudo-tee-privesc
<!-- Detect sudo-to-tee privilege escalation -->
Find instances of an unprivileged account using sudo to run 'tee', a common method to write to root-owned configuration files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Process events showing sudo tee writing to system directories. This indicates
  an attempt to bypass file permissions.
reads:
- device_hostname
- user_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, user_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%sudo %' AND LOWER(process_cmd_line) LIKE '% tee %') AND (LOWER(process_cmd_line) LIKE '%/etc/cron%' OR LOWER(process_cmd_line) LIKE '%/etc/rc.d%' OR LOWER(process_cmd_line) LIKE '%/usr/sbin/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-persistence
<!-- Corroborate with Cron and File Activity -->
parallel:
- → rare-cron-jobs
- → cron-file-writes
join: → triage-agent

## rare-cron-jobs
<!-- Identify rare scheduled jobs -->
Identify cron entries that are unique or rare across the fleet, which may represent malicious implants like BRICKSTORM or AGENTPSD.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rarity_threshold=rarity_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of cron jobs appearing on very few hosts. Attackers often use unique
  script names or paths.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- job_cmd_line
- job_name
- job_user_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT job_cmd_line, job_name, job_user_name, COUNT(DISTINCT device_hostname) AS host_count, GROUP_CONCAT(DISTINCT device_hostname) AS affected_hosts FROM hb_scheduled_job WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_cmd_line, job_name, job_user_name HAVING host_count <= {{rarity_threshold}} ORDER BY host_count ASC
```

## cron-file-writes
<!-- File activity in system configuration directories -->
Look for non-package-manager writes to crontab or cron.d files, particularly those matching indicators from the report.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, persistence_scripts=persistence_scripts)
~~~yaml
expected: Specific writes to cron files. Silence may occur if the attacker removed
  the file immediately, which is why we also rely on the process and scheduled job
  surfaces.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '/etc/cron%' OR LOWER(file_path) LIKE '/etc/crontab' OR LOWER(file_path) LIKE '/etc/rc.d/%') AND activity_id IN (1, 3) AND (instr(',' || '{{persistence_scripts}}' || ',', ',' || LOWER(file_path) || ',') > 0 OR LOWER(file_path) LIKE '%ssync%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze Appliance Persistence Indicators -->
```agent target=hunter
cite: required
context:
- scope-linux-appliances
- sudo-tee-privesc
- rare-cron-jobs
- cron-file-writes
max_iterations: 4
objective: Determine if any host shows evidence of local privilege escalation (sudo
  tee) paired with rare cron/scheduled job creation or modifications to /etc/cron
  directories.
success_criteria: A per-host verdict of Malicious | Suspicious | Benign with citations
  of specific command lines or file paths.
tools:
- endpoint
```

## route-verdict
<!-- Route based on agent verdict -->
if~: "the agent verdict is Malicious for any host" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: limited-appliance-telemetry)
else: → analyst-triage

## isolate-appliance
<!-- Isolate affected appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the network interface of the affected Linux appliance and initiate a memory dump for BRICKSTORM/AGENTPSD analysis.
```
→ analyst-triage

## analyst-triage
<!-- Analyst Review of Triage Results -->
```manual target=analyst
Review the agent's cited rows. Verify if the sudo tee commands and cron jobs are part of documented maintenance by the MSP or evidence of VerdantBamboo activity.
```
→ end
