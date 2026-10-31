---
analysis: This is a hunt because a single 'admin login' alert is too noisy for storage
  appliances. We combine scoping of specific vulnerable appliance types with a stack-count
  of source IPs and identifying specific web management URIs to differentiate actor
  behavior from MSP maintenance.
blind_spots:
- id: missing-appliance-telemetry
  question: whether commands were executed on the appliance after the web login
  requires: EDR agent or Syslog from the storage appliance
  risk: Without process telemetry from the NAS itself, we rely on HTTP logs to see
    the activity, which may miss command execution if it occurs outside the web interface.
  stage: lateral-movement-and-nas-compromise
- id: vpn-source-anonymity
  question: which external actor is tied to an internal IP in the sign-in logs
  requires: VPN session logs correlated with internal IP assignments
  risk: If hb_auth_signin logs only the internal VPN IP, we cannot distinguish between
    a compromised employee and a compromised MSP user without joining to external
    VPN gateway logs.
  stage: initial-access-stolen-appliance-credentials
coverage:
- stage: initial-access-stolen-appliance-credentials
  status: covered
  steps:
  - rare-admin-auth-sources
  - triage-appliance-access
- stage: lateral-movement-and-nas-compromise
  status: covered
  steps:
  - appliance-management-web-access
  - triage-appliance-access
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: local-privilege-escalation-sudo-tee
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: persistence-via-scheduled-cron
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: malware-deployment-brickstorm-agentpsd
  status: out_of_scope
- reason: 'Belongs to another part of the ''VERDANTBAMBOO: Just Another BRICKSTORM
    in the Firewall'' series.'
  stage: c2-proxying-via-doh-and-cloudflare
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: VerdantBamboo targets edge appliances as a bridge into cloud and
    internal environments, using stolen credentials to bypass MFA. A negative result
    across these critical systems validates the security of the administrative plane.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used stolen administrative or service account credentials
  to access edge appliances via VPN or SSH, subsequently using web-based management
  interfaces to pivot further or deploy persistence.
labels:
- hunt
- attack.t1078
- attack.t1133
- attack.t1059
- attack.t1090.003
- attack.t1505.003
name: VerdantBamboo Stolen Credential and Pivot Hunt
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication and web activity.
    from:
      kind: manual
      observed: '2026-06-04'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: 'Optional: List of storage appliance hostnames to focus the hunt;
      leave empty for whole estate.'
    from:
      kind: manual
      observed: '2026-06-04'
      ref: analyst-scoping
    type: list[host]
  target_users:
    default:
    - egnyteservice
    - admin
    - root
    description: Administrative and service accounts targeted in this campaign.
    from:
      kind: article
      observed: '2026-06-04'
      ref: Volexity VERDANTBAMBOO
    type: list[string]
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
rationale: Start by identifying all Egnyte Storage Sync and Synology NAS systems using
  software inventory. Focus on administrative subnets and systems where administrative
  interfaces are exposed to the VPN network or public internet.
references:
- name: "Volexity \u2014 VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall"
  url: https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/
related:
- hunt: verdantbamboo-malware-persistence
  reason: Persistence via cron and BRICKSTORM binary deployment requires file and
    scheduled task surfaces which are covered in a companion hunt.
  relation: out-of-scope-alternative
- hunt: verdantbamboo-edge-appliance-post-exploitation
  relation: follows
scenario:
  stages:
  - name: Access via Stolen Appliance Credentials
    observables:
    - egnyteservice
    - SSH logins to Egnyte Storage Sync
    - VPN IP address source for administrative logins
    slug: initial-access-stolen-appliance-credentials
    tactic: initial-access
    techniques:
    - T1078
    - T1133
  - name: Local Privilege Escalation via Sudo Tee
    observables:
    - sudo /usr/bin/tee
    - /usr/local/bin/egnyte/rsync_data_migration.sh
    - /usr/bin/systemctl restart networking
    slug: local-privilege-escalation-sudo-tee
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Persistence via Scheduled Cron Jobs
    observables:
    - /etc/cron.d/ssync
    - /home/egnyteservice/ssync.sh
    - /etc/crontab entry for egnyte_host_monitor_client
    - /etc/rc.d/cron modification on pfSense
    slug: persistence-via-scheduled-cron
    tactic: persistence
    techniques:
    - T1059
  - name: Deployment of BRICKSTORM and AGENTPSD
    observables:
    - /usr/sbin/ (BRICKSTORM directory)
    - /usr/local/bin/egnyte/egnyte_host_monitor_client
    - /usr/local/libexec/ipsec/blacklist
    slug: malware-deployment-brickstorm-agentpsd
    tactic: execution
    techniques:
    - T1059
    - T1505.003
  - name: C2 and Proxying via DoH and Cloudflare
    observables:
    - 8.8.8.8:443
    - TLS connections to Google Public DNS
    - Cloudflare IP addresses
    - M365 access via internal proxy traffic
    slug: c2-proxying-via-doh-and-cloudflare
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: Lateral Movement to Synology NAS
    observables:
    - Synology NAS web interface admin logins
    - PLENET malware deployment
    - SSH enabled via web interface
    slug: lateral-movement-and-nas-compromise
    tactic: lateral-movement
    techniques:
    - T1078
    - T1133
  summary: VerdantBamboo compromised an MSP to obtain administrative credentials,
    which were then used to breach edge appliances including Egnyte Storage Sync,
    pfSense firewalls, and Synology NAS systems. The actor deployed BRICKSTORM and
    AGENTPSD malware to establish persistence and create proxy tunnels into internal
    networks and Microsoft 365 environments, effectively bypassing conditional access
    policies by appearing as internal traffic.
series:
  index: 2
  slug: verdantbamboo-just-another-brickstorm-in-the-firewall
  title: 'VERDANTBAMBOO: Just Another BRICKSTORM in the Firewall'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# VerdantBamboo Stolen Credential and Pivot Hunt

This hunt identifies VerdantBamboo tradecraft focusing on edge appliances like Egnyte Storage Sync and Synology NAS. The actor uses compromised credentials for the egnyteservice account and other administrative logins, often bypassing MFA by connecting through established VPN tunnels. The hunt first scopes the environment for these appliances using software inventory, then fans out to stack-count authentication source IPs and investigate suspicious web-based management activity. An agent correlates these signals to identify lateral movement or unauthorized appliance configuration.

## scope-appliances
<!-- Scope storage and firewall appliances -->
Identify hosts running software associated with the targeted appliances to focus subsequent queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to storage or firewall appliances. If empty,
  the hunt can still run but will lack specific appliance context.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%egnyte%' OR LOWER(package_name) LIKE '%synology%' OR LOWER(package_name) LIKE '%pfsense%' OR LOWER(vendor_name) LIKE '%egnyte%' OR LOWER(vendor_name) LIKE '%synology%')
```

## corroborate-activity
<!-- Corroborate activity on two surfaces -->
parallel:
- → rare-admin-auth-sources
- → appliance-management-web-access
join: → triage-appliance-access

## rare-admin-auth-sources
<!-- Rare admin authentication sources -->
Stack-count source IPs for administrative logins to find external or rare actors.

```sqlite target=identity role=baseline params=(target_users=target_users, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Administrative logins from a source IP seen on only one or two hosts. This
  isolates potentially malicious VPN or SSH access from legitimate broad MSP usage.
prevalence:
  by: dst_endpoint_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, actor_user_name, COUNT(DISTINCT dst_endpoint_name) AS host_count, COUNT(*) AS login_total, MIN(time) AS first_login, MAX(time) AS last_login FROM hb_auth_signin WHERE (instr(',' || '{{target_users}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0) AND status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name HAVING host_count <= 2 ORDER BY host_count ASC
```

## appliance-management-web-access
<!-- Appliance management web access -->
Detect access to administrative web paths on storage appliances.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct access to management URLs. Unauthorized source IPs accessing these
  paths suggests an actor is reconfiguring the device via the web interface.
reads:
- device_hostname
- src_endpoint_ip
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_path, src_endpoint_ip, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/webman/%' OR LOWER(url_path) LIKE '%/syno/%' OR LOWER(url_path) LIKE '%/egnyte/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-appliance-access
<!-- Triage appliance access -->
```agent target=hunter
cite: required
context:
- scope-appliances
- rare-admin-auth-sources
- appliance-management-web-access
max_iterations: 4
objective: Determine if any host shows evidence of administrative credential abuse
  from a rare source IP followed by web-based reconfiguration or SSH access.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  specific rows from auth and http activity.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host showing both a rare authentication source and web management access" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-appliance-telemetry)
else: → analyst-review

## contain-host
<!-- Isolate appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified appliance hostname. Rotate passwords for egnyteservice and administrative accounts. Terminate all active VPN and SSH sessions associated with these accounts.
```
→ forensic-verification

## forensic-verification
<!-- Forensic verification -->
```manual target=analyst
Perform forensic analysis on the isolated appliance. Search for the PLENET backdoor or AGENTPSD (Python reverse shell). Check /usr/sbin, /home/egnyteservice, and /etc/crontab for unauthorized modifications. Review sudoers for the tee privilege escalation vulnerability.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the agent's triage and forensic findings. Verify if the source IPs for the SSH/VPN logins match known MSP infrastructure. Document any discovered indicators for the broader SOC and close out the hunt.
```
→ end
