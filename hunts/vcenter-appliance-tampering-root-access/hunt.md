---
analysis: While a single rule might fire on sudo use, it misses the context of the
  management API call that enabled the shell in the first place. This hunt correlates
  management plane API activity with OS-level execution while using stack-counting
  to find rare events across a fleet of standardized appliances.
blind_spots:
- id: missing-linux-audit
  question: what commands were run within the root shell
  requires: hb_linux_audit with record_type EXECVE
  risk: Without EXECVE logging, we can see sudo was used to spawn a shell but not
    the specific actions taken by the intruder inside it.
  stage: root-shell-access
- id: proxied-api-traffic
  question: the true source IP of the management API requests
  requires: hb_http_activity
  risk: If a proxy sits in front of the vCenter appliance, the src_endpoint_ip may
    show the proxy's IP, obscuring the attacker's true origin.
  stage: remote-management-enablement
coverage:
- stage: appliance-account-persistence
  status: covered
  steps:
  - api-management-activity
  - os-privilege-escalation
- stage: remote-management-enablement
  status: covered
  steps:
  - api-management-activity
- stage: root-shell-access
  status: covered
  steps:
  - os-privilege-escalation
- reason: 'Belongs to another part of the ''Rapid7 Analysis: VMware vCenter SRP Authentication
    Bypass to Root (CVE-2026-123890)'' series.'
  stage: rpc-srp-auth-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Rapid7 Analysis: VMware vCenter SRP Authentication
    Bypass to Root (CVE-2026-123890)'' series.'
  stage: directory-database-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Compromise of the vCenter appliance grants full administrative control
    over the virtualized infrastructure; detecting post-exploitation tampering is
    essential to preventing data center-wide data theft or destruction.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is established on a vCenter appliance and is using administrative
  APIs to create local persistence and enable restricted shells for root-level command
  execution.
labels:
- hunt
- attack.t1136.001
- attack.t1562.001
- attack.t1059.004
- credential access
- defense evasion
- execution
- initial access
- persistence
name: vCenter Appliance Administrative Tampering and Root Access
parameters:
  api_paths:
    default:
    - /api/appliance/access/ssh
    - /api/appliance/access/shell
    - /api/appliance/local-accounts
    description: Management API paths used for appliance configuration.
    from:
      kind: article
      observed: '2026-11-24'
      ref: CVE-2026-123890
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-policy
    type: number
  persistence_groups:
    default:
    - superAdmin
    description: High-privilege appliance groups used for persistence.
    from:
      kind: article
      observed: '2026-11-24'
      ref: CVE-2026-123890
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to these vCenter hostnames; leave empty for the whole
      estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on hosts identified as VMware vCenter Server Appliances. Use the
  presence of the vpxd package or the vCenter management API to scope. If available,
  prioritize hosts with a detected CVE-2026-123890 finding from hb_vulnerability_finding.
references:
- name: 'Rapid7 Analysis: VMware vCenter SRP Authentication Bypass to Root (CVE-2026-123890)'
  url: https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890
related:
- hunt: vcenter-rpc-auth-bypass-mechanics
  reason: This hunt focuses on the tampering aftermath; the low-level mechanics of
    the RPC SRP handle collision require distinct DCE/RPC network telemetry.
  relation: out-of-scope-alternative
- hunt: vcenter-directory-service-exploitation-credential-theft
  relation: follows
scenario:
  stages:
  - name: vCenter Directory Service RPC Bypass
    observables:
    - TCP 2012
    - CVE-2026-123890
    - Srv_rpc_srp_verifier_get_session_key
    - administrator@vsphere.local
    - vCenter Server Appliance 8.0.2.00400
    - build 23929136
    slug: rpc-srp-auth-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Directory Database and Signing Key Theft
    observables:
    - data.mdb
    - STS private signing key
    - directory database-copy interface
    slug: directory-database-theft
    tactic: credential-access
    techniques:
    - T1003
  - name: Administrative Account Creation
    observables:
    - vmware.appliance.localaccounts
    - superAdmin
    - sebastian-fritsch
    - useradd -m -G superAdmin
    slug: appliance-account-persistence
    tactic: persistence
    techniques:
    - T1136.001
  - name: SSH and Shell Access Enablement
    observables:
    - com.vmware.appliance.version1.access.ssh.set
    - com.vmware.appliance.version1.access.shell.set
    - enable=True
    slug: remote-management-enablement
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: SSH Login and Root Escalation
    observables:
    - TCP 22
    - sshd
    - sudo -n /bin/bash -i
    - root
    slug: root-shell-access
    tactic: execution
    techniques:
    - T1059.004
  summary: Attackers exploit an authentication bypass in the VMware vCenter Directory
    Service (CVE-2026-123890) to retrieve SRP session keys and impersonate administrators
    without passwords. This access is leveraged to exfiltrate the directory database
    and forge administrative assertions, which are then used to create local superuser
    accounts and enable SSH for root-level command execution.
series:
  index: 2
  slug: rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890
  title: 'Rapid7 Analysis: VMware vCenter SRP Authentication Bypass to Root (CVE-2026-123890)'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# vCenter Appliance Administrative Tampering and Root Access

This hunt identifies post-exploitation activity on VMware vCenter Server Appliances following an authentication bypass. It looks for the use of management APIs to create administrative local accounts and the enablement of SSH or the Bash shell. It correlates these management plane changes with OS-level execution logs where an attacker typically joins the 'superAdmin' group and uses sudo to spawn interactive root shells. By stack-counting these events across the appliance fleet, the hunt separates legitimate maintenance from targeted tampering.

## scoping-vcenter-hosts
<!-- Identify vCenter Appliances -->
Inventory the hosts that run vCenter services to define the hunt's blast radius.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts currently identified as vCenter appliances. Silence indicates
  no vCenter software is present.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%vcenter%' OR LOWER(package_name) LIKE '%vpxd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## appliance-tampering-fan-out
<!-- Check API and OS for Tampering -->
parallel:
- → api-management-activity
- → os-privilege-escalation
join: → triage-vcenter-tampering

## api-management-activity
<!-- Rare Management API Activity -->
Detect rare or unauthorized use of the appliance configuration APIs that enable SSH or create accounts.

```sqlite target=web role=baseline params=(api_paths=api_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An API call used on one or two appliances, suggesting non-standard maintenance.
  Normal activity typically appears fleet-wide.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- url_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT url_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE (instr(',' || '{{api_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR LOWER(url_path) LIKE '%/api/appliance/access/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_path HAVING host_count <= 2 ORDER BY host_count ASC
```

## os-privilege-escalation
<!-- OS Persistence and Root Escalation -->
Search Linux audit logs for command arguments used in administrative persistence and root shell spawning.

```sqlite target=endpoint role=detection-candidate params=(persistence_groups=persistence_groups, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows showing the manual creation of a superAdmin user or the use of sudo
  to open an interactive Bash shell as root.
reads:
- device_hostname
- raw_record
- time
silence: not_evidence_of_absence
source: hb_linux_audit
verified: dry-run
verified_at: '2026-11-25'
~~~
SELECT device_hostname, raw_record, time FROM hb_linux_audit WHERE record_type = 'EXECVE' AND ( (LOWER(raw_record) LIKE '%useradd%' AND instr(',' || LOWER('{{persistence_groups}}') || ',', ',superadmin,') > 0 AND LOWER(raw_record) LIKE '%superadmin%') OR (LOWER(raw_record) LIKE '%sudo%' AND LOWER(raw_record) LIKE '%/bin/bash%') ) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-vcenter-tampering
<!-- Triage Tampering Evidence -->
```agent target=hunter
cite: required
context:
- scoping-vcenter-hosts
- api-management-activity
- os-privilege-escalation
max_iterations: 4
objective: Determine if the rare API calls to management paths and the OS-level user/shell
  modifications confirm unauthorized tampering. Contrast against the software inventory
  to ensure these are production vCenter hosts.
success_criteria: A verdict of malicious | suspicious | benign for each host, citing
  the API paths and audit record command lines.
tools:
- endpoint
- web
```

## routing-decision
<!-- Route on Triage Result -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-appliance
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: missing-linux-audit)
else: → close-out

## isolate-appliance
<!-- Isolate Compromised Appliance -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the vCenter appliance and revoke all active administrative API sessions and SSH keys.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Forensic Review of vmdir Logs -->
```manual target=analyst
Examine the vmdir logs for unexpected SRP verifier creation. Verify if any directory database copies were granted before the account creation. Reconstruct the attacker's shell commands from /var/log/audit/audit.log.
```
→ remediation-verification

## remediation-verification
<!-- Verify Remediation and Patching -->
```manual target=analyst
Verify that the appliance has been updated to the fixed version (e.g., 8.0 U3m). Confirm that all local accounts created during the intrusion have been deleted.
```
→ close-out

## close-out
<!-- Close-out and Documentation -->
```manual target=analyst
Archive the forensic findings. If any benign activity was found, update the hunt parameters to exclude the authorized administrative source IPs.
```
→ end
