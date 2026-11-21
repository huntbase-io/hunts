---
analysis: A standard detection rule for LAPS access is often too noisy for large environments.
  This hunt uses a multi-stage approach by scoping to vulnerable appliances and applying
  prevalence baselining to separate legitimate management activity from attacker discovery.
blind_spots:
- id: ad-audit-log-gaps
  owner: Identity Engineering
  question: whether the attacker queried LAPS or BitLocker attributes if the DC did
    not log the specific attribute read
  remediation: Enable Audit Object Access and ensure SACLs are set to audit Read access
    for the Everyone or Authenticated Users group on LAPS/BitLocker attributes.
  requires: Active Directory Object Access auditing (Event ID 4662) and appropriate
    SACLs on sensitive attributes
  risk: Attackers can harvest secrets without detection if auditing is only enabled
    for objects and not specifically for sensitive attributes like ms-LAPS-Password.
  stage: discovery-ad-secrets
coverage:
- stage: discovery-ad-secrets
  status: covered
  steps:
  - discovery-attribute-access
  - baseline-attribute-readers
- reason: This hunt focuses specifically on post-compromise AD activity; web exploitation
    is handled in the appliance-side hunt.
  stage: initial-access-web-exploitation
  status: out_of_scope
- reason: Payload execution on the Ivanti appliance is covered by endpoint-centric
    hunts.
  stage: execution-root-payloads
  status: out_of_scope
- reason: Belongs to another part of the 'Additional Ivanti Connect Secure zero-days
    exploited in the wild (CVE-2026-111357, CVE-2026-118527)' series.
  stage: defense-evasion-selective-deletion
  status: out_of_scope
- reason: Belongs to another part of the 'Additional Ivanti Connect Secure zero-days
    exploited in the wild (CVE-2026-111357, CVE-2026-118527)' series.
  stage: c2-external-comms
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors targeting Ivanti appliances frequently move to the
    identity plane to gain broad administrative access. Detecting this transition
    is critical for preventing lateral movement and complete domain compromise.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder uses a compromised Ivanti Connect Secure appliance to query
  Active Directory for sensitive attributes, such as LAPS passwords or BitLocker recovery
  keys, to prepare for lateral movement.
labels:
- hunt
- attack.t1087.002
- attack.t1212
- command and control
- defense evasion
- discovery
- execution
- initial access
name: Ivanti VPN AD Sensitive Attribute Access
parameters:
  appliance_accounts:
    default: []
    description: List of user accounts associated with Ivanti appliances, discovered
      in the scoping step.
    type: list[string]
  ivanti_cves:
    default:
    - CVE-2026-104935
    - CVE-2026-111357
    - CVE-2026-118527
    description: CVE IDs associated with the Ivanti Connect Secure exploitation chain.
    from:
      kind: article
      observed: '2026-11-02'
      ref: https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for Active Directory queries.
    type: number
  scope_hosts:
    default: []
    description: Domain Controllers to narrow the Active Directory search.
    type: list[host]
  sensitive_attributes:
    default:
    - ms-MCSC-Password
    - ms-LAPS-Password
    - ms-FVE-RecoveryPassword
    description: AD attributes used to store LAPS passwords and BitLocker recovery
      keys.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying Ivanti appliances in the vulnerability findings and
  pasting their associated service accounts into the appliance_accounts parameter.
  If none are found, widen the hunt to any rare access of LAPS or BitLocker attributes
  from non-admin accounts across all Domain Controllers.
references:
- name: "Rapid7 \u2014 Additional Ivanti Connect Secure zero-days exploited in the\
    \ wild"
  url: https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527
related:
- hunt: ivanti-vpn-root-payload-execution
  reason: Initial access and execution of payloads on the appliance itself are handled
    in a separate hunt focused on endpoint process and file activity.
  relation: out-of-scope-alternative
- hunt: ivanti-appliance-exploitation-persistence
  relation: follows
scenario:
  stages:
  - name: Web Application Exploitation
    observables:
    - /dana-na/auth/url_default/welcome.cgi
    - 'X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi'
    - 'X-DSCGI-PATH: /home/runtime/tmp/'
    - CVE-2026-104935
    - CVE-2026-118527
    slug: initial-access-web-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Root-Level Payload Execution
    observables:
    - ml.py
    - rq5.py
    - mk.py
    - rr.py
    - pu.txt
    - sp_out.txt
    - spray_hits.json
    - dsstatmond
    - ics-root-run-inband-*.pl
    - CVE-2026-111357
    slug: execution-root-payloads
    tactic: execution
    techniques:
    - T1059.006
    - T1068
  - name: Defense Evasion and Log Tampering
    observables:
    - /home/runtime/dlogs/debuglog
    - /var/log/audit/audit.log
    - /data/.icscap/
    - h.py
    slug: defense-evasion-selective-deletion
    tactic: defense-evasion
    techniques:
    - T1070.002
  - name: Active Directory Secret Discovery
    observables:
    - Active Directory queries for Windows LAPS passwords
    - Active Directory queries for BitLocker recovery keys
    slug: discovery-ad-secrets
    tactic: discovery
    techniques:
    - T1087.002
    - T1212
  - name: Command and Control Traffic
    observables:
    - 108.165.147.64
    slug: c2-external-comms
    tactic: c2
    techniques:
    - T1071.001
  summary: The threat actor UTA0576 exploited a chain of three zero-day vulnerabilities
    in Ivanti Connect Secure (CVE-2026-104935, CVE-2026-111357, and CVE-2026-118527)
    to gain unauthenticated root access. After establishing a foothold, they deployed
    Python payloads to steal credentials and queried Active Directory for high-value
    targets including LAPS passwords and BitLocker recovery keys.
series:
  index: 2
  slug: additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527
  title: Additional Ivanti Connect Secure zero-days exploited in the wild (CVE-2026-111357,
    CVE-2026-118527)
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


# Ivanti VPN AD Sensitive Attribute Access

This hunt targets post-compromise activity following the exploitation of Ivanti Connect Secure zero-days (CVE-2026-111357, CVE-2026-118527). Attackers like UTA0576 often pivot from the network edge to the identity plane. We specifically look for unusual Active Directory attribute access targeting Windows LAPS and BitLocker recovery information, which are high-value objectives for credential harvesting. The hunt first scopes vulnerable appliances and then uses Active Directory object access logs to identify anomalous queries for these secrets, using the appliance identities discovered during scoping.

## scoping-vulnerable-appliances
<!-- Identify vulnerable Ivanti appliances -->
Find hosts currently flagged with the relevant Ivanti CVEs to focus the search for compromised accounts.

```sqlite target=endpoint role=scoping params=(ivanti_cves=ivanti_cves)
~~~yaml
expected: A list of resource IDs or device IDs vulnerable to the ICS exploit chain.
  Silence implies no vulnerable appliances were detected in the inventory.
reads:
- resource_uid
- device_uid
- cve_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT resource_uid, device_uid, cve_uid, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{ivanti_cves}}' || ',', ',' || cve_uid || ',') > 0
```

## discovery-fan-out
<!-- Evaluate AD discovery activity -->
parallel:
- → discovery-attribute-access
- → baseline-attribute-readers
join: → agent-triage-access

## discovery-attribute-access
<!-- Sensitive attribute access logs -->
Detect if an attacker used or hijacked an appliance account to query LAPS and BitLocker secrets in AD logs.

```sqlite target=endpoint role=detection-candidate params=(sensitive_attributes=sensitive_attributes, appliance_accounts=appliance_accounts, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating which appliance accounts read sensitive attributes. Unexpected
  reads by these accounts are a high-risk indicator of compromise.
reads:
- actor_user_name
- entity_name
- attribute_name
- time
- device_hostname
silence: not_evidence_of_absence
source: hb_entity_management
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT actor_user_name, entity_name, attribute_name, time, device_hostname FROM hb_entity_management WHERE (instr(',' || '{{sensitive_attributes}}' || ',', ',' || attribute_name || ',') > 0) AND ('{{appliance_accounts}}' = '' OR instr(',' || '{{appliance_accounts}}' || ',', ',' || actor_user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-attribute-readers
<!-- Rare attribute readers prevalence -->
Identify rare actors querying sensitive attributes to distinguish between legitimate management tools and manual attacker discovery.

```sqlite target=endpoint role=baseline params=(sensitive_attributes=sensitive_attributes, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count of actors who infrequently access secret attributes. Legitimate
  automation typically reads from many hosts; attacker activity appears as a rare
  event.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- device_hostname
- time
- attribute_name
silence: not_evidence_of_absence
source: hb_entity_management
verified: dry-run
verified_at: '2026-11-18'
~~~
SELECT actor_user_name, COUNT(DISTINCT device_hostname) AS dc_count, COUNT(*) AS access_events, MIN(time) AS first_seen FROM hb_entity_management WHERE instr(',' || '{{sensitive_attributes}}' || ',', ',' || attribute_name || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name HAVING dc_count < 3
```

## agent-triage-access
<!-- Triage Active Directory discovery -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-appliances
- discovery-attribute-access
- baseline-attribute-readers
max_iterations: 5
objective: Determine if any account associated with vulnerable Ivanti appliances or
  any rare principal is querying LAPS or BitLocker secrets in a way that suggests
  post-compromise reconnaissance.
success_criteria: A verdict for every identified actor citing the specific attribute
  reads and prevalence findings.
tools:
- endpoint
```

## decision-route-access
<!-- Route on discovery verdict -->
if~: "the triage verdict is malicious for at least one account querying sensitive AD attributes" (confidence: high, judge=hunter)
then: → action-revoke-identity
indeterminate: → task-verify-findings
unavailable: → task-verify-findings (blind_spot: ad-audit-log-gaps)
else: → task-close-out

## action-revoke-identity
<!-- Revoke compromised account -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the account identified by the agent as performing malicious AD discovery. Rotate the credentials if the account is used by the VPN appliance.
```
→ task-verify-findings

## task-verify-findings
<!-- Manual verify findings -->
```manual target=analyst
Review the hb_entity_management rows cited by the agent. Cross-reference the actor_user_name with known service accounts for Ivanti VPN appliances. Check for concurrent network connections from the appliances to the Domain Controllers.
```
→ end

## task-close-out
<!-- Close out hunt -->
```manual target=analyst
Record that no malicious AD attribute discovery was found associated with vulnerable Ivanti appliances. Note any tuning required for prevalence queries.
```
→ end
