# Ivanti VPN Post-Compromise Active Directory Attribute Discovery

### Why this hunt? 
 Rapid7 recently detailed vulnerabilities in Ivanti Connect Secure, including [CVE-2026-111357 and CVE-2026-118527](https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527). These zero-days allow attackers to gain an initial foothold on the network edge. We observe that threat actors like UTA0576 do not stop at the appliance. They quickly pivot to the identity plane, seeking credentials that facilitate lateral movement across the internal domain. 
 
 ### Hypothesis 
 An intruder uses a compromised Ivanti Connect Secure appliance to query Active Directory for sensitive attributes, such as LAPS passwords or BitLocker recovery keys, to prepare for lateral movement. 
 
 ### How the hunt flows 
 The hunt begins by identifying vulnerable appliances. A scoping query checks the vulnerability inventory for hosts flagged with the relevant Ivanti CVE IDs. This focus ensures that subsequent discovery searches prioritize the service accounts and identities associated with the compromised edge devices. 
 
 The next phase executes two parallel searches on the identity surface. The first query monitors Active Directory object access logs for any actor reading sensitive attributes like ms-LAPS-Password or ms-FVE-RecoveryPassword. These attributes are high-value targets because they provide local administrator access to workstations and servers across the environment. 
 
 Simultaneously, the hunt performs a prevalence baseline. It identifies rare principals that query these attributes on fewer than three Domain Controllers. While automated management tools often read these secrets at scale, an attacker performing manual reconnaissance typically targets specific hosts, appearing as a statistical outlier. 
 
 Finally, an analyst triages the results by cross-referencing the timing of AD queries with the appliance exploitation window. They determine if the actor is a legitimate service account or a hijacked identity used for discovery. If the activity is malicious, the playbook directs the analyst to revoke the compromised identity and investigate the beachhead appliance. 
 
 ### Blind spots 
 This hunt relies on Active Directory Object Access auditing (Event ID 4662). If this auditing is disabled, or if System Access Control Lists (SACLs) are not specifically configured for the sensitive attributes, the queries will not generate logs. Security teams should ensure that Read access for LAPS and BitLocker attributes is audited for the Authenticated Users group to maintain visibility. 
 
 ### How to run it 
 This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. Because the process uses scoping and prevalence instead of static signatures, it effectively distinguishes between routine administration and the manual discovery patterns characteristic of post-compromise activity.
