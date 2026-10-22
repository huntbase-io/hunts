# Virtualization Pivot and Host Encryption Following PAN-OS Exploitation

### Why now

Unit 42 recently updated their report, [Active Exploitation of PAN-OS CVE-2026-0257](https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/), detailing how attackers exploit VPN gateways to reach internal virtualization layers. Once inside, these actors target vCenter and backup systems to disable defenses and deploy ransomware across the virtual fleet. This hunt focuses on the sophisticated tradecraft used to bridge the gap between initial access and final impact.

### The Hypothesis

The adversary has exploited a VPN gateway to breach the perimeter and is now pivoting to the virtualization layer to disable security controls and deploy ransomware via virtual disk manipulation.

### How the hunt flows

The hunt begins with scoping by querying the vulnerability surface. An analyst identifies hosts running vulnerable Veeam components, specifically those affected by CVE-2023-27532. These servers act as the primary targets for credential theft and lateral movement because they often store high-privileged access tokens.

Once the targets are set, the hunt fans out to collect beachhead evidence. The process surface identifies rare Remote Monitoring and Management (RMM) tools that do not belong in the environment. Simultaneously, the authentication surface looks for interactive RDP or network logons to critical infrastructure keywords like vCenter, ESXi, and domain controllers from unexpected source IPs.

If the initial triage confirms suspicious activity, the hunt pivots into deep virtualization analysis. The first query in this phase searches process command lines for evidence of virtual disk (VMDK) mounting or dumping. This indicates the adversary is attempting to harvest credentials from virtual machines offline. The second query examines the syslog surface for hypervisor-level configuration changes, such as disabling the execInstalledOnly security control on ESXi hosts.

The final phase checks for impact. The file activity surface monitors for high-frequency renaming operations or the presence of specific file extensions associated with the Qilin or Inc ransomware families. This provides a definitive signal that the attack has moved from preparation to execution.

### Blind spots

This hunt has two primary blind spots. First, it cannot see what an attacker runs on the hypervisor after they disable execInstalledOnly unless you have direct host-based agents on the ESXi host. Second, it misses direct SQL-based credential extraction from Veeam databases if the environment lacks full database auditing logs.

### How to run the hunt

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md specification. Because it joins multiple disparate surfaces—from vulnerabilities to syslog and file activity—it is a coordinated hunt rather than a single detection rule. This structure allows you to distinguish between standard administrative maintenance and a multi-stage ransomware intrusion.
