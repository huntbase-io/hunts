# vCenter Post-Exploitation and Administrative Tampering Hunt

### Background

Recent analysis from Rapid7 (Rapid7 Analysis: VMware vCenter SRP Authentication Bypass to Root (CVE-2026-123890) at https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890) details a critical authentication bypass in VMware vCenter Server. This vulnerability allows an attacker to gain root access to the appliance. Our team developed a hunt to find the specific tampering that occurs after an attacker successfully bypasses authentication.

### Hypothesis

An attacker is established on a vCenter appliance and is using administrative APIs to create local persistence and enable restricted shells for root-level command execution.

### Hunt Flow

The hunt begins by identifying the blast radius. The first query lists every host running the vCenter service or the vpxd package by searching software inventory logs. This step ensures that the subsequent, more resource-intensive queries only target relevant appliances across the estate.

Once we define the scope, the hunt fans out to examine the management plane through HTTP activity logs. The analyst searches for rare calls to API paths that enable SSH or create local accounts, such as /api/appliance/access/ssh. By stack-counting these requests across the fleet, the hunt identifies configurations that differ from standard maintenance patterns.

Simultaneously, the hunt searches the operating system plane using Linux audit logs. It looks for execution records where an attacker adds a user to the superAdmin group or uses sudo to spawn an interactive bash shell. These signals provide the proof of the privilege escalation that follows the initial management plane tampering.

Finally, the hunt correlates the rare API activity with the suspicious OS commands. This activity is a hunt rather than a detection because it relies on the rarity and timing of these events across standardized appliances. A single sudo use might be benign, but sudo plus a rare management API call indicates a high-confidence exploit chain.

### Blind Spots

This hunt has two primary limitations. If the management traffic passes through a proxy, the HTTP logs may only show the proxy's IP address rather than the attacker's true origin. Additionally, if EXECVE logging is disabled in the Linux audit configuration, the hunt identifies that a shell was opened but cannot see the specific commands the attacker executed inside it.

### How to Run

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It uses a tiered structure to identify vCenter hosts before executing the deeper correlation queries.
