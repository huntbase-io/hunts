# Zimbra secret theft and lateral movement via SSH identity

### Why now
Microsoft recently published details on CVE-2026-73570 (https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/), an unauthenticated command injection vulnerability in internet-facing Zimbra mail servers. This vulnerability allows an attacker to execute commands via the SNMP component. Once they gain access, attackers focus on harvesting credentials and expanding their reach to other parts of the infrastructure. This hunt addresses the post-compromise phase where an adversary maps the cluster and moves laterally.

### Hypothesis
An intruder uses Zimbra administrative utilities to dump service credentials and move laterally to peer nodes using the zimbra service account’s SSH identity.

### How the hunt flows
The hunt begins by identifying every host in the environment running the Zimbra Collaboration Suite. The first query searches the software inventory surface for packages containing the name Zimbra. This scoping step is necessary to focus behavioral analysis on the relevant mail servers and avoid processing logs from unrelated systems.

The next phase identifies early evidence of discovery and secret theft. The hunt looks for rare executions of administrative tools like zmprov or ldapsearch. While administrators use these tools for maintenance, they typically do so in a predictable, cluster-wide manner. Attackers use them to map node roles and identify targets for lateral movement. Simultaneously, the hunt monitors for the zmlocalconfig utility being used with the -s flag. This specific command allows an actor to dump sensitive LDAP and replication passwords from the local configuration.

After identifying potential secret theft, the analyst pivots to look for follow-on movement and exfiltration staging. The hunt searches for the reuse of the zimbra_identity SSH key. If an attacker has compromised the main node, they will use this key to access peer nodes. The hunt also tracks rsync operations and SSH processes running in batch mode, which indicate automated movement or data synchronization across the cluster.

The final stage of the flow focuses on exfiltration and persistence staging. The hunt examines file activity for the creation of compressed archives in /tmp or other non-standard directories. It specifically looks for files associated with known Zimbra exfiltration tools, such as zimdown2, zimclient2, or zimbra-exfil. The presence of these files suggests that mailbox data is being staged for removal from the network.

### What the hunt cannot see
This hunt cannot identify activity on nodes without an endpoint agent. If an attacker exfiltrates the SSH identity to an external machine and connects back into the environment, the local process logs will not capture those external connection attempts as they originate from outside the managed fleet. Additionally, the hunt does not monitor network-level SSH traffic, only the process execution on the Zimbra nodes.

### How to run it
This hunt is an open hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime. Analysts provide a list of target hostnames and a lookback window to begin the execution. Because it uses behavioral baselining, it helps separate legitimate cluster management from the manual, localized actions of an intruder.
