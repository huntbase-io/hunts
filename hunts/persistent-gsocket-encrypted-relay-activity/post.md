# Finding Persistent GSocket Relays on Vulnerable Linux Servers

### Why now

Recent research from Microsoft, [The global socket: how threat actors are weaponizing GSocket for stealthy C2](https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/), describes how adversaries use GSocket to maintain a persistent backdoor on Linux systems. These actors often exploit the Dirty Frag kernel vulnerability (CVE-2026-43284) to gain the privileges needed for installation. Because GSocket uses a shared public relay network and initiates connections outbound, it bypasses many standard firewall configurations. We designed this hunt to find these relays by looking for the overlap of vulnerable kernels, masqueraded persistence, and relay infrastructure lookups.

### The hypothesis

An intruder maintains persistent access to a Linux server by deploying a GSocket relay after exploiting a kernel vulnerability. They masquerade the relay as a legitimate system service, such as systemd-remount, while communicating outbound to a shared public relay network to evade detection.

### How the hunt flows

The first phase identifies the attack surface. A query against vulnerability management data lists every Linux host currently reporting the Dirty Frag vulnerability. This provides a focused list of high-risk targets where an adversary likely succeeded in elevating privileges. While the hunt can run across the entire estate, these vulnerable hosts serve as the primary anchors for the analysis.

Next, the hunt initiates two parallel checks for evidence of weaponization. One query examines scheduled jobs in cron and systemd units. It looks for rare entries that use masqueraded names like 'systemd-remount-d' or 'defunct.service', or those that reference staging paths in /dev/shm. Simultaneously, a DNS activity query checks for outbound resolution attempts to known GSocket relay domains. This identifies hosts attempting to join the global relay network.

In the triage phase, an agent correlates these signals for each host. The agent weighs the presence of the Dirty Frag vulnerability against any discovered persistence mechanisms or DNS lookups. If a host shows both a vulnerable kernel and evidence of GSocket infrastructure, the agent assigns a malicious verdict. This correlation reduces noise from administrators who might use GSocket for legitimate, though non-standard, remote management.

Finally, the hunt provides a path to remediation. If the agent identifies a malicious relay, the playbook routes the host for immediate isolation. An analyst then terminates the masqueraded processes and removes the persistence artifacts before patching the kernel vulnerability to close the initial entry point.

### What the hunt cannot see

This hunt has two primary blind spots. First, GSocket traffic is end-to-end encrypted. Without egress proxy TLS inspection, we cannot see the content of the C2 commands and must rely on process context and domain reputation to determine intent. Second, sophisticated variants of GSocket may use kernel-thread masquerading or system calls like prctl to rename threads dynamically. If the telemetry only captures the initial process command line and not subsequent thread renames, these more advanced persistence methods might remain hidden.

### How to run it

This hunt is available as an open hunt.md playbook. You can import the markdown file directly into Huntbase or any runtime that supports the hunt.md format. The playbook includes the necessary SQL queries and automated triage logic to scan your Linux estate and identify active GSocket intrusions.
