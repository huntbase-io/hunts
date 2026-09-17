# Hunting Stealthy Infrastructure Pivoting via SPA and Ghost NICs

### Background and Context

Recent reporting by Google Cloud’s Mandiant team on [UNC6201 exploiting a Dell RecoverPoint zero-day](https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day) highlights a sophisticated approach to infrastructure persistence. Beyond initial exploitation, the adversary uses kernel-level networking features to hide their command-and-control (C2) presence and manipulate the virtualization layer to move between network segments. We have published a `hunt.md` playbook to help teams look for these specific behaviors across their Linux appliances and VMware environments.

### The Hypothesis

We hypothesize that an adversary is using Single Packet Authorization (SPA) via iptables to keep C2 listeners hidden from port scanners. Under this model, a port remains closed until a specific trigger string is received. Furthermore, the adversary creates temporary 'Ghost' network interfaces to facilitate stealthy pivoting between virtualized segments, leaving minimal footprint in standard configuration audits.

### How the Hunt Flows

The hunt begins by scoping the environment to affected assets. We prioritize Dell RecoverPoint appliances and any hosts with known vulnerability findings for the related CVE. This step ensures the hunt is focused on the most likely entry points, though it can be expanded to broader Linux fleets.

In the second phase, we examine process activity for specific `iptables` command-line patterns. We aren't looking for generic firewall changes; we are searching for the specific use of the `-m string`, `--hex-string`, and `--rcheck` modules. These are the building blocks of SPA, allowing the system to monitor incoming packets for a secret trigger before dynamically opening a port.

Third, the hunt pivots to correlate network and interface activity. We look for the prevalence of connections to port 10443, which the report identifies as a common non-standard C2 port for this actor. Simultaneously, we look for 'Ghost NIC' creation—process execution involving `ip link add`, `ifconfig add`, or `esxcli network interface add`. Detecting these commands in a production environment, outside of a maintenance window, is a high-fidelity indicator of infrastructure manipulation.

Finally, the hunt uses an automated triage agent to group these signals. A host showing both unusual `iptables` configuration and rare connections to port 10443 is flagged for immediate isolation and volatile memory collection.

### Blind Spots and Limitations

This hunt relies heavily on process-level telemetry (like Auditd or EDR) from Linux appliances. Many proprietary or hardened appliances do not support standard agents, which remains a primary blind spot. Additionally, because SPA occurs at the kernel level, the 'trigger' that opens the port is invisible to this hunt without full packet capture (PCAP) or raw payload analysis. The activation will appear as spontaneous traffic to an otherwise closed port.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime environment that supports the `hunt.md` standard. The parameters for lookback windows and specific C2 ports are configurable to match your environment's logging retention and threat profile.
