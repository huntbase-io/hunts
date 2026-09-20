# Hunt for UNC6201 Network Evasion and Evasive C2

### Why this hunt?

Mandiant recently detailed [UNC6201 exploiting a Dell RecoverPoint zero-day](https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day). The threat actor gains initial access, then secures their foothold using custom persistence and highly evasive network tradecraft. They use Single Packet Authorization (SPA) to hide ingress and DNS-over-HTTPS (DoH) to mask egress. This hunt focuses on identifying these stealthy network pivots within your environment.

### Hypothesis

The adversary uses iptables REDIRECT rules for Single Packet Authorization and DNS-over-HTTPS for command-and-control to hide ingress traffic and outbound beacons on compromised appliances.

### How the hunt flows

The hunt begins by scoping the environment for Dell RecoverPoint for Virtual Machines. The first query searches the software inventory to identify high-value targets and narrow the search space to the relevant Linux-based appliances. This ensures the subsequent, more intensive queries focus on the most likely points of entry.

Once the scope is set, the hunt fans out into two parallel queries. The first query searches process activity for specific iptables command-line arguments. The adversary uses redirection rules and the u32 module or hex-string matching to implement SPA, allowing them to open ports only when a specific packet sequence is received.

The second branch of the fan-out examines DNS activity. It looks for resolution attempts to common DoH providers like Google, Cloudflare, and NextDNS. Because DoH is common in modern browsers, the hunt baselines this activity across the fleet and focuses on rare lookups originating from the appliances identified in the scoping phase.

An automated agent then correlates these findings. It looks for hosts that exhibit both unusual iptables manipulation and rare DoH activity. If the agent finds a match, it routes the host for isolation and triggers an analyst review to confirm the presence of a web shell or unauthorized persistence.

### What this hunt cannot see

This hunt relies on process-level telemetry for iptables. If the adversary manipulates the network stack through direct kernel module interaction or direct API calls that bypass the iptables binary, the process logs will remain silent. Additionally, this hunt does not cover VMware infrastructure changes, such as the creation of "Ghost NICs" on ESXi hosts, as that requires audit logs from the hypervisor layer which are not currently part of the target surfaces.

### Why this is a hunt, not a detection

A standard detection rule for iptables commands often triggers false positives because administrators use the utility for legitimate network maintenance. Similarly, DNS-over-HTTPS is increasingly common in modern environments. This playbook functions as a hunt because it applies environmental context: it baselines DoH activity against the fleet and only alerts when it correlates with rare, specific network redirection commands on high-value appliances.

### How to run it

This hunt is available as an open-source hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime to begin scanning your Dell RecoverPoint estate. The playbook includes automated triage logic to help you filter out administrative noise and focus on active compromises.
