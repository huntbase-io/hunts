# Hunting for N-central Post-Exploitation Tunneling and Persistence

Recent reports from Huntress, specifically their analysis of [Critical N-able N-central Vulnerability and Active Exploitation](https://www.huntress.com/blog/n-able-vulnerability-exploitation), highlight a significant risk to RMM infrastructure. When an adversary compromises an RMM server, they gain broad access to the downstream estate. This hunt focuses on the persistence phase: how the attacker maintains that access after the initial vulnerability is exploited. 

### The Hypothesis
Our team is hunting for evidence that an adversary has established persistence on an N-central server or its managed endpoints. We expect to find this via two primary methods: the use of Cloudflare tunnels (identified by a specific malicious account tag) and the execution of masqueraded payloads—specifically 'svchost.exe'—running from user-writable directories like Documents or Public folders.

### How the Hunt Flows
The hunt begins with a scoping phase using the `hb_software_inventory` surface. We identify any hosts running N-central software or agents. This helps focus the hunt on the systems most likely to be targeted or used as jump boxes, though the hunt can be expanded to the entire fleet to catch lateral movement.

Once scoped, the hunt pivots into a parallel execution phase across multiple telemetry surfaces. We first look at `hb_process_activity` to find instances of 'svchost.exe' that are not running from the standard System32 directory. We apply a prevalence filter, looking for paths seen on fewer than three hosts to reduce noise from legitimate but unusual software.

Simultaneously, we monitor for the execution of the Cloudflare tunnel client. While `cloudflared` has legitimate uses, the hunt specifically looks for a known malicious account tag (5568cd69c754b392121f1dbb8f900fda) within the command-line arguments. This is a high-fidelity indicator that the tunnel is controlled by the threat actor.

To corroborate these findings, we check `hb_network_connection` for outbound traffic to known intruder IPs associated with Tzulo VPN and previous N-central exploitation. Finally, we use `hb_file_activity` to trace the initial write of the 'svchost.exe' payload to the filesystem, which provides the timeline for when the persistence was first established.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, it relies on endpoint telemetry. If an attacker drops a payload on a system without an active agent or on unmanaged workstations, the hunt will not find it. Second, the lookback window is a factor. If the initial tunnel setup or file write occurred 30 days ago and the logs only go back 14 days, we will miss the original installation event, though we may still catch the active process execution.

### Running This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. Because it correlates process, file, and network activity, it is more robust than a simple static detection and is intended for periodic execution during active campaign windows.
