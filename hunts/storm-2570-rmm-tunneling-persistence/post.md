# Hunting for Storm-2570 RMM Persistence and Tunneling Activity

### Why hunt for Storm-2570 persistence?

Microsoft recently detailed the consistent tradecraft of Storm-2570 in the article [Beyond the ransomware: Tracking Storm-2570’s consistent tradecraft across deployments](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/). This group acts as an access provider and ransomware affiliate, focusing on maintaining long-term access to victim networks through Remote Monitoring and Management (RMM) tools. They often move quickly from establishing a foothold to deploying ransomware, making early detection of their persistent bridges critical to disruption.

### The Hypothesis

An intruder has established redundant persistent access using commercial RMM tools and outbound tunneling utilities to bypass firewalls and conduct internal reconnaissance. The adversary renames these tools to blend into the environment and pairs them with utilities like Cloudflared to create encrypted outbound channels.

### How the Hunt Flows

The hunt begins with a scoping phase that scans the software inventory surface. The first query looks for installed instances of Atera, ScreenConnect, MeshAgent, and other RMM packages mentioned in the research. This inventory helps the analyst prioritize hosts that already host management software, which the actor may misuse or supplement with their own instances.

Next, the hunt moves into a parallel corroboration phase across process and network surfaces. One branch searches for the execution of RMM agents. It specifically looks for renamed binaries by checking the original filename property and searching for common naming patterns in the command line. This allows the analyst to find MeshAgent or Atera even if the intruder renamed the executable to something innocuous.

The second branch of the corroboration phase examines network connections. It looks for outbound traffic targeting known tunnel providers like ngrok or trycloudflare. It also flags internal network discovery activity, such as outbound RDP connections or the use of scanning tools like NetScan and Nmap. This correlates the presence of a tool with its actual behavior on the wire.

Finally, an analyst or automated agent triages the results. They evaluate the correlated data to distinguish between legitimate IT administration and unauthorized intruder activity. If the hunt confirms a malicious presence, the playbook provides steps for immediate endpoint isolation and a manual forensic review of the entry point.

### What this hunt cannot see

This hunt relies on comprehensive telemetry. If endpoint agents do not cover specific servers or admin jump hosts, the intruder can establish persistence on those unmanaged assets without detection. Additionally, the hunt may miss ephemeral discovery processes. If an adversary runs a quick scan and the process terminates between telemetry collection intervals, the activity might not appear in the process activity surface.

### How to run it

This hunt is provided as an open `hunt.md` playbook. You can import this file into Huntbase or any other `hunt.md`-aware runtime to execute the queries across your estate. The playbook includes parameters for lookback windows and host scoping to help you tailor the search to your environment.
