# Hunting Storm-3068 Pipeline Code Execution and Network Tunneling

Microsoft recently detailed Storm-3068's shift beyond initial access into deeper infrastructure in [Beyond source code: A path to the keys to the kingdom](https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/). The adversary targets the build process itself, treating pipelines as a vehicle for credential harvesting and network persistence.

### The Hypothesis
An adversary modifies build pipelines to execute malicious code on agents. This execution allows them to deploy RMM tools and establish tunnels for exfiltrating Kubernetes credentials and secrets.

### How the Hunt Flows
The hunt begins by identifying the attack surface. An initial query scans software inventories to list hosts running Kubernetes or DevOps agent software, such as vsts-agent or Docker. This narrows subsequent searches to the actual build infrastructure to reduce noise from general-purpose workstations.

Once scoped, the hunt launches three parallel queries to find evidence of compromise. On the host, the analyst looks for the execution of Atera or Chisel, checking both process names and original file names to catch renamed binaries. At the same time, a network query baselines outbound connections to identify rare external endpoints visited by three or fewer hosts. Finally, the hunt audits cloud logs for Azure DevOps API operations, specifically pipeline creation and updates.

An analyst then correlates these three surfaces. The objective is to find a temporal alignment between a pipeline modification and the execution of a tunneling tool on the corresponding build agent. This correlation distinguishes malicious code injection from legitimate developer use of similar utilities, making it a hunt rather than a simple detection rule for binaries.

### Blind Spots
The hunt has specific limitations. If the adversary executes scripts within ephemeral containers that disappear before telemetry collection, the activity may go unseen. Furthermore, standard Azure DevOps audit logs often show that a pipeline changed but do not provide the Git diff. A manual forensic review of the YAML history is usually necessary to confirm the exact harvesting logic used by the adversary.

### How to Run This Hunt
This hunt is a `hunt.md` playbook. Analysts can import it into Huntbase or any hunt.md-aware runtime. It uses SQLite-based queries targeting process, network, and cloud API surfaces. The parameters allow you to adjust the lookback window and the specific RMM tools you want to monitor based on your own threat intelligence.
