# Hunting for Chrysalis DLL Side-Loading in Bluetooth Services

### Why now

Attackers continue to use DLL side-loading to bypass security controls by piggybacking on trusted, signed binaries. Recent research from Elastic Security Labs in [Benchmarking the Agentic SOC](https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc) highlights how automated workflows can evaluate complex intrusion patterns like the Chrysalis loader. We designed this hunt to find the structural evidence of that specific side-loading technique.

### The hypothesis

An attacker achieves code execution by placing a malicious DLL in the same directory as a legitimate Bluetooth service. The application then exploits the Windows search order to load the malicious code instead of the intended system library, effectively bypassing standard system directory protections and execution policies.

### How the hunt flows

The first phase scopes the environment to find active targets. The query identifies every host currently running the legitimate Bluetooth service executable. This initial filter reduces the data set before we move into more intensive behavioral analysis.

In the second phase, the hunt performs a parallel fan-out to gather evidence. One branch searches for module load events where the DLL resides in the same directory as the service executable, specifically excluding the C:\Windows\System32\ path. A second branch checks for known malicious file hashes associated with the Chrysalis campaign to provide immediate confirmation if a known loader is present.

The third phase uses an automated agent to triage the results. The agent evaluates the directory proximity of the loaded DLLs. It prioritizes the structural relationship between the executable and the library over the specific filename, as attackers can easily rename files to evade simple detections. The agent then assigns a verdict for each host based on the rarity of the module across the fleet.

Finally, the hunt routes the findings for response. If the agent confirms a side-loading intrusion, the playbook prompts for host isolation and forensic preservation of the malicious DLL for further analysis.

### What the hunt cannot see

This hunt relies heavily on module load visibility. If the environment lacks Sysmon EID 7 or equivalent telemetry, the side-loading event remains invisible because the process appears to start normally. Additionally, some legitimate applications ship with their own libraries in the same folder. This may create noise that requires an analyst to tune the results by excluding known-good, third-party application paths that do not match the expected Bluetooth service profile.

### How to run it

We provide this hunt as an open `hunt.md` playbook. You can import it into Huntbase or any hunt-aware runtime to execute the logic against your telemetry. The playbook handles the transitions between scoping, fanning out for evidence, and agent-led triage automatically.
