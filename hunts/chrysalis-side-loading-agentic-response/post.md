# Chrysalis DLL Side-Loading and Agentic Response

The recent research from Elastic Security Labs, [Benchmarking the Agentic SOC](https://www.elastic.co/security-labs/threat-command/llm-benchmarking-agentic-soc), explores how LLM-driven agents handle specific intrusions like the Chrysalis backdoor. We have developed a hunt based on this scenario to identify the persistence technique and the subsequent behavioral patterns of automated response agents.

The hypothesis assumes an adversary has deployed the Chrysalis backdoor via DLL side-loading. Specifically, we are looking for the legitimate `BluetoothService.exe` loading a malicious `log.dll`. This technique often bypasses standard detections because the parent process is a trusted system utility.

The hunt begins with host scoping. We identify Windows servers within the environment, specifically those following naming conventions like `srv-win-defend-01` seen in the research. This step ensures we are looking at the right telemetry sources before executing more expensive behavioral queries.

Following scoping, the hunt moves to side-loading discovery. We monitor module load activity for instances of `log.dll` being loaded by `BluetoothService.exe`. In typical Windows environments, this specific combination is rare and highly indicative of a search-order hijacking or side-loading attempt (T1574.002).

To confirm the nature of the event, we conduct a parallel triage across three independent surfaces. First, we look for file activity involving the EICAR test hash, which was used in the research as a stand-in for the malicious payload. Simultaneously, we monitor DNS activity for lookups to VirusTotal or Slack. These domains are frequently used by both automated SOC agents and modern malware for orchestration and hash verification.

The final phase of the flow examines HTTP orchestration activity. We look for specific API calls directed at Slack or Elastic Case management. This allows us to see if the side-loading event has already triggered an automated response. By correlating the side-loading event with these API calls, we gain a full view of the incident lifecycle, from execution to automated triage.

There are two primary blind spots to consider. First, if Sysmon Event ID 7 or equivalent module load telemetry is not enabled on your Windows fleet, the primary execution indicator (the loading of `log.dll`) will be invisible. Second, many of the orchestration indicators rely on HTTP path visibility. If you lack SSL inspection at the proxy level or endpoint-level HTTP monitoring, you may see the connection to Slack or Elastic, but not the specific API calls that indicate case creation or orchestration.

This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime. This format allows you to run the queries, manage the parameters like lookback windows, and follow the triage logic directly within your existing security workflow.
