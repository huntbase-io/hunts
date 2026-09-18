# Monitoring AI Coding Agents for Malicious Tool-Call Steering

The rapid adoption of AI coding agents has introduced a new 'automated operator' to the developer endpoint. Recent research from Elastic Security Labs, titled "13 million tool calls: auditing every AI coding agent action with Elastic Agent," highlights how these agents use tool-call hooks to interact with the underlying operating system. While these features drive productivity, they also provide a mechanism for adversaries to steer an agent into performing malicious actions via poisoned repositories or rogue Model Context Protocol (MCP) servers.

### The Hypothesis
We hypothesize that an adversary is successfully steering an AI coding agent to execute unauthorized shell commands or access sensitive files—such as .env files or private SSH keys—which are then exfiltrated to unauthorized third-party endpoints. Because developers frequently run shells and access config files, these actions often blend into the noise of a standard workstation. This hunt focuses on the specific parent-child relationship where the AI agent itself is the initiator of high-risk behavior.

### How the Hunt Flows
The hunt begins by identifying the inventory of AI-enhanced IDEs across the estate. We scope the analysis to binaries like Cursor and VS Code to establish which hosts are actively utilizing agentic features. This ensures our behavioral analysis is targeted and reduces the processing load on the telemetry provider.

Once scoped, the hunt executes three parallel audits across different surfaces. First, we examine process activity to find instances where an AI agent process spawns a shell (e.g., bash, powershell) to execute commands. Second, we stack-count file access events to identify rare reads of sensitive patterns like credentials or AWS configs initiated by these agents. Finally, we look for network outliers—connections made by the agent process to domains outside of known-good LLM providers like OpenAI or Anthropic.

In the triage phase, we correlate these signals. A single shell command might be a routine 'npm install' triggered by the agent, but a shell command followed by a rare sensitive file read and an outbound connection to an unknown IP indicates a high probability of malicious steering.

### Limitations and Blind Spots
This hunt relies on endpoint telemetry (hb_process_activity and hb_file_activity). If an AI agent is running on an unmanaged device, its activity remains invisible. Furthermore, without specialized hook logging, we cannot see the specific prompts or JSON payloads that steered the model; we only see the resulting side effects on the system. Identifying the root cause requires the manual review of local project files to find the 'poisoned' context.

### Running the Hunt
This hunt is provided as an open hunt.md playbook. It is designed to be imported into Huntbase or any markdown-aware hunt runtime. Practitioners should adjust the sensitive_patterns and common_llm_domains parameters to match their specific organizational environment before execution.
