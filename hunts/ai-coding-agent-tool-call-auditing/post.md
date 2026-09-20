# AI Coding Agent Tool-Call and Behavior Audit

### Why This Hunt

AI coding agents act as automated operators on the endpoint. They often execute commands and access files within the developer's user context, which can mask malicious activity. This hunt follows the research published by Elastic Security Labs in [13 million tool calls: auditing every AI coding agent action with Elastic Agent](https://www.elastic.co/security-labs/blog/ai-coding-agent-audit-cursor-hooks). As these agents gain the ability to call tools and modify environments, defenders need a flight-recorder audit to reconstruct agent intent.

### The Hypothesis

An AI agent operating under developer credentials is executing rare shell commands, accessing sensitive configuration files, or communicating with third-party Model Context Protocol (MCP) servers without explicit developer intent. This behavior suggests either a model hallucination or a prompt-injection attack where the agent is steered toward discovery or exfiltration.

### How the Hunt Flows

The hunt begins by scoping the estate. The first query identifies every host running the Cursor IDE or its headless agent through software inventory surfaces. This defines the boundaries for subsequent behavioral analysis.

Next, the hunt examines process activity in two parallel streams. The first stream establishes a timeline of agent launches. The second stream baselines shell commands spawned by the agent. By stack-counting these commands across the fleet, the hunt highlights rare outliers, such as unexpected curl commands or local discovery scripts that deviate from the standard development lifecycle.

If rare commands appear, the hunt pivots to impact analysis. It queries file activity for access to sensitive paths like SSH keys, .env files, or git configurations. Simultaneously, it audits network connections to identify outbound traffic to non-standard ports or external hostnames that might represent rogue MCP server communication.

An analyst then reviews the consolidated findings. They determine if the combination of rare shell execution and sensitive file access constitutes a legitimate developer task or a malicious steering event.

### Blind Spots

This hunt has two primary limitations. First, it lacks the "why" behind an action if the host does not have local hook telemetry enabled. While we see the shell command, we cannot see the model's internal reasoning without the tool-call logs described in the source research. Second, Cursor only loads hook configurations at startup. Hosts that have not restarted since a policy change will appear compliant but will not generate the necessary telemetry.

### How to Run This Hunt

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries and manage the triage workflow. The playbook includes parameters to customize the lookback period and define your own list of sensitive file extensions.
