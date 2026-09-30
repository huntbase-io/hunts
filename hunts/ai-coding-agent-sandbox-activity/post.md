# Hunting AI Coding Agent Activity in Production Codebases

### Why this hunt matters

The recent analysis by Huntress, [Fighting AI Slop in Production Codebases](https://www.huntress.com/blog/claude-fable-api-recall), highlights a new challenge for engineering teams: the rapid introduction of automated, often unvetted code via AI coding agents. While these tools promise efficiency, they can bypass traditional code review and introduce insecure patterns if deployed without oversight. This hunt provides the visibility needed to track these agents as they operate within your environment.

### Hypothesis

An unauthorized user runs an AI coding harness to modify production codebases, using automated testing to validate the changes and communicating with external LLM APIs to generate and refine code.

### How the hunt flows

The hunt begins by identifying Docker-capable infrastructure. Because agentic coding harnesses often require isolated environments to execute and test code safely, they frequently provision local containers. The first query scopes the environment to hosts running Docker, providing the necessary sandbox capability. This narrows the investigation to endpoints where automated code manipulation is most likely to occur.

Once the scope is set, the hunt searches for the operational footprint of the harness itself. It looks for rare or unauthorized process names and command-line keywords associated with tools like Lemans or Claude-Code. Simultaneously, it monitors for the modification of configuration files such as CLAUDE.md or specific skill directories. These files serve as the 'brain' for the agent, containing the instructions and project rules the LLM follows during the session.

After establishing that a harness is active, the hunt correlates subsequent operational activity. It searches for automated test validation runs, specifically targeting RSpec executions that follow the modification of codebase artifacts. An automated agent typically runs tests immediately after a change to verify its work. The hunt then joins this endpoint activity with DNS lookups to known LLM providers like Anthropic or OpenAI, confirming the agent's external communication loop.

This workflow is structured as a hunt rather than a single detection because the individual actions—running Docker, updating markdown files, or executing RSpec—are common developer tasks. A single detection rule would generate excessive noise. By treating these events as a session-based sequence, an analyst can weight the cumulative evidence to identify unauthorized automation that mimics human behavior.

### Blind spots and limitations

This hunt has two primary blind spots. First, it relies on snapshots of host activity. If an adversary runs a short-lived container that finishes between inventory intervals, the initial sandbox provisioning may be missed. Second, while the hunt identifies the destination of network traffic, it cannot see the content of the LLM prompts. Without TLS inspection, we cannot determine if proprietary source code or sensitive credentials were sent to the LLM provider.

### How to run this hunt

This hunt is packaged as an open hunt.md playbook. You can import this file directly into Huntbase or any hunt.md-aware runtime to begin execution. The playbook includes the specific KQL and SQLite queries required for each phase. Analysts should review the initial process baseline to filter out sanctioned development workstations before proceeding to the deeper correlation steps.
