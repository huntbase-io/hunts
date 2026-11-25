# Hunting Malicious AI Agent and MCP Server Activity on Workstations

### Why now

Elastic Security Labs recently published a deep dive into AI agent security in their article, Elastic ships 143 detection rules for AI agents and LLM platforms (https://www.elastic.co/security-labs/blog/ai-security-detection-rules-coding-agents-mcp). As developers adopt tools like Cursor, Claude, and various MCP servers, the attack surface shifts toward the workstation. These agents run with the developer identity and access, making them a direct path to sensitive secrets if the agent context is subverted.

### The hypothesis

An intruder has compromised a developer workstation through a malicious MCP server or AI extension. The adversary uses this access to bypass safety checks, read local credentials, and establish persistence via OS-level startup mechanisms.

### How the hunt flows

The hunt begins by building an inventory of hosts running known AI coding tools or MCP server packages using the software inventory surface. This scoping phase identifies developer systems where these tools are present, even if they run as portable binaries rather than installed packages.

Next, the hunt analyzes process and file activity in parallel. The first pivot searches the process activity surface for AI agents launched with dangerous safety-bypass flags like --yolo or --dangerously-skip-permissions. Simultaneously, it queries the file activity surface to see if those same agent processes accessed sensitive files such as SSH keys, AWS credentials, or browser keychains. An analyst or automated agent evaluates these findings to determine if an agent context was likely hijacked.

If the early triage shows suspicious behavior, the hunt pivots to persistence surfaces across the entire host. It examines file writes to startup directories like LaunchAgents or rc.local, registry modifications to Run keys, and new scheduled jobs that involve AI agent binaries. This phase links the initial suspicious execution to evidence of long-term residency on the host.

Finally, the hunt provides a decision point for containment. If an analyst confirms the chain of bypass flags, secret access, and persistence, the workflow directs the isolation of the host to prevent further lateral movement or data exfiltration.

### What the hunt cannot see

This design has two primary blind spots. It cannot see activity on unmanaged developer machines that lack the required endpoint telemetry agent. It also lacks visibility into the specific prompt or poisoned README file that triggered a bypass; it monitors the resulting OS behavior rather than the LLM instruction history.

### How to run it

This hunt is a hunt.md playbook. You can import the logic into Huntbase or any hunt.md-aware runtime to execute the queries and manage the triage steps. It uses standard surfaces for process, file, registry, and scheduled job activity, making it compatible with most modern EDR telemetry sources.
