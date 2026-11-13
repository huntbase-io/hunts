# Hunting AI Agent Post-Training Backdoor Execution

### Why this hunt
Microsoft recently detailed a supply chain risk in [Trained to betray: How post-training supply chain attacks hijack coding agents](https://www.microsoft.com/en-us/security/blog/2026/11/12/trained-to-betray-how-post-training-supply-chain-attacks-hijack-coding-agents/). As teams integrate AI coding assistants and terminal agents into their daily workflows, they introduce a new execution vector. If an adversary poisons a model checkpoint or a fine-tuning dataset, they can bake malicious triggers directly into the agent logic.

### Hypothesis
An adversary compromises an AI agent supply chain via poisoned fine-tuning data or model checkpoints. This causes the agent to execute unauthorized shell commands when triggered by routine user requests, effectively providing a persistent backchannel that ignores traditional input filters.

### How the hunt flows
The hunt begins by building an inventory of hosts running AI agent frameworks. The first query searches software inventory for packages like LangChain, Llama, or OpenAI. This step identifies the relevant systems and provides necessary context for the process activity that follows.

The second phase identifies the execution lead. The hunt monitors Python, Node.js, and VS Code processes for the spawning of shell utilities such as curl, wget, or bash. Because coding agents often use these tools legitimately, the hunt gates these results for triage to determine the intent of the command.

If a command appears suspicious, the hunt pivots into parallel corroboration steps. One path stack-counts the command lines across the entire fleet to find rare, host-specific tool calls that match known poisoning patterns. At the same time, the hunt examines network activity for outbound HTTP requests to domains frequently used to host malicious scripts, such as GitHub Gists or Pastebin.

In the final phase, an analyst synthesizes the evidence. By combining the framework context, the rarity of the command, and the presence of suspicious network fetches, the hunter can confirm whether a model is backdoored.

### What the hunt cannot see
This hunt has three primary blind spots. First, if endpoint telemetry misses the parent process command line, we cannot easily differentiate an agent-spawned shell from a shell opened by a human user. Second, a poisoned agent might use a custom library to fetch payloads over encrypted channels, which can bypass standard proxy or HTTP logging. Finally, this hunt does not audit the integrity of the model files themselves; configuration-based attacks that point to malicious Model Context Protocol (MCP) servers require separate file-integrity monitoring.

### How to run it
This hunt is packaged as a `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the `hunt.md` format. The playbook uses SQLite-based queries against standard telemetry surfaces and provides an automated triage flow to reduce the burden of manual review.
