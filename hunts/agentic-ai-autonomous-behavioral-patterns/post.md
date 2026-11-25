# Hunting for Agentic AI Autonomous Behavioral Patterns

### Why now

Attackers now use autonomous AI agents to compress the attack lifecycle. A recent report from Unit 42, [Recent Trends and Tactics of Agentic AI Attacks](https://unit42.paloaltonetworks.com/autonomous-ai-agent-threat-campaigns/), describes adversaries handing off initial web shell access to AI agents. These agents operate at machine speed, performing reconnaissance and privilege escalation faster than human defenders can typically react. Traditional detections often miss these because the commands themselves may appear standard, but the volume and the reasoning behind them are distinctly non-human.

### The hypothesis

An autonomous AI agent is conducting an intrusion, evidenced by inhuman command velocity, structured section headers in shell output, and chain-of-thought reasoning comments within script telemetry.

### How the hunt flows

The first phase scopes the environment to identify Linux hosts vulnerable to specific kernel exploits like CVE-2024-1086. The adversary targets these systems for rapid, iterative privilege escalation. The hunt uses the `hb_vulnerability_finding` surface to prioritize hosts where an agent might attempt to compile custom exploits.

The second phase looks for the physical fingerprints of an AI operator. We query `hb_process_activity` to find parents launching hundreds of unique child processes in a tight window. Simultaneously, we search `hb_script_activity` for "chain-of-thought" markers like "thought:" or "reasoning:" and machine-readable section headers that agents use to parse their own progress.

Once the hunt identifies a suspicious velocity or reasoning marker, an analyst triages the host to confirm the agentic footprint. We then pivot to look for follow-on activity. This includes high-volume cloud API discovery calls in `hb_cloud_api_activity` and network connections to known GSocket or SSH tunneling relays in `hb_network_connection`.

Finally, the hunt synthesizes these stages into a verdict. If the evidence confirms an autonomous agent, the playbook triggers an isolation action to halt the attack before exfiltration begins.

### What the hunt cannot see

This hunt relies on EDR capturing full script contents and high-resolution timestamps. If the telemetry provider truncates large script blocks, we may lose the "reasoning" comments that distinguish an agent from a standard script. Furthermore, if process creation timestamps are rounded to the nearest second, the 1.4-second command gap characteristic of these agents becomes harder to differentiate from fast human activity or legitimate automation frameworks.

### How to run it

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes parameters for lookback windows and a pre-populated list of C2 infrastructure identified in the Unit 42 research. Use the scoping parameter to target internet-facing servers where web shells are the likely entry point.
