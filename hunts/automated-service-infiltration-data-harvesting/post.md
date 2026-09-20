# Hunting Autonomous AI Agent Infiltration and Internal Reconnaissance

### Why now

Recent investigations by Unit 42 in [An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/) demonstrate how adversaries use autonomous agents to compress the attack lifecycle. AI agents handle reconnaissance, vulnerability research, and internal mapping at speeds that traditional detection rules often miss. This hunt targets the specific behavioral loop of an agentic breach.

### The hypothesis

An intruder uses autonomous AI agents to breach public web services and map internal microservices while harvesting credentials. This process leaves behind unique filesystem artifacts, such as Markdown-based communication files, and generates high-frequency network reconnaissance patterns as the agent discovers the environment.

### How the hunt flows

The hunt begins by narrowing the attack surface. It queries software inventory data to identify hosts running common web service or API packages like Nginx, Apache, or Tomcat. These hosts represent the most likely entry points for an agent-driven exploit.

Once the scope is set, the hunt executes two parallel checks. The first looks for filesystem artifacts characteristic of AI frameworks. It searches for the creation of Markdown files like `plan.md` or `task.md` and identifies localized Python cache directories created in non-standard paths. These files represent the agent passing context between execution loops.

Simultaneously, the hunt analyzes internal network traffic. It looks for bursty HTTP activity where a single source endpoint requests a high diversity of URL paths in a short window. This pattern indicates an automated agent mapping internal microservices or API endpoints.

In the final phase, an analyst or automated agent triages the findings. The hunt correlates the presence of orchestration files with the bursty network traffic on the scoped web hosts. A positive match suggests an active, autonomous intrusion loop requiring immediate isolation and artifact analysis.

### What the hunt cannot see

This hunt relies on an accurate software inventory. If an adversary deploys transient containers or uses software not tracked by package managers, the initial scoping query may miss the beachhead. Additionally, if internal HTTP logs are truncated or if the agent uses non-standard ports not monitored by existing proxies, the reconnaissance signal will be incomplete.

### How to run it

This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any hunt.md-aware runtime. The playbook uses SQLite-based queries against standard telemetry tables, allowing you to adjust lookback periods and the specific list of agent-related filenames as new AI frameworks emerge.
