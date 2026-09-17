# Hunting AI-Agent Orchestrated Perimeter Breaches and Internal Mapping

The Unit 42 report, [An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/), highlights a significant shift in adversary behavior. By leveraging agentic AI frameworks, attackers can automate the decision-making loop, compressing reconnaissance and initial access into hours rather than days. This hunt identifies the front-end of such an attack by looking for patterns of high-velocity automation that distinguish agentic behavior from human-driven intrusions.

The hypothesis is that an adversary using autonomous agents will leave a distinct technical footprint: rapid HTTP authentication state shifts (moving from failed to successful) followed immediately by parallelized internal microservice mapping and orchestration traffic to frontier AI model endpoints (LLM APIs).

The hunt begins by scoping the environment to externally facing web assets with known vulnerabilities. This reduces the telemetry volume for the subsequent phases. We focus on assets running common web servers like Nginx or Apache that serve as the likely entry points for the initial breach.

Next, we pivot to HTTP telemetry to detect rapid transitions from 401 (Unauthorized) to 200 (OK) status codes originating from the same source IP. While a single shift might be a user forgetting a password, a burst of failures followed by a success within a tight one-hour window suggests an automated credential-stuffing or vulnerability-exploitation loop characteristic of an AI agent.

To differentiate this from standard automated noise, the hunt simultaneously looks for internal discovery and outbound orchestration. We baseline internal network connections to identify hosts that suddenly begin mapping a high number of distinct internal targets. At the same time, we check DNS logs for queries to known AI model providers such as OpenAI, Anthropic, or Mistral. The presence of both signals on a host that just experienced an HTTP authentication shift provides high confidence that an autonomous agent is active.

There are two primary blind spots to consider. First, if your environment lacks long-term retention of full HTTP activity logs, you may miss the initial breach signal, especially since these attacks move so quickly. Second, without visibility into internal TLS traffic or mTLS logs, we can identify that internal mapping is occurring but cannot see which specific microservice functions or data endpoints the agent is successfully querying.

This is published as a hunt.md playbook. It is designed for import into Huntbase or any hunt.md-aware runtime. Because the individual signals involved—such as auth failures or internal network scans—frequently produce false positives in isolation, this playbook functions as a hunt to correlate these noisy events into a high-confidence lead.
