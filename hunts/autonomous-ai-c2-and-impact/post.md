# Hunting Autonomous AI Malware and LLM-Driven Command-and-Control

### Why Now

Recent research from [Talos — Trust and the enticing consultancy offer](https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/) details a shift in adversary tradecraft. The CLOSEDQUORUM implant demonstrates how attackers now delegate C2 orchestration to Large Language Models (LLMs). This autonomous behavior allows malware to adapt in real-time without direct human operator input, often concluding in high-speed encryption via Qilin ransomware. We published this hunt to help teams identify the intersection of AI infrastructure usage and rapid file-system impact.

### The Hypothesis

An adversary is using autonomous AI-driven malware to orchestrate command-and-control decisions via LLM API calls, followed by high-volume data encryption for impact.

### How the Hunt Flows

The first phase identifies suspicious process leads. The query searches process activity for specific CLOSEDQUORUM hashes or processes running in a fileless state. This step provides the initial anchors for the hunt, focusing on hosts where an implant might already be resident in memory or executing from a known malicious file.

Once a lead is established, the hunt fans out to corroborate two distinct behaviors: network orchestration and file-system impact. One branch looks for rare DNS queries to AI API endpoints like OpenAI, Anthropic, or Groq. It filters out common fleet usage, highlighting only those hosts where LLM communication is an anomaly. The second branch monitors for high-volume file activity, specifically identifying processes that modify or touch more than 100 files in a short window.

The final phase uses an agent to weigh these disparate telemetry sources. By combining the process context, the rare DNS destinations, and the file modification counts, the hunt differentiates between a developer using AI tools and a malicious agent executing an autonomous C2 loop. This correlation is why the logic is a hunt rather than a simple detection; a single rule on any one of these surfaces would likely produce too many false positives to be actionable.

### Blind Spots

This hunt relies on endpoint process and DNS visibility. If the AI-driven processes run on unmanaged hosts, the activity will only appear as encrypted traffic at the network level, which is difficult to attribute without socket telemetry. Additionally, without TLS inspection for AI API endpoints, we cannot see the specific prompts or instructions received from the LLM. We only see that a connection occurred, not the content of the orchestration.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. This format is designed for portability and can be imported directly into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the SQLite-based queries for process, DNS, and file surfaces, alongside the logic for triage and host isolation.

Find the playbook on our GitHub repository or import the raw markdown into your hunt platform to begin scoping for autonomous AI threats.
