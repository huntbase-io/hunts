# Hunting for Automated AI-Driven Phishing Reconnaissance Workflows

### Why This Hunt Now

Recent research from Huntress, [An attacker blunder gave us a look into their operations](https://www.huntress.com/blog/rare-look-inside-attacker-operation), detailed a rare look into how modern attackers are operationalizing legitimate SaaS tools. The incident revealed an attacker using a combination of automation platforms, AI content generators, and infrastructure search engines to streamline their reconnaissance. This hunt focuses on identifying the telemetry footprints of these 'AI-driven' workflows within your environment.

### The Hypothesis

We hypothesize that attackers are leveraging platforms like Make.com for workflow orchestration and AI assistants like Toolbaz or DocsBot for generating localized phishing lures. These activities, while using legitimate services, produce distinct DNS and web patterns. When combined with specific infrastructure discovery tools like Censys, these patterns deviate significantly from typical corporate usage, marking the 'automated-targeting-recon' stage of an operation.

### How the Hunt Flows

The hunt begins with a scoping phase focused on DNS activity. We look for resolutions to a curated list of automation and AI domains, such as `make.com`, `toolbaz.com`, and `docsbot.ai`. While some of these services might be common in marketing or sales departments, they are often outliers in other business units. This provides the initial list of candidate hosts.

Next, the hunt enters a parallel corroboration phase. On one side, we perform fleet-wide prevalence stacking to isolate hosts using these tools in isolation (rarity). On the other side, we examine HTTP telemetry for specific keywords related to reconnaissance and phishing toolsets, such as searches for 'Censys', 'Evilginx', or translation-heavy activity that suggests lure localization.

Finally, the hunt correlates these signals. An agent-driven triage step evaluates the overlap: a host that is resolving rare AI generation domains while simultaneously performing infrastructure-related web searches is flagged for manual review. This multi-layered approach helps filter out legitimate business automation while surfacing the specific tool-chaining behavior characteristic of modern threat actors.

### Blind Spots and Limitations

Visibility is heavily dependent on the visibility of network traffic. Because most of these platforms use HTTPS, we are limited to observing DNS queries and, where applicable, unencrypted URL metadata or search queries. Without full TLS inspection at the gateway, we cannot see the specific prompts or payloads sent to AI assistants, meaning we cannot distinguish between a legitimate request and the generation of a malicious lure based on content alone.

Furthermore, this hunt focuses on public SaaS platforms. If an attacker uses self-hosted automation (like n8n) or local LLMs running on compromised workstations, they will not trigger the domain-based scoping queries. This hunt should be paired with process-level monitoring for common automation binaries.

### Running the Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime capable of parsing `hunt.md` formats. It utilizes SQLite-based queries against standardized DNS and HTTP tables. Because the tools targeted are often legitimate, this is a hunt—not a high-fidelity detection—and requires an analyst to weigh the business context of the flagged hosts.
