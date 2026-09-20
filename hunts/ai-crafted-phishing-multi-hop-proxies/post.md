# Hunting AI-Crafted Phishing and Multi-Hop C2 Networks

### Why This Hunt Matters
AI-generated phishing scales rapidly. Adversaries now use automated agents to craft highly personalized emails that bypass traditional signature-based filters. Once a user clicks, the resulting payloads often attempt to hide their command-and-control (C2) traffic through multi-hop proxy networks or Tor. We developed this hunt based on concepts from the Red Canary article [Train, triage, repeat: The AI agent changing how we fight phishing](https://redcanary.com/blog/threat-detection/phishing-ai-agent/) to find the behavioral trail these campaigns leave behind.

### The Hypothesis
An adversary uses AI-generated phishing to deliver payloads that establish command-and-control via multi-hop proxy networks. They disguise traffic through Tor entry points or private relay nodes to evade standard network perimeter controls.

### How the Hunt Flows
The hunt starts with process telemetry. It checks if email clients or browsers spawn child processes in AppData, Public, or ProgramData directories. This identifies potential payload execution shortly after a user interacts with a link or attachment. The query specifically looks for processes like Outlook, Chrome, or Edge acting as parents to executable code in user-writable paths.

An agent reviews these executions to assess the lead. It looks for high-sentiment phishing indicators or downloader patterns in command lines. This gate ensures the hunt only runs expensive network and DNS queries on hosts showing high-risk activity.

If the agent finds a suspicious lead, the hunt branches into a parallel investigation. One query searches for rare outbound connections to Tor entry points (ports 9001, 9050, 9150) or unusual high ports. A second query checks DNS logs for domains matching known phishing patterns or AI-generated sentiment keywords, specifically filtering for the process names identified in the first step.

The final triage synthesizes the process, network, and DNS evidence. An agent evaluates the entire chain to confirm whether a suspicious execution led to a functional multi-hop C2 channel. This correlation distinguishes a successful intrusion from a benign automated download.

### Blind Spots and Limitations
This hunt relies on endpoint visibility. If a host lacks EDR coverage, it will not report the process spawns that trigger the gated flow. On the network side, the hunt may miss traffic using Tor bridges or private relays that operate over common ports like 443, as these look like standard web traffic and bypass the rare-port prevalence filters.

### How to Run It
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It requires hb_process_activity, hb_network_connection, and hb_dns_activity telemetry. Use the provided parameters to tune the lookback window and phishing domain lists based on your current threat intelligence. This is a hunt, not a detection: it uses an agent to weigh the intent and context of the entire chain rather than flagging every Tor connection.
