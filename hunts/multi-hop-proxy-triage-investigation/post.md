# Hunting for Multi-hop Proxies and Tunneling in Cloud Environments

### Why this hunt

The shift toward agentic security operations highlights a persistent challenge: triage at scale. In the recent article [Inside Elastic InfoSec's agentic SOC: How we cut AI agent LLM calls by 60%](https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale), the focus was on optimizing how AI agents process security data. This hunt applies that same logic to a high-noise area: multi-hop proxies and tunneling. Adversaries frequently use tools like Ngrok or Tor to bypass traditional firewall restrictions and mask their C2 infrastructure. Because these tools are also used legitimately by developers, a simple detection often leads to alert fatigue. This hunt provides the context needed to make a definitive call.

### The Hypothesis

We hypothesize that an adversary has established a persistent connection to the environment using a multi-hop proxy. This activity likely follows a successful external authentication event and manifests as rare process execution on a public-facing or developer-owned cloud instance. By stacking DNS requests, network connections, and process lineage, we can identify the specific point where a legitimate session was co-opted or an unauthorized tool was introduced.

### How the Hunt Flows

The hunt begins with DNS scoping. We look for hosts resolving known tunneling domains or exhibiting DNS tunneling patterns, such as high-frequency TXT or CNAME lookups and long subdomains. This narrows our focus from the entire fleet to a subset of hosts showing the primary indicator of a tunnel.

Next, we pivot into authentication and process context. For each scoped host, we examine the last 24 hours of successful sign-ins from non-RFC1918 IP addresses. We then analyze process ancestry, filtering out common "noisy" binaries like shells, compilers, and containers to find rare binaries with low prevalence across the environment. This helps distinguish a developer using a tool from a web server process spawning a proxy binary.

Finally, we enrich the findings with cloud metadata and direct network telemetry. We look for outbound TCP connections to common proxy ports like 9001 or 9030. This multi-surface approach—DNS, Auth, Process, and Network—mirrors how an automated agent triages a complex case before handing it off to a human analyst.

### Blind Spots

This hunt has two primary limitations. First, it relies on DNS telemetry for initial scoping. Tunnels established via direct IP connections—bypassing DNS entirely—will not be caught in the first phase. Second, visibility depends on complete endpoint coverage. If the tunnel is established on an unmanaged host or a container without process monitoring, the hunt will only see the network side of the activity, making process-based triage impossible.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. This format is designed to be portable and can be imported into Huntbase or any other runtime environment that supports the `hunt.md` standard. The playbook uses structured queries to walk through the phases of scoping, enrichment, and triage, providing a clear audit trail for the investigation.
