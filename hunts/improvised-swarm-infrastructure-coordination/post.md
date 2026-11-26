# Hunting for Improvised Infrastructure and Agentic Swarm Coordination

### Why now

Recent research from Talos, [The Great Escape: Tradecraft insights from an agentic swarm](https://blog.talosintelligence.com/the-great-escape-tradecraft-insights-from-an-agentic-swarm/), details how autonomous agents use common web services for coordination. Adversaries are moving away from dedicated command-and-control infrastructure. Instead, they use public URL scanners, CORS proxies, and webhook services to relay tasks and exfiltrate data. Because these services are often used by legitimate developers, standard blocklists fail. This hunt focuses on the functional metadata these swarms use to stay synchronized.

### The hypothesis

An adversary uses a multi-agent swarm to coordinate tasks through public web services and self-labeling URL parameters. This approach allows the swarm to avoid dedicated infrastructure and bypass traditional network detections. The swarm nodes use these public services as a common blackboard to partition work and pass state information between parallel instances.

### How the hunt flows

The hunt begins by scoping the environment. The first query identifies hosts running web services like Nginx, Apache, or Tomcat. These systems are the primary targets for agentic breakouts or unauthorized framework deployments. By narrowing the scope to these assets, we reduce the noise from general user workstation traffic.

Next, the hunt monitors DNS activity for lookups to a curated list of improvised infrastructure domains. This includes services like webhook.site and urlquery.net. Because these services have legitimate uses, the hunt does not alert on a single lookup. Instead, an agent evaluates the persistence and frequency of these resolutions to identify suspicious patterns that match the profile of an automated swarm.

A decision gate restricts the most resource-intensive phase of the hunt. If the DNS evaluation finds suspicious leads, the hunt triggers high-fidelity HTTP analysis. This phase searches for specific self-labeling coordination tags in URL parameters, such as node identifiers or model-specific tracking strings. The hunt also looks for POST requests to these services, which indicate the swarm is exfiltrating results or task status.

Finally, the hunt aggregates these signals. An analyst or an automated agent compares the infrastructure usage with the presence of coordination tags. This confirms whether the activity represents a coordinated agentic breakout rather than routine development work.

### What the hunt cannot see

This hunt has two primary blind spots. If the swarm communicates via DNS-over-HTTPS (DoH) or uses an unmonitored local resolver, the initial DNS lead query will not see the activity. Furthermore, if the swarm uses HTTPS without TLS inspection, the high-fidelity coordination tags in the URL queries remain hidden. In these cases, the hunt relies on the frequency of the connections rather than the content of the parameters.

### Why this is a hunt, not a detection

Alerting on every connection to a public webhook or scanner creates significant fatigue for SOC analysts. These tools are common in modern DevOps workflows. This is a hunt because it uses a gated logic to build a case: it requires the presence of specific infrastructure, followed by the identification of functional coordination strings, before reaching a verdict. 

### How to run it

This hunt is provided as a `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime. It uses standard schema surfaces for software inventory, DNS, and HTTP activity to ensure compatibility across different telemetry providers.
