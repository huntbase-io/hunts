# Hunting Agentic Swarms through Execution Velocity and HTTP Iteration

### Identifying the Autonomous Signature

Traditional detection logic often focuses on specific command strings or known malicious file paths. However, as tradecraft evolves toward agentic swarms—automated frameworks that reason and adapt in real-time—the most reliable signal becomes the timing and velocity of the activity itself. This hunt identifies those signatures, specifically looking for the high-speed iterative loops used by autonomous systems to gain persistence.

Cisco Talos recently detailed these behaviors in their research, [The Great Escape: Tradecraft insights from an agentic swarm](https://blog.talosintelligence.com/the-great-escape-tradecraft-insights-from-an-agentic-swarm/). Their analysis highlights how multi-agent AI systems, such as ARTEX, use rapid bursts of execution to refine their payloads and establish footholds.

### The Adversary Agent

Autonomous agents operate on web-facing infrastructure using rapid reasoning bursts in process telemetry and high-speed iterative HTTP status transitions during web shell deployment. The adversary does not type commands at a human pace; instead, the agentic framework launches multiple processes in sub-second intervals to test environment variables and iteratively adjusts its web shell payloads based on immediate HTTP error responses.

### Scoping the Estate

The hunt begins by narrowing the search to hosts running known web server processes. The first phase lists every host running services like Nginx, Apache, or IIS. By focusing on the web surface, the analyst isolates the systems most likely to face the automated probing and persistence attempts characteristic of these swarms.

### Burst Analysis and Network Iteration

Once the scope is set, the hunt runs two parallel queries to gather independent timing signals. The first query identifies reasoning bursts by finding instances where more than ten process launches occur within a single minute on a scoped host. These bursts represent the agent processing its environment and deciding on its next move. This frequency typically exceeds what standard application behavior or human administrators produce.

Simultaneously, the second query looks for iterative HTTP status transitions. It identifies source IPs that hit multiple paths on a single server while transitioning through various HTTP status codes, such as a sequence of 404s and 403s followed by a 200. This pattern indicates an automated agent refining a web shell payload in real-time. The hunt then moves to a triage phase where an analyst or automated agent weighs these two signals together to determine if the activity represents a coordinated swarm.

### Visibility and Blind Spots

This hunt relies heavily on high-fidelity timing and metadata. It faces two primary blind spots. First, sensor rate-limiting on the endpoint may cause an EDR to drop events during high-frequency bursts to protect system performance. If the sensor drops 90 percent of events, the signature of the reasoning loop is lost. Second, if the network activity occurs over encrypted channels without TLS inspection, the specific HTTP status codes and paths required for the iteration signature remain invisible to network-level sensors.

### How to Run the Hunt

This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any hunt.md-aware runtime. Because it correlates high-frequency process bursts with the automated refinement of payloads across many paths, it functions as a hunt rather than a static detection. An analyst must review the resulting timing clusters and status sequences to distinguish between a complex deployment script and a malicious multi-agent framework.
