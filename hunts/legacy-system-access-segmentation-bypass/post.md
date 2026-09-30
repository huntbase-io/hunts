# Hunting Legacy System Access and Segmentation Bypass

### Why this hunt?

A recent report from Talos, "Securing the unpatchable in an age of AI-driven vulnerabilities" (https://blog.talosintelligence.com/securing-the-unpatchable-in-an-age-of-ai-driven-vulnerabilities/), explains how AI-driven discovery makes legacy OT systems more vulnerable. Many organizations maintain critical infrastructure that cannot be patched without significant downtime or risk to physical processes. This hunt provides a structured way to monitor the network boundaries around these assets. Traditional detection rules often fail because they alert on isolated events. A single web exploit attempt or a VPN login from a new location might get lost in the noise. This hunt correlates those events with actual internal movement. By focusing on the intent of the activity — moving toward isolated legacy segments — we can distinguish between background noise and a targeted intrusion.

### The Hypothesis

An adversary exploits unpatchable public-facing services or unauthorized VPN bridges to discover and laterally move toward isolated legacy OT assets.

### How the Hunt Flows

The hunt starts with a scoping phase. The first query identifies hosts with high-severity vulnerabilities or software versions marked as end-of-life. By joining vulnerability findings with device inventory, the hunt builds a specific target list for the subsequent steps. This step ensures the investigation focuses on the most at-risk systems.

Once the scope is clear, the hunt looks for evidence of initial access. It runs two parallel checks. The first identifies HTTP requests containing exploit patterns like directory traversal or shell commands targeted at the potential legacy interfaces. The second identifies successful VPN logins. The goal is to find where an adversary might have gained a foothold. An analyst reviews these events to identify specific beachhead hosts.

The hunt then pivots to internal network activity. It looks for discovery behavior, such as internal scanning or fingerprinting, where a single host connects to many internal targets or ports. Simultaneously, a dedicated query identifies segmentation violations. This checks for any traffic destined for legacy assets from source IPs that are not in the authorized administrative list.

The final stage correlates these phases. An analyst looks for a complete path: an exploit or suspicious login followed by internal scans and attempts to cross into a protected segment. If this chain is confirmed, the playbook provides actions to isolate the beachhead host and revoke active sessions. This correlation is why this is a hunt rather than a detection; it requires synthesizing multiple low-fidelity signals into a high-confidence verdict.

### Blind Spots

Visibility is the primary constraint. This hunt relies on network telemetry from endpoint agents or flow logs. If an adversary moves through a host without an agent or into a network segment without logging, the violation remains hidden. Furthermore, the hunt identifies the "what" but not the "success" of an exploit. Because it does not inspect deep packet payloads to see if a virtual patch blocked the request, an analyst must verify the results against IPS or NGFW logs.

### How to Run this Hunt

This hunt is provided as an open hunt.md playbook. It imports directly into Huntbase or any compatible hunt.md runtime. The design allows you to adjust the lookback period and specify your own authorized management IPs. Running this as a hunt allows for a more holistic view of the intrusion chain than a simple set of disconnected detection alerts.
