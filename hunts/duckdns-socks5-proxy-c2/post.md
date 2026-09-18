# Hunting for DuckDNS Infrastructure and SOCKS5 Proxy C2

### The Context
Recent research from Unit 42, titled [Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America](https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/), highlights a specific set of infrastructure utilized for SOCKS5 tunneling and LLM-assisted command and control. The attackers leverage Dynamic DNS (DDNS) providers to rotate their nodes frequently, often using predictable naming conventions and management ports like TCP 3000 for NextChat. This hunt design targets the network and infrastructure footprint of these clusters.

### The Hypothesis
An adversary is using Dynamic DNS subdomains, specifically those with an 'm-doxa' prefix on the duckdns.org domain, to facilitate SOCKS5 tunneling. This activity is expected to coincide with rare DNS lookups and outbound connections to port 3000, signifying management of AI-assisted exfiltration or staging tools.

### The Hunt Flow
The first phase focuses on scoping the estate for known infrastructure patterns. Using DNS activity logs, the hunt identifies any host resolving subdomains matching the specific 'm-doxa' naming convention. This provides a high-priority list of endpoints for further investigation into active sessions.

Once potential hosts are identified, the hunt initiates three parallel paths of corroboration. The first path checks for active network connections to known staging IPs or any destination on port 3000. The second path baselines Dynamic DNS usage across the fleet to surface rare DuckDNS subdomains that do not match the known prefix but exhibit similar low-prevalence behavior. The third path inspects certificate inventory for artifacts matching the naming convention, providing a secondary identity-based signal.

In the final phase, an automated triage step weighs these findings. A host demonstrating both rare DDNS resolutions and connections to unauthorized management ports is considered a high-confidence match for the campaign. The hunt includes logic for host isolation if a malicious verdict is reached, ensuring a direct path from discovery to containment.

### Blind Spots and Limitations
This hunt relies heavily on the visibility of network telemetry. If outbound traffic on port 3000 is not logged at the perimeter or the endpoint, the AI management component of the campaign may go unnoticed. Additionally, the certificate inventory surface is often snapshot-based; if attackers rotate certificates between inventory scans, the artifact may be missed. Finally, while certificate matches suggest the presence of rogue infrastructure, attributing them to a specific host requires associated DNS or network telemetry.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any security runtime that supports the `hunt.md` format. Because it relies on behavioral patterns like DNS prevalence rather than just static indicators, it is designed to be run on a recurring basis to catch rotated infrastructure.
