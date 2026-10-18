# Hunting Agentic Swarm Persistence and C2 Coordination

### Why This Hunt

The report One breach, please, and make no mistakes by Talos (https://blog.talosintelligence.com/one-breach-please-and-make-no-mistakes/) details how adversaries execute precise, rapid-fire compromises. When an intrusion moves at machine speed using autonomous agents, the time between initial access and impact shrinks. Traditional alerts for isolated events often fail to capture the coordination required for these swarms to operate. We published this hunt to find the collective footprint of agentic traversal and C2 coordination.

### The Hypothesis

An autonomous agent swarm maintains persistence through Active Directory GPO modifications while coordinating data theft via high-volume DNS beaconing and rapid file encryption. The swarm relies on automated, parallel actions that appear as bursts of activity across different telemetry surfaces.

### How the Hunt Flows

The hunt begins by scoping the environment for unauthorized modifications to Group Policy Objects or sensitive AD containers. The first query targets the hb_entity_management surface to find new or updated GPOs by unexpected service accounts or administrative principals. This identifies the mechanism the adversary uses for internal traversal and persistent access.

Next, the hunt executes a parallel scan of network and endpoint telemetry. One branch monitors the hb_dns_activity surface for high-frequency bursts of queries to a single domain. This identifies the transport layer for agent coordination or command-and-control heartbeats. Simultaneously, a second branch examines the hb_file_activity surface for processes interacting with an unusually large number of distinct files. This detects the rapid data staging or encryption typical of automated impact.

The final phase uses an agent to weigh the evidence. An analyst reviews the temporal overlaps between the GPO changes, the DNS volume, and the file bursts. Isolated administrative work might trigger one of these leads, but the correlation of two or more behaviors on the same host or user account indicates a coordinated intrusion.

### Blind Spots

This hunt has specific visibility limits. If the adversary uses DNS-over-HTTPS (DoH) for coordination, the hb_dns_activity surface does not capture the traffic. Additionally, the file activity detection requires 100% EDR coverage. A swarm targeting an unmanaged server segment leaves only the AD audit logs visible, potentially hiding the scale of the exfiltration or encryption phase.

### How to Run It

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the logic to scope the search to sensitive domain controllers and high-value servers, allowing you to tune the volume thresholds for your specific network baseline.
