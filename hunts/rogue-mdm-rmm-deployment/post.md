# Hunting Unauthorized MDM Enrollment and Rogue RMM Persistence

### Why This Hunt Matters

Legitimate administration tools often provide the path of least resistance for attackers. Recent research by Huntress in their article, Managed for Malice: How Attackers Turn MDM into Remote Access (https://www.huntress.com/blog/attackers-turn-mdm-into-remote-access), describes a campaign where adversaries use social engineering to enroll devices into unauthorized Mobile Device Management (MDM) tenants. Once enrolled, the attacker has a privileged, trusted channel to deploy further tools like ScreenConnect. This hunt identifies the footprints left during enrollment and the subsequent deployment of rogue Remote Monitoring and Management (RMM) software.

### The Hypothesis

An adversary uses business-themed phishing lures, such as fake DocuSign or Microsoft Teams installers, to trick users into running an MDM enrollment package. This enrollment grants the attacker persistent, high-privilege access, which they immediately use to deploy a rogue RMM agent for long-term remote control and data exfiltration.

### Scoping the MDM Environment

The first phase identifies every host currently running MDM software associated with this campaign. The query checks the software inventory for Hexnode or Rippling agents. In many enterprise environments, these platforms are either standardized or entirely absent. Any appearance of these tools on a host where IT did not explicitly deploy them serves as the primary pivot point for the rest of the investigation.

### Identifying Early Signals

The hunt simultaneously looks for the social engineering lures and the registry changes that follow enrollment. One query monitors DNS activity for known lookalike domains used to host the fake installers. Another query stacks MDM-related registry keys across the fleet. We look for keys that appear on only a few hosts, indicating an enrollment that deviates from the corporate baseline. Finding a host that both resolved a lure domain and created rare MDM registry keys provides high-confidence evidence of an unauthorized enrollment.

### Correlating Execution and C2

The final phase searches for the actual delivery files and the resulting network traffic. We search file activity for specific installer names like edocusign_installer.msi. We also inspect network connections for outbound traffic to known ScreenConnect relays or activity on port 8041. When a host shows the complete sequence—phishing resolution, MDM enrollment, and RMM relay connections—the analyst can confirm a successful intrusion.

### Blind Spots and Limitations

This hunt relies on endpoint telemetry. It cannot see activity on BYOD or unmanaged devices that lack the corporate security agent. Furthermore, while we can see the presence of the MDM agent, we cannot see the specific commands an attacker issues within the MDM tenant console without direct access to the provider’s audit logs. This makes rapid triage of the endpoint state essential.

### Running the Hunt

This hunt is available as a hunt.md playbook. You can import it into Huntbase or any compatible runtime. The playbook guides an analyst through the scoping, triage, and verdict phases, including an automated isolation step if the complete attack chain is identified on a host.
