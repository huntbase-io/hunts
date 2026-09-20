# Hunting Teams Vishing and RMM Abuse in the Spring Ring Campaign

### Why This Hunt Matters
A recent report by Unit 42, "Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams" (https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/), details how adversaries exploit the trust users place in collaboration platforms. Instead of email, they use external Teams accounts to initiate vishing calls. They impersonate IT staff and guide users to install remote monitoring and management (RMM) tools or execute custom payloads. This hunt identifies the full lifecycle of these attacks, from the initial lure to the establishment of persistence.

### The Hypothesis
An adversary is using external Microsoft Teams accounts to masquerade as IT support and coerce employees into executing RMM tools or custom payloads that perform discovery and persistence.

### How the Hunt Flows
The hunt begins by scoping the environment. It identifies every host currently running or having Microsoft Teams installed to focus the analysis on the most likely targets.

The second phase identifies the initial social engineering engagement. It correlates DNS lookups for known vishing domains—often spoofed onmicrosoft.com subdomains—with the immediate execution of remote management software like Quick Assist or specific campaign payloads. This correlation is vital because Quick Assist is a legitimate tool often used by real IT departments; seeing it follow a suspicious DNS resolution provides the necessary context for a high-confidence alert.

The third phase searches for secondary indicators of compromise. It looks for rare binaries running from the user’s temporary directory, specifically focusing on naming patterns like vhlp- and scnr-. These files represent the adversary's attempt to stage more permanent access once the initial RMM session is established.

Finally, the hunt examines script activity for post-exploitation tradecraft. It identifies PowerShell or command-line blocks attempting to bypass AMSI or perform domain discovery, such as enumerating domain groups. By weighing this evidence against the initial social engineering verdict, the hunt provides a clear picture of the attack's success.

### Blind Spots
This hunt focuses on endpoint and network telemetry. It cannot see the verbal content of the Teams vishing call itself. If an adversary captures credentials verbally or triggers an MFA prompt without executing code on the machine, the initial hook remains invisible. Additionally, while the campaign is known to sideload browser extensions, this hunt does not inspect the internal DOM manipulation or cookie theft performed by those extensions.

### How to Run This Hunt
This hunt is packaged as an open hunt.md playbook. You can import it into Huntbase or any other hunt.md-aware runtime. It uses standard SQL-based queries to interrogate software inventory, DNS logs, and process activity. Because it correlates external network events with local execution, it requires visibility into both DNS and process-level activity.
