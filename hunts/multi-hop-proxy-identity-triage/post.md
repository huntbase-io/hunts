# Triage multi-hop proxies and tunnels with identity context

### Why now
Elastic recently detailed their shift toward automated triage in [Inside Elastic's agentic SOC: How we took AI alert triage from 60% to 92% accuracy](https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents). Their findings show that accuracy improves when a system evaluates more than just a single alert. This hunt applies that logic to tunnels and proxies, which are often noisy but critical to catch when used for C2 obfuscation.

### The hypothesis
An intruder is using a multi-hop proxy or tunneling service to obfuscate C2 traffic. This activity is distinguishable from legitimate researcher or developer activity by correlating network leads with user risk profiles and local port bindings.

### How the hunt flows
The first phase identifies rare outbound connections to known tunneling providers like ngrok or processes with proxy-like names. The query filters for low-prevalence connections to reduce noise from common internal traffic. This step provides the initial list of suspicious hosts and users.

Next, the hunt pivots to three surfaces in parallel to gather evidence. It checks DNS logs for resolutions of Tor gateways, which indicates an attempt to reach the dark web without a local Tor client. Simultaneously, it retrieves the account status and MFA configuration for the involved users to identify high-risk or compromised accounts.

Finally, the hunt examines local network listeners. A process that establishes an outbound tunnel and also binds a local port is likely acting as a proxy or reverse tunnel. An agent or analyst then weighs these combined signals: a non-MFA user running a rare tunnel binary that resolves Tor domains and listens on a local port is a malicious beachhead.

### What this hunt cannot see
This hunt has three primary blind spots. First, if the network listener surface lacks host-specific columns, an analyst must manually correlate PIDs across the fleet. Second, the hunt misses Tor traffic if the adversary connects directly to entry node IPs instead of using DNS gateways. Third, the triage step depends on identity data; if the identity provider lacks job titles or department info, the hunt cannot automatically determine if a user's role justifies proxy usage.

### How to run it
This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` standard. It executes the lead query, performs the parallel enrichment, and then prompts for a verdict based on the correlated findings.
