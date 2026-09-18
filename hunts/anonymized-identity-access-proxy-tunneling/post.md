# Correlating Anonymized Identity Access with Endpoint Proxy Tunneling

Modern adversaries frequently use multi-hop proxy infrastructure to mask their origin and bypass location-based conditional access policies. While many teams monitor for suspicious logins, the real challenge lies in connecting a suspicious authentication event to the actual persistent access mechanism on the host. This hunt, inspired by the concepts in [How threat hunting evolves at scale](https://redcanary.com/blog/threat-detection/threat-hunting-scaled/) by Red Canary, addresses this by correlating SaaS identity logs with granular endpoint telemetry.

### The Hypothesis
An adversary has successfully compromised an identity (e.g., Okta) via a proxy or Tor exit node. Following the initial access, they have established or utilized existing tunneling software on a managed endpoint to maintain a persistent, covert command-and-control channel that is difficult to distinguish from legitimate remote administrative traffic.

### How the Hunt Flows
The hunt begins with a scoping phase using `hb_software_inventory`. We identify managed hosts that already possess proxy-capable or tunneling software. While many of these tools (like Tailscale or Ngrok) have legitimate uses, identifying the potential 'beachhead' hosts allows us to focus our more intensive correlation efforts where the risk is highest.

Next, we pivot to the identity layer using `hb_auth_signin`. We look specifically for successful authentications where the source IP belongs to a known list of VPS providers or Tor exit nodes. These events are not inherently malicious, but when they occur in environments with strict access controls, they serve as high-utility triage markers.

The core of the hunt is a parallel correlation across three endpoint surfaces: `hb_process_activity`, `hb_network_connection`, and `hb_dns_activity`. We look for rare binaries executing with proxy-related flags (e.g., `--socks`, `--tunnel`), connections to ports commonly associated with relays (9001, 9050), and DNS queries for `.onion` or other hidden service TLDs. We look for temporal alignment—did the suspicious login happen just before a rare tunneling process started communicating?

Finally, a triage agent reviews the findings to provide a unified verdict. This step is necessary because the presence of a tool like Chisel or a login from a VPS IP can be benign; the maliciousness is often found in the specific combination of the two within a tight time window.

### What This Hunt Cannot See
This hunt has two primary blind spots. First, it relies on EDR coverage. If an attacker uses a compromised identity to access an unmanaged or BYOD device, the endpoint-level tunneling and process telemetry will be invisible to this playbook. Second, the hunt is currently tuned for data-center VPS and Tor infrastructure. If the adversary uses a residential proxy botnet to mask their origin, the initial identity filter may not trigger, although the endpoint behaviors (like rare process execution) might still be caught if the scoping phase is broadened.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any other hunt.md-aware runtime. By providing the list of VPS IPs and desired lookback window as parameters, you can execute these joins across your identity and endpoint data without manually pivoting between disparate consoles.
