# Finding Multi-hop Proxies and Tor Relays in User-Writable Paths

Adversaries frequently use multi-hop proxies, Tor, and tunneling services to hide the true origin of their command-and-control (C2) traffic. By routing malicious data through these relays, they bypass traditional perimeter monitoring and domain-based blocklists. This hunt design follows the logic of modern security operations, similar to the efficiency improvements discussed in the Elastic Security Labs article, [Inside Elastic InfoSec's agentic SOC](https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale). The focus here is on identifying the behavioral footprints of proxy tools rather than relying on static indicators.

### The Hypothesis
An adversary masks command-and-control traffic by routing it through multi-hop proxies, Tor entry nodes, or tunneling services to bypass perimeter monitoring and egress filters.

### How the Hunt Flows
The first phase identifies the presence of potential proxy binaries. The hunt queries for outbound network connections originating from processes running in user-writable paths like `\Users\Public\`, `\AppData\`, `/tmp/`, or `/var/tmp/`. Legitimate binaries occasionally run from these locations, but persistent network-facing tools here warrant immediate investigation. This initial filter reduces the estate-wide telemetry down to a manageable list of suspicious candidates.

In the second phase, the hunt performs a parallel corroboration check. One branch scans DNS activity for resolutions of known tunneling providers, such as ngrok or PageKite, and any lookups involving `.onion` domains. Simultaneously, another branch checks network logs for traffic directed at common Tor relay ports (9001, 9050, 9150). This dual-path approach ensures that the hunt catches both well-known services and generic SOCKS proxies configured to use standard Tor infrastructure.

The final phase involves a triage step that weighs the evidence from the previous steps. An analyst or agent compares the binary's location, the destination ports, and the resolved domains. A binary in a temporary directory that resolves a tunneling domain and connects over port 9050 provides high-confidence evidence of an unauthorized proxy. This structured correlation allows the team to distinguish between legitimate software updaters and malicious relays without manual per-host analysis.

### Blind Spots
This hunt has two primary limitations. First, if the adversary uses encrypted DNS (DoH/DoT), the `hb_dns_activity` surface remains silent. The hunt cannot see tunneling domain resolutions if the endpoint bypasses local DNS settings. Second, without byte-count telemetry, the hunt cannot distinguish between a low-volume heartbeat and high-volume data exfiltration. This means it finds the tunnel but cannot immediately determine the severity of the data loss without additional flow analysis.

### How to Run This Hunt
This hunt is available as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any hunt.md-aware runtime environment. To execute it, set your lookback period and provide any specific host or process filters if you want to scope the hunt to a specific department or critical server group. The logic is designed to be automated; the triage agent will produce a per-host verdict of malicious, suspicious, or benign based on the combined telemetry signals.
