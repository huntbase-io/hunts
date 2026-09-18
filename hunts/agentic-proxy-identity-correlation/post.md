# Correlating Proxy Usage with Identity Risk and User Tenure

The evolution of security operations increasingly relies on context to separate noise from genuine risk. A recent article by Elastic Security Labs, titled [Inside Elastic's agentic SOC: How we took AI alert triage from 60% to 92% accuracy](https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents), highlights how self-correcting agents can significantly improve triage precision. Inspired by this model, we have developed a hunt that moves beyond static detection of proxy tools to focus on the intersection of identity and network behavior.

The hypothesis for this hunt is that high-risk users, particularly new hires or those in sensitive roles, may use multi-hop proxies like Ngrok or Tor to bypass network controls. In a development environment, these tools are often benign, but when used by non-technical staff or users with very short tenure, the risk of data exfiltration or persistent command-and-control increases. This hunt seeks to distinguish these contexts.

The hunt begins with a scoping phase using the `hb_auth_signin` surface. We map specific high-risk email addresses, such as those from an HR leaver list or a manual watchlist, to their respective hostnames. This ensures that the subsequent technical analysis is focused on the correct endpoints and identities.

Next, the hunt gathers evidence through parallel technical pivots. We examine `hb_network_connection` for established connections to known Ngrok tunneling infrastructure and `hb_dns_activity` for resolutions of Tor-to-Web gateways. These technical signals are then combined with identity context from the `hb_users` surface, where we specifically look for a 'new hire' flag—defined as accounts created within the last 90 days. This correlation is critical: a senior developer using a tunnel might be ignored, but a new hire in finance doing the same is a priority.

The final phase uses an agentic brainstorm step. The agent weighs the rarity of the network connections against the user's tenure and status. This mimics the logic of a tier-2 analyst, reaching a verdict based on the totality of the evidence. If the user is identified as high-risk and the proxy usage is confirmed, the hunt provides a path for host isolation to prevent potential exfiltration.

There are two primary blind spots to consider. First, if the environment lacks granular role metadata (such as department or job title) in the `hb_users` surface, the hunt relies heavily on account age as a proxy for risk. Second, if an adversary uses direct IP-based tunneling without performing DNS lookups, the DNS-based indicators for Tor gateways will be bypassed.

To run this hunt, you can import the provided `hunt.md` playbook into Huntbase or any compatible runtime. This format allows for an automated, repeatable workflow that incorporates both raw query results and agentic reasoning to produce high-fidelity findings.
