# Hunting Unicode Smuggling in Finance-Themed Phishing Evasion

### Why now
Microsoft recently detailed a shift in tradecraft in their article [ASCII smuggling crosses over from AI prompt injection to phishing evasion](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/). Adversaries now use invisible characters to deceive both users and security filters. This hunt provides a structured way to find this crossover technique in your environment.

### The Hypothesis
An adversary uses invisible Unicode tag characters to split keywords in finance-themed phishing lures, bypassing traditional email filters and redirecting victims to disposable infrastructure. This technique allows a malicious link or file to appear benign to automated scanners while still delivering the victim to a controlled landing page.

### How the hunt flows
The hunt starts by narrowing the field to hosts that run Microsoft 365 or Office software. This scoping step ensures the analyst focuses on endpoints where users are most likely to interact with finance-themed email lures. The query builds an inventory of candidate hosts for the subsequent triage phases.

Next, the hunt looks for DNS activity related to known campaign-specific domains. These domains, such as guardiangrowthfunding.com, represent the first stage of the redirection chain. Any host that resolves these addresses becomes a primary lead. An analyst or automated agent then evaluates the volume and timing of these hits to decide which hosts merit a deeper inspection of their web traffic.

For hosts that pass the gate, the hunt runs two parallel checks to find corroborating evidence. The first query searches HTTP telemetry for specific percent-encoded markers—specifically the %f3%a0 prefix used for Unicode Tags. These markers often appear in the URL path or the Referrer header during the smuggling process. Simultaneously, a second query baselines the rarity of connections to the campaign domains across the entire fleet to confirm that the activity is an isolated incident rather than a connection to common shared infrastructure.

In the final phase, an analyst correlates the DNS leads with the HTTP-layer markers. If a host shows both the resolution of a campaign domain and the presence of smuggling characters in its web headers, the hunt provides an action to isolate the host. This prevents further lateral movement while a manual review confirms if the user successfully submitted credentials or downloaded a payload.

### What the hunt cannot see
This hunt has two primary blind spots. First, if a host resolves campaign domains using DNS-over-HTTPS (DoH) or an unmonitored external resolver, the initial lead generation query will stay silent. Second, visibility into the percent-encoded smuggling markers depends on your ability to inspect HTTP traffic. If the traffic is encrypted and your environment lacks proxy-level inspection or host-based HTTP telemetry with full URL capture, the smuggling markers will remain hidden in the TLS stream.

### How to run it
This hunt is available as an open `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the `hunt.md` format. The playbook includes all necessary parameters for campaign domains and lookback periods, allowing you to run the gated queries in sequence or as a single automated workflow.
