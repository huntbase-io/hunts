# Hunting iClickFix Redirection via Compromised WordPress Infrastructure

### Why this hunt

Sekoia.io recently published "Meet IClickFix: a widespread WordPress-targeting framework using the ClickFix tactic" (https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/), detailing a campaign that has compromised over 3,800 WordPress sites. The framework injects malicious scripts into these sites to redirect visitors through a Traffic Distribution System (TDS). This redirection eventually presents users with a fake browser error, leading to the execution of a NetSupport RAT. This hunt identifies the infection chain at the redirection and delivery stage.

### The Hypothesis

An adversary uses compromised WordPress sites to redirect visitors through a YOURLS-based Traffic Distribution System to fetch ClickFix-style malicious scripts.

### How the hunt flows

The hunt starts by identifying the local WordPress footprint. The first query checks the software inventory for any packages or vendors matching "WordPress". While many victims visit external sites, this step helps find internally managed servers that might be compromised and acting as redirection hubs.

The second phase analyzes the redirection infrastructure through a parallel check of DNS and HTTP telemetry. One query identifies rare lookups to known TDS domains or suspicious .pro domains that show low prevalence across the fleet. Simultaneously, another query scans HTTP logs for specific JavaScript paths like ofofo.js and liner.php. This phase targets the high-fidelity indicators of the iClickFix delivery mechanism.

The final phase uses an automated agent to triage the collected evidence. The agent correlates the DNS resolutions with the HTTP activity. If a host resolves a suspicious TDS domain and subsequently fetches a known payload script, the agent issues a malicious verdict. The hunt then routes the analyst to isolate the endpoint and perform a manual review of browser history to confirm the user fell for the ClickFix lure.

### What the hunt cannot see

This hunt has two primary blind spots related to network visibility. It requires either TLS interception or browser-level telemetry to see the specific script names in URI paths. Without this, the hunt relies solely on DNS lookups. Additionally, if the adversary or the browser uses DNS-over-HTTPS (DoH), the initial TDS domain resolutions do not appear in the standard DNS telemetry surface.

### How to run it

This hunt is a hunt.md playbook. You can import it into Huntbase or any security platform that supports the hunt.md standard. It uses common telemetry surfaces, making it portable across environments with standard endpoint and network logging. The design relies on correlating two different data sources to reduce noise and identify the redirection chain before a host executes the final payload.
