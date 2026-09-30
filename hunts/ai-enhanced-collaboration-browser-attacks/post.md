# Hunting AI-Enhanced Social Engineering and Browser Persistence

### Why this hunt

Adversaries now use AI-generated lures to create highly convincing social engineering campaigns that bypass traditional email security filters. The report by Proofpoint, [Proofpoint Stops the Attacks Traditional Defenses Miss in the AI Era](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-stops-attacks-traditional-defenses-miss-ai-era), highlights how these sophisticated interactions often lead to session hijacking or persistent access via collaboration tools. While a simple alert for every new browser extension is too noisy for most environments, this hunt provides a structured way to find malicious implants by looking for them specifically in the context of suspicious initial access.

### The Hypothesis

An adversary bypasses traditional email defenses using AI-enhanced social engineering to trick a user into granting OAuth permissions or installing a malicious browser extension. This interaction leads to session hijacking and provides the attacker with persistent, unauthorized access to the environment.

### How the hunt flows

The first phase scopes the environment. A query against software inventory surfaces every host running common web browsers. This baseline ensures the hunt focuses on endpoints where browser-based persistence is technically possible and narrows the subsequent search for high-risk workstations, such as those in finance or executive leadership.

The second phase searches for initial access evidence across two surfaces. The hunt monitors HTTP activity for connections to known phishing domains or URLs containing keywords like "consent" or "authorize." Simultaneously, it checks cloud API logs for users granting broad application permissions or roles in Microsoft 365. An analyst or automated agent then correlates these events to identify users who likely fell for a lure.

The third phase investigates persistence on the high-risk hosts identified previously. The hunt looks for browser extensions with very low prevalence — those installed on three or fewer devices across the entire fleet. It also checks for successful sign-ins where multi-factor authentication was not recorded, which often indicates that an attacker is reusing a hijacked session token stolen via a malicious extension.

The final phase connects the chain. The analyst verifies if the phishing visit or OAuth grant was followed by a rare extension installation or an anomalous sign-in on the same host. This correlation confirms the full attack path from the initial click to persistent access.

### Limitations and Blind Spots

This hunt has three primary blind spots. First, without TLS decryption on a forward proxy, the hunt sees the domains visited but cannot inspect the payloads. We cannot confirm if a user submitted credentials or tokens, only that they interacted with the site. Second, software inventory typically provides the name and vendor of an extension but not its internal permissions. We cannot see if an extension has the right to read page content or intercept form data. Finally, cloud API logs often suffer from ingestion latency, meaning the very latest OAuth grants may not appear in the results for several minutes.

### How to run it

This hunt is provided as a `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the necessary queries for software inventory, HTTP traffic, and cloud API activity, along with the logic required to correlate findings across the attack chain.
