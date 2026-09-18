# Hunting for Adversary Infrastructure Nodes and Automation Workflows

Recent research from Huntress, titled [An attacker blunder gave us a look into their operations](https://www.huntress.com/blog/rare-look-inside-attacker-operation), provided a rare glimpse into the backend of modern phishing infrastructure. The report detailed how threat actors use legitimate automation platforms to manage their workflows. This shift to "living off the cloud" presents a challenge for traditional security controls: you cannot simply block common automation or messaging APIs without impacting business operations.

### The Hypothesis
Our hunt is built on the hypothesis that an adversary is using legitimate automation platforms and external scanning tools to conduct phishing operations and manage C2 workflows through automated webhooks. If a host in your environment is behaving as an adversary node or jump box, it will likely exhibit a combination of rare software (in the form of browser extensions) and specific network patterns directed toward automation and infrastructure discovery tools.

### How the Hunt Flows
The hunt begins with a scoping phase focused on the software inventory. We look specifically for rare browser extensions. Because many modern attack frameworks and proxy tools interface with the browser, identifying extensions that exist on only a handful of machines across the fleet is a strong pivot point for finding operator-specific tooling.

Next, the hunt moves into parallel network analysis. The first branch baselines DNS activity for known automation platforms. While many developers use platforms like Make.com or Telegram, we look for rare processes making these calls. Seeing a command-line utility or an unusual browser process querying these domains is significantly more interesting than a standard business application doing so.

The second network branch examines HTTP activity for specific intent. We search for traffic to infrastructure discovery engines like Censys or Shodan, combined with URI keywords associated with proxying and phishing infrastructure, such as "evilginx," "mitm," or "webhook." This phase helps differentiate between a developer using automation for work and an operator managing an attack.

Finally, the hunt uses an automated triage step to weigh these signals. A host showing a rare extension alongside both automation traffic and discovery searches is flagged for immediate forensic review and potential isolation.

### Blind Spots and Limitations
This hunt relies on clear-text visibility or metadata for network activity. If an adversary uses a fully custom C2 channel or encrypts all traffic via TLS without interception, the HTTP keyword matching will fail. We also cannot see the specific permissions or background script behaviors of browser extensions through inventory alone; we only know of their presence. A benign-looking extension could still be a custom-built session-hijacking tool.

### How to Run This Hunt
This hunt is packaged as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any security platform that supports the `hunt.md` format. Because this is a hunt rather than a detection, it is intended to be run periodically to baseline your environment and find the "low and slow" infrastructure nodes that don't trigger immediate alerts. It provides the context necessary for an analyst to make an informed verdict on whether a host is being used for sanctioned business automation or malicious activity.

Source: [Huntress — An attacker blunder gave us a look into their operations](https://www.huntress.com/blog/rare-look-inside-attacker-operation)
