# Hunting Cross-Tenant Persistence and Autonomous Agent C2

### Why this hunt

Cloud tenant boundaries often rely on the integrity of delegated administration and remote support features. Recent updates in [What’s new in Microsoft Security: August 2026](https://www.microsoft.com/en-us/security/blog/2026/08/27/whats-new-in-microsoft-security-august-2026/) highlight the evolving ways adversaries exploit these features. Traditional detections often miss the slow transition from a legitimate cross-tenant login to the deployment of autonomous automation agents. This hunt provides a structured way to validate those boundaries.

### The Hypothesis

An adversary has established persistence via cross-tenant delegated administration or unattended remote support, subsequently deploying autonomous agents that communicate through multi-hop proxies. The attacker relies on the assumption that external identity providers and standard remote support binaries will not trigger high-fidelity alerts.

### How the Hunt Flows

The hunt begins by narrowing the focus to endpoints with specific management software. An analyst first queries the software inventory for Microsoft Intune or Remote Help installations. This ensures subsequent behavioral checks target the most relevant assets where unattended support is most likely to be active.

Next, the hunt enters a parallel phase to evaluate access and persistence. One branch looks for rare sign-ins from external identity providers, specifically focusing on providers where an adversary might operate a shadow tenant. Simultaneously, the hunt examines process activity for remote support binaries like Quick Assist or Remote Help. An automated agent then triages these findings to find hosts where a new external login correlates with the execution of a support tool.

Following the identification of suspicious persistence, the hunt shifts to behavioral analysis. It scans script activity logs for keywords associated with autonomous agent frameworks, such as LangChain or AutoGen. In parallel, it inspects DNS activity for lookups involving .onion domains or public web-to-Tor proxy relays. These indicators suggest the presence of a C2 channel that attempts to obfuscate its destination via multi-hop routing.

Finally, a synthesis step combines the persistence evidence with the observed execution and network patterns. If the results show a clear chain from external access to autonomous script behavior, the analyst moves to isolate the host and revoke involved identity sessions.

### Blind Spots and Limitations

Analysts must account for potential gaps in visibility. Script activity logs may suffer from session truncation, which can hide the full parameters of an agent script or its final exfiltration targets. Additionally, this hunt focuses on the activity following a configuration change. It does not audit the Entra ID configuration logs themselves to determine which specific policy change enabled the initial cross-tenant access. This hunt detects the aftermath, not the administrative setup.

### Run the Hunt

This hunt is available as an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md specification. Because this process correlates data across identity, process, and network surfaces, it functions as a hunt rather than a single detection rule. It builds the necessary behavioral context to confirm a sophisticated persistence chain.
