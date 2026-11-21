# AI Coding Agent Device Code Hijacking

### Why this hunt?

Microsoft recently published "The risks of device code authentication for AI coding agents" (https://www.microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents/). The research highlights how attackers exploit the OAuth device code flow to compromise AI agents. This flow, designed for input-constrained devices, allows a user to authorize an application on one device by entering a code on another. Adversaries phish these codes to gain access to developer environments. This hunt detects the full lifecycle of such an attack, from the initial lure to the exfiltration of source code.

### Hypothesis

An attacker hijacks an AI coding agent by phishing a device code from a developer, obtaining an OAuth token to steer local terminal sessions and exfiltrate private repository data.

### How the hunt flows

The hunt begins by identifying the attack surface. We scope the investigation to hosts where developers have installed GitHub Copilot CLI or the GitHub CLI. This narrows the focus to systems where the agent binaries are active.

Next, we look for the initial phishing lure. We query HTTP telemetry for visits to the GitHub device login page. We simultaneously look for GitHub sign-ins from rare or unexpected IP addresses using AI agent client IDs. 

An automated agent then evaluates the timing of these events. If a user visits the login page and an authentication event from a rare IP follows within a short window, the session is likely hijacked. This correlation distinguishes a legitimate developer login from an adversary's session takeover.

The hunt then pivots to the endpoint to confirm activity. We search for the AI agent process spawning shell interpreters like Bash, PowerShell, or CMD. This behavior indicates an attacker is steering the agent to execute local commands. 

Finally, we examine cloud API activity. We look for the phished token being used to enumerate private repositories or access the agent's memory store. This confirms whether the attacker successfully accessed sensitive intellectual property or poisoned the agent's training context.

### Blind spots

This hunt cannot quantify the exact data stolen without GitHub cloud audit logs. If these logs are missing, we see the unauthorized access but not the specific repositories exfiltrated. Additionally, EDR command-line truncation might hide the full scope of local steering commands if they exceed the character limit, making it harder to identify the specific intent of the attacker.

### How to run it

This hunt is provided as an open hunt.md playbook. You can import this into Huntbase or any hunt.md-aware runtime. Because it is a hunt, not a detection, it focuses on correlating temporal signals across identity and endpoint planes rather than alerting on single events. This reduces the fatigue associated with common developer VPN shifts or legitimate agent activity.
