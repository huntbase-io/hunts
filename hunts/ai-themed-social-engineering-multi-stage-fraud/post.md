# Hunting for AI-Themed Social Engineering and Fraud Campaigns

### Why this hunt?

Microsoft recently detailed how attackers exploit employee interest in generative AI to facilitate fraud in "Detect and disrupt AI-themed attacks with Microsoft Defender" (https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/). Attackers register lookalike domains and distribute fake installers that impersonate popular AI tools. Because users often seek out these tools themselves, they frequently bypass standard security warnings. A single detection for a malicious domain is useful, but a hunt allows us to see the entire progression from the initial web request to the final credential theft or malware execution.

### The Hypothesis

An adversary uses lookalike AI domains and installers to trick users into downloading stealers or performing device-code authentication, leading to token theft and financial fraud.

### How the Hunt Flows

The hunt begins by narrowing the environment to hosts that already show signs of AI-related activity. The first step queries hb_process_activity for any process names or paths containing keywords like "gpt", "claude", or "deepseek". This scoping provides a focused list of devices where users are actively attempting to use AI software.

Next, the hunt examines delivery surfaces in parallel. It checks hb_http_activity for direct connections to known lookalike domains and hb_dns_activity for resolutions of suspicious AI-themed hostnames. This dual-surface approach ensures visibility even when full HTTP payloads are encrypted or unavailable. An automated agent then weighs these network signals to identify hosts with confirmed interest in malicious infrastructure.

Once the hunt identifies a lure, it pivots to look for the impact. It searches hb_process_activity for suspicious installers running from user-writable directories like Downloads or Public folders. Simultaneously, it examines hb_auth_signin for successful Microsoft 365 device-code authentication events. This specific authentication flow is a common target for adversaries seeking to harvest session tokens without needing the user's password directly.

Finally, a second agent correlates the initial network lure with the subsequent execution or identity anomalies. This correlation distinguishes between a user visiting a legitimate AI site and a user falling victim to a multi-stage social engineering campaign. If the agent confirms both the lure and the follow-on activity, it recommends immediate host isolation to prevent further data exfiltration.

### What the Hunt Cannot See

Every hunt has limits. This playbook relies on process and network activity within a 14-day window. If an adversary harvested a session token via device-code abuse 30 or 60 days ago, that activity will not appear in the current results even if the token remains active. Additionally, this hunt focuses on standalone binaries. If an adversary uses a malicious browser extension to steal data, it may not trigger the process execution queries, creating a visibility gap on the endpoint.

### How to Run It

This hunt is an open hunt.md playbook. You can import it directly into Huntbase or any security platform that supports the hunt.md format. It allows you to customize parameters like the lookback window and the list of suspected AI domains based on your organization's specific threat profile.
