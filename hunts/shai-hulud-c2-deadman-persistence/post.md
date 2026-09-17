# Hunting for Shai-Hulud Framework Persistence and Deadman Switches

Recent research into the Shai-Hulud framework, as detailed in the Datadog Security Labs article [Shai-Hulud open source framework static analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/), reveals an adversary toolset designed for persistence and retaliatory destruction. The framework is notable for its deadman switch: a service that polls the GitHub API to check if a stolen token is still valid. If the token is revoked, the framework can trigger a script to wipe the user's home directory. This creates a high-stakes environment where standard remediation—rotating credentials—can lead to data loss if the host is not isolated first.

### The Hypothesis
An adversary has established persistence on developer workstations via a GitHub token monitor. This monitor polls the GitHub API every 60 seconds to detect token revocation and exfiltrates data to a spoofed domain or uses GitHub repositories as dead-drops. We expect to find specific persistence files, a unique lock file in /tmp, and high-frequency network activity targeting the GitHub API.

### How the Hunt Flows
The hunt begins by narrowing the scope to workstations that have development environments installed. By querying software inventory for Bun or Node.js, we focus on systems capable of running the Shai-Hulud components, reducing noise from general-purpose endpoints.

Next, the hunt gathers persistence evidence by looking for specific service names. We search for LaunchAgents on macOS named `com.user.gh-token-monitor.plist` and systemd services on Linux named `gh-token-monitor.service`. These are high-fidelity indicators of the framework's deadman switch.

We then correlate this with file and network activity. The framework utilizes a hardcoded lock file at `/tmp/tmp.ts018051808.lock` to prevent multiple instances. Simultaneously, we look for DNS lookups to the primary C2 domain `git-tanstack.com` and analyze network connections for high-frequency polling—specifically processes making more than 60 connections to api.github.com within a short window.

Finally, the hunt uses an automated triage phase to combine these signals. A host showing both the persistence service and the 60-second polling behavior is prioritized for isolation. The goal is to identify the infection and isolate the host before an analyst or automated system revokes the compromised GitHub token.

### Blind Spots and Limitations
This hunt has two primary limitations. First, while we can identify the persistence services, we cannot see the content of the scripts without deep file inspection or script-block logging. Therefore, we cannot confirm if the destructive `rm -rf ~/` command is present in every instance. Second, the hunt is client-side only. We cannot see how the stolen tokens are being used within GitHub's cloud environment without access to GitHub Enterprise Audit Logs.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. You can import this file into Huntbase or any security runtime that supports the open hunt.md format. The parameters, such as the C2 domains and lock file paths, are configurable to adapt to new variants of the framework as they are discovered.
