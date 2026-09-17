# Detecting MacSync Stealer Persistence and TCC Permission Abuse

The MacSync Stealer campaign, recently detailed by Huntress in their report [MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer](https://www.huntress.com/blog/fake-claude-macsync), highlights a shift in how macOS users are targeted. It moves beyond simple shell scripts to more persistent Mach-O binaries. Our team has designed a hunt to identify the footprints of this RAT's residency on a fleet.

### The Hypothesis
An adversary has established persistence on macOS hosts using a LaunchAgent named after a legitimate updater and is utilizing a secondary signed helper to abuse TCC (Transparency, Consent, and Control) screen recording permissions. By correlating these artifacts across different telemetry surfaces, we can identify infected endpoints that automated detections might overlook.

### How the Hunt Flows
The hunt begins by scoping the fleet to Darwin-based hosts. Because MacSync is platform-specific, we narrow our telemetry window to macOS devices to reduce noise before moving into parallel analysis of persistence and collection indicators.

In the first analysis phase, we examine scheduled jobs. MacSync frequently creates LaunchAgents in user or system Library folders. We look for new entries that masquerade as software updaters. To help identify polymorphic naming, we apply a baselining step that stack-counts LaunchAgent names across the fleet, highlighting jobs that appear on three or fewer hosts.

Simultaneously, we pivot to file activity and process command lines. A high-fidelity indicator for MacSync is the creation of a hidden file named `.mpwd` in the user's home directory, which the malware uses to stage stolen credentials. We also hunt for the execution of the malware's specialized capture agent. This helper uses specific command-line flags like `--tcc-only` and `-o` to provision screen recording.

Finally, the hunt looks for network indicators. We check for outbound connections to port 8443 or known C2 IP addresses. By weighing these correlated indicators—rare LaunchAgents, the .mpwd file, and specific TCC helper flags—we can reach a high-confidence verdict on whether a host has been compromised by the MacSync RAT.

### What the Hunt Cannot See
This hunt relies on endpoint visibility for scheduled jobs and file activity. If a macOS device is missing the security agent or is reporting partial telemetry, the persistence mechanism might remain hidden. Additionally, while we can detect the execution of the screen-recording helper, we cannot confirm if the user explicitly granted permission via the TCC prompt without access to unified system logs. We see the attempt, but the success of the screen capture depends on the user's interaction with the operating system.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other hunt.md-aware runtime. It uses a series of structured steps to query your telemetry and provides a triage framework for an analyst to review the findings. Because it is a hunt rather than a static detection, it is intended to be run periodically to catch persistent threats that have successfully evaded initial perimeter defenses.
