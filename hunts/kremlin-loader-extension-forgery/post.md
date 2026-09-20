# Hunting KREMLIN Browser Extension Forgery and DLL Sideloading

### Why hunt for KREMLIN?

Elastic Security Labs recently detailed the [KREMLIN campaign](https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware), a multi-stage operation targeting financial sessions. The adversary bypasses browser security by forging integrity checks rather than just tricking users. This allows them to install extensions that capture banking credentials silently. Because the campaign uses legitimate signed binaries for sideloading and modifies existing browser configuration files, simple signature-based detections may not catch the full chain of activity.

### The Hypothesis

An adversary uses multi-stage JavaScript loaders to install a persistent Node.js task. This task sideloads malware through a signed SentinelOne binary to modify browser configuration files, allowing the installation of malicious extensions that steal banking sessions.

### How the hunt flows

The hunt begins with the `hb_software_inventory` surface. This first step identifies every host running Chrome or Edge to focus the subsequent queries on vulnerable targets.

In the next phase, the hunt runs two queries in parallel. One query monitors `hb_file_activity` for the creation of deceptive JavaScript loaders in user directories. The second query examines `hb_scheduled_job` for a specific task named MicrosoftNodeRuntimeUpdater, which provides the adversary with persistent execution.

Once an agent triages these leads, the hunt pivots to deeper technical payloads. It uses the `hb_module_activity` surface to find a signed SentinelOne binary loading an unsigned or missing-signature DLL. At the same time, it checks `hb_dns_activity` for resolutions to known command-and-control domains or payload delivery paths on archive.org.

Finally, the hunt uses stack-counting on the `hb_file_activity` surface. It looks for rare processes modifying the Secure Preferences files in Chrome or Edge. By excluding legitimate browser executables, the hunt identifies the specific moment the malware forges the HMAC integrity checks required to sideload the extension.

### What the hunt cannot see

This hunt has two primary blind spots. First, it cannot confirm the DLL sideloading stage if the endpoint does not provide module load telemetry, such as Sysmon Event ID 7 or equivalent EDR logs. Second, the initial JavaScript loaders are ephemeral. If the adversary deletes these files before the hunt runs or if the file activity logging window is too short, the earliest indicator of infection will be lost.

### How to run it

This hunt is a standard `hunt.md` playbook. It imports into Huntbase or any hunt.md-aware runtime. Practitioners should run the scoping phase first to limit the data volume. If the hunt identifies hosts with the persistent Node.js task, an analyst should prioritize those endpoints for immediate browser preference audits.
