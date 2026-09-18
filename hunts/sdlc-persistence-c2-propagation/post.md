# Hunting SDLC Persistence and Blockchain-based C2

### The Shift to Developer-Targeted Persistence

Recent research from Unit 42, [Connecting the Dots: Securing the Overlooked Corners of the SDLC Supply Chain](https://unit42.paloaltonetworks.com/sdlc-supply-chain/), highlights how attackers are moving beyond simple credential theft to establish long-term persistence within the software development lifecycle (SDLC). By targeting the tools developers use daily — such as IDEs and modern runtimes like Bun — attackers can insert themselves into the build process, often surviving application code changes and manual rotations of single secrets.

### Hypothesis

We hypothesize that an attacker has compromised a developer workstation or CI/CD runner and established persistence by modifying IDE-specific configurations (such as VS Code tasks). Following this, the attacker uses blockchain infrastructure for resilient command-and-control (C2) and leverages harvested tokens to automate propagation into code registries like GitHub or npm.

### The Hunt Flow

The hunt begins by scoping the environment to identify systems where development tools are present. This uses software inventory surfaces to filter for hosts running Visual Studio Code, Bun, or AI-assisted coding tools like Claude Code. This narrow scope reduces noise and focuses the investigation on high-value targets.

Next, the hunt executes three parallel checks to find overlapping evidence of a compromise. The first check monitors file activity for unauthorized modifications to `.vscode/tasks.json` or related configuration files. We specifically look for instances where these files are modified by processes other than the IDE itself, such as standalone Node.js or Python runtimes, which suggests a script is installing a persistence hook.

The second check pivots to network telemetry, looking for DNS queries to Ethereum JSON-RPC and explorer domains. Using blockchain infrastructure for C2 is a technique observed in the 'ChainDrop' worm, allowing attackers to retrieve configuration or payload locations without relying on traditional, easily blockable domain names.

The final check examines authentication logs for GitHub and npm. We look for spikes in successful authentication events that may indicate a script is using stolen tokens to automate the injection of malicious code or the harvesting of further secrets. This step is critical for identifying the 'worm' behavior of the threat.

Finally, the hunt uses an automated triage phase to correlate these signals. A host that shows both an unauthorized IDE configuration change and blockchain-related network activity is treated as a high-confidence match for a supply chain compromise.

### Blind Spots and Limitations

This hunt has two primary limitations. First, while we can see that a configuration file like `tasks.json` was modified, standard EDR telemetry often lacks the file content diffs required to see exactly what was added. Without these diffs, an analyst must manually inspect the file to distinguish a malicious script from a legitimate configuration change.

Second, the hunt's visibility into propagation depends on the availability of SaaS audit logs. If an attacker uses stolen tokens to modify a repository from an ephemeral CI/CD runner that is destroyed shortly after execution, the activity may be invisible if GitHub or npm logs are not being ingested into your central telemetry platform.

### How to Run this Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the `hunt.md` standard. The playbook includes the necessary logic to scope your environment, correlate the telemetry, and provides a structured path for host isolation and token revocation should a threat be confirmed.
