# Hunting for KREMLIN Loader Persistence and JS Evasion

### Why Now

Recent research from Elastic Security Labs, titled [The extension you never installed: KREMLIN forges Chrome's own integrity checks to steal banking sessions](https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware), details a sophisticated campaign targeting banking users. KREMLIN is notable for its use of a multi-stage infection chain that ultimately drops a malicious browser extension. Because the malware relies on legitimate tools like Node.js and common administrative interfaces like WMI for evasion, relying on static signatures is insufficient. This hunt focuses on the persistence and loader mechanisms that precede the extension's installation.

### The Hypothesis

We hypothesize that KREMLIN can be identified by the specific way it establishes persistence on Windows endpoints. Specifically, we look for an intruder using a JavaScript loader to create a scheduled task named 'MicrosoftNodeRuntimeUpdater' (or similar) that executes a headless Node.js environment. We also expect to find behavioral evidence of sandbox evasion, such as WMI-based process counting, and network indicators tied to Ethereum smart contract dead-drop resolvers.

### How the Hunt Flows

The hunt begins with broad scoping. We identify hosts where targeted browsers (Chrome or Edge) are currently inventoried. Since KREMLIN is designed to steal browser sessions, focusing our search on these environments reduces noise from servers or specialized workstations where the infection is less likely to yield the attacker's desired results.

Next, we pivot to the primary persistence mechanism. We query scheduled job metadata for tasks that specifically reference the 'MicrosoftNodeRuntimeUpdater' name or utilize the `--headless` flag with the Node.js runtime. This is a high-confidence signal, but attackers can easily rename tasks, so this step serves as a starting point rather than a definitive conclusion.

To corroborate these findings, we look for secondary file artifacts. The KREMLIN loader often generates temporary JavaScript files following a `popup_*.js` naming convention to facilitate user lures. We use a prevalence-based query to find these scripts, filtering for files seen on very few hosts across the environment. Finding these rare scripts on the same hosts as the suspicious scheduled tasks significantly increases the likelihood of a true positive.

Finally, we examine behavioral and network telemetry. We search script execution logs for WMI queries that count running processes or desktop objects—a known evasion technique used by KREMLIN to detect sandboxes. This is combined with a search for DNS lookups to Ethereum dead-drop resolvers and Archive.org, which the malware uses to fetch its final stage payloads. This multi-surface approach allows us to see the activity even if individual indicators have been modified.

### Blind Spots

Visibility into the initial JavaScript execution is heavily dependent on the depth of script block logging. If the `hb_script_activity` surface does not capture expanded or deobfuscated strings, the WMI-based evasion logic may remain hidden. Additionally, without full HTTP path visibility, DNS queries to common domains like Archive.org can be noisy and difficult to distinguish from legitimate user traffic without the context of the calling process.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any compatible runtime that supports the `hunt.md` format. The playbook contains the logic to automate the correlation between these disparate signals, providing a unified triage view for the analyst. Because this is a hunt rather than a simple detection, it emphasizes the correlation of low-confidence signals to find novel or modified versions of the KREMLIN loader.
