# Hunting CHAINDROP npm Supply Chain Compromise in Developer Environments

### The Context

Recent reporting by Elastic Security Labs in their article [Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain) details a sophisticated supply chain campaign targeting the npm ecosystem. By compromising high-download packages like `keyv` and `flat-cache`, the adversary gains execution on developer workstations during the installation phase. This hunt focuses on the endpoint-resident behavior of this malware, which uses a secondary JS runtime and modifies IDE settings to maintain persistence.

### Hypothesis

An adversary has compromised local developer environments by installing trojanized npm packages that establish persistence in IDE configurations and harvest credentials using a bundled JS runtime. We expect to see evidence of the infection starting with specific package installations, followed by the execution of a dropper that facilitates subsequent data exfiltration.

### How the Hunt Flows

The hunt begins by scoping the environment using software inventory data. We search for the presence of known-compromised packages—specifically `keyv`, `flat-cache`, and `cacheable-request`—within the npm registry on developer hosts. This provides a high-fidelity list of potentially exposed machines to prioritize for behavioral analysis.

Once the scope is defined, we look for process execution patterns. The malware typically executes a dropper named `setup.mjs` via `node` or a downloaded `bun` runtime. We monitor for these specific command-line arguments and the hashes of the known malicious JS components. Identifying the `bun` runtime in a non-standard path is a significant pivot point for this campaign.

Next, the hunt examines persistence mechanisms within developer tooling. The CHAINDROP malware attempts to inject hooks into VS Code (`tasks.json`) and Claude Code (`settings.json`) configurations. We monitor file activity for modifications to these specific JSON files by `node` or `bun` processes, which is highly atypical for standard development workflows.

Finally, we audit access to credential stores. The collector component of the malware targets sensitive paths including `~/.aws/credentials`, `~/.npmrc`, and SSH keys. By aggregating file access events from the suspected malicious runtimes, we can differentiate between legitimate developer activity and automated credential harvesting.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, if the `bun` binary or the dropper scripts are deleted immediately after execution, the process evidence may be ephemeral depending on the EDR's capture frequency. Second, while we can detect that an IDE configuration file was modified, we cannot inspect the specific file content (such as the presence of 'folderOpen' hooks) through standard file activity logs alone; this requires supplementary script or integrity monitoring.

### Beyond Detection

While a standard detection rule might alert on the execution of `setup.mjs`, this hunt provides a more comprehensive view of the compromise. It correlates the initial package installation with both the persistence and the impact (credential access), allowing responders to understand the full scope of the breach rather than just a single process alert.

### How to Run This Hunt

This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime compatible with the `hunt.md` standard. The queries are designed for SQLite-based telemetry surfaces and include parameters for lookback windows and host scoping.
