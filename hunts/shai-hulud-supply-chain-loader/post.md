# Shai-Hulud Supply Chain Hook and Loader Bootstrap

### Why this hunt

Datadog Security Labs recently published an analysis of the Shai-Hulud framework: "Shai-Hulud open source framework static analysis" (https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/). This modular framework specifically targets the developer supply chain. It does not rely on typical malware delivery vectors. Instead, the adversary hooks into tools developers use every day, such as VSCode and the Claude Code AI assistant, to stage its loaders.

### The Hypothesis

The adversary poisons a developer repository or AI coding assistant configuration to execute the Shai-Hulud loader and establish daemonized persistence. By embedding malicious tasks in a repository configuration, the framework ensures its code runs as soon as a developer opens the project or interacts with an AI assistant. This configuration hook is a stealthy entry point that bypasses traditional file-scan-on-execution defenses.

### How the hunt flows

The investigation begins with the entry point on the hb_file_activity surface. The first query identifies the creation of specific loader files like setup.mjs, config.mjs, and PYTHON_LOADER.py. It also monitors modifications to configuration files like .vscode/tasks.json and .claude/settings.json. These files bootstrap the infection by triggering shell execution when the developer interacts with their local development environment.

After the initial scan, an analyst reviews the leads to confirm if the file activity matches Shai-Hulud staging patterns. This gate prevents the unnecessary execution of expensive, high-volume telemetry queries across the entire environment. The analyst only proceeds to the fan-out phase for hosts where suspicious hook modifications are present. This is a hunt rather than a detection because modifications to these configuration files occur frequently in legitimate development; the context of the change is the deciding factor.

The hunt then pivots to search for execution and persistence in parallel using the hb_process_activity and hb_scheduled_job surfaces. One query finds rare processes running with the __daemonized=1 flag or referencing specific lock files associated with the framework. Simultaneously, the hunt searches for persistence mechanisms, such as systemd services or LaunchAgents named gh-token-monitor. The framework uses these components to monitor for secret revocation and maintain a foothold.

### What the hunt cannot see

This hunt relies on file and process telemetry from the endpoint. If a developer works on a host without an enrolled endpoint agent, the adversary can stage a poisoned repository and execute the loader without detection. Additionally, the hunt uses specific indicator names like gh-token-monitor. If the adversary rotates these names or changes the daemonization flags from the defaults identified in research, the specific queries will return no results.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the gated queries across your estate. The design focuses on developer workstations and CI/CD runner environments where supply chain hooks are most likely to appear. It allows an analyst to confirm the presence of the framework and initiate containment before the adversary can trigger destructive actions.
