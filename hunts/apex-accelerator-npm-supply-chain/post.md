# Hunting Apex Accelerator Malicious npm Supply Chain Packages

### Why now

Elastic Security Labs recently published research titled [Auditing the auditor: Unmasking Apex Accelerator](https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages). The report details a campaign targeting crypto start-ups and Web3 developers through malicious npm packages. These packages, such as `@apexacc/cli`, appear to be legitimate auditing tools but actually deploy platform-specific backdoors. This hunt provides a structured way to identify these packages and any subsequent execution on developer workstations.

### The hypothesis

An adversary targets developer workstations by tricking users into installing malicious npm packages that masquerade as Web3 auditing tools to execute platform-specific backdoors from within the project directory. Once installed, these packages drop hidden configuration folders and launch binaries directly from the `node_modules` tree to establish command and control.

### How the hunt flows

The hunt begins with a scoping phase focused on software inventory. A query against `hb_software_inventory` searches for the specific package names identified in the research and looks for the presence of hidden `.apex` directories within `node_modules`. This first step identifies which hosts and users are potential leads without requiring expensive process telemetry from the entire fleet.

An analyst then evaluates these initial leads. If the software inventory shows no signs of the Apex Accelerator packages, the hunt concludes to save resources. If a lead is confirmed, the hunt gates into a more intensive behavioral analysis phase focused only on the suspicious hosts.

The behavioral phase runs two queries in parallel to corroborate the infection. The first query searches `hb_process_activity` for any executable binary—such as PE files on Windows or Mach-O files on macOS—that launches from a `node_modules` directory. This generalized search captures the loader even if the adversary renames it. The second query examines `hb_network_connection` to find outbound network callbacks initiated by these same processes, identifying the C2 channel.

Finally, the analyst triages the correlated evidence. By combining the inventory lead with confirmed execution and network activity, the analyst reaches a high-confidence verdict. If the activity is malicious, the hunt provides a direct action to isolate the host and preserve its memory for deeper forensic review.

### What the hunt cannot see

This hunt has two primary blind spots. First, local npm installations may not always appear in global software inventory scanners, depending on how the endpoint agent collects data. Second, the hunt relies on high-fidelity process attribution for network flows. If the telemetry cannot reliably link a network connection to the specific binary running in a project directory, the analyst must manually bridge that gap during triage.

### How to run it

This hunt is available as an open `hunt.md` playbook. It follows a modular structure that imports into Huntbase or any other `hunt.md`-aware runtime. To begin, configure the `target_packages` parameter with the latest indicators from the Elastic research and run the software inventory scoping query.
