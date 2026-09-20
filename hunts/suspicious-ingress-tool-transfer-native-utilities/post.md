# Hunting for Malicious File Transfers via Native Utilities

### Why now
Recent research from Elastic Security Labs, [How Elasticsearch ES|QL COMPLETION turns noisy curl and wget rules into high-fidelity cloud security alerts](https://www.elastic.co/security-labs/blog/esql-completion-curl-wget-detection-triage), highlights how native utilities are abused for ingress tool transfer. In many environments, a simple alert on curl or wget creates an unmanageable volume of false positives from package updates and CI/CD pipelines.

### The hypothesis
An adversary is using native Linux or macOS utilities like curl or wget to download malicious payloads from external infrastructure, hiding their activity within the high volume of legitimate cloud automation.

### How the hunt flows
The hunt starts by scoping the environment. The first query searches the software inventory for hosts that have curl or wget installed. This limits the footprint of subsequent behavioral queries to relevant assets.

Following the scope, the hunt fans out into two parallel telemetry searches. One query identifies process executions with command lines that are rare across the fleet. It looks for utility usage that appears on very few hosts. Simultaneously, a second query monitors outbound network connections from these utilities. It specifically ignores known cloud metadata services and platform IPs to focus on external destinations.

Results from both surfaces feed into an automated triage agent. This agent evaluates the combined evidence, weighing rare command lines against the nature of the network destination. It generates a verdict for each host, allowing an analyst to focus only on high-fidelity leads. If the agent confirms malicious activity, the playbook provides a route to isolate the endpoint immediately.

### What the hunt cannot see
We face two primary blind spots. First, if network telemetry lacks process-to-connection mapping, we must correlate by timestamp. This is less reliable than a direct PID mapping. Second, if an adversary renames the utility binary, our process name filters will not see the activity. We rely on the process name remaining unchanged to find the initial signal.

### How to run it
This hunt is available as a `hunt.md` playbook. It can be imported into Huntbase or any compatible runtime to automate the data collection and triage steps. Practitioners can adjust the prevalence thresholds and cloud IP exclusions to match their specific environment requirements.
