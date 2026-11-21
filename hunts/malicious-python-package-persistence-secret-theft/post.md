# Hunting for the Malicious agent-framework PyPI Package Compromise

### Why now

Elastic Security Labs recently reported in [We caught the agent-framework PyPI compromise six minutes after it published](https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published) a supply chain compromise involving the agent-framework PyPI package. The malicious versions, 1.26.1 and 1.26.2, contain a credential stealer that triggers every time a user starts a Python process.

### Hypothesis

An intruder installs a compromised version of the agent-framework package which persists via a .pth hook and harvests cloud credentials by reading environment variables from the /proc filesystem and local configuration files.

### How the hunt flows

The hunt begins with a software inventory check. The first query identifies hosts running the specific malicious versions of agent-framework. This narrows the scope to impacted systems before the analyst proceeds to deeper behavioral analysis.

Next, the hunt branches to look for indicators of persistence and initial execution. One query searches for the .pth hook files and associated telemetry scripts in the filesystem. A parallel query checks process activity for Python commands referencing these telemetry modules. This evidence proves the malicious hook successfully triggered the background stealer.

If the analyst confirms an infection, the hunt pivots to behavioral evidence. It uses Linux audit logs to detect Python processes reading environment files from other processes via the /proc filesystem. This behavior is rare. It indicates the stealer is in its harvesting phase, searching for secrets in the environment of up to 300 running processes.

In the final phase, an analyst reviews the correlated data to assign a verdict. If the hunt confirms active secret theft, the analyst isolates the host and begins rotating cloud credentials, including Azure CLI caches, .npmrc tokens, and GitHub OIDC federated credentials.

### What the hunt cannot see

This hunt relies on specific auditd configurations. If the system does not log reads to the proc filesystem, specifically /proc/*/environ, the harvesting behavior remains invisible to the behavioral query. Additionally, ephemeral containers used in CI/CD pipelines may install the package, execute the theft, and terminate before the inventory scan or file activity logs capture their state.

### How to run it

We provide this hunt as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. This allows you to automate the inventory scoping and behavioral queries across your estate while following a structured triage process for every identified host.
