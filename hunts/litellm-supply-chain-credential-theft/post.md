# Hunting LiteLLM 1.107.0 Supply Chain Compromise and Credential Harvesting

### Why now
Microsoft recently detailed a supply chain attack in the [Inside the LiteLLM 1.107.0 supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) blog post. An adversary distributed a malicious version of the LiteLLM library via PyPI. This version executes a payload called PRIVCOLLECT whenever any Python process starts. This technique is dangerous because it captures credentials silently without requiring the user to explicitly call the compromised library.

### The Hypothesis
An intruder distributed a compromised version of LiteLLM (1.107.0) that uses Python startup hooks to execute a credential harvester upon any Python invocation. This harvester targets cloud provider keys, SSH identities, and browser-stored secrets. We expect to find the package in software inventories and see corresponding file activity where Python processes access sensitive configuration files they typically ignore.

### How the hunt flows
The first phase uses software inventory data to scope the environment. The query scans every host for the specific `litellm` package version `1.107.0`. Because developers and CI/CD systems often use virtual environments, the hunt examines the installation path to pinpoint where the malicious code resides. This scoping provides the list of targets for deeper behavioral analysis.

Next, the hunt runs two parallel behavioral checks. The first check uses stack-counting to identify rare file access. It looks for Python processes reading AWS, SSH, or Kubernetes configuration files. If only a few hosts show Python interacting with these paths, those systems move to the top of the triage list. The second check searches for high-fidelity indicators of the PRIVCOLLECT payload, specifically the creation of `.pc_once` markers and `.pc_e` temporary directories used for staging stolen data.

In the final phase, an agent or analyst triages the findings. A host showing both the compromised package and behavioral markers is a confirmed infection. The hunt then directs the analyst to isolate the host and terminate all Python processes. Because this attack focuses on credential harvesting, the response includes a manual task to rotate every secret found on the affected system.

### What the hunt cannot see
This hunt relies on file activity telemetry to detect the harvest. If the environment lacks detailed file-read auditing (such as Linux auditd or Sysmon EventID 1), we can see that the malicious package exists, but we cannot confirm if the adversary successfully read the content of the secrets. We only see the intent and the presence of the harvester.

Furthermore, supply chain attacks often target ephemeral build environments. If a CI/CD runner is infected, steals a secret, and is destroyed before the software inventory scan runs, the hunt will miss that host. This highlights the need for real-time composition analysis in build pipelines.

### How to run it
This hunt is provided as an open `hunt.md` playbook. You can import this file directly into Huntbase or any compatible `hunt.md` runtime. The playbook contains the logic to automate the scoping and behavioral queries, providing a unified view of the compromise across your fleet.

### Why this is a hunt, not a detection
A standard detection rule for a package version is necessary but often generates noise or lacks context. This hunt provides the behavioral evidence—rare credential access and specific payload markers—needed to confirm exploitation. By moving from a version check to a behavioral investigation, we verify if the threat actually executed and stolen secrets, rather than just identifying a package sitting idle in a directory.
