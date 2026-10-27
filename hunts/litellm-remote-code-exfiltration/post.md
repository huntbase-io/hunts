# Hunting LiteLLM 1.107.0 Remote Code Loading and Credential Exfiltration

### Why hunt for LiteLLM behavior

Microsoft recently detailed a supply chain attack in [Inside the LiteLLM 1.107.0 supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/). The adversary injected malicious startup hooks into the package to facilitate remote code execution and credential exfiltration. While detection rules often target the installation of the package itself, this hunt focuses on the subsequent execution of the payload. Identifying which hosts actually reached the exfiltration stage is critical for response, as it distinguishes between a dormant installation and a successful breach.

### The hypothesis

An adversary uses malicious Python startup hooks in a compromised version of LiteLLM to execute a remote code loader. This loader downloads configuration from GitHub or adversary-controlled domains, then packages and exfiltrates encrypted credential archives from the local system. The adversary stages these files in transient directories before uploading them and cleaning up the local environment.

### How the hunt flows

The hunt begins by narrowing the scope to the vulnerable software. The first step queries the software inventory surface to list every host running LiteLLM version 1.107.0. This provides the primary list of targets for deeper behavioral analysis.

After identifying vulnerable hosts, the hunt pivots to network telemetry. It searches DNS logs for Python or Pip processes resolving specific domains used for exfiltration or loader configuration. This step looks for connections to litellm.dev or GitHub raw content domains that occur outside of standard package management windows.

Simultaneously, the hunt examines file system activity for staging artifacts. The adversary uses specific filenames like data.bin and key.bin, and stages data in hidden directories beginning with .pc_e_. The hunt also looks for a specific lock file used by the remote code loader to prevent multiple executions. These indicators confirm that the malicious hooks successfully activated on the endpoint.

An analyst or automated agent then correlates these signals. A host with both the vulnerable package version and corresponding network or file activity receives a high-confidence verdict for compromise. This allows the team to prioritize these specific systems for isolation and secret rotation.

### Blind spots

This hunt has two primary blind spots. First, the payload attempts to delete its temporary staging files and directories after exfiltration. If the file system telemetry does not capture the creation event or lacks deletion records, the on-disk evidence may vanish. Second, short-lived Python processes might initiate lookups and exit before the endpoint collector captures the full process metadata, potentially leaving the DNS activity unattributed to a specific process name.

### How to run this hunt

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. The playbook includes the specific logic to join software inventory with behavioral telemetry. Ensure your environment retains at least 14 days of DNS and file activity logs to cover the period since the compromise became public.
