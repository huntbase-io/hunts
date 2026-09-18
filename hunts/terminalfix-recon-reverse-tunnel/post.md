# TerminalFix Reverse Tunneling and Asynchronous PowerShell Command Loops

Microsoft recently detailed the TerminalFix campaign in their report, [TerminalFix campaign deploys a reverse tunnel through multistage intrusion](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/). This adversary establishes persistence and internal network access by deploying a reverse WebSocket tunnel that bypasses typical ingress firewall restrictions.

### The Hypothesis
An adversary has established a persistent network-level proxy using a Python-based reverse WebSocket tunnel and a PowerShell file-watching loop. This combination allows the attacker to maintain an interactive proxy for SOCKS-style traffic and an asynchronous command-and-control channel that monitors local files for new instructions.

### How the Hunt Flows
The hunt begins by scoping for known infrastructure. We look for DNS resolutions of domains like `gitnow.dev` and the execution of Python interpreters (`pythonw.exe` or `python.exe`) that are frequently used to run the `client.py` tunnel script in a hidden state.

Once potential hosts are identified, we move to behavioral stacking. We analyze outbound network connections originating specifically from Python processes. By looking for connections to high ports or non-standard endpoints that appear on only a few hosts across the fleet, we can identify the reverse tunnel activity even if the C2 domain has been rotated.

Simultaneously, the hunt searches for a specific PowerShell script pattern that utilizes `FileSystemWatcher`. This pattern identifies the attacker's 'primitive shell' which monitors a local text file for commands and executes them using `Invoke-Expression`. This allows for a parallel check on host activity that does not rely on direct network telemetry.

Finally, we look for the physical presence of the script artifacts, such as `client.py` or supporting batch files. The triage phase correlates these findings, providing a per-host verdict on whether the machine is being used as a network ingress point.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, without PowerShell Script Block Logging (Event ID 4104) enabled, we can identify the infrastructure for the file-watching loop, but we cannot see the actual reconnaissance commands executed through it. Second, if the EDR or network telemetry lacks process-to-network linking, the WebSocket traffic may be difficult to distinguish from legitimate HTTPS traffic to shared hosting providers.

### How to Run the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any hunt.md-aware runtime. It uses a series of SQLite-based queries designed to stack behaviors across your environment rather than just matching static indicators. The design is built to identify the underlying capability of the TerminalFix toolkit, providing a higher degree of confidence than simple domain blocking.
