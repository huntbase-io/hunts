# Identifying Payment Data Harvesting via Compromised IIS Web Workers

### Why This Hunt

A recent report from Huntress, [Determined Attacker Uploads Malicious Webshells to Parks and Rec Management Platform Servers](https://www.huntress.com/blog/parks-recreation-platform-webshell-attack), details an adversary using web shells to scour IIS servers for payment data. The attacker did not stop at initial access; they used shell access to run discovery tools and search for sensitive information like credit card numbers and database credentials. This hunt provides a structured way to find this behavior in environments where web servers handle sensitive transactions.

### The Hypothesis

An intruder uses a compromised IIS web worker to execute discovery tools and search for payment card data or database credentials. Instead of just establishing a persistent connection, the adversary actively probes the local file system for configuration files and transaction logs to extract value from the compromised host.

### How the Hunt Flows

The hunt begins with a cheap lead query to identify interactive command shells spawned by the IIS web worker (w3wp.exe). The query looks for common interpreters like cmd.exe, powershell.exe, or wmic.exe appearing as child processes. An analyst reviews these instances to determine if the activity represents a human operator or legitimate application behavior.

If the lead identifies suspicious shell activity, the hunt gates into a parallel fan-out phase. The first branch of this phase searches for rare administrative commands. It uses prevalence counting to find tools like whoami.exe, netstat.exe, or findstr appearing on three or fewer hosts. This helps isolate unique attacker reconnaissance from widespread automated management scripts.

Simultaneously, the second branch monitors file activity for sensitive access. It watches for shell processes or the web worker itself reading configuration files like web.config or accessing directories associated with payment webhooks. Accessing these files via a shell is a high-confidence indicator of an intruder searching for secrets or harvesting transaction data.

Finally, the hunt correlates the command-line evidence with the file access patterns. An analyst confirms the verdict by looking for the specific chain of events: shell launch, environment discovery, and targeted data harvesting. If confirmed, the hunt provides instructions for host isolation and forensic preservation.

### What This Hunt Cannot See

This hunt relies on process and file telemetry from an endpoint agent. If a web server is not enrolled in monitoring, the adversary can execute shells and harvest data invisibly. Additionally, if the attacker uses obfuscated or encoded PowerShell commands (-enc), the process command-line query will not see the underlying intent without deep script block logging. The hunt also assumes the adversary uses common shell interpreters; custom binaries that do not spawn a shell child process may evade the initial lead.

### How to Run It

This hunt is provided as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md specification. Because the initial lead is inexpensive, you can run it across large web server estates to identify hosts that require deeper, more resource-intensive file activity analysis.
