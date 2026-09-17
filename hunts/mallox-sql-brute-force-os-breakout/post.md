# Mallox: SQL Server Brute-Force to OS Breakout

Recent research from [Sekoia — Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation](https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/) highlights a persistent trend: attackers targeting publicly exposed SQL Servers to gain an initial foothold. These affiliates rely on high-volume brute-force attacks against the 'sa' account, eventually using database features to execute OS-level commands and drop loaders like PureCrypter.

### The Hypothesis
An adversary is targeting exposed SQL Servers with high-frequency brute-force attempts. Upon successful authentication, they will attempt to execute OS-level commands via database shell breakouts (such as `xp_cmdshell` or OLE automation) to facilitate further payload delivery.

### How the Hunt Flows
The hunt begins by scoping the environment to identify all hosts running Microsoft SQL Server components. This ensures we are only processing authentication and process telemetry for the relevant attack surface, reducing the potential for false leads from unrelated systems.

In the first triage phase, we look for high-volume authentication failures specifically targeting the 'sa' account. We use a threshold-based approach to filter out background internet noise, focusing only on sources that demonstrate a sustained brute-force effort over a defined lookback period. These IPs and target hostnames become our primary leads for the next stage.

In the second phase, we pivot to endpoint telemetry to find evidence of a successful breakout. We specifically look for the `sqlservr.exe` process acting as a parent to system shells like `cmd.exe`, `powershell.exe`, or administrative tools like `wmic.exe`. We also perform a rare-child-process analysis to find unique binaries spawned by the SQL engine that may represent custom loaders or dropped tools.

The final phase uses an automated agent to correlate the brute-force leads with the process execution events. If a host shows both a high-volume brute-force attempt and a subsequent shell breakout, it is flagged for immediate isolation and manual review of the command lines to identify downstream activity.

### Blind Spots and Limitations
This hunt relies heavily on process visibility. If an endpoint agent is not present on the SQL Server host, the breakout will be invisible to this playbook even if the brute-force is detected in authentication logs. Additionally, this hunt focuses on the most common breakout method: direct shell spawning. An attacker who uses more stealthy methods—such as modifying internal SQL parameters like `TRUSTWORTHY` or `clr enabled` to load malicious assemblies without spawning a visible shell—might bypass the process-based detection logic.

### How to Run the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any runtime that supports the hunt.md specification. Once imported, you can adjust the lookback period and minimum failure thresholds to match your environment's typical traffic patterns before executing the queries and correlation steps.
