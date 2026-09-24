# Hunting Mallox Ransomware MSSQL Initial Access and Execution

### Why this hunt

Recent research from Sekoia, [Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation](https://blog.sekoia.io/mallox-ransomware-affiliate-leverages-purecrypter-in-microsoft-sql-exploitation-campaigns/), details a consistent pattern of initial access. Adversaries target internet-exposed Microsoft SQL servers with brute-force attacks against the `sa` account. Once they gain access, they use stored procedures like `xp_cmdshell` or OLE automation to execute PowerShell commands. This hunt focuses on the transition from authentication abuse to system execution.

### The Hypothesis

An adversary brute-forces the MSSQL `sa` account to enable administrative features and execute a PowerShell loader from the SQL process.

### How the hunt flows

The hunt begins by identifying every host in the environment running Microsoft SQL Server. This scoping step uses software inventory data to narrow the field of investigation. This reduces the processing load for the subsequent behavioral queries and focuses the analyst on relevant assets.

The second phase runs two queries in parallel. One query scans identity logs for high-volume sign-in failures against the `sa` account or other known administrative users. Simultaneously, another query monitors process activity for `sqlservr.exe` spawning shells such as `cmd.exe`, `powershell.exe`, or `wmic.exe`. While both events might occur independently in a busy environment, their temporal proximity on a single host indicates a high-fidelity intrusion.

In the final phase, an analyst correlates these findings. The goal is to determine if a period of intensive brute-force activity precedes the launch of a shell from the SQL service. This correlation identifies the moment the adversary successfully gains execution privileges. If confirmed, the hunt provides instructions for immediate host isolation and forensic auditing of the SQL engine settings.

### What the hunt cannot see

This hunt relies on process creation events and authentication logs. It does not see internal SQL configuration changes that do not result in a process launch, such as enabling the `TRUSTWORTHY` bit or loading CLR assemblies. These actions require internal SQL trace or audit logs. Additionally, if the adversary uses heavily obfuscated PowerShell script blocks, simple command-line inspection may not reveal the specific download URIs or intent of the secondary payload.

### How to run it

This hunt is available as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any hunt.md-aware runtime. It uses standard SQL-like syntax to query authentication and process telemetry surfaces. You can adjust parameters like the `lookback_days` or the list of `target_accounts` to fit your environment's baseline.

Source: Sekoia — Mallox ransomware affiliate leverages PureCrypter in MSSQL exploitation
