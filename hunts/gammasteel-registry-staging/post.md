# Gammasteel Fileless PowerShell Registry Staging

### Why This Hunt
Sekoia recently detailed the evolution of GammaSteel in their report, [FSB’s matryoshka #3/3: Gamaredon's Gammasteel Infostealer](https://www.sekoia.com/blog/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel). The malware avoids the file system by splitting its logic into dozens of small functions, encrypting them with DPAPI, and hiding them in the user's registry hive. Traditional EDR often misses these writes because the registry keys themselves are not inherently malicious until reassembled and executed in memory.

### Hypothesis
An intruder has staged encrypted PowerShell payloads in the user's Printers registry hive and is executing them via hidden processes that avoid file-based detection.

### How the Hunt Flows
The hunt begins by scoping host behavior for unusual registry write volume. The first query searches for hosts where an anomalous number of registry values are written to the Printers hive. GammaSteel typically writes approximately 71 unique keys to this location. This phase identifies potential staging without needing to decrypt the content or examine process command lines yet.

Once we identify suspicious hosts, the hunt pivots to corroborate the evidence through script activity. We examine script blocks for DPAPI-related functions, searching for PowerShell content that uses ProtectedData or SecureString cmdlets in conjunction with the string "printers". This identifies the specific logic used to stage or retrieve the encrypted payloads.

In parallel, the hunt looks for the orchestrator execution. It searches for PowerShell processes launched with hidden windows or suppressed profiles around the same time as the registry activity. An analyst then correlates these artifacts—high registry volume, cryptographic script content, and hidden processes—to confirm the GammaSteel presence.

### What the Hunt Cannot See
This hunt relies on PowerShell Script Block Logging (Event ID 4104). Without it, we see that a script ran but cannot confirm it used DPAPI to interact with the Printers hive. Furthermore, the hunt requires a stream of registry write activity. If an environment only provides periodic registry snapshots, we can identify that the keys exist but lose the connection to the specific process that created them, making attribution difficult.

### How to Run It
This hunt is available as an open-source hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook includes the SQL queries for registry, script, and process surfaces and provides a structured workflow for host isolation and manual registry remediation once you confirm the staging activity.
