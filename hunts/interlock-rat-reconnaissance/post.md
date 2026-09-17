# Hunting Interlock RAT Post-Exploitation Discovery and Backup Enumeration

### Background
In a recent investigation by The DFIR Report, "KongTuke FileFix Leads to New Interlock RAT Variant" (https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/), analysts detailed the deployment of a PHP-based Remote Access Trojan (RAT). Once established, this variant initiates a discovery phase characterized by both automated profiling and manual hands-on-keyboard enumeration of Active Directory and backup systems.

### Hypothesis
We hypothesize that an intruder is using a PHP-based beachhead to execute PowerShell-based discovery. The adversary aims to map the network, identify domain controllers, and locate backup infrastructure—such as Veeam or VBR servers—to ensure maximum impact during the eventual ransomware phase.

### Hunt Flow
The first phase of the hunt scopes the environment for the execution of the PHP interpreter from user-writable paths. The Interlock RAT variant has been observed running `php.exe` or renamed versions of the binary from the `AppData\Roaming` directory. This surface is high-fidelity for scoping because legitimate PHP usage is typically confined to server-side environments or standard program files.

Once suspicious execution is identified, the hunt pivots to PowerShell script block activity. We look for automated system profiling where discovery commands are piped to `ConvertTo-Json`. This specific pattern is used by the RAT to structure host context (network neighbors, system information, and task lists) for exfiltration back to the C2 server.

Finally, the hunt incorporates a stack-counting phase to identify rare manual discovery. We aggregate script blocks that contain keywords related to Active Directory searching (`adsisearcher`, `nltest`) and backup software identification (`veeam`, `vbr`, `bck`). By filtering for commands that appear on three or fewer hosts, we can isolate the specific reconnaissance activity that deviates from the baseline of administrative noise.

### Blind Spots and Constraints
This hunt relies heavily on PowerShell Script Block Logging (Event ID 4104). Without this logging enabled, the visibility into the automated profiling commands is significantly reduced, leaving only the process execution of the PHP interpreter as a lead. Additionally, heavily obfuscated or base64-encoded command lines may evade the keyword-based components of this hunt unless the runtime performs de-obfuscation before logging.

### Implementation
This hunt is provided as a `hunt.md` playbook. This format allows it to be imported into Huntbase or any other `hunt.md`-aware runtime for immediate execution across your fleet. It provides a structured path from initial scoping to host isolation, ensuring that the triage process is consistent and repeatable. This is a hunt rather than a static detection because it requires stack-ranking and manual verification of administrative tools that may have legitimate uses in your environment.
