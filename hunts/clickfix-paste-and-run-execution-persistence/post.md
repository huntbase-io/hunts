# Hunting ClickFix Execution and Persistence via the Windows Run Box

### Why this hunt?

This hunt follows research published by Huntress in their article, A Buffet of ClickFix: Lures, Infrastructure & Payloads (https://www.huntress.com/blog/tradecraft-tuesday-clickfix-lures-and-infrastructure). ClickFix campaigns use social engineering to bypass perimeter defenses. The adversary tricks a user into copying a command and pasting it into the Windows Run box or a terminal. Because the user acts as the execution vector, these attacks often evade standard email and web filters. This hunt provides a structured way to identify if these lures have established a persistent presence in your environment.

### The Hypothesis

An intruder tricks a user into pasting a malicious command into the Windows Run box, causing explorer.exe to spawn an obfuscated shell. This shell then establishes persistence via scheduled tasks or Run keys, typically pointing to binaries or scripts stored in user-writable paths like AppData.

### How the Hunt Flows

The scoping phase uses process telemetry to identify shell interpreters like powershell.exe or cmd.exe launched directly from explorer.exe. This specific parent-child relationship suggests the user executed a command through the Run box or a desktop shortcut rather than a standard application. The query filters for high-risk flags like -enc, iex, or bypass that commonly appear in ClickFix lure payloads.

An analyst or automated agent evaluates these initial leads to separate legitimate administrative actions from suspicious behavior. This manual or semi-automated check ensures the hunt only proceeds for hosts showing genuine signs of a social engineering lure, such as highly obfuscated command lines or connections to known-malicious domains.

For suspicious hosts, the hunt gathers deobfuscated PowerShell script block content and scans for rare persistence artifacts. It specifically looks for scheduled tasks or registry Run keys that point to user-writable paths like AppData or Public. These artifacts are baselined against the entire fleet to highlight outliers that exist on only a few machines.

The final triage correlates the timing of the initial shell execution with the creation of persistence. An analyst confirms a malicious verdict if a rare persistence mechanism appears within one minute of the shell launch from explorer.exe. This temporal link provides high confidence that the lure successfully established a persistent beachhead on the endpoint.

### Blind Spots

This hunt relies on process telemetry that includes parent-child relationships. If the EDR or logging solution does not consistently capture explorer.exe as the parent of the shell, the initial lead will not trigger. Additionally, the deobfuscation phase requires PowerShell Script Block Logging (Event ID 4104) to be enabled. If this logging is absent, the hunt must rely on less specific process and file activity to determine the intent of the shell command.

### Running the Hunt

We provide this hunt as an open hunt.md playbook. This format allows you to import the logic directly into Huntbase or any other hunt.md-aware runtime. To begin, run the scoping query to identify potential lures over the last 14 days. If the query returns results, use the provided parameters to narrow the subsequent persistence and script block investigations to those specific hosts.
