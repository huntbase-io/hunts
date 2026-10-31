# Hunting for Amatera Infostealer Initial Access and Persistence

### Why now

Recent research from ESET, "Amatera: How the prolific infostealer works and spreads" (https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/), details a professionalized infostealer campaign. Amatera uses social engineering to trick victims into pasting malicious commands directly into Windows system utilities. Because this "ClickFix" technique relies on user interaction and variable command strings, traditional static detections often fail. This hunt identifies the full lifecycle of the threat, from initial paste to persistent execution.

### The Hypothesis

An intruder uses social engineering to trick a user into executing PowerShell commands from the Run dialog, leading to the installation of the Amatera infostealer and persistent scheduled tasks.

### How the hunt flows

The hunt begins by scoping the estate to developer-class workstations. The query searches for software like JetBrains, Claude, or Snowflake. These hosts represent high-value targets for infostealers because they contain session tokens, SSH keys, and cloud credentials.

Next, the hunt identifies initial infection signals. It looks for explorer.exe spawning PowerShell or Rundll32 with download-related or encoded flags. This process relationship is the hallmark of a user manually pasting a command into the Run dialog. Simultaneously, the hunt checks DNS logs for resolutions to known Amatera infrastructure like psw.amatera.

An analyst then triages these early signals. If a host shows suspicious execution corroborated by network activity, the hunt moves to find persistence. It examines the creation of new scheduled tasks, specifically those pointing to user-writable paths or running further PowerShell commands.

Finally, the hunt checks for defense evasion. The adversary often deletes the PowerShell ConsoleHost_history.txt file to remove the record of the initial pasted command. The hunt looks for these specific file deletions on the flagged hosts. This correlation of delivery, network activity, persistence, and evasion forms a high-confidence verdict for infection.

### Blind Spots

This hunt faces two primary limitations. First, if the initial infection occurred outside the 14-day telemetry retention window, the hunt may only see the persistence and evasion steps. Second, we cannot see the user's clipboard. We rely on the process relationship between explorer.exe and the shell to infer a manual paste occurred.

### How to run it

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard to automate the scoping and parallel query phases. If the hunt confirms an infection, the playbook provides instructions for host isolation and mandatory secret rotation for the affected user.

### Why this is a hunt

A single detection rule for PowerShell execution from the Run dialog often generates significant noise from administrators. This hunt manages that noise by pivoting through three distinct phases: the execution context, external network indicators, and the presence of new persistence mechanisms. This multi-stage verification is necessary to distinguish accidental user errors from active malware campaigns.
