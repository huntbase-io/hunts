# Hunting Identity-Based Lateral Movement and Credential Harvesting

### Why this hunt?

The DFIR Report recently published "Blurring the Lines" (https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/), which details an intrusion where attackers used a mix of techniques from different ransomware playbooks. The report highlights how adversaries focus on administrative accounts to move toward critical systems like domain controllers and backup infrastructure. This hunt provides a structured way to find these identity-based pivots before the final stage of an attack. Identity remains the most consistent choke point in modern intrusions, and monitoring it provides the best chance for containment.

### The Hypothesis

An intruder moves laterally to high-value infrastructure like domain controllers and backup servers using hijacked accounts or newly created local admins, then executes scripts to harvest credentials.

### How the Hunt Flows

The hunt begins with a scoping phase on the hb_auth_signin surface. The query identifies successful logins to domain controllers and backup servers that occur rarely. Specifically, it filters for logins seen fewer than ten times from a specific source IP or user within the lookback period. This step isolates the rare administrative access that characterizes account takeover or unauthorized pivoting across the identity plane.

In the second phase, the hunt fans out to search for evidence of activity following these logons. It examines the hb_script_activity surface for keywords like "veeam", "sam", or "sekurlsa". These strings suggest the intruder is attempting to extract secrets from the registry or backup software secrets. At the same time, the hunt checks the hb_process_activity surface for the execution of tools like PsExec or NetScan, and command lines that create new local administrator accounts using the net user command.

The corroboration phase is critical because many attackers use scripts to avoid dropping binaries on disk. By searching for strings related to the Security Account Manager (SAM) or specific backup vendors, the hunt targets the most likely objectives of an attacker who has gained access to a critical server. This combined approach reduces false positives that a single logon rule might generate.

In the final phase, an analyst triages the results. They look for a temporal connection between the rare login and the suspicious script or process execution. If the analyst confirms a malicious link, the hunt directs them to isolate the host and reset the compromised credentials to stop the intrusion. This structured triage ensures that automated or legitimate administrative tasks are correctly identified and dismissed.

### What the Hunt Cannot See

This hunt has specific blind spots. It cannot distinguish between an RDP session using a saved credential and one using an interactive login because the sign-in data lacks granular logon type details. Furthermore, if an adversary uses custom tools that do not match the keyword list, or if they execute code entirely in memory without leaving script block logs, the queries will not identify the activity. Obfuscated PowerShell content also poses a challenge if the script block logging does not capture the de-obfuscated commands.

### Running the Hunt

This hunt is a hunt.md playbook. You can import it into Huntbase or any other hunt.md-aware runtime. The playbook contains all the necessary queries, parameters, and instructions to execute the search across your environment. By importing the file, you can immediately begin scanning for the administrative pivots described in the DFIR Report.
