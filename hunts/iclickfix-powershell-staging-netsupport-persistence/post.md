# iClickFix: Tracking PowerShell Staging and NetSupport RAT Persistence

### Background
Recent research by Sekoia, titled [Meet IClickFix: a widespread WordPress-targeting framework using the ClickFix tactic](https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/), details how thousands of compromised WordPress sites are being used to deliver the NetSupport RAT. The framework relies on social engineering, prompting users to execute a PowerShell command to "fix" a browser error. Once executed, the stager establishes persistent access.

### The Hypothesis
We assume an intruder has successfully used a ClickFix social engineering prompt to trick a user into running an obfuscated PowerShell stager. This stager downloads NetSupport RAT components into the ProgramData directory and establishes persistence via a Windows Registry Run key to maintain access across reboots.

### How the Hunt Flows
The hunt moves through five distinct phases of telemetry analysis to correlate disparate events into a single infection story.

**Phase 1: Identifying the Stager**  
We begin by querying process activity for PowerShell executions utilizing hidden window styles and non-interactive flags. We specifically look for instances where `Invoke-WebRequest` or its aliases are used to pull payloads from external endpoints. This captures the initial execution following the web-based lure.

**Phase 2: Script Logic Extraction**  
Command lines are often truncated or heavily obfuscated. We pivot to script block telemetry to examine the actual logic being executed in memory. We look for specific strings related to the iClickFix infrastructure and common NetSupport filenames like `client32.exe`. This helps confirm the intent of the stager even if the process command line was masked.

**Phase 3: Persistence Verification**  
Next, the hunt examines registry activity, specifically looking for new or modified entries in the `CurrentVersion\Run` keys. We filter for values that point to the ProgramData directory or known NetSupport binaries. This identifies how the malware intends to survive a restart.

**Phase 4: ProgramData Baselining**  
Because ProgramData is a common staging area for both legitimate software and malware, we apply a frequency analysis. We look for rare executables launched from non-Microsoft subfolders of ProgramData that appear on fewer than three hosts across the environment. This helps isolate unique installer behavior associated with the RAT.

**Phase 5: Network Correlation**  
Finally, we enrich the host-based findings with DNS activity. We look for queries made to the specific C2 and stager-hosting domains identified in the research. By correlating these network requests with the rare processes identified in earlier steps, we can confirm active command-and-control communication.

### Blind Spots and Limitations
This hunt relies heavily on endpoint visibility. If EDR coverage is missing on specific workstations, the persistence mechanism may remain invisible. Additionally, without PowerShell Script Block Logging (Event ID 4104) enabled, the hunt may fail to decode the full logic of highly obfuscated stagers, relying instead on simpler process-level indicators. It is also important to note that silence in registry logs only indicates that no *new* writes were captured during the lookback period; it does not guarantee that a Run key does not already exist.

### How to Run This Hunt
This hunt is provided as an open-source `hunt.md` playbook. It is designed to be imported into Huntbase or any hunt.md-aware runtime. By providing the environment-specific C2 domains as parameters, you can customize the network phase to match the latest threat intelligence. The playbook includes a built-in triage agent to synthesize the results from all five phases and provide a per-host verdict.
