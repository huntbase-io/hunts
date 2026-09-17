# Hunting ErrTraffic ClickFix Social Engineering and Infostealer Activity

Recent research from Sekoia, [Unveiling ErrTraffic: a growing ClickFix malware distribution framework](https://blog.sekoia.io/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework), details the evolution of the ClickFix delivery method. This technique relies on social engineering rather than technical exploits, persuading users to copy and run PowerShell commands from their clipboard under the guise of fixing a browser error or passing a CAPTCHA. Because the execution begins with a legitimate user action, it often bypasses standard web filters.

### The Hypothesis
We hypothesize that an intruder has successfully used a ClickFix lure to trick an employee into executing a malicious PowerShell command. This command likely facilitates the deployment of an infostealer (such as Vidar or Stealc) that targets browser credential databases. By looking for specific parent-child relationships and corroborating that with sensitive file access and infrastructure-specific DNS lookups, we can distinguish these infections from routine administrative tasks.

### How the Hunt Flows
The hunt begins by scoping the environment to workstations with active web browsers like Chrome, Edge, and Firefox. These are the primary surfaces for ClickFix lures. We use software inventory data to establish a baseline of potential targets before moving into behavioral analysis.

We then examine process activity for instances of PowerShell or Pwsh being spawned directly from a browser or Windows Explorer. We specifically look for commands containing download keywords like `invoke-webrequest` or `downloadstring`, as well as shorthand encoded flags. This phase identifies the initial execution pattern that follows a user pasting a command from a malicious lure.

To increase confidence, we pivot into corroborating data across multiple surfaces in parallel. We examine de-obfuscated PowerShell script blocks for hidden URLs that may have been Base64-encoded in the process command line. Simultaneously, we look for rare, non-browser processes accessing sensitive files such as the 'Login Data' or 'logins.json' databases. Finally, we check for DNS resolutions to unusual TLDs like .beer, .cfd, and .xyz, which are commonly used in ErrTraffic's Traffic Distribution System (TDS).

The final phase involves an automated triage of these signals. We aggregate the findings for each host to determine if the combination of suspicious parentage, script content, and file access constitutes a malicious event. This multi-surface correlation is what allows us to move beyond simple detection alerts that might trigger on any PowerShell usage.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, it relies on robust PowerShell script block logging; if a script is exceptionally large or the logging is disabled, we may miss the de-obfuscated download logic. Second, because ClickFix involves a manual copy-paste action, we lack visibility into the clipboard contents prior to execution. We see the result of the action, but not the preceding social engineering interaction itself.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the hunt.md standard. It is designed to be run periodically or in response to new threat intelligence regarding ClickFix campaigns.
