# Hunting for iClickFix Web Redirection and PowerShell Execution

Recent research by Sekoia in [Meet iClickFix: a widespread WordPress-targeting framework using the ClickFix tactic](https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/) highlights a framework targeting WordPress sites to serve ClickFix lures. These lures bypass automated detection by requiring manual user action to initiate the infection.

### The Hypothesis
An intruder is leveraging compromised WordPress sites to deliver a 'ClickFix' social engineering lure, tricking users into executing a PowerShell command that downloads a RAT payload staged in ProgramData. This manual execution bypasses many traditional perimeter blocks and endpoint signatures that focus on automated exploitation.

### How the Hunt Flows
The hunt begins by scoping the fleet to hosts that possess both a web browser and PowerShell capabilities, as these are the necessary components for the ClickFix chain to succeed.

Infrastructure monitoring follows, looking for rare DNS lookups to Traffic Direction System (TDS) domains or suspicious TLDs like .pro and .js. We use prevalence to identify domains that are uncommon across the environment, which helps surface new or rotating infrastructure used by the framework.

Simultaneously, we analyze script activity for indicators of the social engineering lure itself. We look specifically for script blocks that use the browser's clipboard API to write text while including strings like 'Verify you are human' or instructions involving 'Ctrl + V'.

Finally, we monitor for the execution of the PowerShell dropper. This stage looks for PowerShell processes initiated with hidden windows and no-profile flags that use Invoke-WebRequest to download remote scripts into C:\ProgramData\. An automated triage agent correlates these DNS, script, and process signals to identify confirmed infection chains.

### What This Hunt Cannot See
This hunt has two primary blind spots. First, it relies on browser-level script logging (hb_script_activity). If certain browsers in the environment do not report this telemetry, the hunt will lose the social engineering context and rely solely on the PowerShell execution signal. Second, the redirection often occurs well before the user executes the command; if DNS retention is shorter than the lookback window, the initial redirection may be missed.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any other hunt.md-aware runtime to automate the correlation of the telemetry surfaces described above. Because this is a hunt, it focuses on identifying the specific behavioral sequence rather than relying on static file hashes or known-bad IPs.
