# Hunting SCKit persistence and ScreenConnect RelayTrap session hijacking

### Why now

Microsoft Security Blog published details on [SCKit abuses ScreenConnect to deploy remote access and target technician sessions](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/). The research describes a sophisticated toolkit that exploits a specific ScreenConnect vulnerability to establish persistence and hijack active sessions. This hunt provides a systematic way to find the toolkit across your estate.

### The hypothesis

An intruder who has compromised a ScreenConnect client maintains access via script-based Registry persistence and uses the RelayTrap component to target connecting technician sessions.

### How the hunt flows

The hunt begins with a scoping phase using the `hb_vulnerability_finding` surface. It identifies unpatched hosts susceptible to CVE-2026-84869. While patching mitigates the initial vector, the hunt proceeds to check these and other hosts for existing infections that occurred before remediation.

The second phase executes a parallel fan-out across three surfaces to gather independent evidence. The `hb_registry_activity` query searches for rare batch or PowerShell scripts added to Run keys, focusing on entries that appear on three or fewer hosts. Simultaneously, the `hb_process_activity` query looks for the execution of known SCKit components like TrapWatch.ps1 or Lite-Alert.ps1. Finally, the `hb_dns_activity` query correlates host behavior with known malicious relay domains such as ns.mo7sen.dev and sc.payproofkit.com.

An agent then triages the collected evidence. It synthesizes the vulnerability status, persistence signals, and process artifacts to reach a verdict for each endpoint. This approach is necessary because individual signals, like Registry Run keys or PowerShell execution, often appear in legitimate IT support contexts. The hunt confirms an infection only when these signals converge, distinguishing the toolkit from standard maintenance.

### What the hunt cannot see

The hunt relies on comprehensive EDR coverage. Any unmanaged hosts running ScreenConnect will not appear in the registry or process logs, which allows persistence to remain unobserved. Additionally, the RelayTrap component may execute and terminate quickly. If process telemetry is based on snapshot sampling rather than continuous event logging, the hunt might miss short-lived toolkit artifacts.

### How to run it

This hunt is provided as an open `hunt.md` playbook. You can import it directly into Huntbase or any compatible hunt.md-aware runtime. The playbook automates the multi-surface queries and provides the logic for the agent-led triage phase to help you isolate compromised hosts efficiently.
