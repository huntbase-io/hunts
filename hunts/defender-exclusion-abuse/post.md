# Hunting for Microsoft Defender Antivirus Exclusion and Stealth Settings Abuse

### Why this hunt

Adversaries often hide their tools in plain sight by telling the security suite to look elsewhere. In "You Can Run, But You Can't Hide: Defender Exclusions" (https://www.huntress.com/blog/you-can-run-but-you-cant-hide-defender-exclusions), Huntress describes how groups like GootKit and WhisperGate add malicious paths to the Microsoft Defender Antivirus (MDAV) exclusion list. These actors ensure their payloads remain undetected by excluding specific folders like the root drive, Downloads, or Windows Temp. They also use registry flags to prevent local administrators or the SYSTEM user from viewing the current exclusion policy, effectively blinding the local defenders. This hunt identifies these modifications across the fleet to find stealthy persistence and defense evasion.

### Hypothesis

An intruder has modified Microsoft Defender exclusions to shield malicious paths from scanning and enabled stealth settings to hide these changes from local administrators.

### How the hunt flows

The first step identifies every host where Defender exclusions were modified or the local admin hiding policy was set. The query monitors registry activity for changes in the Defender Exclusions key or the HideExclusionsFromLocalAdmins value. It checks for common paths like C:\, C:\Temp, and C:\Users\Public. This scoping phase provides the initial list of suspicious hosts for further investigation.

The hunt then pivots into a prevalence check to filter out legitimate administrative noise. By stack-counting exclusion paths across the fleet, the query highlights paths seen on fewer than five hosts. Corporate-wide IT exclusions for legacy software appear frequently and are easily dismissed, while one-off attacker-defined paths stand out immediately. This baseline allows analysts to focus on unique anomalies.

Simultaneously, the hunt examines process activity for explicit configuration commands. It searches for process launches involving Set-MpPreference or Add-MpPreference. While attackers can use WMI or direct registry writes, these PowerShell cmdlets remain a primary vector for modifying Defender settings. Capturing the parent process and the user context helps determine if the change originated from a legitimate admin tool or a malicious script.

Finally, an analyst or automated agent triages the results to reach a verdict. They correlate the registry writes, the rarity of the paths, and the presence of suspicious command lines. The process compares the timing of these events to find clusters of activity. This multi-surface correlation identifies whether the changes reflect an intentional effort to evade detection or a standard IT deployment. While a standard detection rule might fire on a command line, this hunt correlates the final registry state with fleet-wide frequency to find actors who bypass standard command logging.

### Blind Spots

This hunt relies on visibility into registry activity. If an endpoint agent lacks the permissions to read MDAV-protected registry keys, modifications may go unnoticed. Additionally, if an exclusion is set via a Group Policy Object (GPO) modification on a domain controller, the local logs may attribute the change to the SYSTEM account rather than the original actor account used on the domain controller. There is also a risk if the actor uses direct kernel-level manipulation to bypass registry hooks entirely.

### Running the hunt

This hunt is an open hunt.md playbook. It imports into Huntbase or any compatible runtime that supports the hunt.md specification. It uses registry and process telemetry to detect evasion techniques that a standard detection rule might miss by focusing on fleet-wide prevalence and stealth settings. Once a malicious exclusion is confirmed, the playbook provides instructions for network isolation and the removal of unauthorized preferences via PowerShell.
