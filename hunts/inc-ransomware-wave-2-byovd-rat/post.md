# Hunting INC Ransomware Second Wave BYOVD and RAT Tactics

### Why Now

Recent analysis from Huntress in [The Tale of Two INC Ransom Notes: A Ransomware Timeline](https://www.huntress.com/blog/two-inc-ransom-notes) highlights a specific two-wave attack pattern. After an initial access broker establishes persistence, a second actor enters to perform the actual encryption. This second wave relies on specific precursors: the installation of remote access tools (RATs) and the loading of vulnerable drivers to disable security software. We designed this hunt to find these specific transition points.

### The Hypothesis

An adversary has deployed remote access tools and Bring Your Own Vulnerable Driver (BYOVD) loaders to neutralize security products before executing INC ransomware. The actor specifically uses tools like AnyDesk and the HwAudio driver to bypass endpoint protections.

### How the Hunt Flows

The hunt begins with lead scoping using process activity. We look for the deployment of common RATs like AnyDesk, ScreenConnect, or RustDesk. Simultaneously, we inspect process execution from known ransomware staging paths, such as `\users\public\`, `\perflogs\`, and `\programdata\`. This phase identifies the beachhead hosts where the second-wave actor is active.

Once we identify suspicious hosts, the hunt pivots to corroborate defense evasion and impact. We look for the loading of rare kernel modules, specifically targeting the HwAudio driver (`hwauidoos2ec.sys`) and associated loaders. This BYOVD technique is a critical indicator that the adversary is attempting to blind security tools. In parallel, we check for the creation of known INC ransom notes, such as `inc-readme.txt` or `dataleak_press_release.txt`.

An analyst or automated agent then triages these findings. We look for the chronological progression: the RAT appears first, followed by the driver load, and finally the ransom note. This sequence confirms an active infection and allows for immediate host isolation to prevent further encryption.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it depends on telemetry retention. If the adversary waits more than 14 days between installing a RAT and starting the encryption wave—a 17-day lull was observed in the source report—the initial installation events may have rolled off the EDR logs. 

Second, the hunt requires module load visibility. If the environment does not collect Sysmon Event ID 7 or equivalent kernel module telemetry, the BYOVD phase remains invisible. We cannot confirm if the vulnerable driver successfully loaded without these specific events.

### How to Run It

This hunt is available as an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. It uses standard SQL queries against process, module, and file surfaces. Because this focuses on the encryption phase where impact is highest, we recommend running this as a periodic check across your entire fleet.

Source: The Tale of Two INC Ransom Notes: A Ransomware Timeline
