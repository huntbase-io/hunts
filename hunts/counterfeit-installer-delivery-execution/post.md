# Hunting Counterfeit Installer Compromises from Spoofed Software Sites

Recent research from Microsoft titled [Counterfeit installers to system compromise](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/) details how the Silver Fox threat group uses deceptive software download campaigns to compromise systems. The group impersonates popular software like Razer, Edge, and Kaspersky through spoofed domains, delivering malware archives that are regenerated on the server side to evade static detection.

### The Hypothesis
We hypothesize that an intruder has tricked a user into downloading a server-side regenerated malware archive from a spoofed vendor site. This archive then executes a randomized stage-one payload through a common utility like 7-Zip or WinRAR, typically placing the binary in a world-writable directory.

### How the Hunt Flows
The hunt begins by identifying the potential victim profile. We query software inventory to find hosts that already run the legitimate software being impersonated. This scoping step provides context: a user with Razer hardware is far more likely to fall for a fake Razer download lure than one without.

Next, we examine network activity for resolutions to identified brand-spoofing and delivery domains. Because these domains rotate, we do not rely on them alone. Instead, we pivot to process activity, looking for any binary execution occurring in public or program data directories that is rare across the fleet. We are specifically looking for binaries that lack established prevalence and traditional vendor metadata.

The final technical phase looks for the execution 'bridge' — an archive tool like 7-Zip, WinRAR, or 360Zip spawning a child process from a world-writable path. This behavioral pattern is the core indicator of the social engineering chain where the user unzips and runs a manual 'update' or 'installer.'

Finally, the hunt uses an automated triage step to correlate these signals. If a host has recently resolved a lure domain and then shows an archive tool spawning a rare binary, we prioritize that host for isolation and manual review.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, because the malware archives are regenerated server-side for every download, static file hashes are ineffective; we cannot see the malicious nature of the archive before it is extracted. Second, visibility depends on endpoint agent coverage. If a host lacks process-level telemetry, we may see the DNS resolution but will remain blind to the subsequent execution of the payload.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other runtime environment that supports the `hunt.md` standard. The playbook includes the specific domain lists and behavioral queries needed to execute the hunt across your environment, targeting the last 14 days of telemetry.
