# Hunting for RMM Abuse, Renamed Binaries, and Secondary Payloads

### Why now
Legitimate Remote Monitoring and Management (RMM) tools present a significant challenge for security teams because they are, by design, powerful, signed, and frequently excluded from aggressive detection policies. As highlighted by Red Canary in [The dual-use dilemma: Rethinking detection for remote access tool abuse](https://redcanary.com/blog/security-operations/rmm-detection/), the issue isn't just the presence of these tools, but how they are deployed and managed. When an adversary renames a NetSupport binary or sideloads a malicious DLL into a legitimate ITarian process, standard reputation-based alerts often fail.

### The Hypothesis
We are operating under the hypothesis that an adversary has established persistent access using a legitimate RMM tool configured as a service. To evade process monitoring, they may have renamed the binaries or used DLL sideloading (specifically HijackLoader techniques) to hide their activity. Furthermore, we expect the RMM to be a staging point for secondary payloads like DICOMportable or DeerStealer.

### How the Hunt Flows
The hunt begins by examining registry activity to stack-count RMM-related service paths. We look for services like NetSupport or RemotePC running from unusual locations such as `C:\Users\Public`. By aggregating these across the fleet, we can quickly isolate one-off installations that deviate from standard IT deployments.

Next, we pivot to process activity to identify renamed binaries. We compare the internal file description metadata against the actual process name. If a process identifies itself as 'ScreenConnect' or 'SimpleHelp' in its metadata but the executable is named 'Statement.exe' or 'Ecard.exe', it is a high-fidelity indicator of manual evasion and potential phishing lure activity.

We then move into module activity, specifically hunting for DLL sideloading. This phase targets known patterns where RMM processes like ITarian’s `RMMService.exe` load non-system DLLs from writable or non-standard paths. This is a common technique for loaders to execute in the context of a trusted process.

Finally, we search for specific file artifacts. This includes configuration files (like `client32.ini`) and ZIP payloads (like `DICOMportable.zip`) that have been observed in recent ransomware precursor campaigns. The hunt concludes with a triage step to correlate these findings, determining if the RMM usage represents a legitimate tool or an adversary-controlled loader.

### What this hunt cannot see
This hunt has specific limitations. It may miss RMM tools that run entirely in memory or via PowerShell without dropping a persistent binary on disk. There is also a high risk of false positives if internal IT teams rename binaries for their own convenience. Additionally, the sideloading checks rely on module load telemetry; if `hb_module_activity` is not captured, those steps will be ineffective.

### How to run it
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any other `hunt.md`-aware runtime. Because it pivots through multiple surfaces — registry, process, modules, and files — it is best run in environments where historical EDR telemetry is available for at least the last 14 days.
