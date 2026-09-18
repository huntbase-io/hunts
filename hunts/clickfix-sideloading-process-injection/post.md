# ClickFix DLL Sideloading and Process Hollowing

### Why now

Recent research by [Elastic Security Labs](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend) titled "From 88 lines to 1: Detecting DLL hijacking with Elastic Defend" highlights a persistent threat: the ClickFix social engineering campaign. This campaign tricks users into running legitimate, signed Microsoft binaries that are susceptible to DLL search order hijacking. Once the legitimate binary loads a malicious library—often a .NET NativeAOT payload—the adversary moves to hide their presence through process hollowing. Traditional detections often struggle with this chain because the initial execution involves trusted tools.

### The Hypothesis

We hypothesize that an adversary is using ClickFix-themed lures to drop a legitimate Microsoft binary (such as the Visual Basic Upgrade tool) and a malicious library named mscoree.dll into a user-writable directory. This execution achieves DLL sideloading, which is subsequently used to inject an infostealer into a hollowed instance of ServiceModelReg.exe.

### How the Hunt Flows

The hunt begins by scoping the environment for hosts capable of running the NativeAOT payload. We use software inventory data to identify workstations with .NET runtimes installed. This narrows our focus to the systems most likely to be targeted by user-centric social engineering lures.

Next, we pivot to module activity to find instances of mscoree.dll being loaded from non-standard directories. By excluding the usual Windows System32, SysWOW64, and Microsoft.NET folders, we isolate cases where a legitimate binary in a folder like `\Public\` or `\AppData\` has sideloaded a local library. This is our primary indicator of search order hijacking.

To corroborate these leads, the hunt executes three parallel checks. We perform a fleet-wide path baseline on the target Microsoft binaries to find rare execution locations. Simultaneously, we inspect PowerShell script blocks for web requests or file-move operations involving these specific filenames. Finally, we look for hollowing signals, specifically looking for ServiceModelReg.exe running with an `on_disk` status of zero, which confirms the payload has been injected into memory.

### What the Hunt Cannot See

This hunt has two primary blind spots. First, it relies heavily on module load telemetry (`ImageLoaded` events). If your endpoint sensors are not configured to monitor module activity, the initial sideloading event will be invisible, and you will have to rely on the follow-on process hollowing signals. Second, if PowerShell script block logging is disabled, the initial staging and download phase of the ClickFix lure cannot be reconstructed, making it harder to identify the source of the infection.

### Why this is a Hunt, not a Detection

This is designed as a hunt because it pivots across multiple telemetry planes—module loads, path prevalence, and process memory states—to verify a behavioral chain. While a single non-system load of a DLL might be a false positive from a developer tool, the combination of a rare execution path and a hollowed process provides the context needed for a high-confidence verdict.

### How to Run it

This hunt is packaged as a `hunt.md` playbook. It can be imported directly into Huntbase or any runtime environment that supports the hunt.md standard. The playbook includes the specific SQL queries for each step and is designed to handle parameters like lookback periods and host scoping.
