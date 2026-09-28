# Gamaredon Modular Espionage: Hunting the Matryoshka Infection Chain

### The Matryoshka Chain
Gamaredon (UAC-0010) operates at a remarkable pace, primarily targeting government infrastructure. Sekoia recently detailed their latest infection lifecycles in "FSB’s matryoshka #1/3: Inside Gamaredon Cyber Operations" (https://www.sekoia.com/blog/fsbs-matryoshka-1-3-gamaredons-gifts-that-keeps-unpacking-gammaphish-and-gammaworm). Their "Matryoshka" approach involves a series of nested loaders and modular components that hide using standard Windows utilities and the registry. This hunt identifies the full chain, from the initial file-based exploit to the final modular stealer.

### The Hypothesis
An intruder exploits a Windows WinRAR path traversal vulnerability to execute HTA-based loaders. They subsequently deploy VBScript stagers, an ADS-resident worm, and a modular PowerShell stealer that maintains persistence in the registry.

### Scoping the Vulnerable Surface
The first phase of the hunt inventories hosts for vulnerable versions of WinRAR (CVE-2025-8088). Identifying these hosts establishes the initial scope. Even without immediate evidence of an exploit, any host with this vulnerability represents a significant risk, as the adversary frequently targets path traversal to drop their first-stage payloads. By isolating these hosts early, we focus the remaining queries on the most likely points of entry.

### Identifying Staging and Persistence
The hunt then searches for active signs of the GammaPhish and GammaLoad stages. We examine process telemetry for mshta.exe execution that reaches out to remote staging URLs or runs files from the user's Startup directory. In parallel, we inspect the registry Run and RunOnce keys for VBScript loaders. This dual approach identifies both the initial execution of the HTA payload and the persistent VBScript stagers used to maintain access before the more advanced modules arrive.

### Detecting the Worm and Modular Stealer
The final phase tracks the transition to post-exploitation and propagation. We hunt for GammaWorm (LitterDrifter) by identifying the creation of Alternate Data Streams and suspicious LNK shortcut files on the filesystem. To find the GammaSteel stealer, we use a volume-based registry query. The adversary stores approximately 71 encrypted PowerShell modules in specific registry keys. By stacking the count of registry values per key path, we identify the high-volume footprint characteristic of this modular framework, which often bypasses traditional signature-based detections.

### Blind Spots and Limitations
This hunt has specific visibility requirements and limitations. Encryption hides the specific logic of the GammaSteel PowerShell modules; while we can detect the existence of the modules via registry write volume, we cannot determine their functional behavior without forensic extraction. Additionally, the hunt depends on the endpoint sensor's ability to resolve NTFS Alternate Data Streams. If the telemetry truncates these stream identifiers, GammaWorm persistence remains invisible. Unmanaged hosts also represent a blind spot, as they can act as silent sources of propagation.

### How to Run the Hunt
This hunt is packaged as an open hunt.md playbook. It imports directly into Huntbase or any hunt.md-aware runtime environment. Because it correlates initial vulnerability status with multi-stage behavioral indicators, it provides a more comprehensive view of the Gamaredon intrusion lifecycle than a collection of disconnected detection rules.
