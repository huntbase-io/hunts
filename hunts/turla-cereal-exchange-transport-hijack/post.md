# Turla Cereal: Hunting Exchange Transport Hijacking and .NET Stealth

### Why now

Recent research from ESET Research titled [Exchange for breakfast: Turla’s Cereal tricks are not for kids](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/) details Turla's use of a sophisticated .NET-based toolset. The adversary targets Microsoft Exchange servers to intercept and collect emails directly from the transport pipeline. This tradecraft is particularly effective because it avoids external C2 beacons by co-opting the server's own mail-handling processes.

### The Hypothesis

An adversary is using sophisticated .NET tradecraft to hijack an Exchange server's mail transport pipeline in memory. The attacker uses local file markers for command processing and stages encrypted archives of collected emails within standard Exchange installation directories.

### How the Hunt Flows

The hunt begins by inventorying every host in the environment running Microsoft Exchange. This ensures the scope covers the correct infrastructure before running deeper, more resource-intensive queries against module and file event logs. This scoping phase identifies hosts with the relevant software packages or vendors in the software inventory surface.

Next, the hunt pivots to identify early stealth indicators. The first path uses the module activity surface to stack-count unsigned DLLs loaded from the .NET Native Image cache. Legitimate Microsoft native images are signed; Turla's modules often appear here as rare, unsigned files across very few hosts. Simultaneously, the hunt looks for CerealHermit command files—unusual .dat or .bin files created in the Exchange Server v15 directory—using the file activity surface.

Once the hunt identifies these early indicators, an analyst triages the hosts to determine if the combination of rare modules and file markers suggests an active intrusion. If suspicious activity is confirmed, the hunt moves to investigate the actual exploitation phase. This involves checking for module injection into the EdgeTransport.exe process. The query identifies modules loaded into the transport service from non-standard paths like ProgramData or temp directories, which indicates a mail pipeline hijack.

Finally, the hunt examines the file activity surface again to find staged espionage data. The adversary creates compressed and encrypted archives (such as .zip, .enc, or .7z files) in Exchange installation paths to hold collected emails before exfiltration. The final triage synthesizes the injection evidence with the presence of these archives to confirm a high-confidence compromise.

### What the Hunt Cannot See

This hunt relies heavily on module load logging. If your environment lacks Sysmon or advanced EDR telemetry for hb_module_activity, the primary indicator of .NET cache abuse remains invisible. Additionally, this hunt identifies the initial injection of malicious modules but cannot see VTable fixups performed in memory. If an adversary hijacks internal structures without loading a new module, standard endpoint telemetry will not capture the event, necessitating memory forensics.

### How to Run the Hunt

This hunt is provided as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any hunt.md-aware runtime. Because the hunt focuses on prevalence-based detection and rare module loads, it distinguishes active intrusions from legitimate administrator behavior that might otherwise trigger false positives in static detection rules. You should run this across your entire Exchange estate, looking back at least 14 days to capture staging patterns.
