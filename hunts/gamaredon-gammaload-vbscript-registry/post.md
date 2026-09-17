# Hunting Gamaredon GammaLoad via Console Registry and VBScript Patterns

Recent analysis by Sekoia.io in their article [FSB’s Matryoshka: Gamaredon GammaLoad](https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/) details the persistent evolution of the Gamaredon group (UAC-0010). A notable component of their toolkit is GammaLoad, a VBScript-based loader that has adopted an unusual method for caching Command and Control (C2) configurations: using the Windows Console registry hive (HKCU\Console). Because this hive is typically reserved for terminal window settings, it often remains unmonitored by standard security configurations, making it an ideal place for stealthy persistence.

### The Hypothesis
Our hunt is built on the hypothesis that Gamaredon maintains stealth by using VBScript loaders to cache C2 addresses within the HKCU\Console registry hive while simultaneously exfiltrating host fingerprints through crafted User-Agent strings. We expect to find these loaders communicating with legitimate Dead Drop Resolvers (DDR) to obtain their final C2 instructions.

### How the Hunt Flows
The first phase focuses on scoping and registry anomalies. We start by identifying Windows systems and then pivot directly into the HKCU\Console registry hive. The hunt looks for specific value names like HistoryURL or CloudURL, which are known GammaLoad markers. To avoid being blinded by legitimate variations, we apply a prevalence filter to find registry value names that appear on only a few hosts across the fleet, as terminal settings should be relatively consistent across similar user profiles.

Once suspicious registry keys are identified, the hunt pivots to script-level telemetry. Using AMSI-sourced data, we look for VBScript execution patterns that utilize the ExecuteGlobal() function. We specifically look for the unique obfuscation style used by Gamaredon, such as the insertion of specific character patterns every 54 characters, and scripts that attempt to read from the Console registry keys identified in the previous step.

In the final investigative phase, we correlate these endpoint artifacts with network activity. We search for DNS queries targeting known Dead Drop Resolvers like Telegraph, Telegram, and various cloud worker domains. The goal is to find temporal overlap where a host modifies a Console registry key and immediately communicates with a DDR, providing high-confidence evidence of an active GammaLoad infection.

### Blind Spots and Limitations
This hunt relies heavily on endpoint telemetry. If the environment lacks visibility into the HKCU registry hive—which is often excluded from high-volume logging to save on ingest costs—the C2 caching behavior will be missed. Furthermore, the script execution phase requires content-level AMSI telemetry (hb_script_activity). Without this, the loader’s execution inside legitimate script hosts like wscript.exe or cscript.exe will remain opaque to the analyst.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. This format allows the logic to be portable and vendor-agnostic. You can import this file directly into Huntbase or any other `hunt.md`-aware runtime to execute the queries across your fleet. Because this is a hunt rather than a detection, it focuses on stacking and correlation to find the 'known-unknowns' that static rules often overlook.
