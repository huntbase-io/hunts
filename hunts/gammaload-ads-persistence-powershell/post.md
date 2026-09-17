# Gamaredon GammaLoad Persistence: ADS and PowerShell Memory-Load

### The Context
Our team has developed this hunt based on recent research from Sekoia.io, [FSB’s Matryoshka: GammaLoad](https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/). The research details how the Gamaredon group (linked to the FSB) utilizes a multi-stage loader architecture to deploy payloads while minimizing on-disk footprints.

### The Hypothesis
We hypothesize that the adversary has established persistence via a scheduled task named 'DsSvcCleanup' (or similar). This task executes code hidden within an Alternate Data Stream (ADS) located in a temporary directory. The execution of this stream triggers an obfuscated PowerShell loader that performs SSL certificate validation bypass and XOR-decryption of an in-memory payload.

### How the Hunt Flows
The hunt begins with a scoping phase on the `hb_devices` surface to identify active Windows hosts, as this campaign is platform-specific. We then move into the primary persistence identification phase.

First, we query the `hb_scheduled_job` surface. We look for the specific 'DsSvcCleanup' task name or any scheduled job where the command line contains a colon character after the drive letter (e.g., `C:\path\file.exe:stream`), which is a primary indicator of Alternate Data Stream execution in temporary or AppData paths.

Next, the hunt pivots to corroborate this activity across three parallel surfaces. We use `hb_file_activity` to find the actual creation events of these ADS files in temp directories. Simultaneously, we perform a prevalence analysis on `hb_process_activity` to find rare PowerShell command-line flag combinations, such as the use of `-NoL`, `-NoP`, and `-Enc` together on a small subset of the fleet.

Finally, we examine `hb_script_activity` for script-level logic. We are looking for specific PowerShell behaviors reported in the GammaLoad stages: the use of `ServerCertificateValidationCallback` to ignore SSL errors and XOR-based decryption routines paired with `DownloadString`. These script blocks are the final confirmation of the memory-load logic.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, it relies on PowerShell ScriptBlock Logging (Event ID 4104). Without this logging enabled, we can see that an encoded command was run, but we cannot verify the XOR or SSL bypass logic within the script. Second, standard file activity logs may not always capture the creation of named streams; visibility into Sysmon Event ID 15 or equivalent EDR telemetry is required for high-confidence ADS detection.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any environment with a hunt.md-aware runtime. It uses a structured approach to pivot from broad persistence markers to specific in-memory execution indicators, providing a high-fidelity look at potential Gamaredon activity in your environment.
