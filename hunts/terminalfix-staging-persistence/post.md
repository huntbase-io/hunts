# Hunting for TerminalFix Staging and Persistence Mechanisms

### Background
Microsoft recently detailed the [TerminalFix campaign deploys a reverse tunnel through multistage intrusion](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/), which uses a social engineering lure to trick users into executing PowerShell. This campaign is notable for its use of steganography to hide second-stage payloads and its reliance on DLL sideloading through legitimate Windows binaries. Because these techniques use signed binaries and non-executable file types like PNGs, standard detection rules often fail to see the coordination between the steps.

### The Hypothesis
We hypothesize that an adversary is leveraging fake CAPTCHA lures to execute multi-stage PowerShell commands. These commands establish a staging directory within `ProgramData`, deploy a malicious `dui70.dll` to be sideloaded by `LockScreenContentServer.exe`, and extract the final payload from steganographic images. We expect to find traces of this activity in file creation logs, module load events, and PowerShell script block telemetry.

### Hunt Flow
The hunt begins by scoping active Windows hosts within a 14-day window. This provides the baseline for the subsequent parallel analysis of file, module, and registry surfaces.

First, we look for file staging activity. The campaign uses a specific, unique folder identifier in `ProgramData` and a batch file named `1.bat`. While these names may vary across campaigns, their presence in common staging directories is a primary indicator of initial infection.

Next, we pivot to module load events. The hunt specifically looks for `LockScreenContentServer.exe` loading `dui70.dll` from any path outside of the standard `System32` directory. This is a high-confidence indicator of DLL sideloading and suggests the legitimate binary has been subverted to execute attacker code.

To corroborate the intent, we examine script activity for steganographic logic. The hunt searches for PowerShell script blocks that contain keywords like `extract-rawfilefromimage`, `pixel`, or `RGBA`. These strings indicate the logic required to reassemble an executable from the pixel data of an image file, a core component of the TerminalFix delivery chain.

Finally, we check for redundant persistence mechanisms. The hunt examines the Registry for Run keys using a specific masquerading name, `LockScreenContentServer_MuODG5yBM`. By grouping these findings and looking for rare occurrences across the fleet, we can isolate the specific hosts undergoing active intrusion.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, it relies on `hb_module_activity`, which typically requires Sysmon Event ID 7. If your environment lacks real-time module logging, the point-in-time sideloading event may be missed if the process executes and exits quickly. Second, if the PowerShell extraction logic is heavily obfuscated, simple string matching on `pixel` or `RGBA` will fail to flag the script block.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime environment that supports the `hunt.md` standard. The playbook includes automated triage steps that use an agent to weigh the findings from each surface, providing a malicious, suspicious, or benign verdict per host based on the overlap of indicators.
