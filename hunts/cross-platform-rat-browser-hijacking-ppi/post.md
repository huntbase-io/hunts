# PPI Payloads: Hunting Insomnia RAT and ARKTunnel Steganography

Recent research by Unit 42 titled [Untracked Nightmares: The Threats Hiding Behind Commodity Infrastructure](https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/) highlights how the CL-CRI-1171 campaign (OfferLoader) uses pay-per-install (PPI) networks to deliver sophisticated, cross-platform payloads. These are not just generic adware; the infrastructure drops Node.js/Python RATs and steganography-based tunnels that often go untracked because they appear unrelated to the initial loader. 

### The Hypothesis
We hypothesize that an intruder is using commodity PPI installers—often masquerading as legitimate utilities like WinDirStat or Bluetooth drivers—to deploy second-stage payloads including the Insomnia RAT, ARKTunnel, and the Docro browser hijacker. These tools provide persistent, cross-platform access and use evasive techniques like bitmap steganography to mask their arrival.

### How the Hunt Flows
The hunt begins by scoping endpoints that have executed known trojanized installer filenames. This initial filter prioritizes hosts for deeper behavioral analysis, focusing on the activity occurring shortly after the loader's execution.

To identify the Insomnia RAT, we look for Node.js or Python interpreters running from user-writable paths such as `/appdata/` or `/tmp/`. This is a common indicator of cross-platform agents that do not rely on standard system installations of these languages.

For ARKTunnel, the hunt pivots to file activity. We specifically search for processes reading `.bmp` files within temporary directories where the access count is extremely low. This behavior is indicative of the ARKTunnel routine, which extracts its payload from bitmap images using steganography.

To address the Docro hijacker, we monitor the Chrome extension store paths. We look for file modifications in these sensitive directories performed by processes other than the legitimate browser or updater binaries. This helps identify unauthorized extension sideloading.

Finally, we correlate these findings with known C2 infrastructure and rotational redirector domains associated with the PPI cluster to confirm the campaign's presence.

### Blind Spots and Limitations
This hunt relies on process and file telemetry. It cannot verify the contents of the scripts executed by Node.js or Python on macOS without additional script-block logging. Furthermore, while rare BMP access is a strong behavioral signal, without memory inspection or deep file analysis, we cannot definitively confirm steganographic extraction through telemetry alone.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any `hunt.md`-aware runtime to execute the logic across your fleet. It is designed to work across Windows and macOS, utilizing path normalization to catch cross-platform agents.
